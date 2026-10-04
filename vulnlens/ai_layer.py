"""
VulnLens Tier 2 / AI layer  (Groq via the groq SDK).

Two responsibilities, both strictly *secondary* to the Tier 1 rule engine:

  1. explain_findings(findings)
       For each CONFIRMED Tier 1 finding, make one LLM call that produces a
       short plain-English analogy for non-coders. Purely additive: it fills
       Finding.analogy and never changes the detection.

  2. heuristic_scan(source, confirmed)
       The Tier 2 heuristic pass. Ask the model to flag *suspicious* code that
       the rule engine did NOT catch. These come back labeled "unconfirmed /
       needs review" and are always kept separate from Tier 1's confirmed set.

Design guarantees:
  - The API key is read from the GROQ_API_KEY environment variable.
  - If the SDK isn't installed or the key is missing, every function degrades
    gracefully (returns the input unchanged / an empty list) so Tier 1 always
    works with or without AI.

Note: only THIS module knows which AI provider is used. Swapping providers
(Groq / Gemini / Claude / a local model) touches nothing else in the codebase.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import sys
import time

try:
    from groq import Groq
    from groq import RateLimitError
except ImportError:
    Groq = None
    RateLimitError = None

# Free-tier safety: over-limit calls come back as HTTP 429 (not a charge), so retry
# those with exponential backoff and give up gracefully. (Billing only happens if a
# payment method is added in the Groq Console.)
MAX_RETRIES = 4
MAX_SOURCE_CHARS = 40_000          # don't send huge files to the model
CACHE_PATH = os.path.join(os.path.expanduser("~"), ".vulnlens_ai_cache.json")

# Groq retires models over time. Override without editing code via VULNLENS_MODEL.
MODEL = os.environ.get("VULNLENS_MODEL", "openai/gpt-oss-120b")


def _warn(what: str, err: Exception) -> None:
    """One-line stderr note so a failing AI call isn't completely silent."""
    print(f"warning: AI {what} failed ({type(err).__name__}: {str(err)[:120]})",
          file=sys.stderr)


@dataclass
class ReviewItem:
    """An unconfirmed Tier 2 suggestion. Deliberately NOT a Finding."""
    line: int
    issue: str
    why: str


def _get_client():
    """Return a Groq client, or None if AI is unavailable."""
    if Groq is None:
        return None
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return None
    return Groq(api_key=key)


def ai_available() -> bool:
    return _get_client() is not None


def _generate(client, prompt: str, max_tokens: int) -> str:
    """One text-in / text-out chat call to Groq, retrying on 429 rate limits."""
    extra = {"reasoning_effort": "low"} if "gpt-oss" in MODEL else {}
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens + (1000 if extra else 0),  # headroom for reasoning tokens
                temperature=0.2,
                **extra,
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as e:
            if RateLimitError is None or not isinstance(e, RateLimitError) or attempt == MAX_RETRIES:
                raise
            time.sleep(2 ** attempt)   # 1s, 2s, 4s, 8s


def _cache_load() -> dict:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _cache_save(cache: dict) -> None:
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError:
        pass   # caching is an optimisation only


# ----------------------------------------------------------------------
# 1. Analogy layer  (one call per confirmed finding)
# ----------------------------------------------------------------------
_analogy_cache: dict[str, str] = {}


def explain_findings(findings):
    """Fill finding.analogy for each confirmed finding. Returns findings."""
    client = _get_client()
    if client is None:
        return findings

    by_rule = _analogy_cache   # an analogy depends only on the rule: ask once per rule per run
    for f in findings:
        if f.rule in by_rule:
            f.analogy = by_rule[f.rule]
            continue
        prompt = (
            "You are explaining a code security issue to someone who does not "
            "code. In ONE short sentence, give a concrete real-world analogy for "
            "this vulnerability. No jargon. Reply with only the sentence.\n\n"
            f"Issue: {f.rule} ({f.cwe}). {f.message}"
        )
        try:
            f.analogy = by_rule[f.rule] = _generate(client, prompt, max_tokens=80)
        except Exception as e:
            f.analogy = ""  # Tier 1 output is unaffected; just note the failure
            _warn("analogy", e)
            break
    return findings


# ----------------------------------------------------------------------
# 2. Tier 2 heuristic pass
# ----------------------------------------------------------------------
def heuristic_scan(source: str, confirmed, language: str = "Python") -> list[ReviewItem]:
    """Ask the model for suspicious code the rule engine did not catch."""
    client = _get_client()
    if client is None:
        return []

    if len(source) > MAX_SOURCE_CHARS:
        return []

    already = ", ".join(sorted({f.rule for f in confirmed})) or "none"
    # Skip the API for unchanged code: key on file content + flagged rules + model.
    key = hashlib.sha256(f"v2|{MODEL}|{language}|{already}|{source}".encode("utf-8", "replace")).hexdigest()
    cache = _cache_load()
    if key in cache:
        return [ReviewItem(**d) for d in cache[key]]
    # Number the lines: models can't reliably count them, so their "line" answers drift.
    numbered = "\n".join(f"{n}: {ln}" for n, ln in enumerate(source.splitlines(), 1))
    prompt = (
        f"You are a {language} security reviewer. Below is {language} source code. A "
        "deterministic rule engine already flagged these rule types: "
        f"{already}.\n\n"
        "Point out up to 5 OTHER potentially risky patterns it may have missed "
        "(e.g. SQL string building, unvalidated input, unsafe file paths, weak "
        "crypto, memory safety). Do NOT repeat the already-flagged rule types. If nothing else "
        "looks risky, return an empty array.\n\n"
        "Respond ONLY with a JSON array of objects, each with keys "
        '"line" (int), "issue" (short label), "why" (one sentence). '
        'Each source line is prefixed with its line number ("N: "); use those numbers '
        'for "line". No prose or markdown outside the JSON.\n\n'
        f"```\n{numbered}\n```"
    )
    try:
        text = _generate(client, prompt, max_tokens=600)
        # Be tolerant of markdown fences around the JSON.
        if text.startswith("```"):
            text = text.strip("`")
            text = text[text.find("["):]
        data = json.loads(text)
        items = [
            ReviewItem(line=int(d.get("line", 0)),
                       issue=str(d.get("issue", "")).strip(),
                       why=str(d.get("why", "")).strip())
            for d in data
        ]
        cache[key] = [vars(i) for i in items]
        _cache_save(cache)
        return items
    except Exception as e:
        _warn("heuristic review", e)
        return []  # any parse/API failure -> no Tier 2 output, Tier 1 still fine


# ----------------------------------------------------------------------
# 3. Repo security summary narrative
# ----------------------------------------------------------------------
def summarize_repo(summary: dict) -> str:
    """Short plain-English security overview of a repo, from Tier 1 numbers only."""
    client = _get_client()
    if client is None:
        return ""
    prompt = (
        "You are a security engineer. Below are deterministic static-analysis "
        "results for a code repository (JSON). Write a concise security summary "
        "(max 120 words): overall posture, the most important risks, and the top "
        "2-3 things to fix first. Plain text only: no markdown, no headings, no "
        "bold, no title. Use ONLY the facts in the JSON; do not invent "
        "findings or files.\n\n" + json.dumps(summary, indent=2)
    )
    try:
        return _generate(client, prompt, max_tokens=400)
    except Exception as e:
        _warn("summary", e)
        return ""
