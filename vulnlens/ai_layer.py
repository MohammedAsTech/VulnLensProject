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
import json
import os

try:
    from groq import Groq
except ImportError:
    Groq = None

# Groq's free-tier Llama model. Change here if the model name updates.
MODEL = "llama-3.3-70b-versatile"


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
    """One text-in / text-out chat call to Groq."""
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return (resp.choices[0].message.content or "").strip()


# ----------------------------------------------------------------------
# 1. Analogy layer  (one call per confirmed finding)
# ----------------------------------------------------------------------
def explain_findings(findings):
    """Fill finding.analogy for each confirmed finding. Returns findings."""
    client = _get_client()
    if client is None:
        return findings

    for f in findings:
        prompt = (
            "You are explaining a code security issue to someone who does not "
            "code. In ONE short sentence, give a concrete real-world analogy for "
            "this vulnerability. No jargon. Reply with only the sentence.\n\n"
            f"Issue: {f.rule} ({f.cwe}). {f.message}"
        )
        try:
            f.analogy = _generate(client, prompt, max_tokens=80)
        except Exception:
            f.analogy = ""  # stay silent on failure; Tier 1 output is unaffected
    return findings


# ----------------------------------------------------------------------
# 2. Tier 2 heuristic pass
# ----------------------------------------------------------------------
def heuristic_scan(source: str, confirmed) -> list[ReviewItem]:
    """Ask the model for suspicious code the rule engine did not catch."""
    client = _get_client()
    if client is None:
        return []

    already = ", ".join(sorted({f.rule for f in confirmed})) or "none"
    prompt = (
        "You are a Python security reviewer. Below is Python source code. A "
        "deterministic rule engine already flagged these rule types: "
        f"{already}.\n\n"
        "Point out up to 5 OTHER potentially risky patterns it may have missed "
        "(e.g. SQL string building, unvalidated input, unsafe file paths, weak "
        "crypto). Do NOT repeat the already-flagged rule types. If nothing else "
        "looks risky, return an empty array.\n\n"
        "Respond ONLY with a JSON array of objects, each with keys "
        '"line" (int), "issue" (short label), "why" (one sentence). '
        "No prose or markdown outside the JSON.\n\n"
        f"```python\n{source}\n```"
    )
    try:
        text = _generate(client, prompt, max_tokens=600)
        # Be tolerant of markdown fences around the JSON.
        if text.startswith("```"):
            text = text.strip("`")
            text = text[text.find("["):]
        data = json.loads(text)
        return [
            ReviewItem(line=int(d.get("line", 0)),
                       issue=str(d.get("issue", "")).strip(),
                       why=str(d.get("why", "")).strip())
            for d in data
        ]
    except Exception:
        return []  # any parse/API failure -> no Tier 2 output, Tier 1 still fine
