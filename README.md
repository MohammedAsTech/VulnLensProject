# VulnLens

[![VulnLens Security Scan](https://github.com/MohammedAsTech/VulnLensProject/actions/workflows/vulnlens.yml/badge.svg)](https://github.com/MohammedAsTech/VulnLensProject/actions/workflows/vulnlens.yml) ![License: MIT](https://img.shields.io/badge/license-MIT-green)

A static-analysis security scanner for Python and C/C++ that tells confirmed vulnerabilities apart from AI guesses.

I built it to learn how SAST tools actually work: parsing code into syntax trees, tracking untrusted data to dangerous calls, and emitting results CI systems understand. It is a learning project with a small rule set, not a replacement for Bandit, Semgrep or CodeQL (see [Known limitations](#known-limitations)).

**What it does**

- **Tier 1, deterministic:** 14 rules mapped to CWEs. Python is parsed with the standard-library `ast`, C/C++ with [tree-sitter](https://tree-sitter.github.io/). Intraprocedural taint tracking flags findings where untrusted input actually reaches a dangerous call.
- **Tier 2, optional AI (Groq):** suggests suspicious code the rules missed. It is always kept separate from confirmed findings and never affects the exit code.
- **Repo summaries:** give it a GitHub URL and it clones, scans and prints a risk summary.
- **CI-ready:** text, JSON and [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output. A GitHub Actions workflow uploads SARIF to code scanning, and 70 pytest tests run on every push.

## Quick start

Requires Python 3.10+. The Python scanner needs no dependencies.

```bash
git clone https://github.com/MohammedAsTech/VulnLensProject.git
cd VulnLensProject
python main.py tests/vulnerable_samples/            # scan a folder
python main.py https://github.com/owner/repo        # security summary of a GitHub repo
python -m pip install pytest && python -m pytest    # run the tests
```

Optional extras: `pip install tree-sitter tree-sitter-cpp` for C/C++, `pip install groq` for `--ai` (or `pip install -r requirements.txt` for both).

## Usage

```bash
python main.py <file | folder | github-url> [--ai] [--summary] [--format text|json|sarif]
```

| Command | Result |
|---|---|
| `python main.py src/` | Text report |
| `python main.py src/ --format json > report.json` | Structured JSON, nothing else printed |
| `python main.py . --format sarif > vulnlens.sarif` | SARIF for GitHub code scanning |
| `python main.py src/ --summary` | Adds a repo-level risk summary |
| `python main.py src/ --ai` | Adds analogies to findings and a separate *needs review* section |

**GitHub repos:** a `https://github.com/<owner>/<repo>` URL is shallow-cloned to a temp directory (nothing in it is executed), scanned, summarised, and deleted. Unparseable files, such as Python 2 code, are skipped and counted instead of aborting the scan. Requires `git` on your PATH.

**AI setup:** set `GROQ_API_KEY` (PowerShell: `$env:GROQ_API_KEY="..."`). The default model is `openai/gpt-oss-120b`; override it with `VULNLENS_MODEL` since Groq retires models over time. Without a key, VulnLens runs Tier 1 only. To stay within free-tier limits it retries 429 responses with backoff, asks for one analogy per rule, caches Tier 2 results by file hash, skips files over 40k characters, and reviews at most 25 files per run.

**Exit codes:** `0` nothing found (or no supported files), `1` at least one confirmed finding, `2` path not found.

### Rules

| Language | Rules |
|---|---|
| Python | `dangerous-eval` (CWE-95), `shell-injection` (CWE-78), `unsafe-deserialization` (CWE-502), `weak-random` (CWE-330), `hardcoded-secret` (CWE-798), `weak-hash` (CWE-327), `unsafe-yaml-load` (CWE-502), `insecure-request` (CWE-295) |
| C/C++ | `cpp-buffer-overflow` (CWE-120), `cpp-command-injection` (CWE-78), `cpp-weak-random` (CWE-330), `cpp-format-string` (CWE-134), `cpp-hardcoded-secret` (CWE-798), `cpp-weak-hash` (CWE-327) |

Import aliases are resolved, so `import os as o; o.system(...)` and `from os import system` are caught like `os.system(...)`.

## Sample output

```text
$ python main.py tests/vulnerable_samples/taint_sample.py
tests/vulnerable_samples/taint_sample.py
  [HIGH  ] line 12   dangerous-eval  (CWE-95)  !! TAINTED FLOW
           eval()/exec() executes arbitrary code from its input.
           >> untrusted input reaches this call (data-flow confirmed)
           fix: Avoid eval/exec on untrusted input; use ast.literal_eval or explicit parsing.
  [HIGH  ] line 17   dangerous-eval  (CWE-95)
           eval()/exec() executes arbitrary code from its input.
           fix: Avoid eval/exec on untrusted input; use ast.literal_eval or explicit parsing.
  ...
  Scanned 1 file(s). 4 confirmed, 0 to review.
```

Line 12 is tagged `TAINTED FLOW` because a function parameter flows into `eval`. Line 17 is the same dangerous call fed only a constant: still worth a look, but lower priority.

Repo summary, from `python main.py https://github.com/MohammedAsTech/VulnLensProject` (VulnLens scanning itself; the findings come from the deliberately vulnerable files under `tests/`):

```text
  SECURITY SUMMARY  -  MohammedAsTech/VulnLensProject
  Overall risk : HIGH
  Files scanned: 27  (22 python, 5 cpp)
  Findings     : 28  (HIGH 19, MEDIUM 9, LOW 0)
  Taint-confirmed (untrusted input reaches a sink): 20
  Riskiest files:
    tests/cpp_samples/vuln_sample.cpp  (score 32)
    tests/vulnerable_samples/aliased_sample.py  (score 30)
```

## Design: confirmed vs. needs review

Static analysers lose trust when deterministic results and guesses share one list. VulnLens keeps them apart:

- **Confirmed (Tier 1):** every finding fires on a specific syntax-tree pattern, so the same input always gives the same output. Only these drive CI, the exit code, and the `confirmed` results in JSON/SARIF.
- **Needs review (Tier 2):** an LLM can spot things rules don't cover (SQL string building, unsafe paths) but is non-deterministic and can hallucinate. Its output uses a different type (`ReviewItem`, not `Finding`), is labelled unconfirmed, and only appears with `--ai`.
- **The AI never changes detection.** It only adds an explanation to findings the rules already confirmed.
- **The provider is isolated.** Only `vulnlens/ai_layer.py` knows about Groq.

Both language engines return the same `Finding` objects, so reporting, JSON, SARIF and CI are shared and adding a language means adding an engine.

## Testing

`tests/test_vulnlens.py` (70 tests) pins the exact rule, line and taint flag for every sample file, checks that safe counterparts (`ast.literal_eval`, `strncpy`, `printf("%s", x)`) are not flagged, validates JSON and SARIF structure, covers CLI exit codes, and tests the failure paths: no API key, missing tree-sitter, rate limits, bad repo URLs. AI calls are tested against a fake client, so the suite needs no network or key.

## Project layout

```text
main.py                  CLI entry point and text report
vulnlens/
  scanner.py             language dispatch (by file extension)
  engine.py              Python AST rule engine + taint tracking
  cpp_engine.py          C/C++ tree-sitter engine
  rules.json             rule metadata (CWE, severity, message, fix)
  formats.py             JSON and SARIF output
  repo.py, summary.py    GitHub clone + repo-level summary
  ai_layer.py            Tier 2 (Groq): analogies, review, narrative
tests/                   pytest suite + vulnerable_samples/ and cpp_samples/
```

## Known limitations

- **Small, unbenchmarked rule set.** 14 rules, tested on hand-written samples. I haven't measured false-positive or false-negative rates on real-world code.
- **Indirect calls are missed.** Calls are matched by name, so `fn = getattr(os, "system"); fn(cmd)` gives no finding.
- **Taint is intraprocedural only.** It does not cross function boundaries. A nested function that uses its outer function's tainted variable is still flagged, but loses the `TAINTED FLOW` tag.
- **Secret detection is name-based.** A variable named `token`, `password`, `api_key` and similar assigned a string literal is flagged. There is no entropy or key-format check, so it can false-positive (`token = "Bearer"`) and miss secrets under other names.
- **Tier 2 is heuristic.** AI suggestions may be wrong, which is why they are kept out of the confirmed results.

## What I'd build next

1. Interprocedural taint (follow data through function calls).
2. Measure precision and recall against a known-vulnerable benchmark and compare with Bandit.
3. More rules, starting with SQL injection, plus `pip`-installable packaging.

## License

MIT. See [LICENSE](LICENSE).
