# VulnLens

[![VulnLens Security Scan](https://github.com/MohammedAsTech/VulnLensProject/actions/workflows/vulnlens.yml/badge.svg)](https://github.com/MohammedAsTech/VulnLensProject/actions/workflows/vulnlens.yml) ![License: MIT](https://img.shields.io/badge/license-MIT-green)

A two-tier static-analysis security scanner for Python and C/C++.

- **Tier 1** is a deterministic rule engine. Python is analysed with the standard-library `ast` module and C/C++ with [tree-sitter](https://tree-sitter.github.io/). It includes intraprocedural taint tracking, so findings where untrusted input actually reaches a dangerous call are flagged and prioritised.
- **Tier 2** is an optional LLM heuristic pass (Groq). It suggests suspicious code the rules missed, and it is **always kept separate** from confirmed findings.

Output formats: human-readable text, JSON, and [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html). A GitHub Actions workflow uploads the SARIF to GitHub code scanning so findings show up in the Security tab.

## Features

- 8 Python rules and 6 C/C++ rules, each mapped to a CWE and a severity (see [`vulnlens/rules.json`](vulnlens/rules.json)).
- Import-alias resolution: `import os as o; o.system(...)` and `from os import system` are detected the same as `os.system(...)`.
- Intraprocedural taint analysis: `TAINTED FLOW` marks findings where a function parameter or `input()` value reaches a sink.
- Language dispatch layer: both engines return the same `Finding` objects, so reporting, JSON, SARIF and CI are shared.
- Graceful degradation: no Groq key means Tier 1 only, and no tree-sitter means C/C++ files are skipped with a warning.
- Exit codes suitable for CI (see below).

### Rules

| Language | Rules |
|---|---|
| Python | `dangerous-eval` (CWE-95), `shell-injection` (CWE-78), `unsafe-deserialization` (CWE-502), `weak-random` (CWE-330), `hardcoded-secret` (CWE-798), `weak-hash` (CWE-327), `unsafe-yaml-load` (CWE-502), `insecure-request` (CWE-295) |
| C/C++ | `cpp-buffer-overflow` (CWE-120), `cpp-command-injection` (CWE-78), `cpp-weak-random` (CWE-330), `cpp-format-string` (CWE-134), `cpp-hardcoded-secret` (CWE-798), `cpp-weak-hash` (CWE-327) |

## Install

Requires Python 3.10+. The core Python scanner uses only the standard library.

```bash
git clone https://github.com/MohammedAsTech/VulnLensProject.git
cd VulnLensProject
```

Optional extras:

```bash
pip install tree-sitter tree-sitter-cpp   # C/C++ scanning
pip install groq                          # Tier 2 AI layer (--ai)
# or everything at once:
pip install -r requirements.txt
```

## Usage

```bash
python main.py <file-or-folder> [--ai] [--format text|json|sarif]
```

**Text report (default)**

```bash
python main.py tests/vulnerable_samples/
```

**JSON**: only structured output is printed, so it can be piped to a file or another tool.

```bash
python main.py src/ --format json > report.json
```

**SARIF 2.1.0**: for GitHub code scanning or any SARIF viewer.

```bash
python main.py . --format sarif > vulnlens.sarif
```

**Tier 2 AI pass**: adds plain-English analogies to confirmed findings and a separate *needs review* section.

```bash
export GROQ_API_KEY=your_key_here     # PowerShell: $env:GROQ_API_KEY="your_key_here"
python main.py src/ --ai
```

**Security summary of a GitHub repo**: pass a `https://github.com/<owner>/<repo>` URL. VulnLens shallow-clones it to a temp directory (nothing in it is executed), scans every Python and C/C++ file, prints a summary, then deletes the clone. `--summary` gives the same summary for a local path.

```bash
python main.py https://github.com/owner/repo
python main.py https://github.com/owner/repo --ai --format json   # summary + AI narrative in JSON
```

The summary is computed deterministically: overall risk rating, files and languages scanned, findings by severity and rule, how many are taint-confirmed, and the riskiest files. With `--ai`, a short plain-English narrative is added. It only describes those numbers and never adds findings. Files that can't be parsed (for example Python 2 code) are skipped and counted instead of aborting the scan. Requires `git` on your PATH.

**AI model and free-tier safeguards**: the default model is `openai/gpt-oss-120b`. Groq retires models from time to time, so override it with `VULNLENS_MODEL` (list what your key can use with `client.models.list()`). To stay inside free-tier limits, VulnLens retries HTTP 429 rate-limit responses with exponential backoff, asks for one analogy per rule rather than per finding, caches Tier 2 results by file hash (`~/.vulnlens_ai_cache.json`) so unchanged files cost nothing on re-runs, and skips files over 40k characters. Billing only starts if you add a payment method in the Groq Console.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing found, or no supported files in the target |
| `1` | At least one confirmed (Tier 1) finding |
| `2` | Target path does not exist |

Tier 2 suggestions never affect the exit code.

## Sample output

```text
$ python main.py tests/vulnerable_samples/taint_sample.py
======================================================================
  CONFIRMED FINDINGS  (Tier 1 - deterministic rule engine)
======================================================================

tests/vulnerable_samples/taint_sample.py
  [HIGH  ] line 12   dangerous-eval  (CWE-95)  !! TAINTED FLOW
           eval()/exec() executes arbitrary code from its input.
           >> untrusted input reaches this call (data-flow confirmed)
           fix: Avoid eval/exec on untrusted input; use ast.literal_eval or explicit parsing.
  [HIGH  ] line 17   dangerous-eval  (CWE-95)
           eval()/exec() executes arbitrary code from its input.
           fix: Avoid eval/exec on untrusted input; use ast.literal_eval or explicit parsing.
  [HIGH  ] line 23   shell-injection  (CWE-78)  !! TAINTED FLOW
           A shell command built from input can be hijacked to run extra commands.
           >> untrusted input reaches this call (data-flow confirmed)
           fix: Use subprocess.run with an argument list; avoid os.system and shell=True.
  [HIGH  ] line 28   shell-injection  (CWE-78)
           A shell command built from input can be hijacked to run extra commands.
           fix: Use subprocess.run with an argument list; avoid os.system and shell=True.

======================================================================
  NEEDS REVIEW  (Tier 2 - AI heuristic pass, unconfirmed)
======================================================================

  Tier 2 disabled. Re-run with --ai to enable.

----------------------------------------------------------------------
  Scanned 1 file(s). 4 confirmed, 0 to review.
----------------------------------------------------------------------
```

Lines 12 and 23 carry the `TAINTED FLOW` tag because a function parameter flows into the sink. Lines 17 and 28 are the same dangerous calls fed only constants: still worth a look, but lower priority.

JSON output:

```json
{
  "tool": "VulnLens",
  "confirmed": [
    {
      "file": "tests/vulnerable_samples/shell_sample.py",
      "line": 8,
      "rule": "shell-injection",
      "cwe": "CWE-78",
      "severity": "HIGH",
      "tainted": true,
      "message": "A shell command built from input can be hijacked to run extra commands.",
      "fix": "Use subprocess.run with an argument list; avoid os.system and shell=True."
    }
  ],
  "needs_review": []
}
```

## Demo: summarising a GitHub repo

Real output from `python main.py https://github.com/MohammedAsTech/VulnLensProject` (VulnLens scanning its own repo; the findings come from the deliberately vulnerable files under `tests/`):

```text
======================================================================
  SECURITY SUMMARY  -  MohammedAsTech/VulnLensProject
======================================================================
  Overall risk : HIGH
  Files scanned: 27  (22 python, 5 cpp)
  Findings     : 28  (HIGH 19, MEDIUM 9, LOW 0)
  Taint-confirmed (untrusted input reaches a sink): 20

  By rule:
      6  shell-injection (CWE-78)
      5  cpp-command-injection (CWE-78)
      3  dangerous-eval (CWE-95)
      ...

  Riskiest files:
    tests/cpp_samples/vuln_sample.cpp  (score 32)
    tests/vulnerable_samples/aliased_sample.py  (score 30)
    tests/vulnerable_samples/taint_sample.py  (score 30)
```

The test suite (`pytest`, 50 tests) pins the exact rule, line and taint flag for every sample file, so a regression in any rule or in the taint tracker fails CI.

## GitHub Actions / code scanning

[`.github/workflows/vulnlens.yml`](.github/workflows/vulnlens.yml) scans the repository on every push and pull request to `main`, writes SARIF, and uploads it with `github/codeql-action/upload-sarif`. The scan step uses `continue-on-error` because the scanner exits `1` when it finds something, and the upload must still run.

## Design: confirmed vs. needs review

Static analysers lose trust when deterministic results and guesses are mixed in one list. VulnLens keeps them apart on purpose:

- **Confirmed (Tier 1)**: every finding fires on a specific AST pattern, so the same input always produces the same output. These are safe to gate CI on, and they alone drive the exit code and the JSON/SARIF `confirmed` results.
- **Needs review (Tier 2)**: an LLM is good at spotting patterns a rule set does not cover (SQL string building, unsafe file paths) but is non-deterministic and can hallucinate. Its output is labelled *unconfirmed*, uses a different type (`ReviewItem`, not `Finding`), is never counted in the exit code, and is only shown when the user asks for it with `--ai`.
- **The AI never changes detection.** The analogy layer only fills in an explanatory sentence on findings the rules already confirmed.
- **The provider is isolated.** Only `vulnlens/ai_layer.py` knows about Groq; swapping providers touches nothing else.

## Project layout

```text
main.py                  CLI entry point and text report
vulnlens/
  scanner.py             language dispatch (by file extension)
  engine.py              Python AST rule engine + taint tracking
  cpp_engine.py          C/C++ tree-sitter engine
  rules.json             rule metadata (CWE, severity, message, fix)
  formats.py             JSON and SARIF serialisation
  ai_layer.py            Tier 2 (Groq): analogies + heuristic review
tests/
  vulnerable_samples/    Python samples
  cpp_samples/           C/C++ samples
```

Detection logic lives in the engines, and rule metadata lives in `rules.json`.

## Known limitations

VulnLens is a pattern-based scanner, not a full program analyser. Known gaps:

- **Indirect calls are missed.** Calls are matched by name, so `fn = getattr(os, "system"); fn(cmd)` produces no finding.
- **Taint is intraprocedural only.** Taint does not cross function boundaries. A nested function that uses its outer function's tainted variable is still flagged, but it loses the `TAINTED FLOW` tag.
- **Secret detection is name-based.** The `hardcoded-secret` rule fires when a variable named like `token`, `password`, `secret`, `api_key` and similar is assigned a string literal. It does not measure entropy or match key formats, so it can false-positive (for example `token = "Bearer"`) and can miss secrets stored under other names.
- **Tier 2 is heuristic.** LLM suggestions may be wrong or incomplete, which is why they are kept out of the confirmed results.

## License

MIT. See [LICENSE](LICENSE).
