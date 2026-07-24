"""
VulnLens command-line entry point.

Usage:
    python main.py <file-or-folder>          # Tier 1 only (fast, offline)
    python main.py <file-or-folder> --ai     # also run the Tier 2 AI layer

Scans Python files with the Tier 1 rule engine and prints a report.
The report is split into two sections on purpose:
  - CONFIRMED    -> deterministic Tier 1 findings (high confidence)
  - NEEDS REVIEW -> Tier 2 AI heuristic findings (unconfirmed), enabled with --ai
"""
import argparse
import os
import sys

from vulnlens.engine import scan_source, Finding
from vulnlens import ai_layer


def collect_python_files(target: str) -> list[str]:
    """Return a list of .py files for a single file or a whole folder."""
    if os.path.isfile(target):
        return [target] if target.endswith(".py") else []
    files = []
    for root, _dirs, names in os.walk(target):
        for name in names:
            if name.endswith(".py"):
                files.append(os.path.join(root, name))
    return sorted(files)


def severity_rank(finding: Finding) -> int:
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return order.get(finding.severity, 3)


def print_confirmed(results: dict) -> int:
    total = 0
    print("=" * 70)
    print("  CONFIRMED FINDINGS  (Tier 1 - deterministic rule engine)")
    print("=" * 70)

    any_found = False
    for path, data in results.items():
        findings = data["findings"]
        if not findings:
            continue
        any_found = True
        print(f"\n{path}")
        for f in sorted(findings, key=severity_rank):
            total += 1
            print(f"  [{f.severity:<6}] line {f.line:<4} {f.rule}  ({f.cwe})")
            print(f"           {f.message}")
            print(f"           fix: {f.fix}")
            if f.analogy:
                print(f"           in plain terms: {f.analogy}")

    if not any_found:
        print("\n  No confirmed issues found.")
    return total


def print_needs_review(results: dict, ai_on: bool) -> int:
    print("\n" + "=" * 70)
    print("  NEEDS REVIEW  (Tier 2 - AI heuristic pass, unconfirmed)")
    print("=" * 70)

    if not ai_on:
        print("\n  Tier 2 disabled. Re-run with --ai to enable.")
        return 0

    total = 0
    any_found = False
    for path, data in results.items():
        items = data["review"]
        if not items:
            continue
        any_found = True
        print(f"\n{path}")
        for it in items:
            total += 1
            print(f"  [REVIEW] line {it.line:<4} {it.issue}")
            print(f"           {it.why}")

    if not any_found:
        print("\n  No additional suspicious patterns flagged.")
    return total


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnlens",
        description="Scan Python code for security issues (Tier 1 rules + optional Tier 2 AI).",
    )
    parser.add_argument("target", help="A .py file or a folder to scan.")
    parser.add_argument("--ai", action="store_true",
                        help="Also run the Tier 2 AI heuristic pass and analogy layer.")
    args = parser.parse_args(argv)

    if not os.path.exists(args.target):
        print(f"error: path not found: {args.target}", file=sys.stderr)
        return 2

    files = collect_python_files(args.target)
    if not files:
        print("No Python files found to scan.")
        return 0

    ai_on = args.ai
    if ai_on and not ai_layer.ai_available():
        print("note: --ai requested but no GROQ_API_KEY / groq SDK found; "
              "running Tier 1 only.\n", file=sys.stderr)
        ai_on = False

    # Scan every file. Store Tier 1 findings and (optionally) Tier 2 review items.
    results = {}
    for path in files:
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
        findings = scan_source(source)
        review = []
        if ai_on:
            findings = ai_layer.explain_findings(findings)   # fill analogies
            review = ai_layer.heuristic_scan(source, findings)
        results[path] = {"findings": findings, "review": review}

    confirmed_total = print_confirmed(results)
    review_total = print_needs_review(results, ai_on)

    print("\n" + "-" * 70)
    print(f"  Scanned {len(files)} file(s). "
          f"{confirmed_total} confirmed, {review_total} to review.")
    print("-" * 70)

    return 1 if confirmed_total else 0


if __name__ == "__main__":
    sys.exit(main())
