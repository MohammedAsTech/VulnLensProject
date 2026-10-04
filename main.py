"""
VulnLens command-line entry point.

Usage:
    python main.py <file-or-folder>                    # Tier 1 text report
    python main.py <file-or-folder> --ai               # also run the Tier 2 AI layer
    python main.py <file-or-folder> --format json      # machine-readable JSON
    python main.py <file-or-folder> --format sarif      # SARIF for GitHub code scanning

Scans Python files with the Tier 1 rule engine and prints a report.
The report is split into two sections on purpose:
  - CONFIRMED    -> deterministic Tier 1 findings (high confidence)
  - NEEDS REVIEW -> Tier 2 AI heuristic findings (unconfirmed), enabled with --ai
"""
import argparse
import json
import os
import sys

from vulnlens.engine import Finding
from vulnlens import scanner
from vulnlens import ai_layer
from vulnlens import formats
from vulnlens import repo
from vulnlens import summary as summary_mod


MAX_TIER2_FILES = 25   # cap AI review calls per run (one call per file)


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
            taint_tag = "  !! TAINTED FLOW" if f.tainted else ""
            print(f"  [{f.severity:<6}] line {f.line:<4} {f.rule}  ({f.cwe}){taint_tag}")
            print(f"           {f.message}")
            if f.tainted:
                print(f"           >> untrusted input reaches this call (data-flow confirmed)")
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
    parser.add_argument("target", help="A .py/.c/.cpp file, a folder, or a "
                                       "https://github.com/<owner>/<repo> URL.")
    parser.add_argument("--summary", action="store_true",
                        help="Print a repo-level security summary (always on for GitHub URLs). "
                             "With --ai, adds a plain-English narrative.")
    parser.add_argument("--ai", action="store_true",
                        help="Also run the Tier 2 AI heuristic pass and analogy layer.")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                        help="Output format (default: text).")
    args = parser.parse_args(argv)

    if repo.is_github_url(args.target):
        try:
            with repo.cloned(args.target) as root:
                return _run(args, root, repo.repo_name(args.target), summary_on=True)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    return _run(args, args.target, "", summary_on=args.summary)


def _run(args, target: str, repo_label: str, summary_on: bool) -> int:
    if not os.path.exists(target):
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    files = scanner.collect_files(target)
    if not files:
        print("No supported source files (.py, .c/.cpp) found to scan.")
        return 0

    # C++ files without tree-sitter can't be scanned: skip them, and count them as skipped so
    # a repo of C++ files never looks "clean" when nothing was actually analysed.
    skipped = []
    if not scanner.cpp_engine.cpp_available():
        cpp_files = [p for p in files if scanner.language_of(p) == "cpp"]
        if cpp_files:
            print("note: C++ files found but tree-sitter isn't installed; skipping C++. "
                  "Install with: pip install tree-sitter tree-sitter-cpp\n", file=sys.stderr)
            skipped += [os.path.relpath(p, target) if repo_label else p for p in cpp_files]
            files = [p for p in files if p not in cpp_files]

    ai_on = args.ai
    if ai_on and not ai_layer.ai_available():
        print("note: --ai requested but no GROQ_API_KEY / groq SDK found; "
              "running Tier 1 only.\n", file=sys.stderr)
        ai_on = False

    # Scan every file. Store Tier 1 findings and (optionally) Tier 2 review items.
    results, tier2_left = {}, MAX_TIER2_FILES
    for path in files:
        shown = os.path.relpath(path, target) if repo_label else path
        try:
            findings = scanner.scan_file(path)
        except (SyntaxError, ValueError, RecursionError):
            skipped.append(shown.replace(os.sep, "/"))   # e.g. Python 2 code or odd encodings
            continue
        review = []
        if ai_on:
            findings = ai_layer.explain_findings(findings)   # fill analogies
            if tier2_left > 0:
                tier2_left -= 1
                lang = "Python" if scanner.language_of(path) == "python" else "C/C++"
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    review = ai_layer.heuristic_scan(fh.read(), findings, lang)
            elif tier2_left == 0:
                tier2_left = -1   # say it once
                print(f"note: Tier 2 review limited to the first {MAX_TIER2_FILES} files "
                      "to protect free-tier quota.", file=sys.stderr)
        results[shown] = {"findings": findings, "review": review}

    confirmed_total = sum(len(d["findings"]) for d in results.values())

    if skipped:
        shown_names = ", ".join(skipped[:5]) + (" ..." if len(skipped) > 5 else "")
        print(f"warning: {len(skipped)} file(s) were NOT analysed (unparseable or unsupported "
              f"here): {shown_names}", file=sys.stderr)

    summ = summary_mod.build_summary(results, skipped, repo_label) if summary_on else None
    narrative = ai_layer.summarize_repo(summ) if (summ and ai_on) else ""

    # Machine-readable formats: emit only the structured output (nothing else),
    # so the result can be piped straight to a file or a CI tool.
    if args.format == "json":
        out = json.loads(formats.to_json(results))
        if summ:
            out["summary"] = dict(summ, narrative=narrative)
        print(json.dumps(out, indent=2))
        return 1 if confirmed_total else 0
    if args.format == "sarif":
        print(formats.to_sarif(results))
        return 1 if confirmed_total else 0

    # Default: human-readable text report.
    if summ:
        print(summary_mod.format_text(summ, narrative) + "\n")
    print_confirmed(results)
    review_total = print_needs_review(results, ai_on)

    print("\n" + "-" * 70)
    skipped_note = f" {len(skipped)} skipped (not analysed)." if skipped else ""
    print(f"  Scanned {len(results)} file(s).{skipped_note} "
          f"{confirmed_total} confirmed, {review_total} to review.")
    print("-" * 70)

    return 1 if confirmed_total else 0


if __name__ == "__main__":
    sys.exit(main())
