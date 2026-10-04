"""
Repo-level security summary.

build_summary() condenses scan results into plain numbers (deterministic, no AI):
totals by severity / rule / language, how many findings are taint-confirmed, the
riskiest files, and an overall risk rating. format_text() renders it. The optional
AI narrative (ai_layer.summarize_repo) only *describes* these numbers; it never
adds or removes findings.
"""
import os
from collections import Counter

from vulnlens import scanner

_WEIGHT = {"HIGH": 5, "MEDIUM": 2, "LOW": 1}


def _risk_rating(severity: Counter, tainted: int) -> str:
    if severity["HIGH"] and tainted:
        return "HIGH"
    if severity["HIGH"] or tainted or severity["MEDIUM"] >= 5:
        return "MEDIUM"
    if sum(severity.values()):
        return "LOW"
    return "NONE"


def build_summary(results: dict, skipped: list[str] | None = None, name: str = "") -> dict:
    severity, rules, languages, file_score = Counter(), Counter(), Counter(), Counter()
    tainted = 0
    for path, data in results.items():
        languages[scanner.language_of(path)] += 1
        for f in data["findings"]:
            severity[f.severity] += 1
            rules[f"{f.rule} ({f.cwe})"] += 1
            tainted += f.tainted
            file_score[path] += _WEIGHT.get(f.severity, 1) * (2 if f.tainted else 1)
    return {
        "name": name,
        "files_scanned": len(results),
        "languages": dict(languages),
        "total_findings": sum(severity.values()),
        "tainted_findings": tainted,
        "by_severity": {s: severity[s] for s in ("HIGH", "MEDIUM", "LOW")},
        "by_rule": dict(rules.most_common()),
        "riskiest_files": [{"file": p.replace(os.sep, "/"), "score": s}
                           for p, s in file_score.most_common(5)],
        "risk": _risk_rating(severity, tainted),
        "skipped_files": skipped or [],
    }


def format_text(s: dict, narrative: str = "") -> str:
    langs = ", ".join(f"{n} {lang}" for lang, n in s["languages"].items()) or "none"
    sev = s["by_severity"]
    title = f"  SECURITY SUMMARY  -  {s['name']}" if s["name"] else "  SECURITY SUMMARY"
    lines = ["=" * 70, title, "=" * 70,
             f"  Overall risk : {s['risk']}",
             f"  Files scanned: {s['files_scanned']}  ({langs})",
             f"  Findings     : {s['total_findings']}  "
             f"(HIGH {sev['HIGH']}, MEDIUM {sev['MEDIUM']}, LOW {sev['LOW']})",
             f"  Taint-confirmed (untrusted input reaches a sink): {s['tainted_findings']}"]
    if s["by_rule"]:
        lines += ["", "  By rule:"] + [f"    {n:>3}  {r}" for r, n in s["by_rule"].items()]
    if s["riskiest_files"]:
        lines += ["", "  Riskiest files:"] + [f"    {x['file']}  (score {x['score']})"
                                             for x in s["riskiest_files"]]
    if s["skipped_files"]:
        lines += ["", f"  Skipped (could not parse): {len(s['skipped_files'])}"]
    if narrative:
        lines += ["", "  AI narrative (Tier 2, descriptive only):", ""] + \
                 ["    " + ln for ln in narrative.splitlines()]
    return "\n".join(lines)
