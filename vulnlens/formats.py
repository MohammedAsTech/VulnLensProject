"""
Output formatters for VulnLens.

- to_json:  simple machine-readable JSON (confirmed findings + any review items).
- to_sarif: SARIF 2.1.0, the standard format GitHub code scanning ingests, so
            findings show up as alerts in the repo's Security tab.

Both take the `results` dict built in main.py:
    { file_path: {"findings": [Finding, ...], "review": [ReviewItem, ...]} }
"""
import json

from vulnlens.rules import RULES

# SARIF uses "error"/"warning"/"note"; GitHub also reads a numeric
# security-severity (0-10) to sort alerts.
_SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_SECURITY_SEVERITY = {"HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0"}


def _cwe_url(cwe: str) -> str:
    num = cwe.split("-")[-1]
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def _uri(path: str) -> str:
    # SARIF wants forward-slash relative paths.
    return path.replace("\\", "/").lstrip("./")


def to_json(results: dict) -> str:
    out = {"tool": "VulnLens", "confirmed": [], "needs_review": []}
    for path, data in results.items():
        for f in data["findings"]:
            out["confirmed"].append({
                "file": _uri(path), "line": f.line, "rule": f.rule,
                "cwe": f.cwe, "severity": f.severity,
                "tainted": f.tainted,
                "message": f.message, "fix": f.fix,
            })
        for it in data.get("review", []):
            out["needs_review"].append({
                "file": _uri(path), "line": it.line,
                "issue": it.issue, "why": it.why,
            })
    return json.dumps(out, indent=2)


def to_sarif(results: dict) -> str:
    # Describe every rule once in the tool driver.
    rules = []
    for rule_id, meta in RULES.items():
        rules.append({
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": meta["message"]},
            "helpUri": _cwe_url(meta["cwe"]),
            "properties": {
                "cwe": meta["cwe"],
                "security-severity": _SECURITY_SEVERITY.get(meta["severity"], "5.0"),
            },
        })

    sarif_results = []
    for path, data in results.items():
        for f in data["findings"]:
            sarif_results.append({
                "ruleId": f.rule,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.message} Fix: {f.fix}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(path)},
                        "region": {"startLine": f.line},
                    }
                }],
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "VulnLens",
                "informationUri": "https://github.com/MohammedAsTech/VulnLensProject",
                "version": "0.1.0",
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)
