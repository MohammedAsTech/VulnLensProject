"""Automated tests for VulnLens: detection, taint, safe code, output formats, CLI, degradation."""
import json
import os

import pytest

import main as cli
from vulnlens import scanner

HERE = os.path.dirname(os.path.abspath(__file__))
PY_DIR = os.path.join(HERE, "vulnerable_samples")
CPP_DIR = os.path.join(HERE, "cpp_samples")

needs_cpp = pytest.mark.skipif(not scanner.cpp_engine.cpp_available(),
                               reason="tree-sitter / tree-sitter-cpp not installed")

# file -> sorted list of (rule, line, tainted). Safe counterparts in each sample must NOT appear.
PY_EXPECTED = {
    "aliased_sample.py": [("shell-injection", 13, True), ("shell-injection", 18, True),
                          ("unsafe-deserialization", 23, True)],
    "eval_sample.py": [("dangerous-eval", 6, True)],              # ast.literal_eval (line 13) is safe
    "hash_sample.py": [("weak-hash", 7, True)],                   # sha256 is safe
    "pickle_sample.py": [("unsafe-deserialization", 8, True)],    # json.loads is safe
    "random_sample.py": [("weak-random", 8, False)],              # secrets is safe
    "request_sample.py": [("insecure-request", 7, True)],
    "secret_sample.py": [("hardcoded-secret", 6, False), ("hardcoded-secret", 7, False)],
    "shell_sample.py": [("shell-injection", 8, True), ("shell-injection", 13, True)],  # arg list is safe
    "taint_sample.py": [("dangerous-eval", 12, True), ("dangerous-eval", 17, False),
                        ("shell-injection", 23, True), ("shell-injection", 28, False)],
    "yaml_sample.py": [("unsafe-yaml-load", 7, True)],            # safe_load is safe
}

CPP_EXPECTED = {
    "aliased_sample.cpp": [("cpp-command-injection", 7, True)],
    "hash_sample.cpp": [("cpp-weak-hash", 6, True), ("cpp-weak-hash", 7, True)],
    "secret_sample.cpp": [("cpp-hardcoded-secret", 5, False)],
    "taint_sample.cpp": [("cpp-command-injection", 7, True), ("cpp-command-injection", 12, False),
                         ("cpp-command-injection", 18, True)],
    # strncpy (14) and printf("%s", x) (23) are safe and must not be flagged.
    "vuln_sample.cpp": [("cpp-buffer-overflow", 9, True), ("cpp-command-injection", 18, True),
                        ("cpp-format-string", 22, True), ("cpp-weak-random", 27, False)],
}


def triples(path):
    return sorted((f.rule, f.line, f.tainted) for f in scanner.scan_file(path))


def test_every_sample_has_an_expectation():
    assert set(PY_EXPECTED) == set(os.listdir(PY_DIR))
    assert set(CPP_EXPECTED) == set(os.listdir(CPP_DIR))


@pytest.mark.parametrize("name", sorted(PY_EXPECTED))
def test_python_samples(name):
    assert triples(os.path.join(PY_DIR, name)) == sorted(PY_EXPECTED[name])


@needs_cpp
@pytest.mark.parametrize("name", sorted(CPP_EXPECTED))
def test_cpp_samples(name):
    assert triples(os.path.join(CPP_DIR, name)) == sorted(CPP_EXPECTED[name])


# ---- taint ----------------------------------------------------------------
def test_python_taint_cases():
    by_line = {f.line: f.tainted for f in scanner.scan_file(os.path.join(PY_DIR, "taint_sample.py"))}
    assert by_line[12] is True     # eval_tainted
    assert by_line[23] is True     # system_propagated (param -> cmd -> os.system)
    assert by_line[17] is False    # eval_constant: flagged, not tainted
    assert by_line[28] is False    # system_constant: flagged, not tainted


@needs_cpp
def test_cpp_taint_cases():
    by_line = {f.line: f.tainted for f in scanner.scan_file(os.path.join(CPP_DIR, "taint_sample.cpp"))}
    assert by_line == {7: True, 12: False, 18: True}


# ---- safe code ------------------------------------------------------------
def test_safe_python_not_flagged():
    src = ("import ast, json, hashlib, secrets, subprocess, yaml\n"
           "ast.literal_eval('1')\n"
           "json.loads('{}')\n"
           "hashlib.sha256(b'x')\n"
           "secrets.token_hex(8)\n"
           "subprocess.run(['ls'])\n"
           "yaml.safe_load('a: 1')\n"
           "db_password = None\n"
           "timeout = 30\n")
    from vulnlens import engine
    assert engine.scan_source(src) == []


@needs_cpp
def test_safe_cpp_not_flagged():
    src = ('#include <cstdio>\n#include <cstring>\n'
           'void f(char* in) { char b[10]; strncpy(b, in, sizeof(b)); printf("%s", in); }\n')
    assert scanner.cpp_engine.scan_source(src) == []


# ---- output formats -------------------------------------------------------
def run_cli(capsys, *args):
    code = cli.main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_json_output(capsys):
    code, out, _ = run_cli(capsys, PY_DIR, "--format", "json")
    data = json.loads(out)
    assert code == 1
    assert data["tool"] == "VulnLens"
    assert data["needs_review"] == []
    assert len(data["confirmed"]) == sum(len(v) for v in PY_EXPECTED.values())
    for item in data["confirmed"]:
        assert {"file", "line", "rule", "cwe", "severity", "tainted", "message", "fix"} <= set(item)
        assert isinstance(item["tainted"], bool)


def test_sarif_output(capsys):
    code, out, _ = run_cli(capsys, PY_DIR, "--format", "sarif")
    sarif = json.loads(out)
    assert code == 1
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnLens"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert len(run["results"]) == sum(len(v) for v in PY_EXPECTED.values())
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1


def test_text_output_marks_tainted_flow(capsys):
    code, out, _ = run_cli(capsys, os.path.join(PY_DIR, "taint_sample.py"))
    assert code == 1
    assert out.count("TAINTED FLOW") == 2
    assert "4 confirmed" in out


# ---- CLI exit codes -------------------------------------------------------
def test_exit_1_when_findings(capsys):
    assert run_cli(capsys, os.path.join(PY_DIR, "eval_sample.py"))[0] == 1


def test_exit_0_when_clean(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    assert run_cli(capsys, str(tmp_path))[0] == 0


def test_exit_0_for_empty_dir(tmp_path, capsys):
    assert run_cli(capsys, str(tmp_path))[0] == 0


def test_exit_2_for_missing_path(tmp_path, capsys):
    code, _, err = run_cli(capsys, str(tmp_path / "nope"))
    assert code == 2
    assert "not found" in err


# ---- graceful degradation -------------------------------------------------
def test_ai_without_key_runs_tier1_only(monkeypatch, capsys):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    code, out, err = run_cli(capsys, os.path.join(PY_DIR, "eval_sample.py"), "--ai")
    assert code == 1
    assert "running Tier 1 only" in err
    assert "1 confirmed, 0 to review" in out


def test_cpp_skipped_with_warning_when_tree_sitter_missing(monkeypatch, capsys):
    monkeypatch.setattr(scanner.cpp_engine, "_CPP_LANGUAGE", None)
    code, out, err = run_cli(capsys, CPP_DIR)
    assert code == 0                      # nothing scanned -> no findings
    assert "tree-sitter isn't installed" in err
    assert "0 confirmed" in out


# ---- repo summary + GitHub URLs ------------------------------------------
from contextlib import contextmanager  # noqa: E402

from vulnlens import ai_layer, repo, summary  # noqa: E402


@pytest.mark.parametrize("url,ok", [
    ("https://github.com/owner/repo", True),
    ("https://github.com/owner/repo.git", True),
    ("https://github.com/owner/repo/", True),
    ("https://evil.com/owner/repo", False),
    ("--upload-pack=calc", False),
    ("git@github.com:owner/repo.git", False),
    ("tests/vulnerable_samples", False),
])
def test_is_github_url(url, ok):
    assert repo.is_github_url(url) is ok


def test_repo_name():
    assert repo.repo_name("https://github.com/owner/repo.git") == "owner/repo"


def test_build_summary_counts():
    results = {os.path.join(PY_DIR, n): {"findings": scanner.scan_file(os.path.join(PY_DIR, n)),
                                         "review": []} for n in PY_EXPECTED}
    s = summary.build_summary(results, skipped=["bad.py"], name="o/r")
    assert s["total_findings"] == 17
    assert s["by_severity"] == {"HIGH": 12, "MEDIUM": 5, "LOW": 0}
    assert s["tainted_findings"] == 12
    assert s["risk"] == "HIGH"
    assert s["languages"] == {"python": 10}
    assert s["skipped_files"] == ["bad.py"]
    assert len(s["riskiest_files"]) == 5


def test_summary_risk_none_for_clean_code():
    assert summary.build_summary({})["risk"] == "NONE"


def test_summary_flag_text_and_json(capsys):
    code, out, _ = run_cli(capsys, PY_DIR, "--summary")
    assert code == 1 and "SECURITY SUMMARY" in out and "Overall risk : HIGH" in out
    code, out, _ = run_cli(capsys, PY_DIR, "--summary", "--format", "json")
    assert json.loads(out)["summary"]["total_findings"] == 17


def _fake_clone(path):
    @contextmanager
    def fake(url):
        yield path
    return fake


def test_github_url_scans_clone_and_summarises(monkeypatch, tmp_path, capsys):
    (tmp_path / "a.py").write_text("import os\ndef f(x):\n    os.system(x)\n")
    (tmp_path / "bad.py").write_text("print 'python 2'\n")           # unparseable -> skipped, no crash
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text("eval('1')\n")        # .git is never scanned
    monkeypatch.setattr(repo, "cloned", _fake_clone(str(tmp_path)))
    code, out, _ = run_cli(capsys, "https://github.com/o/r", "--format", "json")
    data = json.loads(out)
    assert code == 1
    assert [c["file"] for c in data["confirmed"]] == ["a.py"]        # repo-relative path
    assert data["summary"]["name"] == "o/r"
    assert data["summary"]["skipped_files"] == ["bad.py"]


def test_github_clone_failure_exits_2(monkeypatch, capsys):
    @contextmanager
    def boom(url):
        raise RuntimeError("could not clone")
        yield
    monkeypatch.setattr(repo, "cloned", boom)
    code, _, err = run_cli(capsys, "https://github.com/o/r")
    assert code == 2 and "could not clone" in err


# ---- AI layer with a fake Groq client ------------------------------------
class _FakeClient:
    def __init__(self, reply):
        self.reply = reply
        self.chat = self
        self.completions = self

    def create(self, **kw):
        msg = type("M", (), {"content": self.reply})
        return type("R", (), {"choices": [type("C", (), {"message": msg})]})


def test_ai_narrative_and_review(monkeypatch, capsys):
    replies = iter(["Like leaving a door unlocked.",                 # analogy for the one finding
                    '[{"line": 1, "issue": "x", "why": "y"}]',        # Tier 2 review items
                    "Overall posture is poor; fix eval first."])      # repo narrative
    monkeypatch.setattr(ai_layer, "_get_client",
                        lambda: type("C", (), {"chat": type("X", (), {"completions": type(
                            "Y", (), {"create": staticmethod(lambda **kw: _FakeClient(next(replies)).create())})})})())
    code, out, _ = run_cli(capsys, os.path.join(PY_DIR, "eval_sample.py"), "--ai", "--summary")
    assert code == 1
    assert "Like leaving a door unlocked." in out
    assert "[REVIEW] line 1" in out
    assert "fix eval first" in out


def test_ai_failures_degrade_silently(monkeypatch):
    class Broken:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    raise RuntimeError("api down")
    monkeypatch.setattr(ai_layer, "_get_client", lambda: Broken)
    assert ai_layer.summarize_repo({"a": 1}) == ""
    assert ai_layer.heuristic_scan("x = 1", []) == []


# ---- free-tier safeguards: retry on 429, caching, size cap ---------------
import time  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_ai_state(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_layer, "CACHE_PATH", str(tmp_path / "cache.json"))
    ai_layer._analogy_cache.clear()


class _RateLimited(Exception):
    pass


def _flaky_client(fail_times, reply="ok"):
    calls = {"n": 0}

    class Completions:
        @staticmethod
        def create(**kw):
            calls["n"] += 1
            if calls["n"] <= fail_times:
                raise _RateLimited("429")
            msg = type("M", (), {"content": reply})
            return type("R", (), {"choices": [type("C", (), {"message": msg})]})

    return type("Cl", (), {"chat": type("Ch", (), {"completions": Completions})})(), calls


def test_retries_on_rate_limit_with_backoff(monkeypatch):
    sleeps = []
    monkeypatch.setattr(ai_layer, "RateLimitError", _RateLimited)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    client, calls = _flaky_client(fail_times=2)
    assert ai_layer._generate(client, "hi", 10) == "ok"
    assert calls["n"] == 3 and sleeps == [1, 2]


def test_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(ai_layer, "RateLimitError", _RateLimited)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    client, calls = _flaky_client(fail_times=99)
    with pytest.raises(_RateLimited):
        ai_layer._generate(client, "hi", 10)
    assert calls["n"] == ai_layer.MAX_RETRIES + 1


def test_non_rate_limit_errors_are_not_retried(monkeypatch):
    monkeypatch.setattr(ai_layer, "RateLimitError", _RateLimited)
    client, calls = _flaky_client(fail_times=0)
    client.chat.completions.create = staticmethod(lambda **kw: (_ for _ in ()).throw(KeyError("x")))
    with pytest.raises(KeyError):
        ai_layer._generate(client, "hi", 10)


def test_heuristic_scan_caches_by_content(monkeypatch):
    client, calls = _flaky_client(0, reply='[{"line": 2, "issue": "i", "why": "w"}]')
    monkeypatch.setattr(ai_layer, "_get_client", lambda: client)
    first = ai_layer.heuristic_scan("x = 1", [])
    second = ai_layer.heuristic_scan("x = 1", [])
    assert first == second and first[0].line == 2
    assert calls["n"] == 1                        # second call served from cache
    ai_layer.heuristic_scan("x = 2", [])
    assert calls["n"] == 2                        # changed file -> new call


def test_heuristic_scan_skips_huge_files(monkeypatch):
    client, calls = _flaky_client(0)
    monkeypatch.setattr(ai_layer, "_get_client", lambda: client)
    assert ai_layer.heuristic_scan("x" * (ai_layer.MAX_SOURCE_CHARS + 1), []) == []
    assert calls["n"] == 0


def test_analogy_requested_once_per_rule(monkeypatch):
    client, calls = _flaky_client(0, reply="like a door")
    monkeypatch.setattr(ai_layer, "_get_client", lambda: client)
    findings = scanner.scan_file(os.path.join(PY_DIR, "taint_sample.py"))   # 2 eval + 2 shell
    ai_layer.explain_findings(findings)
    assert calls["n"] == 2
    assert all(f.analogy == "like a door" for f in findings)


# ---- extra Python patterns (popen, pickle.load, yaml safe loaders) --------
from vulnlens import engine  # noqa: E402


@pytest.mark.parametrize("code,rule", [
    ("""
import os
def f(x):
    os.popen(x)
""", "shell-injection"),
    ("""
import os as o
def f(x):
    o.popen(x)
""", "shell-injection"),
    ("""
import pickle
def f(p):
    pickle.load(open(p, 'rb'))
""", "unsafe-deserialization"),
    ("""
import yaml
def f(x):
    yaml.load(x)
""", "unsafe-yaml-load"),
    ("""
import yaml
def f(x):
    yaml.load(x, Loader=yaml.FullLoader)
""", "unsafe-yaml-load"),
])
def test_extra_python_patterns_flagged(code, rule):
    assert [f.rule for f in engine.scan_source(code)] == [rule]


@pytest.mark.parametrize("code", [
    """
import yaml
def f(x):
    yaml.load(x, Loader=yaml.SafeLoader)
""",
    """
import yaml
def f(x):
    yaml.load(x, yaml.CSafeLoader)
""",
    """
from yaml import SafeLoader, load
def f(x):
    load(x, Loader=SafeLoader)
""",
])
def test_yaml_with_safe_loader_not_flagged(code):
    assert engine.scan_source(code) == []


# ---- regression tests for bugs found while testing on real repos ----------
from vulnlens import formats  # noqa: E402


@pytest.mark.parametrize("path,expected", [
    (".github/scripts/x.py", ".github/scripts/x.py"),   # leading dot must survive
    ("./a.py", "a.py"),
    ("../x.py", "../x.py"),
    (r"src\a.py", "src/a.py"),
    ("src/a.py", "src/a.py"),
])
def test_sarif_uri_keeps_leading_dots(path, expected):
    assert formats._uri(path) == expected


def test_nested_call_reported_once(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("def f(s):\n    exec(compile(s, 'f', 'exec'))\n")
    found = scanner.scan_file(str(f))
    assert [(x.rule, x.line, x.tainted) for x in found] == [("dangerous-eval", 2, True)]


def test_unparseable_file_is_reported_not_silently_clean(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("print 'py2'\n")
    code, out, err = run_cli(capsys, str(tmp_path / "bad.py"))
    assert code == 0
    assert "NOT analysed" in err and "bad.py" in err
    assert "1 skipped" in out


def test_cpp_without_tree_sitter_counts_as_skipped(monkeypatch, capsys):
    monkeypatch.setattr(scanner.cpp_engine, "_CPP_LANGUAGE", None)
    code, out, err = run_cli(capsys, CPP_DIR, "--summary")
    assert "NOT analysed" in err
    assert "Scanned 0 file(s). 5 skipped" in out


def test_tier2_is_capped_per_run(monkeypatch, tmp_path, capsys):
    client, calls = _flaky_client(0, reply="[]")
    monkeypatch.setattr(ai_layer, "_get_client", lambda: client)
    monkeypatch.setattr(cli, "MAX_TIER2_FILES", 3)
    for i in range(6):
        (tmp_path / f"f{i}.py").write_text(f"x = {i}\n")
    _, _, err = run_cli(capsys, str(tmp_path), "--ai")
    assert calls["n"] == 3                        # no findings -> no analogies; 3 files reviewed
    assert "limited to the first 3 files" in err


def test_tier2_prompt_names_the_language(monkeypatch):
    seen = []

    class Completions:
        @staticmethod
        def create(**kw):
            seen.append(kw["messages"][0]["content"])
            msg = type("M", (), {"content": "[]"})
            return type("R", (), {"choices": [type("C", (), {"message": msg})]})

    client = type("Cl", (), {"chat": type("Ch", (), {"completions": Completions})})()
    monkeypatch.setattr(ai_layer, "_get_client", lambda: client)
    ai_layer.heuristic_scan("int main(){}", [], "C/C++")
    assert "C/C++ security reviewer" in seen[0] and "Python" not in seen[0]


def test_analogy_cache_spans_files(monkeypatch):
    client, calls = _flaky_client(0, reply="like a door")
    monkeypatch.setattr(ai_layer, "_get_client", lambda: client)
    a = scanner.scan_file(os.path.join(PY_DIR, "eval_sample.py"))
    b = scanner.scan_file(os.path.join(PY_DIR, "taint_sample.py"))
    ai_layer.explain_findings(a)
    ai_layer.explain_findings(b)
    assert calls["n"] == 2                        # eval once, shell once, across both files
