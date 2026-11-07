"""Tests for WorkflowHardeningScanner"""

from pathlib import Path

import pytest

from scripts.workflow_hardening_scanner import WorkflowHardeningScanner


def _write_workflow(repo: Path, name: str, content: str) -> Path:
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    path = wf_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def test_unpinned_action_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    rule_ids = {f.rule_id for f in result.findings}
    assert "unpinned-action" in rule_ids
    assert result.high >= 1


def test_pinned_action_not_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    assert not any(f.rule_id == "unpinned-action" for f in result.findings)


def test_write_all_permissions_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    assert any(f.rule_id == "write-all-permissions" for f in result.findings)


def test_pwn_request_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "pr.yml",
        """
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    pwn = [f for f in result.findings if f.rule_id == "pwn-request"]
    assert len(pwn) == 1
    assert pwn[0].severity == "critical"


def test_script_injection_flagged(tmp_path):
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [pull_request]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    inj = [f for f in result.findings if f.rule_id == "script-injection"]
    assert len(inj) == 1
    assert inj[0].cwe == "CWE-78"


def test_no_workflows_is_empty(tmp_path):
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    assert result.files_scanned == 0
    assert result.total_findings == 0

def test_multiple_unpinned_in_same_file_have_distinct_lines(tmp_path):
    """Two unpinned actions in one file must produce two findings with distinct lines."""
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    unpinned = [f for f in result.findings if f.rule_id == "unpinned-action"]
    assert len(unpinned) == 2, f"Expected 2 findings, got {len(unpinned)}"
    lines = [f.line for f in unpinned]
    assert all(ln > 0 for ln in lines), f"Some lines are 0: {lines}"
    assert len(set(lines)) == 2, f"Lines are not distinct: {lines}"



def test_parse_error_reported(tmp_path):
    _write_workflow(tmp_path, "bad.yml", "on: [push\n  bad: yaml: here")
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    assert any(f.rule_id == "workflow-parse-error" for f in result.findings)

def test_same_line_different_job_have_distinct_findings(tmp_path):
    """YAML anchors can place the same 'uses:' text on multiple jobs at the same physical line."""
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps: &common-steps
      - uses: actions/checkout@v4
  b:
    runs-on: ubuntu-latest
    steps: *common-steps
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))
    unpinned = [f for f in result.findings if f.rule_id == "unpinned-action"]
    assert len(unpinned) == 2, f"Expected 2 findings, got {len(unpinned)}"
    assert unpinned[0].line == unpinned[1].line
    assert {f.job_name for f in unpinned} == {"a", "b"}

def test_normalizer_produces_findings(tmp_path, monkeypatch):
    from scripts.normalizer import base as base_mod

    monkeypatch.setattr(
        base_mod.Normalizer,
        "_get_git_context",
        lambda self: {"repo": "test/repo", "commit_sha": "deadbeef", "branch": "main"},
    )

    _write_workflow(
        tmp_path,
        "ci.yml",
        """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
    )
    result = WorkflowHardeningScanner().scan_filesystem(str(tmp_path))

    from scripts.normalizer.workflow_hardening import WorkflowHardeningNormalizer

    findings = WorkflowHardeningNormalizer().normalize(result)
    assert len(findings) >= 1
    f = findings[0]
    assert f.origin == "workflow-hardening"
    assert f.category == "CI_CD"
    assert f.asset_type == "config"
    assert f.severity in ("critical", "high", "medium", "low")
    assert f.risk_score > 0
