"""Tests for AgentConfigScanner"""

from pathlib import Path

from scripts.agent_config_scanner import AgentConfigScanner


def _write_config(repo: Path, name: str, content: str) -> Path:
    cfg_dir = repo / ".claude"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def test_pgpassword_flagged(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ["Bash(PGPASSWORD=supersecret123 psql -h db -U admin)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.critical == 1
    f = result.findings[0]
    assert f.pattern_name == "pgpassword"
    assert f.rule_id == "agent-config-secret"
    # Secret must be redacted in the evidence snippet
    assert "supersecret123" not in f.evidence_snippet
    assert "su***23" in f.evidence_snippet or "***" in f.evidence_snippet


def test_sshpass_flagged(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ["Bash(sshpass -p rootpass ssh root@192.168.1.1)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.critical == 1
    assert result.findings[0].pattern_name == "sshpass"


def test_mysql_p_flag_flagged(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ["Bash(mysql -u root -pMySecretPw -e \'select 1\')"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert any(f.pattern_name == "mysql_p_flag" for f in result.findings)


def test_url_credentials_flagged(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ["Bash(psql postgresql://admin:hunter2@db.example.com/prod)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert any(f.pattern_name == "url_credentials" for f in result.findings)


def test_bearer_token_flagged(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ["Bash(curl -H \'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xyz\' https://api.example.com)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert any(f.pattern_name == "bearer_token" for f in result.findings)


def test_clean_rule_not_flagged(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ["Bash(npm run build:*)", "Bash(git status)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.total_findings == 0


def test_shared_settings_json_also_scanned(tmp_path):
    _write_config(
        tmp_path,
        "settings.json",
        '{"permissions": {"allow": ["Bash(MYSQL_PWD=topsecret mysql -u root)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.total_findings == 1
    assert result.findings[0].pattern_name == "mysql_pwd"


def test_ask_bucket_also_scanned(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"ask": ["Bash(PGPASSWORD=anotherpass psql -h db)"]}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.total_findings == 1


def test_no_config_files_is_empty(tmp_path):
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.files_scanned == 0
    assert result.total_findings == 0


def test_parse_error_reported(tmp_path):
    _write_config(tmp_path, "settings.local.json", "{not valid json")
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert any(f.rule_id == "agent-config-parse-error" for f in result.findings)


def test_multiple_secrets_distinct_findings(tmp_path):
    _write_config(
        tmp_path,
        "settings.local.json",
        '{"permissions": {"allow": ['
        '"Bash(PGPASSWORD=one psql -h db)",'
        '"Bash(sshpass -p two ssh root@host)"'
        ']}}',
    )
    result = AgentConfigScanner().scan_filesystem(str(tmp_path))
    assert result.total_findings == 2
