#!/usr/bin/env python3
"""
Agent Config Secret Scanner

Detects secrets embedded in AI coding agent configuration files:
- .claude/settings.local.json and .claude/settings.json
- .cursor/, .gemini/, .specstory/ (if present)

When a developer approves a shell command with "Yes, and don't ask again",
Claude Code saves the full command text -- including any inline password or
token -- into .claude/settings.local.json. If that file is committed, the
secret is public. Gitleaks and TruffleHog miss most of these because the
secrets don't match provider key formats (a password after PGPASSWORD= looks
like an ordinary word in an ordinary shell command).

Reference: The Hacker News, 2026-11-07, "Claude Code's Don't Ask Again File
Exposes Passwords and Keys in 1,122 Public Copies on GitHub"
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Config files to scan, relative to the target root
_AGENT_CONFIG_GLOBS = [
    ".claude/settings.local.json",
    ".claude/settings.json",
    ".cursor/settings.json",
    ".gemini/settings.json",
]

# --- Embedded-secret patterns -------------------------------------------------
# Each tuple: (pattern_name, severity, compiled_regex, secret_group_index)
# secret_group_index is the capture group that holds the actual secret.
_PATTERNS: list[tuple[str, str, re.Pattern, int]] = [
    # Database passwords in inline env assignments
    ("pgpassword", "critical",
     re.compile(r"\bPGPASSWORD\s*=\s*(\S+)"), 1),
    ("mysql_pwd", "critical",
     re.compile(r"\bMYSQL_PWD\s*=\s*(\S+)"), 1),
    ("rediscli_auth", "critical",
     re.compile(r"\bREDISCLI_AUTH\s*=\s*(\S+)"), 1),
    ("database_url", "critical",
     re.compile(r"\b(?:DATABASE_URL|DB_URL)\s*=\s*([^\s'\"]+)"), 1),
    ("supabase_key", "critical",
     re.compile(r"\b(?:SUPABASE_ACCESS_TOKEN|SUPABASE_SERVICE_ROLE_KEY)\s*=\s*(\S+)"), 1),

    # SSH / MySQL password flags
    ("sshpass", "critical",
     re.compile(r"\bsshpass\s+-p\s+['\"]?([^\s'\"]+)"), 1),
    ("mysql_p_flag", "high",
     re.compile(r"\bmysql\s+[^\n]*-p\s*['\"]?([^\s'\"]+)"), 1),

    # Credentials embedded in URLs (postgres://user:pass@host, etc.)
    ("url_credentials", "critical",
     re.compile(r"://[^/\s:]+:([^@\s/]+)@"), 1),

    # Generic password flags
    ("generic_password_flag", "high",
     re.compile(r"(?:--password|-P)\s+['\"]?([^\s'\"]+)"), 1),

    # Bearer tokens in curl -H "Authorization: Bearer ..."
    ("bearer_token", "critical",
     re.compile(r"[Aa]uthorization:\s*[Bb]earer\s+([A-Za-z0-9._\-]+)"), 1),
]


@dataclass
class AgentConfigFinding:
    """A single secret-in-agent-config finding"""

    rule_id: str          # agent-config-secret | agent-config-parse-error
    pattern_name: str     # pgpassword | sshpass | url_credentials | ...
    severity: str         # critical | high | medium | low
    message: str
    file_path: str
    rule_index: int = -1  # position in the permissions array
    evidence_snippet: str = ""
    cwe: Optional[str] = None
    references: list[str] = field(default_factory=list)


@dataclass
class AgentConfigScanResult:
    """Aggregate result from an agent config scan"""

    scan_type: str           # always "agent_config"
    target: str
    timestamp: str
    files_scanned: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[AgentConfigFinding]
    scan_duration_seconds: float
    scanner_version: str = "1.0.0"


def _redact(secret: str) -> str:
    """Redact a secret for inclusion in a report snippet."""
    if len(secret) <= 4:
        return "***"
    return secret[:2] + "***" + secret[-2:]


class AgentConfigScanner:
    """
    Scan AI agent configuration files for secrets embedded in command strings.

    Usage:
        scanner = AgentConfigScanner()
        result = scanner.scan_filesystem("/path/to/repo")
        for f in result.findings:
            print(f.severity, f.pattern_name, f.file_path, f.message)
    """

    SCANNER_NAME = "agent-config"
    SCANNER_VERSION = "1.0.0"
    CAPABILITIES = ["secrets", "agent-config", "supply-chain"]
    SUPPORTED_LANGUAGES = ["json"]

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def is_available(self) -> bool:
        return True

    # ------------------------------------------------------------------ public

    def scan_filesystem(
        self, target_path: str, output_file: Optional[str] = None
    ) -> AgentConfigScanResult:
        """Scan a repo for agent config files containing embedded secrets."""
        start = datetime.now()
        target = Path(target_path)
        logger.info(f"🔍 Scanning agent config files under: {target}")

        config_files = self._discover_configs(target)
        if not config_files:
            logger.warning("⚠️  No agent config files found")

        findings: list[AgentConfigFinding] = []
        for cfg in config_files:
            findings.extend(self._scan_file(cfg, target))

        duration = (datetime.now() - start).total_seconds()

        result = AgentConfigScanResult(
            scan_type="agent_config",
            target=str(target),
            timestamp=start.isoformat(),
            files_scanned=len(config_files),
            total_findings=len(findings),
            critical=sum(1 for f in findings if f.severity == "critical"),
            high=sum(1 for f in findings if f.severity == "high"),
            medium=sum(1 for f in findings if f.severity == "medium"),
            low=sum(1 for f in findings if f.severity == "low"),
            findings=findings,
            scan_duration_seconds=duration,
        )

        logger.info(
            f"✅ Agent config scan complete: {result.total_findings} findings "
            f"({result.critical} critical, {result.high} high) in {duration:.2f}s"
        )

        if output_file:
            from dataclasses import asdict
            Path(output_file).write_text(json.dumps(asdict(result), indent=2))
            logger.info(f"   Report written to {output_file}")

        return result

    def scan(self, file_path: Path) -> list[dict]:
        """ScannerRegistry-compatible single-file entry point."""
        from dataclasses import asdict

        target = Path(file_path)
        if target.is_dir():
            result = self.scan_filesystem(str(target))
        else:
            findings = self._scan_file(target, target.parent)
            result = AgentConfigScanResult(
                scan_type="agent_config",
                target=str(target),
                timestamp=datetime.now().isoformat(),
                files_scanned=1,
                total_findings=len(findings),
                critical=sum(1 for f in findings if f.severity == "critical"),
                high=sum(1 for f in findings if f.severity == "high"),
                medium=sum(1 for f in findings if f.severity == "medium"),
                low=sum(1 for f in findings if f.severity == "low"),
                findings=findings,
                scan_duration_seconds=0.0,
            )
        return [asdict(f) for f in result.findings]

    # ----------------------------------------------------------------- private

    def _discover_configs(self, root: Path) -> list[Path]:
        """Find all known agent config files under the target."""
        found: list[Path] = []
        for rel in _AGENT_CONFIG_GLOBS:
            p = root / rel
            if p.is_file():
                found.append(p)
        return found

    def _scan_file(self, path: Path, repo_root: Path) -> list[AgentConfigFinding]:
        """Parse one agent config file and match embedded-secret patterns."""
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"⚠️  Could not parse {path}: {e}")
            return [
                AgentConfigFinding(
                    rule_id="agent-config-parse-error",
                    pattern_name="",
                    severity="low",
                    message=f"Could not parse agent config file: {e}",
                    file_path=str(path),
                )
            ]

        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            rel = path

        permissions = (data or {}).get("permissions") or {}
        findings: list[AgentConfigFinding] = []

        for key in ("allow", "ask", "deny"):
            rules = permissions.get(key)
            if not isinstance(rules, list):
                continue
            for idx, rule in enumerate(rules):
                if not isinstance(rule, str):
                    continue
                findings.extend(
                    self._scan_rule(rule, str(rel), idx, key)
                )

        return findings

    def _scan_rule(
        self, rule: str, rel_path: str, rule_index: int, permission_bucket: str
    ) -> list[AgentConfigFinding]:
        """Match embedded-secret patterns in a single permission rule string."""
        out: list[AgentConfigFinding] = []
        for name, severity, pattern, group in _PATTERNS:
            m = pattern.search(rule)
            if not m:
                continue
            try:
                secret = m.group(group)
            except IndexError:
                continue
            if not secret:
                continue

            # Redact the secret itself in the report -- do not leak it twice.
            redacted = _redact(secret)
            safe_rule = rule[:200] + ("..." if len(rule) > 200 else "")
            evidence = safe_rule.replace(secret, redacted)

            out.append(
                AgentConfigFinding(
                    rule_id="agent-config-secret",
                    pattern_name=name,
                    severity=severity,
                    message=(
                        f"Secret matched pattern '{name}' in "
                        f"permissions.{permission_bucket}[{rule_index}]. "
                        f"Rotate the credential and remove it from the rule."
                    ),
                    file_path=rel_path,
                    rule_index=rule_index,
                    evidence_snippet=evidence,
                    cwe="CWE-798",  # Use of Hard-coded Credentials
                    references=[
                        "https://thehackernews.com/2026/11/claude-codes-dont-ask-again-file.html"
                    ],
                )
            )
            # One finding per rule is enough; avoid duplicate alerts.
            break

        return out


# ---------------------------------------------------------------- CLI entry

def main():
    import argparse
    from dataclasses import asdict

    parser = argparse.ArgumentParser(description="Agent Config Secret Scanner")
    parser.add_argument("target", help="Repository or directory to scan")
    parser.add_argument("--output", "-o", help="Write JSON report to this path")
    args = parser.parse_args()

    scanner = AgentConfigScanner()
    result = scanner.scan_filesystem(args.target, output_file=args.output)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.critical == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
