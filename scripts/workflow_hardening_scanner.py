#!/usr/bin/env python3
"""
CI/CD Workflow Hardening Scanner

Detects supply-chain attack vectors in CI/CD pipeline definitions:
- Mutable action tags (TeamPCP vector: force-pushed @v4 -> malicious commit)
- pull_request_target + PR head checkout (pwn-request)
- Overly broad workflow/job permissions
- Script injection via untrusted ${{ }} expressions in run: blocks

Targets .github/workflows/*.yml and *.yaml. Designed to run alongside
Trivy/TruffleHog/Gitleaks in the hybrid pipeline.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# A full 40-char Git commit SHA. Anything else (tag, branch, short SHA) is mutable.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Untrusted GitHub expression contexts. These are attacker-controlled on fork PRs.
_UNTRUSTED_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:pull_request|issue|comment|review)[^}\s]*"
    r"|head_ref"
    r"|event\.(?:head_ref|workflow_run\.head_branch))[^}]*\}\}"
)


@dataclass
class WorkflowFinding:
    """A single workflow hardening finding"""

    rule_id: str          # unpinned-action | pwn-request | write-all-permissions | script-injection | workflow-parse-error
    severity: str         # critical | high | medium | low
    message: str
    file_path: str
    line: int = 0
    job_name: str = ""
    step_index: int = -1
    evidence_snippet: str = ""
    cwe: Optional[str] = None
    references: list[str] = field(default_factory=list)


@dataclass
class WorkflowHardeningScanResult:
    """Aggregate result from a workflow hardening scan"""

    scan_type: str           # always "ci_cd"
    target: str
    timestamp: str
    files_scanned: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[WorkflowFinding]
    scan_duration_seconds: float
    scanner_version: str = "1.0.0"


class WorkflowHardeningScanner:
    """
    Scan .github/workflows/*.yml for supply-chain and injection weaknesses.

    Usage:
        scanner = WorkflowHardeningScanner()
        result = scanner.scan_filesystem("/path/to/repo")
        for f in result.findings:
            print(f.severity, f.rule_id, f.file_path, f.message)
    """

    SCANNER_NAME = "workflow-hardening"
    SCANNER_VERSION = "1.0.0"
    CAPABILITIES = ["secrets", "supply-chain", "iac", "ci-cd"]
    SUPPORTED_LANGUAGES = ["yaml"]

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.severity_filter = self.config.get(
            "severity_filter", {"critical", "high", "medium", "low"}
        )

    def is_available(self) -> bool:
        """No external binary required."""
        return True

    # ------------------------------------------------------------------ public

    def scan_filesystem(
        self, target_path: str, output_file: Optional[str] = None
    ) -> WorkflowHardeningScanResult:
        """
        Scan a repository or directory for workflow hardening issues.

        Args:
            target_path: Root of the repository/directory to scan.
            output_file: Optional path to write JSON report.

        Returns:
            WorkflowHardeningScanResult
        """
        start = datetime.now()
        target = Path(target_path)
        logger.info(f"🔍 Scanning CI/CD workflows under: {target}")

        workflow_files = self._discover_workflows(target)
        if not workflow_files:
            logger.warning("⚠️  No .github/workflows/*.yml files found")

        findings: list[WorkflowFinding] = []
        for wf in workflow_files:
            findings.extend(self._scan_file(wf, target))

        # Severity filter
        findings = [f for f in findings if f.severity in self.severity_filter]

        duration = (datetime.now() - start).total_seconds()

        result = WorkflowHardeningScanResult(
            scan_type="ci_cd",
            target=str(target),
            timestamp=start.isoformat(),
            files_scanned=len(workflow_files),
            total_findings=len(findings),
            critical=sum(1 for f in findings if f.severity == "critical"),
            high=sum(1 for f in findings if f.severity == "high"),
            medium=sum(1 for f in findings if f.severity == "medium"),
            low=sum(1 for f in findings if f.severity == "low"),
            findings=findings,
            scan_duration_seconds=duration,
        )

        logger.info(
            f"✅ Workflow scan complete: {result.total_findings} findings "
            f"({result.critical} critical, {result.high} high) in {duration:.2f}s"
        )

        if output_file:
            import json
            from dataclasses import asdict

            Path(output_file).write_text(json.dumps(asdict(result), indent=2))
            logger.info(f"   Report written to {output_file}")

        return result

    def scan(self, file_path: Path) -> list[dict]:
        """
        ScannerRegistry-compatible single-file entry point.
        Returns a list of dicts (one per finding) so the registry CLI can
        enumerate results without knowing the dataclass shape.
        """
        from dataclasses import asdict

        target = Path(file_path)
        # If given a directory, scan it; if given a file, scan just that file.
        if target.is_dir():
            result = self.scan_filesystem(str(target))
        else:
            findings = self._scan_file(target, target.parent.parent.parent)
            result = WorkflowHardeningScanResult(
                scan_type="ci_cd",
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

    def _discover_workflows(self, root: Path) -> list[Path]:
        """Find .github/workflows/*.yml and *.yaml under the target."""
        wf_dir = root / ".github" / "workflows"
        if not wf_dir.is_dir():
            return []
        files = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))
        return files

    def _scan_file(self, path: Path, repo_root: Path) -> list[WorkflowFinding]:
        """Parse one workflow file and run all checks."""
        try:
            text = path.read_text(encoding="utf-8")
            doc = yaml.safe_load(text)
        except (OSError, yaml.YAMLError) as e:
            logger.warning(f"⚠️  Could not parse {path}: {e}")
            return [
                WorkflowFinding(
                    rule_id="workflow-parse-error",
                    severity="low",
                    message=f"Could not parse workflow file: {e}",
                    file_path=str(path),
                )
            ]

        if not isinstance(doc, dict):
            return []

        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            rel = path

        findings: list[WorkflowFinding] = []
        jobs = doc.get("jobs") or {}
        if not isinstance(jobs, dict):
            jobs = {}

        top_perms = doc.get("permissions")
        triggers = self._get_triggers(doc)

        # Top-level permissions check
        if self._is_write_all(top_perms):
            findings.append(
                WorkflowFinding(
                    rule_id="write-all-permissions",
                    severity="high",
                    message=(
                        "Workflow grants `permissions: write-all` at the top level. "
                        "A compromised step can push code, modify releases, or exfiltrate secrets. "
                        "Grant only the permissions each job needs."
                    ),
                    file_path=str(rel),
                    references=[
                        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"
                    ],
                )
            )

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if self._is_write_all(job_perms):
                findings.append(
                    WorkflowFinding(
                        rule_id="write-all-permissions",
                        severity="high",
                        message=f"Job '{job_name}' grants `permissions: write-all`.",
                        file_path=str(rel),
                        job_name=job_name,
                    )
                )

            steps = job.get("steps") or []
            if not isinstance(steps, list):
                continue

            step_occurrences: dict[str, int] = {}

            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                findings.extend(
                    self._check_step(
                        step=step,
                        idx=idx,
                        job_name=job_name,
                        triggers=triggers,
                        rel_path=str(rel),
                        raw_text=text,
                        occurrences=step_occurrences,
                    )
                )

        return findings

    @staticmethod

    def _find_line(text: str, needle: str, occurrence: int = 0) -> int:
        """Return the 1-based line number of the Nth occurrence of `needle`."""
        pos = -1
        for _ in range(occurrence + 1):
            pos = text.find(needle, pos + 1)
            if pos < 0:
                return 0
        return text.count("\n", 0, pos) + 1

    def _check_step(
        self,
        step: dict,
        idx: int,
        job_name: str,
        triggers: dict,
        rel_path: str,
        raw_text: str,
        occurrences: dict[str, int] | None = None,
    ) -> list[WorkflowFinding]:
        out: list[WorkflowFinding] = []
        occurrences = occurrences or {}
        uses = step.get("uses")
        run = step.get("run")

        # 1. Unpinned actions
        if isinstance(uses, str) and "@" in uses:
            ref = uses.rsplit("@", 1)[1]
            if not _SHA_RE.match(ref):

                snippet = f"uses: {uses}"
                occ = occurrences.get(snippet, 0)
                occurrences[snippet] = occ + 1
                line = self._find_line(raw_text, snippet, occ)
                out.append(
                    WorkflowFinding(
                        rule_id="unpinned-action",
                        line=line,
                        severity="high",
                        message=(
                            f"Action '{uses}' in job '{job_name}' is not pinned to a full 40-char commit SHA. "
                            f"A force-pushed tag could execute attacker code with your GITHUB_TOKEN. "
                            f"Pin: `{uses.split('@')[0]}@<commit-sha>`."
                        ),
                        file_path=rel_path,
                        job_name=job_name,
                        step_index=idx,
                        evidence_snippet=f"uses: {uses}",
                        references=[
                            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
                        ],
                    )
                )

        # 2. pwn-request: pull_request_target + checkout of PR head
        if isinstance(uses, str) and uses.startswith("actions/checkout"):
            if self._has_pr_target(triggers):
                with_block = step.get("with") or {}
                ref = str(with_block.get("ref", ""))
                if "head.sha" in ref or "head.ref" in ref:
                    snippet = f"uses: {uses}"
                    occ = occurrences.get(snippet, 0)
                    occurrences[snippet] = occ + 1
                    line = self._find_line(raw_text, snippet, occ)
                    out.append(
                        WorkflowFinding(
                            rule_id="pwn-request",
                            line=line,
                            severity="critical",
                            message=(
                                f"Job '{job_name}' uses `pull_request_target` and checks out "
                                f"PR head code (`ref: {ref}`). This gives fork authors access to "
                                f"base-repo secrets and write tokens — a classic 'pwn request'."
                            ),
                            file_path=rel_path,
                            job_name=job_name,
                            step_index=idx,
                            evidence_snippet=f"uses: {uses} with ref: {ref}",
                            references=[
                                "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
                            ],
                        )
                    )


        # 3. Script injection via untrusted expressions in run:
        if isinstance(run, str):
            for m in _UNTRUSTED_EXPR_RE.finditer(run):
                expr = m.group(0)
                snippet = "run:"
                occ = occurrences.get(snippet, 0)
                occurrences[snippet] = occ + 1
                line = self._find_line(raw_text, snippet, occ)
                out.append(
                    WorkflowFinding(
                        rule_id="script-injection",
                        line=line,
                        severity="high",
                        message=(
                            f"Untrusted expression '{expr}' interpolated directly into `run:` "
                            f"in job '{job_name}'. Attacker-controlled input can break out "
                            f"of quoting and execute arbitrary commands. Use an env: intermediate."
                        ),
                        file_path=rel_path,
                        job_name=job_name,
                        step_index=idx,
                        evidence_snippet=expr,
                        cwe="CWE-78",
                        references=[
                            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
                        ],
                    )
                )

        return out

    @staticmethod
    def _get_triggers(doc: dict) -> dict:
        """
        Return the `on:` block as a dict, handling all YAML forms:
          on: push
          on: [push, pull_request]
          on: { push: {...}, pull_request_target: {...} }
          on: true        # yaml parses bare `on` as True
        """
        triggers = doc.get("on", doc.get(True))
        if isinstance(triggers, str):
            return {triggers: {}}
        if isinstance(triggers, list):
            return {str(t): {} for t in triggers}
        if isinstance(triggers, dict):
            # Normalise possible True keys for bare triggers
            return {(k if isinstance(k, str) else str(k)): (v or {}) for k, v in triggers.items()}
        return {}

    @staticmethod
    def _has_pr_target(triggers: dict) -> bool:
        return "pull_request_target" in triggers

    @staticmethod
    def _is_write_all(perms: Any) -> bool:
        return perms == "write-all"


# ---------------------------------------------------------------- CLI entry

def main():
    import argparse
    import json
    from dataclasses import asdict

    parser = argparse.ArgumentParser(description="CI/CD Workflow Hardening Scanner")
    parser.add_argument("target", help="Repository or directory to scan")
    parser.add_argument("--output", "-o", help="Write JSON report to this path")
    parser.add_argument(
        "--severity", default="critical,high,medium,low",
        help="Comma-separated severities (default: all)",
    )
    args = parser.parse_args()

    scanner = WorkflowHardeningScanner(
        config={"severity_filter": set(s.strip() for s in args.severity.split(","))}
    )
    result = scanner.scan_filesystem(args.target, output_file=args.output)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.critical == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
