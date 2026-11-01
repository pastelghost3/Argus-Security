"""Workflow Hardening normalizer

Converts WorkflowHardeningScanResult (or its asdict() form) into Finding objects
for the hybrid pipeline.
"""

from dataclasses import asdict
from typing import Any

from .base import Finding, Normalizer


class WorkflowHardeningNormalizer(Normalizer):
    """Normalize WorkflowHardeningScanner output to Finding format"""

    def normalize(self, raw_output: Any) -> list[Finding]:
        """
        Args:
            raw_output: A WorkflowHardeningScanResult instance, or its asdict() form.

        Returns:
            List of Finding objects.
        """
        if not isinstance(raw_output, dict):
            raw_output = asdict(raw_output)

        findings = []
        git_context = self._get_git_context()

        for wf in raw_output.get("findings", []):
            rel_path = wf.get("file_path", "unknown")

            finding = Finding(
                id=self._generate_id(
                    {
                        "repo": git_context["repo"],
                        "path": rel_path,
                        "rule_id": wf.get("rule_id", "unknown"),
                        "line": wf.get("line", 0),
                    }
                ),
                origin="workflow-hardening",
                repo=git_context["repo"],
                commit_sha=git_context["commit_sha"],
                branch=git_context["branch"],
                asset_type="config",
                path=rel_path,
                rule_id=wf.get("rule_id", "unknown"),
                rule_name=wf.get("rule_id", "unknown").replace("-", " ").title(),
                category="CI_CD",
                severity=self._map_severity(wf.get("severity", "medium")),
                line=wf.get("line") or None,
                cwe=wf.get("cwe"),
                evidence={
                    "message": wf.get("message", ""),
                    "snippet": wf.get("evidence_snippet", ""),
                    "job_name": wf.get("job_name", ""),
                    "step_index": wf.get("step_index", -1),
                },
                references=wf.get("references", []),
                confidence=0.95,
            )

            # CI/CD supply-chain findings are exploitable with low friction
            # when the workflow actually runs on PR events.
            if finding.rule_id in ("unpinned-action", "pwn-request"):
                finding.exploitability = "trivial"
            elif finding.rule_id == "script-injection":
                finding.exploitability = "moderate"

            finding.risk_score = finding.calculate_risk_score()
            findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
        }
        return mapping.get(str(severity).upper(), "medium")
