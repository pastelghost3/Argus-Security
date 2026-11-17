"""
Hybrid Security Analysis Data Models.

This module contains the core dataclass definitions used across the hybrid
security analysis pipeline. Extracted from hybrid_analyzer.py for better
modularity and reusability.

Classes:
    HybridFinding: Unified finding from multiple security tools
    HybridScanResult: Aggregated results from hybrid security scan
"""

from dataclasses import dataclass, field
from datetime import datetime # <--- ADD THIS IMPORT AT THE TOP OF THE FILE

# ... (HybridFinding class) ...

@dataclass
class HybridFinding:
    """Unified finding from multiple security tools"""

    finding_id: str
    id: str = ""  # Alias for finding_id
    source_tool: str = "unknown"  # MUST HAVE A DEFAULT if it comes after other defaults, OR move it up
    severity: str = "unknown"
    category: str = "unknown"
    title: str = ""
    description: str = ""
    file_path: str = ""
    line_number: int | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    exploitability: str | None = None
    recommendation: str | None = None
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0
    llm_enriched: bool = False
    sandbox_validated: bool = False
    iris_verified: bool = False
    iris_confidence: float | None = None
    iris_verdict: str | None = None
    secret_verified: bool = False
    reachability: str = "unknown"
    service_tier: str = "unknown"

    @property
    def scanner_name(self) -> str:
        """Alias for source_tool (backward compat with older code)."""
        return self.source_tool

    def __post_init__(self):
        if not self.id:
            self.id = self.finding_id

@dataclass
class HybridScanResult:
    """Results from hybrid security scan"""

    target_path: str
    scan_timestamp: str
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_source: dict[str, int]
    findings: list[HybridFinding]
    scan_duration_seconds: float
    cost_usd: float
    phase_timings: dict[str, float]
    tools_used: list[str]
    llm_enrichment_enabled: bool
    scanner_health: dict[str, str] = field(default_factory=dict)
    scan_status: str = "complete"
    policy_gate_result: dict | None = None
    vulnerability_chains: dict | None = None
    timestamp: datetime = field(default_factory=datetime.now)


__all__ = ["HybridFinding", "HybridScanResult"]
