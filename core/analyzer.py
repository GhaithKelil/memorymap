import math
from typing import List, Dict
from core.scanner import Finding


SEVERITY_SCORE = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":    8,
    "LOW":       2,
}


class AnalysisReport:
    def __init__(
        self,
        pid:           int,
        process_name:  str,
        total_regions: int,
        committed_mb:  float,
        findings:      List[Finding],
    ):
        self.pid           = pid
        self.process_name  = process_name
        self.total_regions = total_regions
        self.committed_mb  = committed_mb
        self.findings      = findings
        self.risk_score    = self._calculate_risk()
        self.category_map  = self._group_by_category()
        self.severity_map  = self._group_by_severity()

    def _calculate_risk(self) -> int:
        raw = sum(SEVERITY_SCORE.get(f.severity, 0) for f in self.findings)
        if raw == 0:
            return 0
        return min(100, int(50 * math.log10(raw + 1)))

    @property
    def risk_label(self) -> str:
        if self.risk_score >= 80:
            return "CRITICAL"
        elif self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 25:
            return "MEDIUM"
        elif self.risk_score > 0:
            return "LOW"
        return "CLEAN"

    def _group_by_category(self) -> Dict[str, List[Finding]]:
        d: Dict[str, List[Finding]] = {}
        for f in self.findings:
            d.setdefault(f.category, []).append(f)
        return dict(sorted(d.items(), key=lambda x: len(x[1]), reverse=True))

    def _group_by_severity(self) -> Dict[str, List[Finding]]:
        d: Dict[str, List[Finding]] = {}
        for f in self.findings:
            d.setdefault(f.severity, []).append(f)
        return d

    @property
    def critical_count(self) -> int:
        return len(self.severity_map.get("CRITICAL", []))

    @property
    def high_count(self) -> int:
        return len(self.severity_map.get("HIGH", []))

    @property
    def medium_count(self) -> int:
        return len(self.severity_map.get("MEDIUM", []))

    @property
    def low_count(self) -> int:
        return len(self.severity_map.get("LOW", []))

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def as_dict(self) -> dict:
        return {
            "pid":            self.pid,
            "process_name":   self.process_name,
            "total_regions":  self.total_regions,
            "committed_mb":   round(self.committed_mb, 2),
            "risk_score":     self.risk_score,
            "risk_label":     self.risk_label,
            "total_findings": self.total_findings,
            "critical":       self.critical_count,
            "high":           self.high_count,
            "medium":         self.medium_count,
            "low":            self.low_count,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "match":    f.truncated_match(120),
                    "address":  f"0x{f.address:016X}",
                    "pattern":  f.pattern_name,
                }
                for f in self.findings
            ],
            "categories": {
                cat: len(items) for cat, items in self.category_map.items()
            },
        }


def build_report(
    pid:           int,
    process_name:  str,
    total_regions: int,
    committed_mb:  float,
    findings:      List[Finding],
) -> AnalysisReport:
    return AnalysisReport(
        pid=pid,
        process_name=process_name,
        total_regions=total_regions,
        committed_mb=committed_mb,
        findings=findings,
    )
