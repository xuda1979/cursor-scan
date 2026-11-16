"""Data models shared across scan rules, scoring and reporting."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Canonical scoring dimensions used by the scorecard.
DIMENSIONS = [
    "crypto",
    "secrets",
    "deserialization",
    "injection",
    "permissions",
    "access_control",
]

DIMENSION_LABELS = {
    "crypto": "弱密码学",
    "secrets": "硬编码秘密",
    "deserialization": "不安全反序列化",
    "injection": "注入",
    "permissions": "文件权限",
    "access_control": "访问控制",
}


@dataclass
class Evidence:
    """A single rule hit with file/line evidence and a fix suggestion."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    fix: str
    dimension: str = "crypto"
    code_snippet: str = ""


@dataclass
class ScanResult:
    """Aggregated scan result for one project scan."""

    target: str
    findings: List[Evidence] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    started_at: str = ""
    duration_sec: float = 0.0
    score: int = 100
    grade: str = "A"
    dimensions: Dict[str, "DimensionScore"] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=dict)

    def add(self, evidence: Evidence) -> None:
        self.findings.append(evidence)

    def scorecard(self) -> "Scorecard":
        return Scorecard.from_result(self)


@dataclass
class DimensionScore:
    dimension: str
    score: int
    findings: List[Evidence] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)


@dataclass
class Scorecard:
    overall: int
    grade: str
    dimensions: Dict[str, DimensionScore]

    @staticmethod
    def from_result(result: ScanResult) -> "Scorecard":
        result.dimensions = Scorecard.compute(result.findings)
        overall, grade = Scorecard.grade_overall(result.dimensions)
        result.score = overall
        result.grade = grade
        return Scorecard(
            overall=overall,
            grade=grade,
            dimensions=result.dimensions,
        )

    @staticmethod
    def compute(findings: List[Evidence]) -> Dict[str, DimensionScore]:
        """Per-dimension score: start at 100, subtract severity-weight per finding."""
        dim_map: Dict[str, DimensionScore] = {
            d: DimensionScore(dimension=d, score=100) for d in DIMENSIONS
        }
        weights = {
            "low": 5,
            "medium": 12,
            "high": 20,
            "critical": 30,
        }
        for f in findings:
            ds = dim_map.get(f.dimension)
            if ds is None:
                ds = dim_map.setdefault(f.dimension, DimensionScore(dimension=f.dimension, score=100))
            ds.findings.append(f)
            ds.score = max(0, ds.score - weights.get(f.severity, 5))
        return dim_map

    @staticmethod
    def grade_overall(dims: Dict[str, DimensionScore]) -> tuple[int, str]:
        if dims:
            overall = int(sum(d.score for d in dims.values()) / len(dims))
        else:
            overall = 100
        if overall >= 90:
            grade = "A"
        elif overall >= 75:
            grade = "B"
        elif overall >= 60:
            grade = "C"
        elif overall >= 40:
            grade = "D"
        else:
            grade = "F"
        return overall, grade


def status_from_severity(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 2)
