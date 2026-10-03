"""Risk score: a saturating sum of per-item weights, so one critical item registers clearly
while a pile of low-severity noise cannot reach the top bands on its own."""

from __future__ import annotations

from math import exp
from typing import Iterable

WEIGHTS = {"CRITICAL": 25.0, "HIGH": 12.0, "MEDIUM": 4.0, "LOW": 0.5}
SATURATION = 60.0

# (minimum score, label), checked in order
_BANDS = ((75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (1, "LOW"))


def risk_score(severities: Iterable[str]) -> int:
    raw = sum(WEIGHTS.get(s, 0.0) for s in severities)
    return round(100 * (1 - exp(-raw / SATURATION)))


def risk_label(score: int) -> str:
    for floor, label in _BANDS:
        if score >= floor:
            return label
    return "CLEAN"
