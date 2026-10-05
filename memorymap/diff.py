"""Secret residue testing: compare two snapshots of one process.

The question it answers is "after I did X, which secrets are still in memory?". Findings are
matched by keyed fingerprint, so a snapshot never has to hold plaintext.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from memorymap.scan import ScanResult
from memorymap.scanner import SEVERITY_RANK

SNAPSHOT_FORMAT = "memorymap-snapshot/1"
_STATUS_ORDER = {"persisted": 0, "new": 1, "wiped": 2}

# Verdicts, from worst to most reassuring
RESIDUE = "RESIDUE"            # high-severity secrets survived
MINOR = "MINOR"                # only medium/low-severity data survived
CLEAN = "CLEAN"                # everything sensitive in the baseline is gone
INCONCLUSIVE = "INCONCLUSIVE"  # the baseline held nothing to wipe


def save_snapshot(result: ScanResult, path: str) -> None:
    """Write a snapshot with masked values and fingerprints only; no plaintext secrets."""
    data = result.as_dict(reveal=False, include_regions=False)
    data["format"] = SNAPSHOT_FORMAT
    Path(path).write_text(json.dumps(data, indent=1), encoding="utf-8")


def load_snapshot(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != SNAPSHOT_FORMAT:
        raise ValueError(f"{path} is not a MemoryMap snapshot.")
    return data


def _meta(snap: dict) -> dict:
    return {k: snap.get(k) for k in ("pid", "process_name", "started_at", "score", "label")}


def relevant(f: dict, sensitive_only: bool = True) -> bool:
    """Whether a finding takes part in residue comparisons."""
    if sensitive_only and not f.get("sensitive", True):
        return False
    # Low-severity data inside a module image (emails in a credits table, say) is static, not runtime state.
    in_module = f.get("where", "").startswith("Module ")
    return not (in_module and SEVERITY_RANK[f["severity"]] < SEVERITY_RANK["HIGH"])


def diff_snapshots(before: dict, after: dict, sensitive_only: bool = True) -> dict:
    def index(snap: dict) -> Dict[str, dict]:
        return {f["fp"]: f for f in snap["findings"] if relevant(f, sensitive_only)}

    old, new = index(before), index(after)
    items: List[dict] = []
    for fp in old.keys() | new.keys():
        b, a = old.get(fp), new.get(fp)
        ref = a or b
        items.append({
            "fp": fp,
            "status": "persisted" if a and b else "new" if a else "wiped",
            "category": ref["category"],
            "severity": ref["severity"],
            "value": ref["value"],
            "before": b and {"count": b["count"], "address": b["address"], "where": b.get("where", "")},
            "after": a and {"count": a["count"], "address": a["address"], "where": a.get("where", "")},
        })
    items.sort(key=lambda i: (_STATUS_ORDER[i["status"]], -SEVERITY_RANK[i["severity"]], i["category"]))

    persisted = [i for i in items if i["status"] == "persisted"]
    counts = {s: sum(1 for i in items if i["status"] == s) for s in _STATUS_ORDER}
    serious = [i for i in persisted if SEVERITY_RANK[i["severity"]] >= SEVERITY_RANK["HIGH"]]

    if not old:
        verdict = INCONCLUSIVE
    elif serious:
        verdict = RESIDUE
    elif persisted:
        verdict = MINOR
    else:
        verdict = CLEAN

    return {
        "before": _meta(before),
        "after": _meta(after),
        "same_process": before.get("pid") == after.get("pid"),
        "verdict": verdict,
        "counts": counts,
        "serious_residue": len(serious),
        "items": items,
    }


VERDICT_TEXT = {
    RESIDUE: "High-severity secrets are still in the process's memory after the action.",
    MINOR: "High-severity secrets were wiped; only lower-severity data remains.",
    CLEAN: "Everything sensitive in the baseline is gone.",
    INCONCLUSIVE: "The baseline contained no sensitive findings to wipe. "
                  "Take the baseline while the secret is actually in use.",
}
