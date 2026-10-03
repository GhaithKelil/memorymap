"""Scan pipeline: walk a process, stream its memory through the scanner and detector."""

from __future__ import annotations

import threading
import time
from collections import Counter
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

from memorymap import __version__
from memorymap.anomaly import Anomaly, AnomalyDetector
from memorymap.reader import MemoryRegion, ProcessMemoryReader, process_name
from memorymap.scanner import SEVERITY_RANK, Finding, SecretScanner
from memorymap.scoring import risk_label, risk_score

MiB = 1024 * 1024
MAX_REGIONS_IN_PAYLOAD = 20000


class ScanCancelled(Exception):
    pass


@dataclass
class ScanOptions:
    min_severity: str = "LOW"
    include_images: bool = False  # read-only module pages are identical to disk; skipping them is the big speed win
    chunk_size: int = 8 * MiB


@dataclass
class Progress:
    """Updated by the scan thread, read by whoever is watching (CLI or web)."""
    phase: str = "starting"
    total_bytes: int = 0
    done_bytes: int = 0
    regions_total: int = 0
    regions_done: int = 0
    findings: int = 0
    anomalies: int = 0
    seq: int = 0
    feed: List[dict] = field(default_factory=list)  # most recent discoveries, masked

    @property
    def fraction(self) -> float:
        return min(1.0, self.done_bytes / self.total_bytes) if self.total_bytes else 0.0

    def push(self, severity: str, label: str, detail: str) -> None:
        self.seq += 1
        self.feed.append({"seq": self.seq, "severity": severity, "label": label, "detail": detail})
        del self.feed[:-100]


@dataclass
class ScanResult:
    pid: int
    process_name: str
    started_at: datetime
    duration_s: float
    regions: List[MemoryRegion]
    scanned_bytes: int
    findings: List[Finding]
    anomalies: List[Anomaly]
    options: ScanOptions = field(default_factory=ScanOptions)
    _index: Optional[tuple] = field(default=None, repr=False, compare=False)

    @property
    def committed_bytes(self) -> int:
        return sum(r.size for r in self.regions if r.committed)

    @property
    def score(self) -> int:
        return risk_score([f.severity for f in self.findings] + [a.severity for a in self.anomalies])

    @property
    def label(self) -> str:
        return risk_label(self.score)

    def severity_counts(self) -> dict:
        counts = {s: 0 for s in SEVERITY_RANK}
        for item in (*self.findings, *self.anomalies):
            counts[item.severity] += 1
        return counts

    def region_at(self, address: int) -> Optional[MemoryRegion]:
        if self._index is None:
            committed = sorted((r for r in self.regions if r.committed), key=lambda r: r.base)
            self._index = ([r.base for r in committed], committed)
        bases, regions = self._index
        i = bisect_right(bases, address) - 1
        return regions[i] if i >= 0 and address < regions[i].end else None

    def where(self, address: int) -> str:
        """Human-readable owner of an address: module, mapped file or private memory."""
        r = self.region_at(address)
        if r is None:
            return "unknown"
        if r.kind == "Image":
            return f"Module {r.mapped_file or 'image'}"
        if r.kind == "Mapped":
            return f"Mapped {r.mapped_file}" if r.mapped_file else "Shared memory"
        return "Private memory (heap/stack)"

    def region_stats(self) -> dict:
        """Committed bytes grouped by protection class and by region kind."""
        by_protect: Counter = Counter()
        by_kind: Counter = Counter()
        for r in self.regions:
            if not r.committed:
                continue
            by_kind[r.kind] += r.size
            if r.executable and r.writable:
                by_protect["RWX"] += r.size
            elif r.executable:
                by_protect["Executable"] += r.size
            elif r.writable:
                by_protect["Writable"] += r.size
            else:
                by_protect["Read-only"] += r.size
        return {"by_protect": dict(by_protect), "by_kind": dict(by_kind)}

    def as_dict(self, reveal: bool = False, include_regions: bool = True) -> dict:
        flagged: dict = {}
        for a in self.anomalies:
            flagged.setdefault(a.base, []).append(a.kind.value)

        committed = sorted((r for r in self.regions if r.committed), key=lambda r: r.size, reverse=True)
        shown = sorted(committed[:MAX_REGIONS_IN_PAYLOAD], key=lambda r: r.base)
        return {
            "version": __version__,
            "pid": self.pid,
            "process_name": self.process_name,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "duration_s": round(self.duration_s, 2),
            "committed_bytes": self.committed_bytes,
            "scanned_bytes": self.scanned_bytes,
            "region_count": len(committed),
            "score": self.score,
            "label": self.label,
            "revealed": reveal,
            "counts": {
                "findings": len(self.findings),
                "anomalies": len(self.anomalies),
                "by_severity": self.severity_counts(),
            },
            "stats": self.region_stats(),
            "findings": [{**f.as_dict(reveal), "where": self.where(f.address)} for f in self.findings],
            "anomalies": [a.as_dict() for a in self.anomalies],
            "regions": [
                {"b": r.base, "s": r.size, "p": r.protect, "k": r.kind, "f": r.mapped_file,
                 "x": r.executable, "w": r.writable, "a": flagged.get(r.base, [])}
                for r in shown
            ] if include_regions else [],
            "regions_truncated": max(0, len(committed) - len(shown)),
        }


def _scannable(region: MemoryRegion, options: ScanOptions) -> bool:
    if not region.readable:
        return False
    # Read-only pages backed by a file are identical to what is on disk, so they hold no runtime secrets.
    file_backed = region.kind == "Image" or (region.kind == "Mapped" and region.mapped_file)
    if file_backed and not region.writable and not options.include_images:
        return False
    return True


def run_scan(
    pid: int,
    options: Optional[ScanOptions] = None,
    progress: Optional[Progress] = None,
    cancel: Optional[threading.Event] = None,
    on_update: Optional[Callable[[Progress], None]] = None,
) -> ScanResult:
    options = options or ScanOptions()
    progress = progress or Progress()
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()

    def tick() -> None:
        if cancel is not None and cancel.is_set():
            raise ScanCancelled()
        if on_update:
            on_update(progress)

    with ProcessMemoryReader(pid) as reader:
        progress.phase = "mapping address space"
        regions = list(reader.iter_regions())
        committed = [r for r in regions if r.committed]
        progress.total_bytes = sum(r.size for r in committed if _scannable(r, options))
        progress.regions_total = len(committed)

        scanner = SecretScanner(options.min_severity)
        detector = AnomalyDetector()
        scanned = 0
        progress.phase = "scanning memory"

        for region in committed:
            tick()
            detector.begin(region)
            if _scannable(region, options):
                for offset, data, core in reader.read_chunks(region, options.chunk_size):
                    for f in scanner.feed(data, region.base + offset, core):
                        progress.push(f.severity, f.category, f.display(reveal=False, max_len=44))
                    detector.feed(data, offset, core)
                    progress.done_bytes += core
                    scanned += core
                    tick()
            for a in detector.end():
                progress.push(a.severity, a.as_dict()["title"], f"0x{a.base:X}")
            progress.regions_done += 1
            progress.anomalies = len(detector.anomalies)
            progress.findings = len(scanner)

        progress.phase = "finishing"
        findings = scanner.findings()
        progress.findings = len(findings)

    progress.phase = "done"
    tick()
    return ScanResult(
        pid=pid,
        process_name=process_name(pid),
        started_at=started,
        duration_s=time.perf_counter() - t0,
        regions=regions,
        scanned_bytes=scanned,
        findings=findings,
        anomalies=detector.sorted(),
        options=options,
    )
