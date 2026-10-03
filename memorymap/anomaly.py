"""Behavioural anomaly detection over a process's memory regions.

Each region goes through ``begin`` (permission-based checks), ``feed`` (content checks, once per
chunk) and ``end`` (which emits anomalies). Signals within one region corroborate each other:
an unbacked executable region that also holds a PE image is far more suspicious than either alone.
"""

from __future__ import annotations

import re
import struct
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from math import log2
from typing import Dict, List, Optional

from memorymap.reader import MemoryRegion
from memorymap.scanner import SEVERITY_RANK


class Kind(str, Enum):
    RWX_REGION = "RWX_REGION"
    UNBACKED_EXEC = "UNBACKED_EXEC"
    EMBEDDED_PE = "EMBEDDED_PE"
    HIGH_ENTROPY = "HIGH_ENTROPY"
    SUSPICIOUS_STRINGS = "SUSPICIOUS_STRINGS"


@dataclass(frozen=True)
class KindInfo:
    title: str
    description: str
    technique: str
    severity: str


KINDS: Dict[Kind, KindInfo] = {
    Kind.RWX_REGION: KindInfo(
        "Writable and executable memory",
        "Pages that are both writable and executable let code be written and run in place. "
        "Common staging area for injected code; JIT compilers and some packers also do it legitimately.",
        "T1055 Process Injection", "HIGH"),
    Kind.UNBACKED_EXEC: KindInfo(
        "Executable memory with no backing file",
        "Executable pages that do not map to any module on disk. Typical of injected shellcode "
        "and reflectively loaded code; managed runtimes and JITs produce them legitimately.",
        "T1055 Process Injection", "HIGH"),
    Kind.EMBEDDED_PE: KindInfo(
        "PE image outside any loaded module",
        "A valid PE header inside memory that is not a mapped module. Indicates a manually "
        "mapped or reflectively loaded DLL, or a file read into a buffer.",
        "T1620 Reflective Code Loading", "HIGH"),
    Kind.HIGH_ENTROPY: KindInfo(
        "High-entropy content",
        "Byte distribution close to random. In executable memory this suggests packed or "
        "encrypted code; in data regions it is usually compressed or encrypted content.",
        "T1027 Obfuscated Files or Information", "HIGH"),
    Kind.SUSPICIOUS_STRINGS: KindInfo(
        "Offensive-tooling strings",
        "Strings associated with post-exploitation frameworks or process-injection APIs.",
        "T1055 Process Injection", "HIGH"),
}

ENTROPY_EXEC_THRESHOLD = 7.2
ENTROPY_DATA_THRESHOLD = 7.9
ENTROPY_WINDOW = 65536
ENTROPY_DATA_MIN_REGION = 16 * 1024

_STRONG_STRINGS = re.compile(
    rb"meterpreter|metasploit|reflectiveloader|reflective_loader|beacon\.dll|mimikatz|sekurlsa::"
    rb"|reverse_tcp|reverse_https?|cobaltstrike",
    re.IGNORECASE,
)
_WEAK_STRINGS = re.compile(
    rb"NtUnmapViewOfSection|WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|NtQueueApcThread"
    rb"|QueueUserAPC|SetThreadContext|NtLoadDriver|ZwSetSystemInformation"
    rb"|powershell(?:\.exe)?[ \t]+-(?:e|enc|encodedcommand)\b|\x90{24,}",
    re.IGNORECASE,
)
WEAK_STRING_MIN_DISTINCT = 3

_PE_MACHINES = {0x014C, 0x8664, 0x01C0, 0xAA64}


def _label(raw: bytes) -> str:
    return "nop sled" if raw.startswith(b"\x90") else raw.lower()[:24].decode("ascii", "replace")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * log2(c / n) for c in Counter(data).values())


def find_pe_headers(data: bytes, limit: int = 3) -> List[int]:
    """Offsets of structurally valid PE images (DOS header -> NT header -> known machine/magic)."""
    hits: List[int] = []
    idx = data.find(b"MZ")
    while idx != -1 and len(hits) < limit:
        if idx + 0x40 <= len(data):
            (lfanew,) = struct.unpack_from("<I", data, idx + 0x3C)
            nt = idx + lfanew
            if 0x40 <= lfanew <= 0x1000 and nt + 26 <= len(data) and data[nt:nt + 4] == b"PE\x00\x00":
                (machine,) = struct.unpack_from("<H", data, nt + 4)
                (magic,) = struct.unpack_from("<H", data, nt + 24)
                if machine in _PE_MACHINES and magic in (0x10B, 0x20B):
                    hits.append(idx)
        idx = data.find(b"MZ", idx + 2)
    return hits


@dataclass
class Anomaly:
    kind: Kind
    severity: str
    base: int
    size: int
    region_kind: str
    protect: str
    detail: str = ""
    mapped_file: str = ""

    def as_dict(self) -> dict:
        info = KINDS[self.kind]
        return {
            "kind": self.kind.value,
            "title": info.title,
            "description": info.description,
            "technique": info.technique,
            "severity": self.severity,
            "address": self.base,
            "size": self.size,
            "region_kind": self.region_kind,
            "protect": self.protect,
            "mapped_file": self.mapped_file,
            "detail": self.detail,
        }


class AnomalyDetector:
    def __init__(self) -> None:
        self.anomalies: List[Anomaly] = []
        self._region: Optional[MemoryRegion] = None
        self._reset()

    def _reset(self) -> None:
        self._pe: List[int] = []
        self._entropy = 0.0
        self._strong: set = set()
        self._weak: set = set()

    # -- per-region lifecycle ------------------------------------------------------------------

    def begin(self, region: MemoryRegion) -> None:
        self._region = region
        self._reset()

    def feed(self, data: bytes, offset: int = 0, core_len: Optional[int] = None) -> None:
        r = self._region
        assert r is not None, "begin() must be called first"
        core = data if core_len is None else data[:core_len]

        file_backed = r.kind == "Image" or bool(r.mapped_file)
        if not file_backed:
            for pos in find_pe_headers(data):
                if pos < len(core):
                    self._pe.append(offset + pos)
        if r.kind != "Image":
            self._strong.update(m.group().lower().decode("ascii", "replace")
                                for m in _STRONG_STRINGS.finditer(data) if m.start() < len(core))
            self._weak.update(_label(m.group()) for m in _WEAK_STRINGS.finditer(data) if m.start() < len(core))
        if r.kind != "Image" and (r.executable or r.size >= ENTROPY_DATA_MIN_REGION):
            self._entropy = max(self._entropy, self._sample_entropy(core))

    def end(self) -> List[Anomaly]:
        r = self._region
        assert r is not None
        found: List[Anomaly] = []

        entropy_limit = ENTROPY_EXEC_THRESHOLD if r.executable else ENTROPY_DATA_THRESHOLD
        high_entropy = self._entropy >= entropy_limit
        strings_hit = bool(self._strong) or len(self._weak) >= WEAK_STRING_MIN_DISTINCT
        corroborating: List[str] = []
        if self._pe:
            corroborating.append("embedded PE")
        if self._strong:
            corroborating.append("offensive-tool strings")
        if high_entropy and r.executable:
            corroborating.append("high entropy")

        def add(kind: Kind, severity: str, detail: str) -> None:
            found.append(Anomaly(kind, severity, r.base, r.size, r.kind, r.protect, detail, r.mapped_file))

        def escalate(base: str) -> str:
            return "CRITICAL" if corroborating and r.executable else base

        suffix = f"; corroborated by {', '.join(corroborating)}" if corroborating and r.executable else ""
        if r.executable and r.writable:
            add(Kind.RWX_REGION, escalate("HIGH"), f"{r.protect} {r.kind.lower()} region{suffix}")
        elif r.executable and r.kind != "Image" and not r.mapped_file:
            add(Kind.UNBACKED_EXEC, escalate("HIGH"), f"{r.protect} {r.kind.lower()} region, no module{suffix}")

        if self._pe:
            where = ", ".join(f"+0x{p:X}" for p in self._pe[:3])
            add(Kind.EMBEDDED_PE, "CRITICAL" if r.executable else "HIGH", f"PE header at {where}")

        if high_entropy:
            add(Kind.HIGH_ENTROPY, "HIGH" if r.executable else "LOW",
                f"{self._entropy:.2f} bits/byte (threshold {entropy_limit})")

        if strings_hit:
            names = sorted(self._strong) + sorted(self._weak)
            severity = "HIGH" if self._strong else "MEDIUM"
            add(Kind.SUSPICIOUS_STRINGS, "CRITICAL" if self._strong and r.executable else severity,
                ", ".join(names[:6]))

        self.anomalies.extend(found)
        self._region = None
        return found

    # -- helpers -------------------------------------------------------------------------------

    @staticmethod
    def _sample_entropy(data: bytes) -> float:
        """Max entropy over up to three windows spread across the chunk."""
        if len(data) < 256:
            return 0.0
        step = max(1, (len(data) - ENTROPY_WINDOW) // 2) if len(data) > ENTROPY_WINDOW else len(data)
        return max(shannon_entropy(data[off:off + ENTROPY_WINDOW]) for off in range(0, len(data), step)[:3])

    def sorted(self) -> List[Anomaly]:
        return sorted(self.anomalies, key=lambda a: (-SEVERITY_RANK[a.severity], a.base))
