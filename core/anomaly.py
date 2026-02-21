import math
import re
from dataclasses import dataclass
from typing import List
from enum import Enum


class AnomalyType(str, Enum):
    HIGH_ENTROPY    = "HIGH_ENTROPY"
    RWX_REGION      = "RWX_REGION"
    PE_IN_PRIVATE   = "PE_IN_PRIVATE"
    SUSPICIOUS_STR  = "SUSPICIOUS_STR"
    STACK_ANOMALY   = "STACK_ANOMALY"
    UNBACKED_EXEC   = "UNBACKED_EXEC"
    HEAP_EXEC       = "HEAP_EXEC"


ANOMALY_SEVERITY = {
    AnomalyType.HIGH_ENTROPY:   "HIGH",
    AnomalyType.RWX_REGION:     "HIGH",
    AnomalyType.PE_IN_PRIVATE:  "CRITICAL",
    AnomalyType.SUSPICIOUS_STR: "HIGH",
    AnomalyType.STACK_ANOMALY:  "MEDIUM",
    AnomalyType.UNBACKED_EXEC:  "CRITICAL",
    AnomalyType.HEAP_EXEC:      "MEDIUM",
}

ANOMALY_DESCRIPTION = {
    AnomalyType.HIGH_ENTROPY:   "High-entropy region — may be encrypted payload, shellcode, or packed code",
    AnomalyType.RWX_REGION:     "Read-Write-Execute region — common staging area for injected shellcode",
    AnomalyType.PE_IN_PRIVATE:  "PE/MZ header found in non-image region — indicates reflective DLL injection",
    AnomalyType.SUSPICIOUS_STR: "Known suspicious/malware-related string detected in memory",
    AnomalyType.STACK_ANOMALY:  "Executable stack region — may indicate DEP (NX) bypass attempt",
    AnomalyType.UNBACKED_EXEC:  "Executable private region with no file backing — classic code injection",
    AnomalyType.HEAP_EXEC:      "Heap-sized region marked executable — unusual and suspicious",
}


@dataclass
class Anomaly:
    anomaly_type: AnomalyType
    severity:     str
    description:  str
    base_address: int
    size:         int
    detail:       str = ""

    @property
    def address_hex(self) -> str:
        return f"0x{self.base_address:016X}"

    @property
    def size_kb(self) -> float:
        return round(self.size / 1024, 1)

    def as_dict(self) -> dict:
        return {
            "type":        self.anomaly_type.value,
            "severity":    self.severity,
            "description": self.description,
            "address":     self.address_hex,
            "size_kb":     self.size_kb,
            "detail":      self.detail,
        }


# Known shellcode/malware strings to look for in raw memory
SUSPICIOUS_BYTES: List[bytes] = [
    b"METERPRETER",
    b"meterpreter",
    b"metasploit",
    b"Metasploit",
    b"beacon.dll",
    b"ReflectiveLoader",
    b"reflective_loader",
    b"\x90\x90\x90\x90\x90\x90\x90\x90",  # NOP sled
    b"\xeb\xfe",                            # infinite loop
    b"NtUnmapViewOfSection",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"LoadLibraryA\x00GetProcAddress",
    b"powershell -enc",
    b"powershell -e ",
    b"cmd.exe /c ",
    b"cmd /c ",
    b"reverse_tcp",
    b"reverse_http",
    b"PAYLOAD",
    b"ZwSetSystemInformation",
    b"NtLoadDriver",
    b"\\\\?\\GLOBALROOT",
]

PE_MAGIC    = b"MZ"
PE_NT_HDR   = b"PE\x00\x00"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class AnomalyDetector:
    ENTROPY_HIGH_THRESHOLD = 7.2
    MIN_ANALYSIS_SIZE      = 512

    def __init__(self):
        self.anomalies: List[Anomaly] = []

    def detect(self, regions) -> List[Anomaly]:
        self.anomalies = []

        for region in regions:
            if region.state != "COMMIT":
                continue

            self._check_rwx(region)
            self._check_unbacked_exec(region)
            self._check_heap_exec(region)

            if not region.data or len(region.data) < self.MIN_ANALYSIS_SIZE:
                continue

            self._check_pe_injection(region)
            self._check_entropy(region)
            self._check_suspicious_strings(region)

        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        self.anomalies.sort(key=lambda a: rank.get(a.severity, 0), reverse=True)
        return self.anomalies

    def _add(self, region, atype: AnomalyType, detail: str = ""):
        self.anomalies.append(Anomaly(
            anomaly_type = atype,
            severity     = ANOMALY_SEVERITY[atype],
            description  = ANOMALY_DESCRIPTION[atype],
            base_address = region.base_address,
            size         = region.size,
            detail       = detail,
        ))

    def _check_rwx(self, region):
        if region.is_executable and region.is_writable:
            self._add(region, AnomalyType.RWX_REGION,
                      f"Protection: {region.protect}  Type: {region.region_type}")

    def _check_unbacked_exec(self, region):
        if region.is_executable and region.region_type == "Private" and not region.is_writable:
            self._add(region, AnomalyType.UNBACKED_EXEC,
                      f"Size: {region.size_kb:.1f} KB  Protection: {region.protect}")

    def _check_heap_exec(self, region):
        if (region.is_executable
                and region.region_type in ("Private", "Mapped")
                and region.size > 64 * 1024
                and region.is_writable):
            self._add(region, AnomalyType.HEAP_EXEC,
                      f"Size: {region.size_mb:.2f} MB  Protect: {region.protect}")

    def _check_pe_injection(self, region):
        if region.region_type == "Image (DLL/EXE)":
            return
        data = region.data
        positions = []
        idx = 0
        while True:
            pos = data.find(PE_MAGIC, idx)
            if pos == -1:
                break
            if pos + 0x40 < len(data):
                pe_offset = int.from_bytes(data[pos+0x3C:pos+0x40], "little")
                if pe_offset > 0 and pos + pe_offset + 4 <= len(data):
                    if data[pos+pe_offset:pos+pe_offset+4] == PE_NT_HDR:
                        positions.append(pos)
            idx = pos + 1
            if len(positions) >= 3:
                break

        if positions:
            locs = ", ".join(f"+0x{p:X}" for p in positions[:3])
            self._add(region, AnomalyType.PE_IN_PRIVATE,
                      f"MZ/PE header at offset(s): {locs}  Region type: {region.region_type}")

    def _check_entropy(self, region):
        data       = region.data
        chunk_size = min(len(data), 65536)
        step       = max(1, len(data) // 3)
        entropies  = []

        for off in [0, step, 2 * step]:
            chunk = data[off:off + chunk_size]
            if len(chunk) >= 256:
                entropies.append(shannon_entropy(chunk))

        if not entropies:
            return

        max_ent = max(entropies)
        if max_ent >= self.ENTROPY_HIGH_THRESHOLD:
            self._add(region, AnomalyType.HIGH_ENTROPY,
                      f"Max entropy: {max_ent:.3f} bits/byte  (threshold: {self.ENTROPY_HIGH_THRESHOLD})  "
                      f"Size: {region.size_kb:.1f} KB")

    def _check_suspicious_strings(self, region):
        data = region.data
        hits = []
        for pattern in SUSPICIOUS_BYTES:
            if pattern in data:
                try:
                    readable = pattern.decode("utf-8", errors="replace").strip()
                    if readable and not readable.isspace():
                        hits.append(readable[:40])
                except Exception:
                    hits.append(repr(pattern[:20]))
                if len(hits) >= 5:
                    break

        if hits:
            self._add(region, AnomalyType.SUSPICIOUS_STR,
                      "Matched: " + " | ".join(hits))


def anomaly_summary(anomalies: List[Anomaly]) -> dict:
    by_type    = {}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for a in anomalies:
        by_type.setdefault(a.anomaly_type.value, []).append(a.as_dict())
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

    return {
        "total":       len(anomalies),
        "by_severity": sev_counts,
        "by_type":     {k: len(v) for k, v in by_type.items()},
        "items":       [a.as_dict() for a in anomalies],
    }
