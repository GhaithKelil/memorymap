import os
from datetime import datetime, timezone

import pytest

from memorymap.reader import MemoryRegion
from memorymap.scan import ScanResult
from memorymap.scanner import Finding

os.environ.setdefault("MEMORYMAP_KEY_FILE", os.path.join(os.environ.get("TEMP", "."), "memorymap-test.key"))


def region(base=0x10000, size=0x1000, kind="Private", protect="RW", mapped_file="", **kw) -> MemoryRegion:
    flags = dict(executable="X" in protect, writable="W" in protect, readable=True)
    flags.update(kw)
    return MemoryRegion(base=base, size=size, allocation_base=base, state="COMMIT", protect=protect,
                        kind=kind, mapped_file=mapped_file, **flags)


def finding(value="AKIAIOSFODNN7EXAMPLE", pattern="aws_access_key", category="AWS access key ID",
            severity="CRITICAL", address=0x10010, count=1) -> Finding:
    return Finding(pattern=pattern, category=category, severity=severity, value=value, address=address, count=count)


def make_result(findings=(), anomalies=(), pid=1234) -> ScanResult:
    return ScanResult(
        pid=pid, process_name="demo.exe", started_at=datetime.now(timezone.utc), duration_s=1.0,
        regions=[region(0x10000, 0x10000), region(0x7FF000000000, 0x2000, "Image", "RX", "demo.dll")],
        scanned_bytes=0x10000, findings=list(findings), anomalies=list(anomalies),
    )


@pytest.fixture
def mk():
    return make_result
