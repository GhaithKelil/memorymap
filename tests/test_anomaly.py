import os
import struct

from conftest import region
from memorymap.anomaly import AnomalyDetector, Kind, find_pe_headers, shannon_entropy
from memorymap.scoring import risk_label, risk_score


def pe_blob(machine=0x8664) -> bytes:
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    return bytes(dos) + b"PE\x00\x00" + struct.pack("<H", machine) + bytes(18) + struct.pack("<H", 0x20B) + bytes(64)


def inspect(reg, data=b""):
    d = AnomalyDetector()
    d.begin(reg)
    if data:
        d.feed(data)
    return {a.kind: a for a in d.end()}


def test_pe_header_validation():
    assert find_pe_headers(b"\x00" * 16 + pe_blob()) == [16]
    assert find_pe_headers(b"MZ" + b"\x00" * 200) == []  # no NT header behind it
    assert find_pe_headers(pe_blob(machine=0x1234)) == []  # unknown machine type


def test_rwx_region_is_flagged():
    assert Kind.RWX_REGION in inspect(region(protect="RWX"))


def test_plain_readwrite_heap_is_not_flagged():
    assert inspect(region(protect="RW"), b"hello world" * 100) == {}


def test_file_backed_executable_memory_is_not_flagged():
    assert inspect(region(kind="Image", protect="RX", mapped_file="kernel32.dll")) == {}
    assert Kind.UNBACKED_EXEC not in inspect(region(kind="Mapped", protect="RX", mapped_file="x.dll"))


def test_unbacked_exec_escalates_when_corroborated_by_pe():
    found = inspect(region(protect="RX", size=0x2000), pe_blob())
    assert found[Kind.UNBACKED_EXEC].severity == "CRITICAL"
    assert found[Kind.EMBEDDED_PE].severity == "CRITICAL"


def test_pe_in_plain_heap_is_high_not_critical():
    found = inspect(region(protect="RW", size=0x2000), pe_blob())
    assert found[Kind.EMBEDDED_PE].severity == "HIGH"
    assert Kind.UNBACKED_EXEC not in found


def test_pe_inside_mapped_file_is_ignored():
    assert Kind.EMBEDDED_PE not in inspect(region(kind="Mapped", protect="R", mapped_file="lib.dll"), pe_blob())


def test_high_entropy_executable_memory():
    noise = os.urandom(65536)
    assert shannon_entropy(noise) > 7.9
    assert Kind.HIGH_ENTROPY in inspect(region(protect="RX", size=65536), noise)


def test_weak_strings_need_several_distinct_hits():
    one = b"WriteProcessMemory " * 5
    three = b"WriteProcessMemory CreateRemoteThread VirtualAllocEx"
    assert Kind.SUSPICIOUS_STRINGS not in inspect(region(), one)
    assert Kind.SUSPICIOUS_STRINGS in inspect(region(), three)


def test_strong_string_is_enough():
    found = inspect(region(), b"... ReflectiveLoader ...")
    assert found[Kind.SUSPICIOUS_STRINGS].severity == "HIGH"


def test_strings_inside_images_are_ignored():
    assert inspect(region(kind="Image", protect="R", mapped_file="a.dll"), b"WriteProcessMemory CreateRemoteThread VirtualAllocEx") == {}


def test_scoring_saturates_and_bands():
    assert risk_score([]) == 0 and risk_label(0) == "CLEAN"
    assert risk_label(risk_score(["CRITICAL"])) == "MEDIUM"
    assert risk_label(risk_score(["CRITICAL"] * 4)) == "CRITICAL"
    assert risk_label(risk_score(["LOW"] * 20)) == "LOW"
    assert risk_score(["CRITICAL"] * 1000) <= 100
