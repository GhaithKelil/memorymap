"""Windows process memory access: region enumeration and bulk reads."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import ntpath
import sys
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

import psutil

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

_EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
_WRITE_MASK = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY

PAGE_SIZE = 4096
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87

# Short protection codes: R/W/X, with a trailing C for copy-on-write.
_PROTECT_CODES = {
    PAGE_NOACCESS: "---",
    PAGE_READONLY: "R",
    PAGE_READWRITE: "RW",
    PAGE_WRITECOPY: "RWC",
    PAGE_EXECUTE: "X",
    PAGE_EXECUTE_READ: "RX",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "RWXC",
}
_STATES = {MEM_COMMIT: "COMMIT", MEM_RESERVE: "RESERVE", MEM_FREE: "FREE"}
_KINDS = {MEM_PRIVATE: "Private", MEM_MAPPED: "Mapped", MEM_IMAGE: "Image"}


class _MemoryBasicInformation(ctypes.Structure):
    # Natural alignment yields the right layout on both 32- and 64-bit Python.
    _fields_ = [
        ("BaseAddress", ctypes.c_size_t),
        ("AllocationBase", ctypes.c_size_t),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class _SystemInfo(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wt.WORD),
        ("wReserved", wt.WORD),
        ("dwPageSize", wt.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_size_t),
        ("lpMaximumApplicationAddress", ctypes.c_size_t),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wt.DWORD),
        ("dwProcessorType", wt.DWORD),
        ("dwAllocationGranularity", wt.DWORD),
        ("wProcessorLevel", wt.WORD),
        ("wProcessorRevision", wt.WORD),
    ]


@dataclass
class MemoryRegion:
    base: int
    size: int
    allocation_base: int
    state: str
    protect: str
    kind: str
    executable: bool
    writable: bool
    readable: bool
    mapped_file: str = ""

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def committed(self) -> bool:
        return self.state == "COMMIT"


def decode_protect(protect: int) -> str:
    code = _PROTECT_CODES.get(protect & ~PAGE_GUARD & ~0x200 & ~0x400, f"0x{protect:X}")
    return code + "+G" if protect & PAGE_GUARD else code


def _bind_kernel32() -> ctypes.WinDLL:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.OpenProcess.restype = wt.HANDLE
    k32.CloseHandle.argtypes = [wt.HANDLE]
    k32.CloseHandle.restype = wt.BOOL
    k32.VirtualQueryEx.argtypes = [
        wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(_MemoryBasicInformation), ctypes.c_size_t,
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [
        wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    k32.ReadProcessMemory.restype = wt.BOOL
    k32.K32GetMappedFileNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    k32.K32GetMappedFileNameW.restype = wt.DWORD
    k32.GetSystemInfo.argtypes = [ctypes.POINTER(_SystemInfo)]
    k32.GetSystemInfo.restype = None
    return k32


class ProcessMemoryReader:
    """Read-only view of another process's virtual address space."""

    def __init__(self, pid: int):
        if sys.platform != "win32":
            raise OSError("MemoryMap reads process memory through the Win32 API and only runs on Windows.")
        self.pid = pid
        self._k32 = _bind_kernel32()
        self._handle: Optional[int] = None
        self._mapped_names: Dict[int, str] = {}

    def open(self) -> "ProcessMemoryReader":
        handle = self._k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, self.pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == ERROR_ACCESS_DENIED:
                raise PermissionError(
                    f"Access denied opening PID {self.pid}. Run from an elevated terminal "
                    "to inspect protected or other users' processes."
                )
            if err == ERROR_INVALID_PARAMETER:
                raise ProcessLookupError(f"No process with PID {self.pid}.")
            raise ctypes.WinError(err)
        self._handle = handle
        return self

    def close(self) -> None:
        if self._handle:
            self._k32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> "ProcessMemoryReader":
        return self.open()

    def __exit__(self, *_exc) -> None:
        self.close()

    def iter_regions(self) -> Iterator[MemoryRegion]:
        """Walk the address space, yielding one entry per VirtualQueryEx result."""
        info = _SystemInfo()
        self._k32.GetSystemInfo(ctypes.byref(info))
        limit = info.lpMaximumApplicationAddress
        addr = info.lpMinimumApplicationAddress
        mbi = _MemoryBasicInformation()

        while addr < limit:
            if not self._k32.VirtualQueryEx(self._handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            if mbi.RegionSize == 0:
                break

            state = _STATES.get(mbi.State, f"0x{mbi.State:X}")
            kind = _KINDS.get(mbi.Type, "Unknown")
            committed = mbi.State == MEM_COMMIT
            protect = mbi.Protect if committed else 0
            region = MemoryRegion(
                base=mbi.BaseAddress,
                size=mbi.RegionSize,
                allocation_base=mbi.AllocationBase,
                state=state,
                protect=decode_protect(protect) if committed else "",
                kind=kind,
                executable=bool(protect & _EXEC_MASK),
                writable=bool(protect & _WRITE_MASK),
                readable=committed and not protect & (PAGE_NOACCESS | PAGE_GUARD) and protect != 0,
            )
            if committed and mbi.Type in (MEM_IMAGE, MEM_MAPPED):
                region.mapped_file = self._mapped_file(mbi.AllocationBase, mbi.BaseAddress)
            yield region

            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt

    def _mapped_file(self, allocation_base: int, address: int) -> str:
        cached = self._mapped_names.get(allocation_base)
        if cached is not None:
            return cached
        buf = ctypes.create_unicode_buffer(1024)
        name = ""
        if self._k32.K32GetMappedFileNameW(self._handle, address, buf, len(buf)):
            name = ntpath.basename(buf.value)
        self._mapped_names[allocation_base] = name
        return name

    def read(self, address: int, size: int) -> bytes:
        """Read ``size`` bytes. Unreadable pages come back zero-filled so offsets stay aligned."""
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if self._k32.ReadProcessMemory(self._handle, address, buf, size, ctypes.byref(got)):
            return buf.raw[: got.value]

        out = bytearray(size)
        page = ctypes.create_string_buffer(PAGE_SIZE)
        for off in range(0, size, PAGE_SIZE):
            n = min(PAGE_SIZE, size - off)
            if self._k32.ReadProcessMemory(self._handle, address + off, page, n, ctypes.byref(got)) and got.value:
                out[off : off + got.value] = page.raw[: got.value]
        return bytes(out)

    def read_chunks(self, region: MemoryRegion, chunk_size: int, overlap: int = 512) -> Iterator[tuple]:
        """Yield ``(offset, data, core_len)``.

        ``data`` extends ``overlap`` bytes past the chunk so strings that straddle a boundary
        are still seen; only matches starting inside the first ``core_len`` bytes belong to
        this chunk.
        """
        for off in range(0, region.size, chunk_size):
            core = min(chunk_size, region.size - off)
            extra = min(overlap, region.size - off - core)
            data = self.read(region.base + off, core + extra)
            if data:
                yield off, data, min(core, len(data))


def list_processes() -> List[dict]:
    """Running processes, largest working set first."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "memory_info", "username"]):
        info = proc.info
        mem = info.get("memory_info")
        procs.append({
            "pid": info["pid"],
            "name": info["name"] or "?",
            "rss_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
            "username": (info.get("username") or "").split("\\")[-1],
        })
    return sorted(procs, key=lambda p: p["rss_mb"], reverse=True)


def find_processes(query: str) -> List[dict]:
    """Match by PID or case-insensitive name substring."""
    procs = list_processes()
    if query.isdigit():
        return [p for p in procs if p["pid"] == int(query)]
    q = query.lower()
    exact = [p for p in procs if p["name"].lower() in (q, q + ".exe")]
    return exact or [p for p in procs if q in p["name"].lower()]


def process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return f"PID {pid}"


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False
