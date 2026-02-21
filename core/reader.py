"""
core/reader.py
--------------
Reads memory regions of a target process using Windows API via ctypes.
No third-party C extensions required — pure ctypes + psutil.
"""

import ctypes
import ctypes.wintypes as wintypes
import psutil
import struct
from dataclasses import dataclass, field
from typing import List, Optional

# ── Windows constants ──────────────────────────────────────────────────────────
PROCESS_VM_READ            = 0x0010
PROCESS_QUERY_INFORMATION  = 0x0400
PROCESS_ALL_ACCESS         = 0x001F0FFF

MEM_COMMIT  = 0x1000
MEM_FREE    = 0x10000
MEM_RESERVE = 0x2000

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100

MEM_TYPES = {
    0x20000: "Private",
    0x40000: "Mapped",
    0x1000000: "Image (DLL/EXE)",
}

PAGE_PROTECT_NAMES = {
    PAGE_NOACCESS:          "NO_ACCESS",
    PAGE_READONLY:          "READ_ONLY",
    PAGE_READWRITE:         "READ_WRITE",
    PAGE_WRITECOPY:         "WRITE_COPY",
    PAGE_EXECUTE:           "EXECUTE",
    PAGE_EXECUTE_READ:      "EXEC_READ",
    PAGE_EXECUTE_READWRITE: "EXEC_READ_WRITE",
    PAGE_EXECUTE_WRITECOPY: "EXEC_WRITE_COPY",
}

# ── MEMORY_BASIC_INFORMATION struct ───────────────────────────────────────────
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),
        ("AllocationBase",    ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1",      wintypes.DWORD),
        ("RegionSize",        ctypes.c_ulonglong),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
        ("__alignment2",      wintypes.DWORD),
    ]


# ── Data class for a single region ────────────────────────────────────────────
@dataclass
class MemoryRegion:
    base_address:  int
    size:          int
    state:         str        # COMMIT / RESERVE / FREE
    protect:       str        # READ_WRITE etc.
    region_type:   str        # Private / Mapped / Image
    is_executable: bool
    is_writable:   bool
    data:          bytes = field(default=b"", repr=False)

    @property
    def end_address(self) -> int:
        return self.base_address + self.size

    @property
    def size_kb(self) -> float:
        return self.size / 1024

    @property
    def size_mb(self) -> float:
        return self.size / (1024 * 1024)


# ── Helper: decode state/protect/type ─────────────────────────────────────────
def _decode_state(state: int) -> str:
    return {MEM_COMMIT: "COMMIT", MEM_RESERVE: "RESERVE", MEM_FREE: "FREE"}.get(state, f"0x{state:X}")


def _decode_protect(protect: int) -> str:
    base = protect & ~PAGE_GUARD
    name = PAGE_PROTECT_NAMES.get(base, f"0x{protect:X}")
    if protect & PAGE_GUARD:
        name += "+GUARD"
    return name


def _decode_type(mtype: int) -> str:
    return MEM_TYPES.get(mtype, f"0x{mtype:X}")


def _is_executable(protect: int) -> bool:
    exec_flags = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return bool(protect & exec_flags)


def _is_writable(protect: int) -> bool:
    write_flags = (PAGE_READWRITE | PAGE_WRITECOPY |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return bool(protect & write_flags)


# ── Core reader class ─────────────────────────────────────────────────────────
class ProcessMemoryReader:
    """
    Opens a process handle and iterates over all virtual memory regions.
    Must be run as Administrator for PROCESS_VM_READ on protected processes.
    """

    def __init__(self, pid: int):
        self.pid = pid
        self._handle: Optional[int] = None
        self.kernel32 = ctypes.windll.kernel32

    def open(self) -> bool:
        """Open a handle to the target process. Returns True on success."""
        self._handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            self.pid,
        )
        if not self._handle:
            err = ctypes.get_last_error()
            raise PermissionError(
                f"Cannot open PID {self.pid}. Error code: {err}. "
                "Try running as Administrator."
            )
        return True

    def close(self):
        if self._handle:
            self.kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    # ── Region enumeration ────────────────────────────────────────────────────
    def enumerate_regions(self, read_data: bool = True) -> List[MemoryRegion]:
        """
        Walk the entire virtual address space and return all memory regions.
        Set read_data=True to also read the raw bytes from each COMMIT region.
        """
        regions: List[MemoryRegion] = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)

        while True:
            ret = self.kernel32.VirtualQueryEx(
                self._handle,
                ctypes.c_ulonglong(addr),
                ctypes.byref(mbi),
                mbi_size,
            )
            if ret == 0:
                break  # end of address space

            state   = _decode_state(mbi.State)
            protect = _decode_protect(mbi.Protect)
            rtype   = _decode_type(mbi.Type)

            region = MemoryRegion(
                base_address  = mbi.BaseAddress,
                size          = mbi.RegionSize,
                state         = state,
                protect       = protect,
                region_type   = rtype,
                is_executable = _is_executable(mbi.Protect),
                is_writable   = _is_writable(mbi.Protect),
            )

            if read_data and mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS):
                region.data = self._read_region(mbi.BaseAddress, mbi.RegionSize)

            regions.append(region)
            addr = mbi.BaseAddress + mbi.RegionSize

            # 64-bit address space upper limit
            if addr >= 0x7FFFFFFFFFFF:
                break

        return regions

    # ── Raw memory read ───────────────────────────────────────────────────────
    def _read_region(self, address: int, size: int, chunk: int = 4096) -> bytes:
        """Read `size` bytes from `address`, in chunks to handle partial failures."""
        result = bytearray()
        buf = ctypes.create_string_buffer(chunk)
        read = ctypes.c_size_t(0)
        offset = 0

        while offset < size:
            to_read = min(chunk, size - offset)
            ok = self.kernel32.ReadProcessMemory(
                self._handle,
                ctypes.c_ulonglong(address + offset),
                buf,
                to_read,
                ctypes.byref(read),
            )
            if ok and read.value > 0:
                result.extend(buf.raw[:read.value])
                offset += read.value
            else:
                # Unreadable page — pad with zeros and skip
                result.extend(b"\x00" * to_read)
                offset += to_read

        return bytes(result)


# ── Process lister ────────────────────────────────────────────────────────────
def list_processes() -> List[dict]:
    """Return a list of running processes with pid, name, and memory info."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "memory_info", "username"]):
        try:
            info = proc.info
            mem  = info.get("memory_info")
            procs.append({
                "pid":      info["pid"],
                "name":     info["name"] or "?",
                "rss_mb":   round(mem.rss / (1024 * 1024), 2) if mem else 0,
                "username": info.get("username") or "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(procs, key=lambda p: p["rss_mb"], reverse=True)
