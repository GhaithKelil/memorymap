import ctypes
import ctypes.wintypes as wintypes
import psutil
from dataclasses import dataclass, field
from typing import List, Optional

PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

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
    0x20000:   "Private",
    0x40000:   "Mapped",
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


@dataclass
class MemoryRegion:
    base_address:  int
    size:          int
    state:         str   # COMMIT / RESERVE / FREE
    protect:       str
    region_type:   str
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
    flags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    return bool(protect & flags)


def _is_writable(protect: int) -> bool:
    flags = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    return bool(protect & flags)


class ProcessMemoryReader:
    """Opens a handle to a process and walks its virtual address space."""

    def __init__(self, pid: int):
        self.pid = pid
        self._handle: Optional[int] = None
        self.kernel32 = ctypes.windll.kernel32

    def open(self) -> bool:
        self._handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            self.pid,
        )
        if not self._handle:
            err = ctypes.get_last_error()
            raise PermissionError(
                f"Cannot open PID {self.pid} (error {err}). Try running as Administrator."
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

    def enumerate_regions(self, read_data: bool = True) -> List[MemoryRegion]:
        regions: List[MemoryRegion] = []
        addr = 0
        mbi  = MEMORY_BASIC_INFORMATION()

        while True:
            ret = self.kernel32.VirtualQueryEx(
                self._handle,
                ctypes.c_ulonglong(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break

            region = MemoryRegion(
                base_address  = mbi.BaseAddress,
                size          = mbi.RegionSize,
                state         = _decode_state(mbi.State),
                protect       = _decode_protect(mbi.Protect),
                region_type   = _decode_type(mbi.Type),
                is_executable = _is_executable(mbi.Protect),
                is_writable   = _is_writable(mbi.Protect),
            )

            if read_data and mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS):
                region.data = self._read_region(mbi.BaseAddress, mbi.RegionSize)

            regions.append(region)
            addr = mbi.BaseAddress + mbi.RegionSize

            if addr >= 0x7FFFFFFFFFFF:
                break

        return regions

    def _read_region(self, address: int, size: int, chunk: int = 4096) -> bytes:
        result = bytearray()
        buf    = ctypes.create_string_buffer(chunk)
        read   = ctypes.c_size_t(0)
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
                result.extend(b"\x00" * to_read)
                offset += to_read

        return bytes(result)


def list_processes() -> List[dict]:
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
