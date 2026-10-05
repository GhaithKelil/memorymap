"""A harmless process to try MemoryMap against, including the residue test.

It behaves like a small app with a session: it holds well-known *example* credentials in memory
(AWS documentation keys, a Visa test number, a sample JWT; nothing real), plus one
read-write-execute page with a PE-like header that trips the injection heuristics.

When the flag file appears it "logs out": it wipes four of the seven secrets and, like a real bug,
forgets the other three (JWT, bearer token, database URL). A residue test should report exactly that.

    python examples/demo_target.py            # prints its PID and the flag path, then waits
    memorymap residue <PID>                   # takes the baseline, then asks you to do the action
    echo. > <flag path>                       # the "log out"; then press Enter in the other terminal

Or let the tool do the logging out for you:

    memorymap residue <PID> --action "cmd /c type nul > <flag path> & ping -n 2 127.0.0.1 >nul"
"""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import tempfile
import time

FLAG = os.environ.get("MEMORYMAP_DEMO_FLAG") or os.path.join(tempfile.gettempdir(), "memorymap_demo_logout.flag")

# XOR-encoded so the plaintext never sits in the interpreter's constants; it exists only in the
# buffers below, where this program controls whether it is wiped.
_ENC = {
    "AWS_KEY": bytes.fromhex("1b11131b1315091c151e14146d1f021b170a161f"),
    "AWS_SECRET": bytes.fromhex("3b2d2905293f39283f2e053b39393f292905313f237a677a2d103b3628020f2e341c1f171375116d171e1f141d75380a22083c3319031f021b170a161f111f03"),
    "CARD": bytes.fromhex("393b283e676e6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"),
    "PASSWORD": bytes.fromhex("2a3b29292d35283e7a677a0e286a2f386e3e35287c69223b372a363f"),
    "BEARER": bytes.fromhex("1b2f2e32352833203b2e333534607a183f3b283f287a633c623f6d3e6c396f386e3b696368626b6d6a6c3c6f3f6e3e693968386b3b6a"),
    "JWT": bytes.fromhex("3f231032381d3933153310130f20136b143313291334086f3919136c13312a020c191063743f2310203e0d1333153313221730176a140e0369151e312d13332d3338371c2e0009136c13312a2c3b1d6e3d081d633613346a74093c3611222d081009173f11111c680b0e6e3c2d2a173f103c696c0a15316c23100c053b3e0b29292d6f39"),
    "DB_URL": bytes.fromhex("2a35292e3d283f292b366075753b3e37333460092f2a6928096939283f2e0a3b29291a3e387433342e3f28343b36743f223b372a363f606f6e6968752a28353e"),
}
WIPED_ON_LOGOUT = ("AWS_KEY", "AWS_SECRET", "CARD", "PASSWORD")  # the bug: JWT, BEARER, DB_URL are forgotten

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]


def load_secret(name: str, utf16: bool = False):
    """Decode into a ctypes buffer byte by byte so no plaintext temporary is created."""
    enc = _ENC[name]
    width = 2 if utf16 else 1
    buf = ctypes.create_string_buffer(len(enc) * width + width)  # NUL-terminated, like a C string
    for i, b in enumerate(enc):
        buf[i * width] = (b ^ 0x5A).to_bytes(1, "little")
    return buf


def plant_rwx_page() -> int:
    addr = kernel32.VirtualAlloc(None, 0x2000, 0x3000, 0x40)  # RWX
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    nt = b"PE\x00\x00" + struct.pack("<H", 0x8664) + bytes(18) + struct.pack("<H", 0x20B)
    blob = bytes(dos) + nt + b"\x90" * 64 + b"reflective" + b"loader"
    ctypes.memmove(addr, blob, len(blob))
    return addr


def logout(secrets: dict) -> None:
    for name in WIPED_ON_LOGOUT:
        buf = secrets[name]
        ctypes.memset(buf, 0, ctypes.sizeof(buf))
        if name == "PASSWORD":  # the UTF-16 copy is wiped too
            ctypes.memset(secrets["PASSWORD_W"], 0, ctypes.sizeof(secrets["PASSWORD_W"]))


if __name__ == "__main__":
    secrets = {name: load_secret(name) for name in _ENC}
    secrets["PASSWORD_W"] = load_secret("PASSWORD", utf16=True)
    page = plant_rwx_page()
    if os.path.exists(FLAG):
        os.remove(FLAG)
    print(f"demo target running, PID {os.getpid()}", flush=True)
    print(f"logout flag: {FLAG}", flush=True)
    while True:
        if os.path.exists(FLAG):
            logout(secrets)
            print("logged out (4 of 7 secrets wiped)", flush=True)
            while os.path.exists(FLAG):
                try:
                    os.remove(FLAG)
                except OSError:
                    time.sleep(0.1)  # the writer may still have the file open
        time.sleep(0.2)
