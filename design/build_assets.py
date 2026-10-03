"""Generates MemoryMap's brand and illustration assets.

SVG sources are written to design/svg and rendered to PNG in memorymap/web/static/img with a
headless Chromium-based browser (Edge or Chrome). Deterministic: re-running yields the same files.

    python design/build_assets.py
"""

from __future__ import annotations

import random
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SVG_DIR = ROOT / "design" / "svg"
PNG_DIR = ROOT / "memorymap" / "web" / "static" / "img"

BG = "#0A0E2B"
INK = "#EEF1FF"
CELL = "#8D98E8"
ACCENT = "#5B7CFF"
VIOLET = "#9B5BFF"
RED, ORANGE, YELLOW, GREEN = "#FF4D6A", "#FF9A4D", "#FFD25A", "#2EE6B6"
SEVERITY = [RED, ORANGE, YELLOW]
FONT = "'Segoe UI Variable Display','Segoe UI',system-ui,sans-serif"
MONO = "'Cascadia Mono',Consolas,ui-monospace,monospace"

M_GLYPH = ["10001", "11011", "10101", "10001", "10001"]

BRAND_DEFS = (
    f'<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#232C7A"/>'
    f'<stop offset="1" stop-color="{BG}"/></linearGradient>'
    f'<linearGradient id="core" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6FA0FF"/>'
    f'<stop offset="1" stop-color="{VIOLET}"/></linearGradient>'
)


def svg(w: int, h: int, body: str, defs: str = "") -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
            f"<defs>{defs}</defs>{body}</svg>")


def rect(x, y, s, fill, opacity=1.0, r=None, extra=""):
    r = s * 0.22 if r is None else r
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{s:.1f}" height="{s:.1f}" rx="{r:.1f}" '
            f'fill="{fill}" fill-opacity="{opacity}" {extra}/>')


def _rgb(hexcolor: str):
    h = hexcolor.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def shade(hexcolor: str, factor: float) -> str:
    """factor < 1 darkens, > 1 lightens toward white."""
    r, g, b = _rgb(hexcolor)
    if factor <= 1:
        r, g, b = (int(c * factor) for c in (r, g, b))
    else:
        t = factor - 1
        r, g, b = (int(c + (255 - c) * t) for c in (r, g, b))
    return f"#{r:02X}{g:02X}{b:02X}"


# --- logo ----------------------------------------------------------------------------------------

def logo(size=512, background=True, ink=INK, dim=0.14) -> str:
    pad = size * 0.17
    pitch = (size - 2 * pad) / 5
    cell = pitch * 0.80
    off = (pitch - cell) / 2
    out = []
    if background:
        out.append(f'<rect width="{size}" height="{size}" rx="{size * 0.225:.1f}" fill="url(#bg)"/>')
        out.append(f'<rect x="1" y="1" width="{size - 2}" height="{size - 2}" rx="{size * 0.22:.1f}" fill="none" '
                   'stroke="#8FA2FF" stroke-opacity="0.28" stroke-width="2"/>')
    for r, row in enumerate(M_GLYPH):
        for c, ch in enumerate(row):
            x, y = pad + c * pitch + off, pad + r * pitch + off
            if (r, c) == (2, 2):
                out.append(rect(x, y, cell, "url(#core)"))
            elif ch == "1":
                out.append(rect(x, y, cell, ink))
            else:
                out.append(rect(x, y, cell, ink, dim))
    return svg(size, size, "".join(out), BRAND_DEFS)


# --- isometric 3D hero ---------------------------------------------------------------------------

def _column(cx, cy, a, h, base, top_a=0.95, side_a=0.8):
    hh = a * 0.5
    top = f"{cx:.1f},{cy - h - hh:.1f} {cx + a:.1f},{cy - h:.1f} {cx:.1f},{cy - h + hh:.1f} {cx - a:.1f},{cy - h:.1f}"
    left = f"{cx - a:.1f},{cy - h:.1f} {cx:.1f},{cy - h + hh:.1f} {cx:.1f},{cy + hh:.1f} {cx - a:.1f},{cy:.1f}"
    right = f"{cx + a:.1f},{cy - h:.1f} {cx:.1f},{cy - h + hh:.1f} {cx:.1f},{cy + hh:.1f} {cx + a:.1f},{cy:.1f}"
    return (f'<polygon points="{left}" fill="{shade(base, 0.78)}" fill-opacity="{side_a}"/>'
            f'<polygon points="{right}" fill="{shade(base, 0.55)}" fill-opacity="{side_a}"/>'
            f'<polygon points="{top}" fill="{shade(base, 1.28)}" fill-opacity="{top_a}"/>')


def iso(w=760, h=420, n=10) -> str:
    rnd = random.Random(21)
    a = 31
    spots = {}
    while len(spots) < 11:
        spots[(rnd.randrange(1, n - 1), rnd.randrange(1, n - 1))] = rnd.choice([RED, RED, ORANGE, ORANGE, YELLOW, GREEN])
    cols = []
    for s in range(2 * n - 1):  # back to front
        for i in range(n):
            j = s - i
            if not 0 <= j < n:
                continue
            cx = w / 2 + (i - j) * a * 0.93
            cy = 120 + (i + j) * a * 0.465
            if (i, j) in spots:
                height = rnd.randrange(54, 118)
                color = spots[(i, j)]
                cols.append(("hot", cx, cy, height, color))
            else:
                height = rnd.choice([10, 14, 18, 24, 30, 38, 48]) if rnd.random() > 0.2 else rnd.randrange(52, 84)
                cols.append(("cold", cx, cy, height, "#6E7CF0" if rnd.random() > 0.35 else "#8B6BFF"))
    glow, body = [], []
    for kind, cx, cy, height, color in cols:
        a_eff = a * 0.9
        if kind == "hot":
            glow.append(_column(cx, cy, a_eff, height, color, 0.9, 0.9))
        body.append(_column(cx, cy, a_eff, height, color, 0.95 if kind == "hot" else 0.7, 0.95 if kind == "hot" else 0.55))
    defs = '<filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="9"/></filter>'
    return svg(w, h, f'<g filter="url(#glow)" opacity="0.65">{"".join(glow)}</g>{"".join(body)}', defs)


# --- illustrations -------------------------------------------------------------------------------

def hero(w=1280, h=300) -> str:
    rnd = random.Random(7)
    pitch, cell = 20, 15
    cols, rows = w // pitch, h // pitch
    scan_col = int(cols * 0.64)
    hot = {(rnd.randrange(6, scan_col - 2), rnd.randrange(1, rows - 1)): rnd.choice(SEVERITY) for _ in range(15)}
    out = []
    for r in range(rows):
        for c in range(cols):
            x, y = c * pitch + (w - cols * pitch) / 2, r * pitch + (h - rows * pitch) / 2
            if (c, r) in hot:
                out.append(rect(x, y, cell, hot[(c, r)]))
                continue
            base = 0.30 if c < scan_col else 0.11
            a = base * (0.45 + 0.55 * rnd.random())
            if rnd.random() < 0.05:
                a += 0.16
            out.append(rect(x, y, cell, CELL, round(a, 3)))
    sx = scan_col * pitch + (w - cols * pitch) / 2 - 2.5
    out.append(f'<rect x="{sx - 90:.1f}" y="0" width="90" height="{h}" fill="url(#glow)"/>')
    out.append(f'<rect x="{sx:.1f}" y="0" width="2.5" height="{h}" fill="{ACCENT}"/>')
    defs = (f'<linearGradient id="glow" x1="0" x2="1"><stop offset="0" stop-color="{ACCENT}" stop-opacity="0"/>'
            f'<stop offset="1" stop-color="{ACCENT}" stop-opacity="0.22"/></linearGradient>'
            '<linearGradient id="fade" x1="0" x2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/>'
            '<stop offset="0.12" stop-color="#fff"/><stop offset="0.88" stop-color="#fff"/>'
            '<stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient>'
            f'<mask id="m"><rect width="{w}" height="{h}" fill="url(#fade)"/></mask>')
    return svg(w, h, f'<g mask="url(#m)">{"".join(out)}</g>', defs)


def clean(w=520, h=300) -> str:
    cols, rows, pitch, cell = 21, 12, 24, 18
    ox, oy = (w - cols * pitch) / 2, (h - rows * pitch) / 2
    check = {(5, 6), (6, 7), (7, 8), (8, 9), (9, 8), (10, 7), (11, 6), (12, 5), (13, 4), (14, 3)}
    rnd = random.Random(3)
    out = []
    for r in range(rows):
        for c in range(cols):
            x, y = ox + c * pitch, oy + r * pitch
            if (c, r) in check:
                out.append(rect(x, y, cell, GREEN))
            else:
                out.append(rect(x, y, cell, CELL, round(0.08 + 0.12 * rnd.random(), 3)))
    return svg(w, h, "".join(out))


def diff_scene(w=760, h=300, labels=True) -> str:
    rnd = random.Random(11)
    cols, rows, pitch, cell = 11, 8, 26, 20
    gw, gh = cols * pitch, rows * pitch
    gx1, gx2, gy = 20, w - gw - 20, (h - gh) / 2 + (8 if labels else 0)
    spots = []
    while len(spots) < 9:
        p = (rnd.randrange(cols), rnd.randrange(rows))
        if p not in spots:
            spots.append(p)
    colors = [RED, RED, ORANGE, ORANGE, ORANGE, YELLOW, YELLOW, YELLOW, YELLOW]
    kept = {0, 3, 4}
    out = []
    for gx, after in ((gx1, False), (gx2, True)):
        for r in range(rows):
            for c in range(cols):
                x, y = gx + c * pitch, gy + r * pitch
                if (c, r) in spots:
                    i = spots.index((c, r))
                    if not after:
                        out.append(rect(x, y, cell, colors[i]))
                    elif i in kept:
                        out.append(rect(x - 3, y - 3, cell + 6, colors[i], 0.2, r=7))
                        out.append(rect(x, y, cell, colors[i]))
                    else:
                        out.append(rect(x, y, cell, "none", 1, extra=f'stroke="{GREEN}" stroke-width="1.5" '
                                                                   'stroke-dasharray="3 3"'))
                else:
                    out.append(rect(x, y, cell, CELL, round(0.10 + 0.12 * rnd.random(), 3)))
    ax, ay = w / 2, gy + gh / 2
    out.append(f'<path d="M{ax - 22:.1f} {ay:.1f} H{ax + 18:.1f} M{ax + 6:.1f} {ay - 12:.1f} L{ax + 20:.1f} {ay:.1f} '
               f'L{ax + 6:.1f} {ay + 12:.1f}" stroke="{CELL}" stroke-width="3" fill="none" '
               'stroke-linecap="round" stroke-linejoin="round"/>')
    if labels:
        for gx, text in ((gx1, "BEFORE"), (gx2, "AFTER")):
            out.append(f'<text x="{gx}" y="{gy - 14}" fill="{CELL}" font-family="{MONO}" font-size="13" '
                       f'letter-spacing="2">{text}</text>')
    return svg(w, h, "".join(out))


def _embed(markup: str, x: float, y: float, scale: float = 1.0) -> str:
    """Inline another asset's drawing (without its <svg> wrapper) at a position."""
    inner = markup[markup.index(">") + 1: markup.rindex("</svg>")]
    return f'<g transform="translate({x} {y}) scale({scale})">{inner}</g>'


def social(w=1280, h=640) -> str:
    body = (
        '<rect width="1280" height="640" fill="url(#page)"/>'
        '<circle cx="1060" cy="120" r="360" fill="url(#orb1)"/><circle cx="120" cy="620" r="320" fill="url(#orb2)"/>'
        + _embed(iso(), 520, 150, 1.0) +
        _embed(logo(132, True), 80, 84) +
        f'<text x="236" y="170" fill="{INK}" font-family="{FONT}" font-size="76" font-weight="650" '
        f'letter-spacing="-2">MemoryMap</text>'
        f'<text x="82" y="290" fill="#A9B2E8" font-family="{FONT}" font-size="34">Live process memory forensics</text>'
        f'<text x="82" y="336" fill="#A9B2E8" font-family="{FONT}" font-size="34">for Windows.</text>'
        f'<text x="82" y="440" fill="{INK}" font-family="{FONT}" font-size="40" font-weight="600" '
        f'letter-spacing="-0.5">After logout, is the secret</text>'
        f'<text x="82" y="496" fill="url(#hl)" font-family="{FONT}" font-size="40" font-weight="650" '
        f'letter-spacing="-0.5">still in RAM?</text>'
        f'<text x="82" y="572" fill="#7882C0" font-family="{FONT}" font-size="21" letter-spacing="0.5">'
        'residue testing  /  secret scanning  /  injection anomalies</text>'
    )
    defs = (BRAND_DEFS +
            f'<linearGradient id="page" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#101654"/>'
            f'<stop offset="1" stop-color="#070A22"/></linearGradient>'
            f'<radialGradient id="orb1"><stop offset="0" stop-color="{ACCENT}" stop-opacity="0.45"/>'
            f'<stop offset="1" stop-color="{ACCENT}" stop-opacity="0"/></radialGradient>'
            f'<radialGradient id="orb2"><stop offset="0" stop-color="{VIOLET}" stop-opacity="0.38"/>'
            f'<stop offset="1" stop-color="{VIOLET}" stop-opacity="0"/></radialGradient>'
            f'<linearGradient id="hl" x1="0" x2="1"><stop offset="0" stop-color="#7EA2FF"/>'
            f'<stop offset="1" stop-color="#B58BFF"/></linearGradient>'
            '<filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="9"/></filter>')
    return svg(w, h, body, defs)


ASSETS = {
    "logo": (logo(512), 512, 512, 1),
    "logo-mark-dark": (logo(512, background=False, ink="#EEF1FF"), 512, 512, 1),
    "logo-mark-light": (logo(512, background=False, ink="#1B2230", dim=0.10), 512, 512, 1),
    "favicon": (logo(64), 64, 64, 2),
    "hero": (iso(), 760, 420, 2),
    "hero-grid": (hero(), 1280, 300, 2),
    "empty-clean": (clean(), 520, 300, 2),
    "empty-diff": (diff_scene(), 760, 300, 2),
    "social-preview": (social(), 1280, 640, 1),
}


def find_browser() -> str:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    found = shutil.which("msedge") or shutil.which("chrome") or shutil.which("google-chrome")
    if not found:
        sys.exit("No Edge or Chrome found for rendering.")
    return found


def main() -> None:
    SVG_DIR.mkdir(parents=True, exist_ok=True)
    PNG_DIR.mkdir(parents=True, exist_ok=True)
    browser = find_browser()
    for name, (markup, w, h, scale) in ASSETS.items():
        src = SVG_DIR / f"{name}.svg"
        src.write_text(markup, encoding="utf-8")
        dest = PNG_DIR / f"{name}.png"
        subprocess.run([
            browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
            "--default-background-color=00000000", f"--force-device-scale-factor={scale}",
            f"--window-size={w},{h}", f"--screenshot={dest}", src.as_uri(),
        ], check=True, capture_output=True)
        print(f"{name}: {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
