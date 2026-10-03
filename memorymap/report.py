"""Self-contained HTML forensics report."""

from __future__ import annotations

from datetime import datetime

from jinja2 import Environment, PackageLoader, select_autoescape

from memorymap import __version__
from memorymap.scan import ScanResult

_env = Environment(
    loader=PackageLoader("memorymap", "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["hex"] = lambda n: f"0x{n:012X}"
_env.filters["size"] = lambda n: (
    f"{n / 2**30:.2f} GB" if n >= 2**30 else f"{n / 2**20:.1f} MB" if n >= 2**20 else f"{n / 2**10:.0f} KB"
)

MAX_FINDINGS = 500


def render_report(result: ScanResult, reveal: bool = False) -> str:
    data = result.as_dict(reveal=reveal)
    top_regions = sorted(data["regions"], key=lambda r: r["s"], reverse=True)[:25]
    return _env.get_template("report.html").render(
        r=data,
        findings=data["findings"][:MAX_FINDINGS],
        findings_omitted=max(0, len(data["findings"]) - MAX_FINDINGS),
        top_regions=top_regions,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        version=__version__,
    )
