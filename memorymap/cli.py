"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress as RichProgress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from memorymap import __version__
from memorymap.diff import (CLEAN, INCONCLUSIVE, MINOR, RESIDUE, VERDICT_TEXT, diff_snapshots, load_snapshot,
                            save_snapshot)
from memorymap.reader import find_processes, is_admin, list_processes
from memorymap.scan import MiB, Progress, ScanCancelled, ScanOptions, ScanResult, run_scan
from memorymap.scanner import SEVERITY_RANK, pattern_info

console = Console()
err = Console(stderr=True)

SEV_STYLE = {"CRITICAL": "bold red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "steel_blue", "CLEAN": "green"}
VERDICT_STYLE = {RESIDUE: "bold red", MINOR: "yellow", CLEAN: "bold green", INCONCLUSIVE: "steel_blue"}
EXIT_RESIDUE, EXIT_INCONCLUSIVE, EXIT_THRESHOLD, EXIT_USAGE = 1, 3, 2, 64


def sev(s: str) -> Text:
    return Text(s, style=SEV_STYLE.get(s, ""))


def fmt_bytes(n: int) -> str:
    return f"{n / 2**30:.2f} GB" if n >= 2**30 else f"{n / 2**20:.1f} MB" if n >= 2**20 else f"{n / 2**10:.0f} KB"


# --- target resolution ---------------------------------------------------------------------------

def resolve_target(query: Optional[str]) -> Tuple[int, str]:
    if query is None:
        query = pick_interactively()
    matches = find_processes(query)
    if not matches:
        err.print(f"[red]No process matches '{query}'.[/red]")
        raise SystemExit(EXIT_USAGE)
    if len(matches) > 1:
        err.print(f"[yellow]'{query}' matches {len(matches)} processes; use a PID:[/yellow]")
        for p in matches[:10]:
            err.print(f"  {p['pid']:>7}  {p['name']}  {p['rss_mb']} MB")
        raise SystemExit(EXIT_USAGE)
    return matches[0]["pid"], matches[0]["name"]


def pick_interactively() -> str:
    if not sys.stdin.isatty():
        err.print("[red]Give a PID or process name.[/red]")
        raise SystemExit(EXIT_USAGE)
    print_processes(list_processes()[:25])
    return console.input("\nPID or name to inspect: ").strip()


def print_processes(procs: List[dict]) -> None:
    t = Table(box=None, header_style="dim", pad_edge=False)
    for col, justify in (("PID", "right"), ("Process", "left"), ("Memory", "right"), ("User", "left")):
        t.add_column(col, justify=justify)
    for p in procs:
        t.add_row(str(p["pid"]), p["name"], f"{p['rss_mb']:,.1f} MB", p["username"])
    console.print(t)


# --- scanning with progress ----------------------------------------------------------------------

def scan_with_progress(pid: int, options: ScanOptions) -> ScanResult:
    prog = Progress()
    bar = RichProgress(TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(),
                       TimeElapsedColumn(), console=err, transient=True)
    with bar:
        task = bar.add_task("Mapping address space", total=None)

        def update(p: Progress) -> None:
            bar.update(task, description=f"{p.phase.capitalize()}  [dim]{p.findings} findings, {p.anomalies} anomalies[/dim]",
                       total=p.total_bytes or None, completed=p.done_bytes)

        try:
            return run_scan(pid, options, prog, on_update=update)
        except (PermissionError, ProcessLookupError) as exc:
            err.print(f"[red]{exc}[/red]")
            raise SystemExit(EXIT_USAGE)
        except ScanCancelled:
            raise SystemExit(130)


def options_from(args: argparse.Namespace) -> ScanOptions:
    return ScanOptions(min_severity=args.min_severity.upper(), include_images=args.include_images,
                       chunk_size=args.chunk_mb * MiB, max_values=args.max_values)


# --- output --------------------------------------------------------------------------------------

def print_result(res: ScanResult, reveal: bool, top: int) -> None:
    counts = res.severity_counts()
    head = Text.assemble((f"{res.score}", f"bold {SEV_STYLE[res.label].split()[-1]}"), "/100  ", sev(res.label), "\n",
                         (f"{res.process_name}  PID {res.pid}", "bold"), "\n",
                         (f"scanned {fmt_bytes(res.scanned_bytes)} of {fmt_bytes(res.committed_bytes)} committed "
                          f"in {res.duration_s:.1f}s", "dim"), "\n",
                         "  ".join(f"{counts[s]} {s.lower()}" for s in SEVERITY_RANK))
    console.print(Panel(head, title="MemoryMap", title_align="left", border_style="dim", padding=(1, 2)))

    if res.anomalies:
        t = Table(title="Anomalies", title_justify="left", header_style="dim", box=None, pad_edge=False)
        for c in ("Severity", "Address", "Type", "Detail"):
            t.add_column(c)
        for a in res.anomalies[:top]:
            t.add_row(sev(a.severity), f"0x{a.base:012X}", a.as_dict()["title"], a.detail)
        console.print(t)
        console.print()

    if res.findings:
        t = Table(title="Findings", title_justify="left", header_style="dim", box=None, pad_edge=False)
        for c, j in (("Severity", "left"), ("Category", "left"), ("Value", "left"), ("Where", "left"), ("Copies", "right")):
            t.add_column(c, justify=j)
        for f in res.findings[:top]:
            t.add_row(sev(f.severity), f.category, f.display(reveal, 48), res.where(f.address), str(f.count))
        console.print(t)
        hidden = len(res.findings) - top
        if hidden > 0:
            console.print(f"[dim]{hidden} more in --json / --html output[/dim]")
        if res.capped:
            names = ", ".join(pattern_info(pid).category for pid in sorted(res.capped))
            console.print(f"[yellow]Capped at {min(res.capped.values()):,} distinct values: {names}. "
                          f"Counts for these are lower bounds; raise --max-values to keep more.[/yellow]")
    elif not res.anomalies:
        console.print("[green]Nothing sensitive or suspicious found.[/green]")


def print_diff(d: dict, top: int = 40) -> None:
    style = VERDICT_STYLE[d["verdict"]]
    c = d["counts"]
    console.print(Panel(Text.assemble((d["verdict"], style), "\n", VERDICT_TEXT[d["verdict"]], "\n\n",
                                      (f"{c['persisted']} still present", "red"), "   ",
                                      (f"{c['wiped']} wiped", "green"), "   ",
                                      (f"{c['new']} new", "yellow")),
                        title="Residue test", title_align="left", border_style="dim", padding=(1, 2)))
    if not d["items"]:
        return
    t = Table(header_style="dim", box=None, pad_edge=False)
    for col, j in (("Status", "left"), ("Severity", "left"), ("Category", "left"), ("Value", "left"),
                   ("Location", "left"), ("Copies", "right")):
        t.add_column(col, justify=j)
    status_style = {"persisted": "red", "wiped": "green", "new": "yellow"}
    for i in d["items"][:top]:
        here = i["after"] or i["before"]
        copies = f"{i['before']['count']} → {i['after']['count']}" if i["status"] == "persisted" else str(here["count"])
        t.add_row(Text(i["status"], style=status_style[i["status"]]), sev(i["severity"]), i["category"], i["value"],
                  here.get("where", ""), copies)
    console.print(t)
    if len(d["items"]) > top:
        console.print(f"[dim]{len(d['items']) - top} more in --json output[/dim]")


def verdict_exit_code(verdict: str) -> int:
    return {RESIDUE: EXIT_RESIDUE, INCONCLUSIVE: EXIT_INCONCLUSIVE}.get(verdict, 0)


# --- commands ------------------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    procs = list_processes()
    if args.filter:
        q = args.filter.lower()
        procs = [p for p in procs if q in p["name"].lower() or q == str(p["pid"])]
    print_processes(procs[: args.limit])
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    pid, _ = resolve_target(args.target)
    res = scan_with_progress(pid, options_from(args))
    print_result(res, args.reveal, args.top)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res.as_dict(reveal=args.reveal), fh, indent=2)
        console.print(f"[dim]JSON written to {args.json}[/dim]")
    if args.html:
        from memorymap.report import render_report
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_report(res, reveal=args.reveal))
        console.print(f"[dim]Report written to {args.html}[/dim]")
    if args.fail_on:
        floor = SEVERITY_RANK[args.fail_on.upper()]
        if any(SEVERITY_RANK[s] >= floor and n for s, n in res.severity_counts().items()):
            return EXIT_THRESHOLD
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    pid, _ = resolve_target(args.target)
    res = scan_with_progress(pid, options_from(args))
    save_snapshot(res, args.output)
    sensitive = sum(1 for f in res.findings if f.sensitive)
    console.print(f"Snapshot of [bold]{res.process_name}[/bold] saved to {args.output} "
                  f"([dim]{sensitive} sensitive findings, stored as fingerprints and masked values[/dim])")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        d = diff_snapshots(load_snapshot(args.before), load_snapshot(args.after))
    except (OSError, ValueError, KeyError) as exc:
        err.print(f"[red]{exc}[/red]")
        return EXIT_USAGE
    print_diff(d)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
    return verdict_exit_code(d["verdict"])


def cmd_residue(args: argparse.Namespace) -> int:
    pid, name = resolve_target(args.target)
    options = options_from(args)
    console.print(f"[bold]Baseline[/bold]  scanning {name} (PID {pid}). Make sure the secret is in use right now.")
    before = scan_with_progress(pid, options)
    sensitive = sum(1 for f in before.findings if f.sensitive)
    console.print(f"  {sensitive} sensitive findings in the baseline\n")

    if args.action:
        console.print(f"[bold]Action[/bold]    {args.action}")
        subprocess.run(args.action, shell=True, check=False)
    elif args.wait:
        console.print(f"[bold]Action[/bold]    waiting {args.wait}s for you to do it")
        import time
        time.sleep(args.wait)
    else:
        console.input("[bold]Action[/bold]    do the thing that should clear the secret "
                      "(sign out, lock, close), then press Enter ")

    console.print("[bold]Re-scan[/bold]")
    after = scan_with_progress(pid, options)
    d = diff_snapshots(before.as_dict(include_regions=False), after.as_dict(include_regions=False))
    print_diff(d)
    if args.save:
        save_snapshot(before, args.save + ".before.json")
        save_snapshot(after, args.save + ".after.json")
        console.print(f"[dim]Snapshots saved as {args.save}.before.json / .after.json[/dim]")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
    return verdict_exit_code(d["verdict"])


def cmd_serve(args: argparse.Namespace) -> int:
    from memorymap.web.app import serve
    pid = resolve_target(args.target)[0] if args.target else None
    serve(pid=pid, host=args.host, port=args.port, open_browser=not args.no_browser, reveal=args.reveal,
          options=options_from(args))
    return 0


# --- argument parsing ----------------------------------------------------------------------------

def _scan_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--min-severity", default="low", choices=[s.lower() for s in SEVERITY_RANK],
                   help="ignore findings below this severity (default: low)")
    p.add_argument("--include-images", action="store_true",
                   help="also scan read-only, file-backed pages (slower; they match what is on disk)")
    p.add_argument("--max-values", type=int, default=2000, metavar="N",
                   help="distinct values kept per low/medium pattern (default: 2000); bounds memory on text-heavy processes")
    p.add_argument("--chunk-mb", type=int, default=8, help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="memorymap",
        description="Live process memory forensics for Windows, with secret residue testing.",
        epilog="Exit codes: 0 ok, 1 residue found, 2 --fail-on threshold hit, 3 residue test inconclusive, 64 usage error.",
    )
    ap.add_argument("--version", action="version", version=f"memorymap {__version__}")
    sub = ap.add_subparsers(dest="command", metavar="command")

    p = sub.add_parser("list", help="list running processes")
    p.add_argument("-f", "--filter", help="name substring or PID")
    p.add_argument("-n", "--limit", type=int, default=40)
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("scan", help="scan one process for secrets and anomalies")
    p.add_argument("target", nargs="?", help="PID or process name (prompts if omitted)")
    p.add_argument("--json", metavar="FILE")
    p.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    p.add_argument("--reveal", action="store_true", help="show full secret values (default: masked)")
    p.add_argument("--top", type=int, default=25, help="rows to print per table")
    p.add_argument("--fail-on", choices=[s.lower() for s in SEVERITY_RANK], metavar="LEVEL",
                   help="exit 2 if anything at or above this severity is found")
    _scan_options(p)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("snapshot", help="save a snapshot (fingerprints and masked values only) for a later diff")
    p.add_argument("target")
    p.add_argument("-o", "--output", required=True, metavar="FILE")
    _scan_options(p)
    p.set_defaults(fn=cmd_snapshot)

    p = sub.add_parser("diff", help="compare two snapshots: what persisted, what was wiped, what is new")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--json", metavar="FILE")
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("residue", help="baseline, run an action, re-scan, and report what survived")
    p.add_argument("target")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--action", metavar="CMD", help="shell command to run between the scans")
    g.add_argument("--wait", type=int, metavar="SECONDS", help="wait this long instead of prompting")
    p.add_argument("--save", metavar="PREFIX", help="also keep both snapshots as PREFIX.before.json / .after.json")
    p.add_argument("--json", metavar="FILE")
    _scan_options(p)
    p.set_defaults(fn=cmd_residue)

    p = sub.add_parser("serve", help="open the web dashboard")
    p.add_argument("target", nargs="?", help="scan this PID or name on start")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--reveal", action="store_true", help="show full secret values in the dashboard")
    _scan_options(p)
    p.set_defaults(fn=cmd_serve)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:  # legacy Windows code pages cannot encode arrows or the masking bullet
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        args = parser.parse_args(["serve", *(argv or [])])  # bare `memorymap` opens the dashboard
    if sys.platform != "win32":
        err.print("[red]MemoryMap reads process memory through the Win32 API and only runs on Windows.[/red]")
        return EXIT_USAGE
    if not is_admin() and args.command in ("scan", "residue", "snapshot"):
        err.print("[dim]Not elevated: protected and other users' processes will be inaccessible.[/dim]")
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
