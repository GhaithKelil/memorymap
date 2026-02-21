
import argparse
import sys
import os
from colorama import init, Fore, Style
from tabulate import tabulate
from core.reader import list_processes, ProcessMemoryReader
from core.scanner import SecretScanner
from core.analyzer import build_report

init(autoreset=True)  # colorama on Windows


BANNER = f"""
{Fore.CYAN}
  __  __                  __  __            
 |  \/  | ___ _ __ ___  |  \/  | __ _ _ __  
 | |\/| |/ _ \ '_ ` _ \ | |\/| |/ _` | '_ \ 
 | |  | |  __/ | | | | || |  | | (_| | |_) |
 |_|  |_|\___|_| |_| |_||_|  |_|\__,_| .__/ 
                                       |_|   
{Style.RESET_ALL}
{Fore.YELLOW}  RAM Forensics & Process Memory Analyzer{Style.RESET_ALL}
  ─────────────────────────────────────────
"""


def print_banner():
    print(BANNER)


def print_process_table(procs: list, limit: int = 40):
    """Pretty-print top N processes by memory usage."""
    rows = []
    for i, p in enumerate(procs[:limit], 1):
        rows.append([
            f"{Fore.GREEN}{i}{Style.RESET_ALL}",
            f"{Fore.CYAN}{p['pid']}{Style.RESET_ALL}",
            p["name"],
            f"{Fore.YELLOW}{p['rss_mb']} MB{Style.RESET_ALL}",
            p["username"],
        ])

    print(tabulate(
        rows,
        headers=["#", "PID", "Process Name", "RAM Usage", "User"],
        tablefmt="rounded_outline",
    ))


def pick_process(procs: list) -> dict:
    """Let the user pick a process interactively."""
    while True:
        choice = input(
            f"\n{Fore.CYAN}Enter # or PID to inspect "
            f"(or 'q' to quit): {Style.RESET_ALL}"
        ).strip()

        if choice.lower() == "q":
            sys.exit(0)

        # Try as list index
        if choice.isdigit():
            val = int(choice)
            # Check if it could be a list index (1-based)
            if 1 <= val <= len(procs):
                return procs[val - 1]
            # Otherwise try as direct PID
            for p in procs:
                if p["pid"] == val:
                    return p
            print(f"{Fore.RED}  Not found. Try again.{Style.RESET_ALL}")
        else:
            # Search by name substring
            matches = [p for p in procs if choice.lower() in p["name"].lower()]
            if len(matches) == 1:
                return matches[0]
            elif len(matches) > 1:
                print(f"{Fore.YELLOW}  Multiple matches:{Style.RESET_ALL}")
                for m in matches:
                    print(f"    PID {m['pid']} — {m['name']}")
            else:
                print(f"{Fore.RED}  No process named '{choice}'. Try again.{Style.RESET_ALL}")


def scan_process(pid: int, proc_name: str):
    """Open the process and dump memory region info."""
    print(f"\n{Fore.CYAN}▶ Opening process: {Fore.YELLOW}{proc_name} (PID {pid}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}▶ Reading memory regions...{Style.RESET_ALL}\n")

    try:
        with ProcessMemoryReader(pid) as reader:
            regions = reader.enumerate_regions(read_data=True)
    except PermissionError as e:
        print(f"{Fore.RED}✗ {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Tip: Run this script as Administrator.{Style.RESET_ALL}")
        sys.exit(1)

    # ── Summary stats ──────────────────────────────────────────────────────────
    committed = [r for r in regions if r.state == "COMMIT"]
    total_mb  = sum(r.size for r in committed) / (1024 * 1024)
    readable  = sum(len(r.data) for r in committed if r.data)

    print(f"  {Fore.GREEN}✔ Found {len(regions)} regions  |  "
          f"{len(committed)} committed  |  "
          f"{total_mb:.2f} MB total virtual{Style.RESET_ALL}\n")

    # ── Region table ───────────────────────────────────────────────────────────
    rows = []
    for r in committed[:60]:  # show first 60 for now
        exec_flag  = f"{Fore.RED}✔{Style.RESET_ALL}" if r.is_executable else ""
        write_flag = f"{Fore.YELLOW}✔{Style.RESET_ALL}" if r.is_writable  else ""
        data_len   = f"{len(r.data):,} B" if r.data else "—"

        rows.append([
            f"0x{r.base_address:016X}",
            f"0x{r.end_address:016X}",
            f"{r.size_kb:,.1f} KB",
            r.protect,
            r.region_type,
            exec_flag,
            write_flag,
            data_len,
        ])

    print(tabulate(
        rows,
        headers=["Base", "End", "Size", "Protect", "Type", "Exec", "Write", "Bytes Read"],
        tablefmt="rounded_outline",
    ))

    if len(committed) > 60:
        print(f"\n  {Fore.YELLOW}(showing first 60 of {len(committed)} committed regions){Style.RESET_ALL}")

    # ── Secret Scanner ─────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}▶ Running secret scanner on {len(committed)} committed regions...{Style.RESET_ALL}")
    scanner  = SecretScanner(min_severity="LOW")
    findings = scanner.scan_regions(committed)
    report   = build_report(
        pid=pid,
        process_name=proc_name,
        total_regions=len(regions),
        committed_mb=total_mb,
        findings=findings,
    )

    # ── Risk banner ────────────────────────────────────────────────────────────
    risk_color = {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.CYAN,
        "CLEAN":    Fore.GREEN,
    }.get(report.risk_label, Fore.WHITE)

    print(f"""
  ┌──────────────────────────────────────┐
  │  Risk Score : {risk_color}{report.risk_score:>3}/100  [{report.risk_label:<8}]{Style.RESET_ALL}       │
  │  Findings   : {Fore.RED}{report.critical_count} CRITICAL{Style.RESET_ALL}  {Fore.YELLOW}{report.high_count} HIGH{Style.RESET_ALL}  {report.medium_count} MED  {report.low_count} LOW   │
  └──────────────────────────────────────┘""")

    if not findings:
        print(f"\n  {Fore.GREEN}✔ No sensitive data found in memory.{Style.RESET_ALL}")
    else:
        # ── Findings table ─────────────────────────────────────────────────────
        sev_color = {
            "CRITICAL": Fore.RED,
            "HIGH":     Fore.YELLOW,
            "MEDIUM":   Fore.CYAN,
            "LOW":      Fore.WHITE,
        }
        rows = []
        for f in findings[:50]:
            c = sev_color.get(f.severity, Fore.WHITE)
            rows.append([
                f"{c}{f.severity}{Style.RESET_ALL}",
                f.category,
                f"0x{f.address:016X}",
                f.truncated_match(60),
            ])
        print()
        print(tabulate(
            rows,
            headers=["Severity", "Category", "Address", "Match (truncated)"],
            tablefmt="rounded_outline",
        ))
        if len(findings) > 50:
            print(f"  {Fore.YELLOW}(showing 50 of {len(findings)} total findings){Style.RESET_ALL}")

        # ── Category summary ───────────────────────────────────────────────────
        print(f"\n  {Fore.CYAN}Categories:{Style.RESET_ALL}")
        for cat, items in report.category_map.items():
            print(f"    {cat:<30} {len(items):>4} finding(s)")

    print(f"\n{Fore.GREEN}✔ Scan complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Next up: web dashboard (Phase 3) — launch with: python ui/app.py{Style.RESET_ALL}\n")
    return regions, report


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="MemoryMap — Process RAM Forensics Tool"
    )
    parser.add_argument("--pid",  type=int, help="Target process PID directly")
    parser.add_argument("--list", action="store_true", help="List processes and exit")
    args = parser.parse_args()

    # ── Fetch process list ─────────────────────────────────────────────────────
    print(f"{Fore.CYAN}▶ Enumerating running processes...{Style.RESET_ALL}\n")
    procs = list_processes()
    print_process_table(procs)

    if args.list:
        sys.exit(0)

    # ── Pick target ────────────────────────────────────────────────────────────
    if args.pid:
        target = next((p for p in procs if p["pid"] == args.pid), None)
        if not target:
            print(f"{Fore.RED}PID {args.pid} not found.{Style.RESET_ALL}")
            sys.exit(1)
    else:
        target = pick_process(procs)

    scan_process(target["pid"], target["name"])


if __name__ == "__main__":
    main()
