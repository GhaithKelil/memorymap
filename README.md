# MemoryMap

A command-line tool for Windows built around one question: **after your app is done with a secret, is it still in RAM?**

MemoryMap scans a running process for credentials and personal data, flags injection-style memory anomalies, and can compare two snapshots to show which secrets survived an action such as logging out, locking a vault or closing a session.

```
memorymap residue 4321 --action "myapp.exe --logout"
```

```
┌─ Residue test ──────────────────────────────────────────────────────────────┐
│                                                                             │
│  RESIDUE                                                                    │
│  High-severity secrets are still in the process's memory after the action.  │
│                                                                             │
│  8 still present   4 wiped   0 new                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
Status     Severity  Category         Value            Location          Copies
persisted  HIGH      Bearer token     9f8e••••••••••…  Private memory     1 → 1
                                                       (heap/stack)
persisted  HIGH      Database         p••••••@db.int…  Private memory     1 → 1
                     connection                        (heap/stack)
                     string
persisted  HIGH      JSON Web Token   eyJh••••••••••…  Private memory     1 → 1
                                                       (heap/stack)
  ... five MEDIUM email rows trimmed ...
wiped      CRITICAL  AWS access key   AKIA••••••••••…  Private memory         1
                     ID                                (heap/stack)
wiped      CRITICAL  AWS secret       wJal••••••••••…  Private memory         1
                     access key                        (heap/stack)
wiped      CRITICAL  Payment card     4111••••••••••…  Private memory         1
                     number                            (heap/stack)
wiped      HIGH      Password         Tr•••••••        Private memory         2
                     assignment                        (heap/stack)
```

That is real output from the demo process described below. Four secrets were wiped on "logout" and three high-severity ones were forgotten, which is exactly what the test should report.

## Residue testing

Most memory tools answer "what is in this process right now?" MemoryMap's focus is what is *still there afterwards*, which is the question developers, pentesters and incident responders ask when they want to know whether an application cleans up after itself.

1. **Baseline.** Scan the process while the secret is in use (signed in, vault unlocked).
2. **Act.** Do the thing that should make the app forget: sign out, lock, close the document.
3. **Re-scan.** MemoryMap matches findings by fingerprint and reports each one as *still present*, *wiped* or *new*, with where it lives (heap or stack, module, mapped file) and how many copies existed before and after.

The verdict is one of `RESIDUE` (high-severity secrets survived), `MINOR`, `CLEAN`, or `INCONCLUSIVE` (the baseline held nothing to wipe, so the test proves nothing).

`memorymap residue` takes the baseline, runs your action (or waits for you, interactively, or for `--wait N` seconds), re-scans, prints the diff and exits non-zero if secrets survived, so it works as a regression test in CI:

| Exit code | Meaning |
|-----------|---------|
| 0 | Clean, or only low-severity data survived |
| 1 | Residue: high-severity secrets are still in memory |
| 2 | `scan --fail-on` found something at or above the threshold |
| 3 | Inconclusive: the baseline contained nothing to wipe |
| 64 | Usage error (unknown process, bad file, and so on) |

You can also do it in two steps and diff later:

```
memorymap snapshot 4321 -o before.json
# ...act...
memorymap snapshot 4321 -o after.json
memorymap diff before.json after.json
```

Snapshot files never contain plaintext secrets. Each finding is stored as a masked preview plus a keyed fingerprint (an HMAC under a per-machine key in `%LOCALAPPDATA%\memorymap\`), so a snapshot is not a second copy of what you are trying to protect. The consequence is that snapshots can be diffed on the machine that made them.

## Everything else it does

- **Secret scanner.** About 20 detectors for cloud keys, tokens, private keys, connection strings, passwords, payment cards and similar. Memory is reduced to ASCII and UTF-16LE strings, which matters because Windows stores most text as UTF-16. Candidates with a checksum or structure are validated before they are reported: Luhn for card numbers, base58check for Bitcoin addresses, JSON structure for JWTs.
- **Anomaly detector.** Five checks, each mapped to a MITRE ATT&CK technique, with signals corroborating each other inside a region (an unbacked executable region that also holds a PE image is escalated to critical):

  | Check | Looks for |
  |-------|-----------|
  | Writable and executable memory | RWX pages (T1055) |
  | Executable memory with no backing file | Injected or reflectively loaded code (T1055) |
  | PE image outside any loaded module | Manually mapped DLLs, validated through the NT header (T1620) |
  | High-entropy content | Packed or encrypted code (T1027) |
  | Offensive-tooling strings | Post-exploitation frameworks, or several injection API names together |

- **Reports.** `scan` can write a self-contained HTML report (print it to PDF) and a JSON export.
- **A risk score** from 0 to 100 that rises with the number and severity of findings and anomalies.

## Install

Windows 10 or later, Python 3.9 or later.

```
git clone https://github.com/GhaithKelil/memorymap.git
cd memorymap
pip install -e .
```

Run from an elevated terminal to inspect protected processes or other users' processes. If the `memorymap` command is not found (the Python `Scripts` folder is not always on `PATH`, notably with the Microsoft Store build), use `python -m memorymap` instead.

## Usage

```
memorymap list -f chrome                     find a process by name or PID
memorymap scan 4321                          scan a process (a name works too)
memorymap scan 4321 --html report.html --json result.json
memorymap scan 4321 --fail-on high           exit 2 if anything high or above is found
memorymap scan 4321 --reveal                 show full secret values instead of masked ones
memorymap residue 4321                       interactive residue test
memorymap residue 4321 --action "cmd"        run a command between the two scans
memorymap snapshot 4321 -o before.json       save a snapshot for a later diff
memorymap diff before.json after.json        compare two snapshots
```

`scan`, `snapshot` and `residue` also take `--min-severity`, `--include-images` and `--max-values`; run any command with `--help` for details. Run `memorymap scan` without a target to pick a process from a list.

### Try it safely

`examples/demo_target.py` is a harmless process that holds well-known example credentials (AWS documentation keys, a Visa test number, a sample JWT), plants an RWX page with a PE-like header, and "logs out" when a flag file appears, wiping four secrets and forgetting three. A correct residue test reports exactly that.

```
python examples/demo_target.py
memorymap residue <printed PID>
```

The demo prints the path of its flag file. Create that file when the tool asks you to perform the action.

## Safe by default

- **Detected secrets are masked** in every output (`AKIA••••••••••••LE`). Only `scan --reveal` shows full values.
- **Nothing is written to disk except what you ask for.** The commands write only the files you name. The one exception is the fingerprint key (32 random bytes, created on first use in `%LOCALAPPDATA%\memorymap\`).
- Everything runs locally. There is no network access and no telemetry.

## Limits

- Findings describe what was in memory at scan time. They do not prove compromise, and executable unbacked memory is normal for JIT compilers and managed runtimes.
- Read-only file-backed pages (module code, mapped files) are skipped because they match what is on disk. Use `--include-images` to scan them.
- Memory that has been paged out, other processes, and the kernel are not covered. Scanning your own process includes the scanner's own strings.
- The diff ignores URLs, host:port and API paths, and low-severity data inside module images, which is static rather than runtime state.
- A wiped secret can still exist in a place the scan cannot see, such as the pagefile.
- Pattern matching produces some false positives, especially for emails and passwords. Treat the output as leads.
- Low and medium severity patterns (URLs, emails and similar) keep at most 2,000 distinct values each, so a process full of text cannot exhaust memory. When a pattern hits the cap the scan says so, and its counts are lower bounds. `--max-values` changes the limit. High and critical patterns keep scanning and store up to 20,000 distinct values each.
- Speed depends on how much text a process holds. On a deliberately hostile test process (617 MB, every line a unique email and URL, plus 300 MB of random bytes) a scan takes about a minute and the scanner stays under 60 MB. Real processes will differ, and text-heavy ones are the slow case.

## Background

Checking whether secrets outlive their use is not new, and MemoryMap builds on existing work.

- The study [Keep your memory dump shut](https://arxiv.org/html/2404.00423v1) tested two dozen password managers by dumping each process's memory after unlocking, locking, idling and restarting, then searching the dumps for plaintext passwords. Most left secrets in RAM, including the master password while locked.
- [TaintBochs](https://www.usenix.org/conference/13th-usenix-security-symposium/understanding-data-lifetime-whole-system-simulation) (USENIX Security 2004) tracked sensitive data through whole-system simulation and found that large applications such as Mozilla and Apache scatter passwords through memory and keep them there.
- Security guidance for secret handling already recommends the same test: seed a known secret, run the code path, then inspect memory afterwards.

Those approaches are mostly manual (dump, then search) or need a research simulator. MemoryMap automates the loop for a live Windows process: baseline, action, re-scan, then a verdict, an exit code a CI job can act on, and snapshots that never store the secrets themselves. I did not find another tool that packages it this way, but I have not searched exhaustively, so treat that as "built for", not "the only".

## How it compares

[Volatility](https://github.com/volatilityfoundation/volatility3) and [MemProcFS](https://github.com/ufrisk/MemProcFS) analyse full memory dumps. [System Informer](https://systeminformer.sourceforge.io/) browses live process memory and strings. [PE-sieve](https://github.com/hasherezade/pe-sieve) and [Moneta](https://github.com/forrest-orr/moneta) are stronger at detecting injection. MemoryMap is not a replacement for any of them. It adds secret detection and the before-and-after residue workflow to a single live-scan tool.

## Project layout

```
memorymap/
  reader.py     Win32 memory access (VirtualQueryEx, ReadProcessMemory)
  scanner.py    string extraction, patterns, validators, masking, fingerprints
  anomaly.py    region checks and corroboration
  scan.py       the streaming scan pipeline
  diff.py       snapshots and the residue diff
  scoring.py    risk score
  report.py     HTML report
  cli.py        command line
examples/       demo target
tests/
```

## Development

```
pip install -e ".[dev]"
pytest
```

The CLI tests fake the scans; the live tests launch the demo target as a separate process and run a real residue test against it.

## License

MIT
