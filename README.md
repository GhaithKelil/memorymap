# MemoryMap

**You logged out. Is your password actually gone?**

Apps promise to forget your secrets when they're done with them. A lot of them don't. A password, an API key or a session token can sit in the computer's memory long after the "Sign out" button did its thing, readable by anything that can get at that memory.

MemoryMap is a command-line tool for Windows that checks. It looks inside a running app before and after you log out, and tells you what's still lying around.

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

That's real output from the demo app that ships with the repo. It "logs out", wipes four secrets, and forgets three. MemoryMap catches all of it. The secrets are masked, so output like this is much safer to share. It still shows the first and last few characters of each value and the domain of each email, so give it a glance before you paste it anywhere public.

## The idea, in plain words

Picture writing your PIN on a whiteboard, using it, then wiping the board. MemoryMap photographs the board before and after the wipe. If the PIN is still faintly there in the second photo, the app didn't clean up properly.

1. **Baseline.** Scan the app while the secret is in use (signed in, vault unlocked).
2. **Act.** Do the thing that should make it forget: sign out, lock, close the document.
3. **Re-scan.** Every finding is sorted into *still present*, *wiped* or *new*, with where it lives and how many copies existed before and after.

Then you get one verdict:

| Verdict | What it means |
|---------|---------------|
| `RESIDUE` | High-severity secrets survived. This is the bad one. |
| `MINOR` | The serious secrets are gone, but low-severity data remains. |
| `CLEAN` | Everything sensitive in the baseline is gone. |
| `INCONCLUSIVE` | The baseline held nothing to wipe, so the test proves nothing. Take it again while the secret is in use. |

## Try it in two minutes

You need Windows 10 or later and Python 3.9 or later. The demo lives in the repo, so clone it:

```bash
git clone https://github.com/GhaithKelil/memorymap.git
```

```bash
cd memorymap
```

```bash
pip install -e .
```

Start the demo app. It holds fake example credentials (AWS documentation keys, a Visa test number, a sample token) and nothing real. Leave it running:

```bash
python examples/demo_target.py
```

It prints a line like `demo target running, PID 12345`. In a second terminal, run the test against that number:

```text
python -m memorymap residue 12345 --action "cmd /c type nul > %TEMP%\memorymap_demo_logout.flag & ping -n 2 127.0.0.1 >nul"
```

You should get **RESIDUE**, with 4 wiped and the rest still present, and exit code 1. Stop the demo with Ctrl+C when you're done.

> **Just want the tool, not the demo?** `pip install git+https://github.com/GhaithKelil/memorymap.git` installs it in one line (it needs `git` on your machine). If the `memorymap` command isn't found afterwards, the Python `Scripts` folder isn't on your `PATH`, which is common with the Microsoft Store build. Use `python -m memorymap` instead; it always works.

## Point it at your own apps

```text
memorymap list -f chrome                     find a process by name or PID
memorymap scan 4321                          scan a process (a name works too)
memorymap residue 4321                       interactive: it tells you when to log out
memorymap scan 4321 --html report.html --json result.json
memorymap scan 4321 --fail-on high           exit 2 if anything high or above is found
memorymap snapshot 4321 -o before.json       save a snapshot now, diff it later
memorymap diff before.json after.json        compare two snapshots
```

`scan`, `snapshot` and `residue` also take `--min-severity`, `--include-images` and `--max-values`; add `--help` to any command for details. Run `memorymap scan` with no target to pick a process from a list.

A few things worth knowing before you aim it at real apps:

- **It reads that app's memory,** so it can find real personal data. Everything is masked by default (`AKIA••••••••••••LE`), including the `--json` and `--html` files. Only `scan --reveal` prints full values, so use it deliberately, and treat any file you write with it as sensitive.
- **Some processes won't open** unless the terminal is run as Administrator. The tool tells you when that's the problem.
- **Big, text-heavy apps like browsers take longer.** A progress bar shows while it works.

## What it finds

- **Secrets.** About 20 detectors for cloud keys, tokens, private keys, connection strings, passwords, payment cards and similar. Windows stores most text as UTF-16, so MemoryMap reads both ASCII and UTF-16. Anything with a checksum or structure is validated before it's reported (Luhn for card numbers, base58check for Bitcoin addresses, JSON structure for tokens), which keeps random digits from being flagged as credit cards.
- **Signs of code injection.** Five checks, each mapped to a MITRE ATT&CK technique. Signals in the same region back each other up: an unbacked executable region that also holds a PE image is escalated to critical.

  | Check | Looks for |
  |-------|-----------|
  | Writable and executable memory | RWX pages (T1055) |
  | Executable memory with no backing file | Injected or reflectively loaded code (T1055) |
  | PE image outside any loaded module | Manually mapped DLLs, validated through the NT header (T1620) |
  | High-entropy content | Packed or encrypted code (T1027) |
  | Offensive-tooling strings | Post-exploitation frameworks, or several injection API names together |

- **A risk score** from 0 to 100 that rises with the number and severity of what it finds.
- **Reports** you can keep: a self-contained HTML page (print it to PDF) and a JSON export.

## Use it as a test in CI

`memorymap residue` exits non-zero when secrets survive, so a pipeline can fail the build on it:

| Exit code | Meaning |
|-----------|---------|
| 0 | Clean, or only low-severity data survived |
| 1 | Residue: high-severity secrets are still in memory |
| 2 | `scan --fail-on` found something at or above the threshold |
| 3 | Inconclusive: the baseline contained nothing to wipe |
| 64 | Usage error (unknown process, bad file, and so on) |

Snapshots never contain plaintext secrets. Each finding is stored as a masked preview plus a keyed fingerprint (an HMAC under a per-machine key in `%LOCALAPPDATA%\memorymap\`), so a snapshot isn't a second copy of what you're trying to protect. The catch is that snapshots can be compared on the machine that made them.

## Safe by default

- **Detected secrets are masked** in every output. Only `scan --reveal` shows full values.
- **Nothing is written to disk except what you ask for.** The one exception is the fingerprint key (32 random bytes, created on first use).
- **Everything runs locally.** No network access, no telemetry.

<details>
<summary><b>The honest limits</b></summary>

- Findings describe what was in memory at scan time. They don't prove compromise, and executable unbacked memory is normal for JIT compilers and managed runtimes.
- Read-only file-backed pages (module code, mapped files) are skipped because they match what's on disk. Use `--include-images` to scan them.
- Paged-out memory, other processes and the kernel aren't covered. Scanning your own process includes the scanner's own strings.
- A wiped secret can still exist somewhere the scan can't see, such as the pagefile.
- The diff ignores URLs, host:port and API paths, and low-severity data inside module images, which is static rather than runtime state.
- Pattern matching produces some false positives, especially for emails and passwords. Treat the output as leads.
- Low and medium severity patterns (URLs, emails and similar) keep at most 2,000 distinct values each, so a process full of text can't exhaust memory. When a pattern hits the cap the scan says so, and its counts are lower bounds. `--max-values` changes the limit. High and critical patterns keep scanning and store up to 20,000 distinct values each.
- Speed depends on how much text a process holds. On a deliberately hostile test process (617 MB, every line a unique email and URL, plus 300 MB of random bytes) a scan takes about a minute and the scanner stays under 60 MB. Real processes will differ, and text-heavy ones are the slow case.

</details>

<details>
<summary><b>Where the idea comes from</b></summary>

Checking whether secrets outlive their use isn't new, and MemoryMap builds on existing work.

- The study [Keep your memory dump shut](https://arxiv.org/html/2404.00423v1) tested two dozen password managers by dumping each process's memory after unlocking, locking, idling and restarting, then searching the dumps for plaintext passwords. Most left secrets in RAM, including the master password while locked.
- [TaintBochs](https://www.usenix.org/conference/13th-usenix-security-symposium/understanding-data-lifetime-whole-system-simulation) (USENIX Security 2004) tracked sensitive data through whole-system simulation and found that large applications such as Mozilla and Apache scatter passwords through memory and keep them there.
- Security guidance for secret handling already recommends the same test: seed a known secret, run the code path, then inspect memory afterwards.

Those approaches are mostly manual (dump, then search) or need a research simulator. MemoryMap automates the loop for a live Windows process: baseline, action, re-scan, then a verdict, an exit code a CI job can act on, and snapshots that never store the secrets themselves. I didn't find another tool that packages it this way, but I haven't searched exhaustively, so read that as "built for", not "the only".

**How it compares.** [Volatility](https://github.com/volatilityfoundation/volatility3) and [MemProcFS](https://github.com/ufrisk/MemProcFS) analyse full memory dumps. [System Informer](https://systeminformer.sourceforge.io/) browses live process memory and strings. [PE-sieve](https://github.com/hasherezade/pe-sieve) and [Moneta](https://github.com/forrest-orr/moneta) are stronger at detecting injection. MemoryMap isn't a replacement for any of them. It adds secret detection and the before-and-after residue workflow to a single live-scan tool.

</details>

<details>
<summary><b>Under the hood</b></summary>

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
examples/       the demo app
tests/
```

To work on it:

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

The CLI tests fake the scans; the live tests launch the demo app as a separate process and run a real residue test against it.

</details>

## License

MIT
