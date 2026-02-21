# MemoryMap 🧠

A live RAM forensics tool for Windows. Attach to any running process, scan memory for secrets and sensitive data, detect behavioral anomalies, and export a forensics report.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-Dashboard-black?logo=flask" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
</p>

## Demo

![MemoryMap Dashboard](assets/dashboard.png)

![Anomaly Detection](assets/anomalies.png)

## What it does

- **Secret Scanner** — 20+ regex patterns for JWT tokens, API keys, credit cards, passwords, Bitcoin addresses, emails and more
- **Anomaly Detector** — 7 heuristics: PE injection, RWX regions, high-entropy payloads, shellcode strings, unbacked executable memory
- **Web Dashboard** — dark-mode Chart.js dashboard with charts, memory map, findings table, and anomaly cards
- **Report Export** — self-contained HTML forensics report, printable to PDF

## Installation

```bash
git clone https://github.com/GhaithKelil/memorymap.git
cd memorymap
pip install psutil pywin32 flask colorama tabulate
```

> Windows only. Run as Administrator for full access to system processes.

## Usage

**CLI (interactive process picker)**
```bash
python cli.py
```

**CLI (direct PID)**
```bash
python cli.py --pid 1234
```

**Web dashboard**
```bash
python ui/app.py --pid 1234
```
Open http://localhost:5000 in your browser.

**Export report**

Click the Export Report button in the dashboard header, or go to `http://localhost:5000/export`.

## Project Structure

```
memorymap/
├── core/
│   ├── reader.py       # Windows memory reader (VirtualQueryEx, ReadProcessMemory)
│   ├── scanner.py      # Secret/PII pattern scanner
│   ├── analyzer.py     # Risk scoring
│   └── anomaly.py      # Behavioral anomaly detection
├── ui/
│   ├── app.py          # Flask server
│   └── templates/
│       └── dashboard.html
├── reports/
│   └── generator.py    # HTML report builder
└── cli.py
```

## Real-World Results

Scanning a standard `python3.11.exe` process found:

- Credit card numbers and Bitcoin addresses in heap memory
- PE/MZ headers in private memory regions (C-extensions loaded reflectively)
- High entropy regions at 7.7 bits/byte (likely compressed bytecode)
- Meterpreter and ReflectiveLoader strings from Python's ssl/ctypes modules

## License

MIT
