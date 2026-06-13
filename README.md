# ⚡ VulnScan Pro

A professional cybersecurity vulnerability scanner built with Python 3.13 and PyQt6.
Designed for **authorised security assessments, educational research, and defensive cybersecurity**.

---

## ⚠ Legal Notice

> **This tool must only be used on systems you own or have explicit written permission to test.**
> Unauthorised scanning of systems you do not own is illegal in most jurisdictions.
> The authors accept no liability for misuse.

---

## Features

| Feature | Description |
|---|---|
| **Port Scanner** | Fast multithreaded TCP scanning with up to 500 concurrent threads |
| **Service Detection** | Banner grabbing and fingerprinting for 15+ common services |
| **Vulnerability Engine** | Local CVE database with 40+ known vulnerabilities |
| **Severity System** | Critical / High / Medium / Low / Informational ratings with CVSS scores |
| **Dashboard** | Live charts showing severity distribution, trends, and statistics |
| **Scan History** | SQLite-backed history with full results persistence |
| **PDF Reports** | Professional ReportLab-generated assessment reports |
| **CSV Export** | Export scan history to CSV for further analysis |
| **Filtering** | Filter by severity, host, port, and service |
| **Recommendations** | Actionable remediation advice for every finding |
| **Scheduling** | Recurring scan scheduler |
| **Dark Theme** | Cybersecurity-grade dark UI with cyan accent |

---

## Installation

### Prerequisites

- Python 3.10 or later (3.13 recommended)
- pip

### Steps

```bash
# 1. Navigate to the project directory
cd "VulnScan_Pro"

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the application
python main.py
```

---

## Usage

### Starting a Scan

1. Click **New Scan** in the sidebar
2. Enter your target:
   - Single IP: `192.168.1.1`
   - CIDR range: `192.168.1.0/24`
   - IP range: `192.168.1.1-254`
   - Hostname: `myserver.local`
3. Select a port preset (Common Ports recommended for quick scans)
4. Adjust thread count and timeout as needed
5. Click **▶ Start Scan**

### Viewing Results

Results appear automatically in the **Results** page after each scan.  
Each finding shows:
- CVE ID and name
- Severity and CVSS score
- Detailed description
- Remediation advice
- Detected service version

### Generating Reports

1. Navigate to **Reports**
2. Select a completed scan
3. Click **Generate PDF Report**
4. Choose a save location

### Filtering Results

Use the filter bar at the top of the Results page to filter by:
- Severity level
- Host IP
- Port number
- Service name

---

## Project Structure

```
VulnScan_Pro/
├── main.py                  # Application entry point
├── requirements.txt
├── core/
│   ├── scanner.py           # Multithreaded port scanner (QThread)
│   ├── service_detector.py  # Banner grabbing & service fingerprinting
│   ├── vuln_engine.py       # CVE matching engine
│   ├── risk_calculator.py   # CVSS-weighted risk score
│   └── scheduler.py         # Recurring scan scheduler
├── gui/
│   ├── main_window.py       # Main window with sidebar navigation
│   ├── dashboard.py         # Statistics dashboard with charts
│   ├── scan_page.py         # Scan configuration & execution
│   ├── results_page.py      # Findings browser with filtering
│   ├── history_page.py      # Historical scan management
│   ├── reports_page.py      # PDF report generation
│   ├── settings_page.py     # Application preferences
│   └── widgets/
│       ├── stat_card.py     # Metric summary card
│       ├── charts.py        # DonutChart, BarChart, LineChart
│       └── severity_badge.py# Severity pill badge
├── database/
│   ├── db_manager.py        # SQLite CRUD operations
│   └── vuln_db.py           # Local vulnerability database (40+ CVEs)
├── reports/
│   └── pdf_generator.py     # ReportLab PDF report builder
└── utils/
    ├── validators.py         # Input validation
    ├── network_utils.py      # Socket utilities
    └── logger.py             # Centralised logging
```

---

## Vulnerability Database

The local CVE database covers common services including:

| Service | CVEs Covered |
|---|---|
| OpenSSH | CVE-2023-38408, CVE-2021-41617, CVE-2018-15473 |
| Apache HTTP | CVE-2021-41773, CVE-2021-42013, CVE-2021-40438, CVE-2022-22720 |
| Nginx | CVE-2021-23017, CVE-2022-41741 |
| MySQL | CVE-2023-21980, CVE-2022-21589 |
| PostgreSQL | CVE-2022-1552, CVE-2022-41862 |
| Redis | CVE-2021-32626, CVE-2022-24736 |
| vsftpd | CVE-2011-2523 (backdoor) |
| SMB | CVE-2017-0144 (EternalBlue) |
| RDP | CVE-2019-0708 (BlueKeep) |
| Telnet | Insecure protocol detection |
| FTP | Cleartext credential warning |

---

## Ethical Use

This tool is built for:
- ✅ Testing your own systems
- ✅ Authorised penetration testing engagements
- ✅ Educational cybersecurity labs
- ✅ Defensive security assessment
- ❌ Scanning systems without permission
- ❌ Malicious reconnaissance
- ❌ Any illegal activity

---

## Architecture Notes

- **Threading**: All network I/O runs in `QThread` workers using `ThreadPoolExecutor` for parallel port probing. The GUI never blocks.
- **Database**: SQLite with WAL mode and foreign key enforcement via `db_manager.py`.
- **Charts**: Custom QPainter-based widgets — no external charting library required.
- **Reports**: ReportLab Platypus framework with branded dark-theme styling.
