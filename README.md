# 🛡️ Linux System Security Auditor

A lightweight Python-based CLI tool that audits a Linux server for common
security vulnerabilities and generates professional **HTML** and **PDF** reports.

![Python](https://img.shields.io/badge/Python-3.8+-3b82f6?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-22c55e?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-8b5cf6?style=flat-square)
![Reports](https://img.shields.io/badge/Reports-HTML%20%2B%20PDF-ef4444?style=flat-square)

---

## 📋 Table of Contents

- [What It Does](#-what-it-does)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output](#-output)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)

---

## 🔍 What It Does

This tool runs three security audit modules on your Linux system:

| Module | What It Checks | Why It Matters |
|--------|---------------|----------------|
| 🔑 **SUID/SGID Scanner** | Binaries with elevated privileges | Unknown SUID bins = privilege escalation risk |
| 📂 **World-Writable Scanner** | Files/dirs writable by any user | Allows unauthorized modification of system files |
| 🔐 **Failed Login Detector** | SSH brute-force & failed logins | Detects active attackers on your server |

All findings are compiled into a **timestamped HTML dashboard** and a **PDF report**
with color-coded risk levels (🔴 High / 🟢 Low).

---

## ✅ Requirements

- Python **3.8** or higher
- Linux OS (Ubuntu, Debian, CentOS, RHEL, Arch — any distro)
- `pip` package manager
- Read access to `/var/log/auth.log` (or `/var/log/secure` on RHEL/CentOS)

> **Note:** Run as `sudo` for a complete scan. Without sudo, some system
> paths will be skipped due to permission restrictions.

---

## 📥 Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/shivajigandham/linux-audit.git
cd linux-audit
```

### Step 2 — Install Dependencies

```bash
pip install reportlab
```

Or if you are using a system-managed Python (Ubuntu 23+):

```bash
pip install reportlab --break-system-packages
```

Or use a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate
pip install reportlab
```

### Step 3 — Verify Installation

```bash
python3 main.py --help
```

Expected output:
```
usage: main.py [-h] [--html-only] [--json] [--out OUT] [--scan ...] [--quiet]

Linux System Security Auditor
...
```

---

## 🚀 Usage

### Basic — Full Audit (HTML + PDF)

```bash
python3 main.py
```

### HTML Report Only

```bash
python3 main.py --html-only
```

### Save Reports to a Custom Directory

```bash
python3 main.py --out /home/shivaji/reports
```

### Also Export Raw JSON Data

```bash
python3 main.py --json
```

### Scan Specific Directories Only

```bash
python3 main.py --scan /usr /home /opt
```

### Run as Root (Full System Scan)

```bash
sudo python3 main.py --out /root/audit-reports
```

### Suppress Terminal Output (Silent Mode)

```bash
python3 main.py --quiet --out ./reports
```

### All Options Together

```bash
sudo python3 main.py --out ./reports --json
```

---

## 📊 Output

After running, you will get:

```
reports/
├── audit_report_20260421_042101.html   ← Open in any browser
├── audit_report_20260421_042101.pdf    ← Share with your team
└── audit_data_20260421_042101.json     ← Raw data (if --json used)
```

### HTML Report Includes:
- Overall risk badge (Critical / High / Medium / Low)
- 4 summary stat cards
- Full SUID/SGID binary table with risk levels
- World-writable files table with sticky bit status
- Top attacker IPs with attempt counts
- Top targeted usernames
- Recent failed login events (last 30)

### Terminal Summary:
```
── Audit Summary ──────────────────────────
  Suspicious SUID bins : 14
  World-writable (high): 9
  Failed logins        : 143
  Brute-force IPs      : 3
───────────────────────────────────────────
```

---

## 📁 Project Structure

```
linux-audit/
├── main.py          # CLI entry point — run this
├── auditor.py       # Core scan engine (3 modules)
├── html_report.py   # HTML dashboard generator
├── pdf_report.py    # PDF report generator (ReportLab)
└── README.md        # This file
```

---

## 🔧 Troubleshooting

### ❌ `ModuleNotFoundError: No module named 'reportlab'`

```bash
pip install reportlab
# or
pip3 install reportlab
# or (Ubuntu 23+)
pip install reportlab --break-system-packages
```

---

### ❌ `PermissionError` during scan

You don't have access to some system directories. Run with sudo:

```bash
sudo python3 main.py
```

---

### ❌ `No auth log files found`

Your system might use `journald` instead of flat log files. Run this manually to see failed logins:

```bash
sudo journalctl _SYSTEMD_UNIT=sshd.service | grep "Failed"
```

Or check if your log path is different:

```bash
ls /var/log/auth*
ls /var/log/secure*
```

Then pass the correct path by editing `AUTH_LOG_PATHS` in `auditor.py`:

```python
AUTH_LOG_PATHS = [
    "/var/log/your-custom-auth.log",
]
```

---

### ❌ PDF not generating / blank PDF

Make sure `reportlab` is properly installed:

```bash
python3 -c "import reportlab; print(reportlab.Version)"
```

If it prints a version, run HTML-only mode and share the HTML:

```bash
python3 main.py --html-only
```

---

### ❌ `wkhtmltoimage` or browser rendering issues

The HTML report is fully self-contained — no internet or external fonts needed.
Open it directly in any browser:

```bash
firefox audit_report_*.html
# or
google-chrome audit_report_*.html
# or just double-click the file in your file manager
```

---

### ❌ Scan taking too long

Limit the scan to specific directories instead of the whole system:

```bash
python3 main.py --scan /usr /home /tmp /opt
```

---

### ❌ Python version error

Check your Python version:

```bash
python3 --version
```

This tool requires Python 3.8+. If you have an older version:

```bash
# Ubuntu/Debian
sudo apt install python3.10

# CentOS/RHEL
sudo dnf install python3.10
```

---

## ❓ FAQ

**Q: Do I need to be root to run this?**
Running as a normal user works but will miss files in restricted directories.
`sudo` gives a complete, accurate scan.

**Q: Will this modify any files on my system?**
No. The tool is **read-only**. It only reads file metadata and log files — it
never writes, deletes, or modifies anything on your system.

**Q: How often should I run this?**
At minimum, run it after every new software installation, user addition,
or configuration change. For production servers, weekly automated scans
are recommended.

**Q: Can I run this on a remote server?**
Yes. SSH into your server and run it there:

```bash
ssh user@your-server
git clone https://github.com/shivajigandham/linux-audit.git
cd linux-audit && pip install reportlab
sudo python3 main.py --out ~/reports
```

Then copy reports to your local machine:

```bash
scp user@your-server:~/reports/audit_report_*.html ./
```

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Shivaji Gandham**
- GitHub: [@shivajigandham](https://github.com/shivajigandham)
- Email: shivajigandham999@gmail.com
