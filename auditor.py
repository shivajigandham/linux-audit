#!/usr/bin/env python3
"""
Linux System Auditor
Performs security audits and generates timestamped HTML + PDF reports.
Modules: SUID/SGID binaries, world-writable files, failed login detection.
"""

import os
import stat
import subprocess
import re
import json
import socket
import platform
from datetime import datetime
from pathlib import Path
from collections import defaultdict


# ─────────────────────────────────────────────
#  MODULE 1: SUID / SGID Binary Scanner
# ─────────────────────────────────────────────

KNOWN_SAFE_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/fusermount",
    "/usr/bin/fusermount3", "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/sbin/unix_chkpwd",
    "/usr/bin/ping", "/usr/bin/wall", "/usr/bin/write",
    "/bin/mount", "/bin/umount", "/bin/ping", "/bin/su",
}

def scan_suid_sgid(scan_paths=None):
    """Find all SUID and SGID binaries on the system."""
    if scan_paths is None:
        scan_paths = ["/usr", "/bin", "/sbin", "/home", "/tmp", "/opt", "/var"]

    results = []
    errors  = []

    for base in scan_paths:
        if not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base, followlinks=False):
            # Skip noisy virtual/proc dirs
            dirs[:] = [d for d in dirs if not d.startswith(("proc", "sys", "dev"))]
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    st = os.lstat(fpath)
                    mode = st.st_mode
                    flags = []
                    if mode & stat.S_ISUID:
                        flags.append("SUID")
                    if mode & stat.S_ISGID:
                        flags.append("SGID")
                    if flags:
                        known = fpath in KNOWN_SAFE_SUID
                        results.append({
                            "path":    fpath,
                            "flags":   flags,
                            "owner":   st.st_uid,
                            "group":   st.st_gid,
                            "perms":   oct(mode)[-4:],
                            "known":   known,
                            "risk":    "Low" if known else "High",
                        })
                except (PermissionError, FileNotFoundError, OSError) as e:
                    errors.append(str(e))

    results.sort(key=lambda x: (x["risk"] == "Low", x["path"]))
    return results, errors


# ─────────────────────────────────────────────
#  MODULE 2: World-Writable File Scanner
# ─────────────────────────────────────────────

SKIP_DIRS = {"/proc", "/sys", "/dev", "/run"}

def scan_world_writable(scan_paths=None):
    """Find files and directories writable by any user (o+w)."""
    if scan_paths is None:
        scan_paths = ["/tmp", "/var/tmp", "/usr", "/etc", "/home", "/opt"]

    results = []
    errors  = []

    for base in scan_paths:
        if not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base, followlinks=False):
            if any(root.startswith(s) for s in SKIP_DIRS):
                dirs.clear()
                continue

            all_entries = [(d, True) for d in dirs] + [(f, False) for f in files]
            for name, is_dir in all_entries:
                fpath = os.path.join(root, name)
                try:
                    st = os.lstat(fpath)
                    mode = st.st_mode
                    if mode & stat.S_IWOTH:
                        sticky = bool(mode & stat.S_ISVTX)
                        results.append({
                            "path":    fpath,
                            "type":    "Directory" if is_dir else "File",
                            "perms":   oct(mode)[-4:],
                            "owner":   st.st_uid,
                            "sticky":  sticky,
                            "risk":    "Low" if sticky else "High",
                        })
                except (PermissionError, FileNotFoundError, OSError) as e:
                    errors.append(str(e))

    results.sort(key=lambda x: (x["risk"] == "Low", x["path"]))
    return results, errors


# ─────────────────────────────────────────────
#  MODULE 3: Failed Login Detector
# ─────────────────────────────────────────────

AUTH_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",          # RHEL/CentOS
    "/var/log/auth.log.1",
]

FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"),
    re.compile(r"Invalid user (\S+) from (\S+)"),
    re.compile(r"authentication failure.*user=(\S+).*rhost=(\S+)"),
    re.compile(r"pam_unix\(sshd:auth\): authentication failure.*user=(\S+)"),
]

SUDO_FAIL_PATTERN = re.compile(
    r"sudo:.*?(\S+)\s*:.*?command not allowed|sudo:.*?FAILED"
)

def parse_failed_logins(log_paths=None):
    """Parse auth logs for failed login attempts, brute-force IPs, and sudo failures."""
    if log_paths is None:
        log_paths = AUTH_LOG_PATHS

    ip_attempts   = defaultdict(int)
    user_attempts = defaultdict(int)
    raw_events    = []
    sudo_failures = []
    log_found     = False

    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue
        log_found = True
        try:
            with open(log_path, "r", errors="replace") as fh:
                for line in fh:
                    # SSH failed password
                    for pat in FAIL_PATTERNS:
                        m = pat.search(line)
                        if m:
                            groups = m.groups()
                            user = groups[0] if groups else "unknown"
                            ip   = groups[1] if len(groups) > 1 else "unknown"
                            ip_attempts[ip] += 1
                            user_attempts[user] += 1
                            raw_events.append({
                                "timestamp": line[:15].strip(),
                                "user":      user,
                                "ip":        ip,
                                "line":      line.strip(),
                            })
                            break
                    # Sudo failures
                    if SUDO_FAIL_PATTERN.search(line):
                        sudo_failures.append(line.strip())
        except PermissionError:
            pass

    # Brute-force detection: IPs with ≥ 5 attempts
    brute_force = {ip: cnt for ip, cnt in ip_attempts.items() if cnt >= 5}

    return {
        "log_found":      log_found,
        "total_failures": len(raw_events),
        "unique_ips":     len(ip_attempts),
        "unique_users":   len(user_attempts),
        "brute_force_ips": dict(sorted(brute_force.items(), key=lambda x: -x[1])),
        "top_users":      dict(sorted(user_attempts.items(), key=lambda x: -x[1])[:10]),
        "top_ips":        dict(sorted(ip_attempts.items(), key=lambda x: -x[1])[:10]),
        "recent_events":  raw_events[-50:],
        "sudo_failures":  sudo_failures[-20:],
    }


# ─────────────────────────────────────────────
#  SYSTEM INFO
# ─────────────────────────────────────────────

def get_system_info():
    hostname = socket.gethostname()
    uname    = platform.uname()
    uptime   = ""
    try:
        result = subprocess.run(["uptime", "-p"], capture_output=True, text=True)
        uptime = result.stdout.strip()
    except Exception:
        pass

    users = []
    try:
        result = subprocess.run(["who"], capture_output=True, text=True)
        users  = result.stdout.strip().splitlines()
    except Exception:
        pass

    return {
        "hostname":    hostname,
        "os":          f"{uname.system} {uname.release}",
        "machine":     uname.machine,
        "python":      platform.python_version(),
        "uptime":      uptime,
        "logged_users": users,
        "scan_time":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
#  RUNNER
# ─────────────────────────────────────────────

def run_audit(verbose=True):
    def log(msg):
        if verbose:
            print(msg)

    log("\n╔══════════════════════════════════════════╗")
    log("║      Linux System Security Auditor       ║")
    log("╚══════════════════════════════════════════╝\n")

    log("[*] Collecting system information...")
    sysinfo = get_system_info()

    log("[*] Scanning for SUID/SGID binaries...")
    suid_results, suid_errors = scan_suid_sgid()
    high_suid = [r for r in suid_results if r["risk"] == "High"]
    log(f"    Found {len(suid_results)} SUID/SGID binaries ({len(high_suid)} suspicious)")

    log("[*] Scanning for world-writable files...")
    ww_results, ww_errors = scan_world_writable()
    high_ww = [r for r in ww_results if r["risk"] == "High"]
    log(f"    Found {len(ww_results)} world-writable entries ({len(high_ww)} without sticky bit)")

    log("[*] Parsing authentication logs...")
    login_data = parse_failed_logins()
    log(f"    {login_data['total_failures']} failed login attempts from {login_data['unique_ips']} IPs")
    log(f"    Brute-force IPs detected: {len(login_data['brute_force_ips'])}")

    return {
        "sysinfo":      sysinfo,
        "suid":         {"results": suid_results, "errors": suid_errors},
        "world_write":  {"results": ww_results,   "errors": ww_errors},
        "logins":       login_data,
    }
