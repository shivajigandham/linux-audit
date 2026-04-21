#!/usr/bin/env python3
"""
HTML Report Generator for Linux System Auditor
Produces a self-contained, timestamped HTML report.
"""

from datetime import datetime


# ─────────────────────────────────────────────
#  RISK HELPERS
# ─────────────────────────────────────────────

def risk_badge(risk):
    color = {"High": "#ef4444", "Low": "#22c55e", "Medium": "#f59e0b"}.get(risk, "#6b7280")
    return f'<span class="badge" style="background:{color}">{risk}</span>'

def severity_color(count, high_threshold=10, med_threshold=3):
    if count >= high_threshold:
        return "#ef4444"
    elif count >= med_threshold:
        return "#f59e0b"
    return "#22c55e"


# ─────────────────────────────────────────────
#  SUMMARY CARD
# ─────────────────────────────────────────────

def summary_card(title, value, subtitle, color="#3b82f6", icon=""):
    return f"""
    <div class="stat-card">
        <div class="stat-icon" style="background:{color}20;color:{color}">{icon}</div>
        <div class="stat-body">
            <div class="stat-value" style="color:{color}">{value}</div>
            <div class="stat-title">{title}</div>
            <div class="stat-sub">{subtitle}</div>
        </div>
    </div>"""


# ─────────────────────────────────────────────
#  SECTION BUILDERS
# ─────────────────────────────────────────────

def build_suid_section(suid_data):
    results = suid_data["results"]
    high    = [r for r in results if r["risk"] == "High"]
    low     = [r for r in results if r["risk"] == "Low"]

    rows = ""
    for r in results[:200]:    # cap to 200 rows in HTML
        flags_html = " ".join(
            f'<span class="tag tag-{"red" if f == "SUID" else "orange"}">{f}</span>'
            for f in r["flags"]
        )
        rows += f"""
        <tr class='{"row-high" if r["risk"]=="High" else ""}'>
            <td class="mono">{r["path"]}</td>
            <td>{flags_html}</td>
            <td class="mono">{r["perms"]}</td>
            <td class="mono">{r["owner"]}:{r["group"]}</td>
            <td>{risk_badge(r["risk"])}</td>
        </tr>"""

    return f"""
    <section class="section">
        <h2 class="section-title">
            <span class="section-icon">🔑</span> SUID / SGID Binaries
        </h2>
        <div class="section-summary">
            <div class="summary-pill pill-red">⚠ {len(high)} Suspicious</div>
            <div class="summary-pill pill-green">✓ {len(low)} Known Safe</div>
            <div class="summary-pill pill-blue">∑ {len(results)} Total Found</div>
        </div>
        <p class="section-desc">
            SUID binaries run with the file owner's privileges (typically root).
            Unexpected SUID binaries can be exploited for privilege escalation.
        </p>
        <div class="table-wrap">
        <table>
            <thead><tr>
                <th>Path</th><th>Flags</th><th>Permissions</th><th>Owner:Group</th><th>Risk</th>
            </tr></thead>
            <tbody>{rows if rows else "<tr><td colspan='5' class='empty'>No SUID/SGID binaries found.</td></tr>"}</tbody>
        </table>
        </div>
        {"<p class='truncate-note'>⚠ Showing first 200 results. Run with --json for full output.</p>" if len(results) > 200 else ""}
    </section>"""


def build_worldwrite_section(ww_data):
    results = ww_data["results"]
    high    = [r for r in results if r["risk"] == "High"]
    low     = [r for r in results if r["risk"] == "Low"]

    rows = ""
    for r in results[:200]:
        rows += f"""
        <tr class='{"row-high" if r["risk"]=="High" else ""}'>
            <td class="mono">{r["path"]}</td>
            <td><span class="tag tag-{'blue' if r['type']=='Directory' else 'gray'}">{r["type"]}</span></td>
            <td class="mono">{r["perms"]}</td>
            <td>{"<span class='tag tag-green'>Yes</span>" if r["sticky"] else "<span class='tag tag-red'>No</span>"}</td>
            <td>{risk_badge(r["risk"])}</td>
        </tr>"""

    return f"""
    <section class="section">
        <h2 class="section-title">
            <span class="section-icon">📂</span> World-Writable Files &amp; Directories
        </h2>
        <div class="section-summary">
            <div class="summary-pill pill-red">⚠ {len(high)} No Sticky Bit</div>
            <div class="summary-pill pill-green">✓ {len(low)} Sticky Bit Set</div>
            <div class="summary-pill pill-blue">∑ {len(results)} Total Found</div>
        </div>
        <p class="section-desc">
            World-writable files can be modified by any user. Without a sticky bit,
            directories like <code>/tmp</code> allow anyone to delete others' files.
        </p>
        <div class="table-wrap">
        <table>
            <thead><tr>
                <th>Path</th><th>Type</th><th>Permissions</th><th>Sticky Bit</th><th>Risk</th>
            </tr></thead>
            <tbody>{rows if rows else "<tr><td colspan='5' class='empty'>No world-writable entries found.</td></tr>"}</tbody>
        </table>
        </div>
        {"<p class='truncate-note'>⚠ Showing first 200 results.</p>" if len(results) > 200 else ""}
    </section>"""


def build_login_section(login_data):
    total    = login_data["total_failures"]
    brute    = login_data["brute_force_ips"]
    top_ips  = login_data["top_ips"]
    top_users= login_data["top_users"]
    events   = login_data["recent_events"]
    sudos    = login_data["sudo_failures"]

    # Top IPs table
    ip_rows = "".join(
        f"<tr><td class='mono'>{ip}</td><td><div class='bar-wrap'>"
        f"<div class='bar' style='width:{min(100, int(cnt/max(top_ips.values(),default=1)*100))}%'></div></div></td>"
        f"<td><strong>{cnt}</strong></td>"
        f"<td>{'<span class=\"tag tag-red\">Brute Force</span>' if ip in brute else ''}</td></tr>"
        for ip, cnt in top_ips.items()
    )

    # Top users table
    user_rows = "".join(
        f"<tr><td class='mono'>{user}</td><td><strong>{cnt}</strong></td></tr>"
        for user, cnt in top_users.items()
    )

    # Recent events
    evt_rows = "".join(
        f"<tr><td class='mono small'>{e['timestamp']}</td>"
        f"<td class='mono'>{e['user']}</td>"
        f"<td class='mono'>{e['ip']}</td>"
        f"<td class='small truncate-cell'>{e['line']}</td></tr>"
        for e in reversed(events[-30:])
    )

    sudo_block = ""
    if sudos:
        sudo_lines = "".join(f"<div class='log-line'>{l}</div>" for l in sudos)
        sudo_block = f"""
        <h3 class="sub-heading">Sudo Failures ({len(sudos)})</h3>
        <div class="log-box">{sudo_lines}</div>"""

    no_log_warn = ""
    if not login_data["log_found"]:
        no_log_warn = """
        <div class="warn-box">
            ⚠ No auth log files found at standard paths (/var/log/auth.log, /var/log/secure).
            This may be a container or a system using journald only.
            Run: <code>journalctl _SYSTEMD_UNIT=sshd.service | grep "Failed"</code>
        </div>"""

    return f"""
    <section class="section">
        <h2 class="section-title">
            <span class="section-icon">🔐</span> Failed Login Attempts
        </h2>
        {no_log_warn}
        <div class="section-summary">
            <div class="summary-pill pill-red">⚠ {total} Total Failures</div>
            <div class="summary-pill pill-orange">🚨 {len(brute)} Brute-Force IPs</div>
            <div class="summary-pill pill-blue">👤 {login_data['unique_users']} Unique Users</div>
            <div class="summary-pill pill-gray">🌐 {login_data['unique_ips']} Unique IPs</div>
        </div>

        <div class="two-col">
            <div>
                <h3 class="sub-heading">Top Attacker IPs</h3>
                <div class="table-wrap">
                <table>
                    <thead><tr><th>IP Address</th><th>Attempts</th><th>Count</th><th>Flag</th></tr></thead>
                    <tbody>{ip_rows if ip_rows else "<tr><td colspan='4' class='empty'>No data</td></tr>"}</tbody>
                </table>
                </div>
            </div>
            <div>
                <h3 class="sub-heading">Top Targeted Usernames</h3>
                <div class="table-wrap">
                <table>
                    <thead><tr><th>Username</th><th>Failed Attempts</th></tr></thead>
                    <tbody>{user_rows if user_rows else "<tr><td colspan='2' class='empty'>No data</td></tr>"}</tbody>
                </table>
                </div>
            </div>
        </div>

        <h3 class="sub-heading">Recent Events (last 30)</h3>
        <div class="table-wrap">
        <table>
            <thead><tr><th>Timestamp</th><th>User</th><th>Source IP</th><th>Raw Log</th></tr></thead>
            <tbody>{evt_rows if evt_rows else "<tr><td colspan='4' class='empty'>No recent events found.</td></tr>"}</tbody>
        </table>
        </div>
        {sudo_block}
    </section>"""


# ─────────────────────────────────────────────
#  MAIN HTML BUILDER
# ─────────────────────────────────────────────

def build_html_report(audit_data):
    sysinfo    = audit_data["sysinfo"]
    suid_data  = audit_data["suid"]
    ww_data    = audit_data["world_write"]
    login_data = audit_data["logins"]

    ts       = sysinfo["scan_time"]
    hostname = sysinfo["hostname"]

    suid_results = suid_data["results"]
    ww_results   = ww_data["results"]

    high_suid    = len([r for r in suid_results if r["risk"] == "High"])
    high_ww      = len([r for r in ww_results   if r["risk"] == "High"])
    total_fail   = login_data["total_failures"]
    brute_count  = len(login_data["brute_force_ips"])

    overall_risk = "Critical" if (high_suid > 5 or brute_count > 0) else \
                   "High"     if (high_suid > 0 or high_ww > 5)     else \
                   "Medium"   if (total_fail > 10 or high_ww > 0)   else "Low"
    risk_color   = {"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#22c55e"}[overall_risk]

    # Summary cards
    cards = (
        summary_card("Suspicious SUID Bins",  high_suid,   f"{len(suid_results)} total found",  "#ef4444", "🔑") +
        summary_card("World-Writable (No Sticky)", high_ww, f"{len(ww_results)} total found",   "#f97316", "📂") +
        summary_card("Failed Logins",         total_fail,  f"{login_data['unique_ips']} unique IPs", "#3b82f6", "🔐") +
        summary_card("Brute-Force IPs",       brute_count, "≥5 attempts each",                  "#8b5cf6", "🚨")
    )

    suid_section  = build_suid_section(suid_data)
    ww_section    = build_worldwrite_section(ww_data)
    login_section = build_login_section(login_data)

    logged_users_html = ""
    if sysinfo["logged_users"]:
        logged_users_html = "<br>".join(sysinfo["logged_users"])
    else:
        logged_users_html = "<span style='color:#6b7280'>No active sessions</span>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Linux Security Audit — {hostname} — {ts}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #263148;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
    --font: 'Segoe UI', system-ui, sans-serif;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  
  /* ── Header ── */
  .header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 60%, #1a0a2e 100%);
             border-bottom: 1px solid var(--border); padding: 32px 40px; }}
  .header-top {{ display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }}
  .logo {{ font-size: 32px; }}
  .header h1 {{ font-size: 22px; font-weight: 700; color: #f8fafc; }}
  .header-meta {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  .header-meta span {{ margin-right: 24px; }}
  .overall-badge {{ display: inline-flex; align-items: center; gap: 8px;
                    padding: 6px 16px; border-radius: 999px; font-size: 13px; font-weight: 600;
                    background: {risk_color}20; color: {risk_color}; border: 1px solid {risk_color}40;
                    margin-top: 12px; }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 0 24px; }}
  
  /* ── System Info Bar ── */
  .sysbar {{ background: var(--surface); border-bottom: 1px solid var(--border);
             padding: 12px 40px; display: flex; gap: 32px; flex-wrap: wrap; font-size: 12px; color: var(--muted); }}
  .sysbar strong {{ color: var(--text); }}

  /* ── Stat Cards ── */
  .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 24px 0 8px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
                padding: 18px; display: flex; gap: 14px; align-items: center;
                transition: transform .15s; }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-icon {{ width: 46px; height: 46px; border-radius: 10px; display: flex;
                align-items: center; justify-content: center; font-size: 20px; flex-shrink: 0; }}
  .stat-value {{ font-size: 26px; font-weight: 800; line-height: 1; }}
  .stat-title {{ font-size: 12px; font-weight: 600; color: var(--muted); margin-top: 3px; text-transform: uppercase; letter-spacing: .5px; }}
  .stat-sub   {{ font-size: 11px; color: #64748b; margin-top: 2px; }}

  /* ── Sections ── */
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
              padding: 24px; margin: 20px 0; }}
  .section-title {{ font-size: 16px; font-weight: 700; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
  .section-icon {{ font-size: 18px; }}
  .section-desc {{ color: var(--muted); font-size: 13px; margin-bottom: 16px; line-height: 1.5; }}
  .section-summary {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }}

  .sub-heading {{ font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase;
                  letter-spacing: .5px; margin: 18px 0 8px; }}

  /* ── Pills / Tags ── */
  .summary-pill {{ padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
  .pill-red    {{ background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }}
  .pill-green  {{ background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40; }}
  .pill-blue   {{ background: #3b82f620; color: #3b82f6; border: 1px solid #3b82f640; }}
  .pill-orange {{ background: #f9731620; color: #f97316; border: 1px solid #f9731640; }}
  .pill-gray   {{ background: #64748b20; color: #94a3b8; border: 1px solid #64748b40; }}

  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }}
  .tag   {{ display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; margin: 1px; }}
  .tag-red    {{ background: #ef444425; color: #f87171; border: 1px solid #ef444440; }}
  .tag-orange {{ background: #f9731625; color: #fb923c; border: 1px solid #f9731640; }}
  .tag-green  {{ background: #22c55e25; color: #4ade80; border: 1px solid #22c55e40; }}
  .tag-blue   {{ background: #3b82f625; color: #60a5fa; border: 1px solid #3b82f640; }}
  .tag-gray   {{ background: #64748b25; color: #94a3b8; border: 1px solid #64748b40; }}

  /* ── Tables ── */
  .table-wrap {{ overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead tr {{ background: #1a2744; }}
  th {{ padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 700;
        text-transform: uppercase; letter-spacing: .5px; color: var(--muted);
        border-bottom: 1px solid var(--border); white-space: nowrap; }}
  td {{ padding: 9px 14px; border-bottom: 1px solid #1e293b; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1a2744; }}
  .row-high td {{ background: #ef444408; }}
  .row-high:hover td {{ background: #ef444415; }}
  .empty {{ text-align: center; color: var(--muted); padding: 24px !important; }}
  .mono  {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; }}
  .small {{ font-size: 11px; }}
  .truncate-cell {{ max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }}
  .truncate-note {{ color: #f59e0b; font-size: 12px; margin-top: 10px; }}

  /* ── Bar ── */
  .bar-wrap {{ background: #1e293b; border-radius: 4px; height: 6px; width: 100px; overflow: hidden; }}
  .bar {{ height: 100%; background: #3b82f6; border-radius: 4px; }}

  /* ── Two Col ── */
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 8px; }}

  /* ── Warn Box ── */
  .warn-box {{ background: #f59e0b15; border: 1px solid #f59e0b40; border-radius: 8px;
               padding: 12px 16px; color: #fcd34d; font-size: 13px; margin-bottom: 14px; }}
  .warn-box code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; }}

  /* ── Log Box ── */
  .log-box {{ background: #0f172a; border: 1px solid var(--border); border-radius: 8px;
              padding: 12px; font-family: monospace; font-size: 11px; color: #94a3b8;
              max-height: 200px; overflow-y: auto; }}
  .log-line {{ padding: 1px 0; border-bottom: 1px solid #1e293b30; }}

  /* ── Footer ── */
  .footer {{ text-align: center; color: #475569; font-size: 12px; padding: 32px 0 48px; }}

  code {{ background: #1e293b; padding: 1px 5px; border-radius: 3px; font-size: 12px; color: #7dd3fc; }}

  @media (max-width: 768px) {{
    .stats-grid {{ grid-template-columns: 1fr 1fr; }}
    .two-col {{ grid-template-columns: 1fr; }}
    .header, .sysbar {{ padding: 20px; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="container">
    <div class="header-top">
      <span class="logo">🛡️</span>
      <div>
        <h1>Linux System Security Audit</h1>
        <div class="header-meta">
          <span>🖥 {hostname}</span>
          <span>🕐 {ts}</span>
          <span>⚙ {sysinfo['os']}</span>
        </div>
      </div>
    </div>
    <div class="overall-badge">Overall Risk: {overall_risk}</div>
  </div>
</div>

<div class="sysbar">
  <span>Kernel: <strong>{sysinfo['os']}</strong></span>
  <span>Arch: <strong>{sysinfo['machine']}</strong></span>
  <span>Uptime: <strong>{sysinfo['uptime'] or 'N/A'}</strong></span>
  <span>Active Sessions: <strong>{len(sysinfo['logged_users'])}</strong></span>
  <span>Python: <strong>{sysinfo['python']}</strong></span>
</div>

<div class="container">
  <div class="stats-grid">
    {cards}
  </div>

  {suid_section}
  {ww_section}
  {login_section}

  <div class="footer">
    Generated by <strong>linux-audit</strong> · {ts} · Host: {hostname}
  </div>
</div>

</body>
</html>"""


def save_html_report(audit_data, output_dir="."):
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"audit_report_{ts}.html"
    filepath = f"{output_dir}/{filename}"

    html = build_html_report(audit_data)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath
