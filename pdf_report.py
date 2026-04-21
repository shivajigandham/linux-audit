#!/usr/bin/env python3
"""
PDF Report Generator for Linux System Auditor
"""

from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Palette ──────────────────────────────────
C_BG       = colors.HexColor("#0f172a")
C_SURFACE  = colors.HexColor("#1e293b")
C_BORDER   = colors.HexColor("#334155")
C_TEXT     = colors.HexColor("#e2e8f0")
C_MUTED    = colors.HexColor("#94a3b8")
C_RED      = colors.HexColor("#ef4444")
C_ORANGE   = colors.HexColor("#f97316")
C_BLUE     = colors.HexColor("#3b82f6")
C_GREEN    = colors.HexColor("#22c55e")
C_PURPLE   = colors.HexColor("#8b5cf6")
C_YELLOW   = colors.HexColor("#f59e0b")
C_WHITE    = colors.white
C_ROW_ALT  = colors.HexColor("#1a2744")
C_ROW_HIGH = colors.HexColor("#3b1a1a")


def make_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Normal"],
            fontSize=20, textColor=C_WHITE, fontName="Helvetica-Bold",
            spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"],
            fontSize=10, textColor=C_MUTED, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base["Normal"],
            fontSize=13, textColor=C_WHITE, fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Normal"],
            fontSize=10, textColor=C_MUTED, fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4, textTransform="uppercase"),
        "body": ParagraphStyle("body", parent=base["Normal"],
            fontSize=9, textColor=C_MUTED, leading=13, spaceAfter=6),
        "mono": ParagraphStyle("mono", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#7dd3fc"),
            fontName="Courier", leading=11),
        "warn": ParagraphStyle("warn", parent=base["Normal"],
            fontSize=9, textColor=C_YELLOW, leading=12, spaceAfter=6),
        "cell": ParagraphStyle("cell", parent=base["Normal"],
            fontSize=8, textColor=C_TEXT, leading=11,
            fontName="Courier"),
        "cell_muted": ParagraphStyle("cell_muted", parent=base["Normal"],
            fontSize=8, textColor=C_MUTED, leading=11,
            fontName="Courier"),
    }


def risk_color(risk):
    return {"High": C_RED, "Medium": C_YELLOW, "Low": C_GREEN}.get(risk, C_MUTED)


def stat_table(stats):
    """4-column summary stat row."""
    data = [[
        _stat_cell(stats[0]),
        _stat_cell(stats[1]),
        _stat_cell(stats[2]),
        _stat_cell(stats[3]),
    ]]
    t = Table(data, colWidths=[42*mm]*4)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
        ("BOX",        (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, C_BORDER),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    return t


def _stat_cell(s):
    val, label, sub, col = s
    return Paragraph(
        f'<font size="20" color="{col.hexval()}">'
        f'<b>{val}</b></font><br/>'
        f'<font size="8" color="{C_MUTED.hexval()}">{label}</font><br/>'
        f'<font size="7" color="#64748b">{sub}</font>',
        ParagraphStyle("sc", fontSize=9, leading=13, textColor=C_TEXT)
    )


def section_header(title, icon, st):
    return Paragraph(f"{icon}  {title}", st["h2"])


def make_table(headers, rows, col_widths, style_extra=None):
    header_row = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
        "th", fontSize=8, textColor=C_MUTED, fontName="Helvetica-Bold", leading=10
    )) for h in headers]

    table_data = [header_row] + rows

    ts = TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#1a2744")),
        ("BACKGROUND",    (0,1), (-1,-1), C_SURFACE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_SURFACE, C_ROW_ALT]),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("LINEBELOW",     (0,0), (-1,0),  0.8, C_BORDER),
        ("LINEBELOW",     (0,1), (-1,-1), 0.3, colors.HexColor("#1e293b")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ])
    if style_extra:
        for s in style_extra:
            ts.add(*s)

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(ts)
    return t


def build_pdf_report(audit_data, output_path):
    sysinfo    = audit_data["sysinfo"]
    suid_data  = audit_data["suid"]
    ww_data    = audit_data["world_write"]
    login_data = audit_data["logins"]

    st = make_styles()

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title=f"Linux Security Audit – {sysinfo['hostname']}",
        author="linux-audit"
    )

    W = A4[0] - 36*mm   # usable width
    story = []

    # ── Cover ────────────────────────────────
    story.append(Paragraph("🛡  Linux System Security Audit", st["title"]))
    story.append(Paragraph(
        f"Host: <b>{sysinfo['hostname']}</b>  ·  "
        f"OS: {sysinfo['os']}  ·  "
        f"Scan time: {sysinfo['scan_time']}",
        st["subtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=12))

    # ── Summary stats ────────────────────────
    suid_results = suid_data["results"]
    ww_results   = ww_data["results"]
    high_suid    = len([r for r in suid_results if r["risk"] == "High"])
    high_ww      = len([r for r in ww_results   if r["risk"] == "High"])
    total_fail   = login_data["total_failures"]
    brute_count  = len(login_data["brute_force_ips"])

    story.append(stat_table([
        (str(high_suid),   "Suspicious SUID",    f"{len(suid_results)} total", C_RED),
        (str(high_ww),     "World-Writable",      f"{len(ww_results)} total",  C_ORANGE),
        (str(total_fail),  "Failed Logins",       f"{login_data['unique_ips']} IPs", C_BLUE),
        (str(brute_count), "Brute-Force IPs",     "≥5 attempts",               C_PURPLE),
    ]))
    story.append(Spacer(1, 14))

    # ── SUID / SGID ──────────────────────────
    story.append(section_header("SUID / SGID Binaries", "🔑", st))
    story.append(Paragraph(
        "SUID binaries execute with the owner's privileges. "
        "Unknown SUID binaries may indicate a backdoor or misconfiguration.", st["body"]
    ))

    rows = []
    for r in suid_results[:80]:
        c = C_ROW_HIGH if r["risk"] == "High" else C_SURFACE
        rows.append([
            Paragraph(r["path"],           st["cell"]),
            Paragraph(", ".join(r["flags"]), st["cell"]),
            Paragraph(r["perms"],          st["cell"]),
            Paragraph(r["risk"],           ParagraphStyle(
                "rc", fontSize=8, fontName="Helvetica-Bold",
                textColor=risk_color(r["risk"]), leading=11
            )),
        ])

    if rows:
        extra = [("BACKGROUND", (0, i+1), (-1, i+1), C_ROW_HIGH)
                 for i, r in enumerate(suid_results[:80]) if r["risk"] == "High"]
        story.append(make_table(
            ["Path", "Flags", "Perms", "Risk"],
            rows,
            [W*0.58, W*0.14, W*0.14, W*0.14],
            extra
        ))
    else:
        story.append(Paragraph("No SUID/SGID binaries found.", st["body"]))

    if len(suid_results) > 80:
        story.append(Paragraph(
            f"⚠ Showing 80 of {len(suid_results)} entries. See HTML report for full list.", st["warn"]))

    story.append(Spacer(1, 12))

    # ── World-Writable ───────────────────────
    story.append(section_header("World-Writable Files & Directories", "📂", st))
    story.append(Paragraph(
        "Files with o+w permissions are writable by any local user. "
        "Without a sticky bit, directories become unsafe shared spaces.", st["body"]
    ))

    rows = []
    for r in ww_results[:80]:
        rows.append([
            Paragraph(r["path"],          st["cell"]),
            Paragraph(r["type"],          st["cell"]),
            Paragraph(r["perms"],         st["cell"]),
            Paragraph("Yes" if r["sticky"] else "No",
                ParagraphStyle("sc", fontSize=8, fontName="Helvetica-Bold",
                    textColor=C_GREEN if r["sticky"] else C_RED, leading=11)),
            Paragraph(r["risk"], ParagraphStyle(
                "rc", fontSize=8, fontName="Helvetica-Bold",
                textColor=risk_color(r["risk"]), leading=11
            )),
        ])

    if rows:
        extra = [("BACKGROUND", (0, i+1), (-1, i+1), C_ROW_HIGH)
                 for i, r in enumerate(ww_results[:80]) if r["risk"] == "High"]
        story.append(make_table(
            ["Path", "Type", "Perms", "Sticky", "Risk"],
            rows,
            [W*0.50, W*0.12, W*0.12, W*0.12, W*0.12],
            extra
        ))
    else:
        story.append(Paragraph("No world-writable entries found.", st["body"]))

    story.append(Spacer(1, 12))

    # ── Failed Logins ────────────────────────
    story.append(section_header("Failed Login Attempts", "🔐", st))

    if not login_data["log_found"]:
        story.append(Paragraph(
            "⚠ No auth log found. This system may use journald only.", st["warn"]))

    # Top IPs
    story.append(Paragraph("Top Attacker IPs", st["h3"]))
    ip_rows = []
    for ip, cnt in list(login_data["top_ips"].items())[:15]:
        flag = " [BRUTE FORCE]" if ip in login_data["brute_force_ips"] else ""
        ip_rows.append([
            Paragraph(ip,          st["cell"]),
            Paragraph(str(cnt),    ParagraphStyle("cnt", fontSize=9, fontName="Helvetica-Bold",
                textColor=C_RED if flag else C_TEXT, leading=11)),
            Paragraph(flag.strip(), ParagraphStyle("fl", fontSize=8,
                textColor=C_RED, fontName="Helvetica-Bold", leading=11)),
        ])

    if ip_rows:
        story.append(make_table(["IP Address", "Attempts", "Flag"], ip_rows,
                                [W*0.45, W*0.2, W*0.35]))
    else:
        story.append(Paragraph("No failed logins found.", st["body"]))

    # Top Users
    story.append(Paragraph("Top Targeted Usernames", st["h3"]))
    user_rows = [[
        Paragraph(u, st["cell"]),
        Paragraph(str(c), ParagraphStyle("cnt2", fontSize=9,
            fontName="Helvetica-Bold", textColor=C_ORANGE, leading=11)),
    ] for u, c in list(login_data["top_users"].items())[:10]]

    if user_rows:
        story.append(make_table(["Username", "Failures"], user_rows, [W*0.6, W*0.4]))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.3, color=C_BORDER, spaceAfter=6))
    story.append(Paragraph(
        f"Generated by linux-audit · {sysinfo['scan_time']} · {sysinfo['hostname']}",
        ParagraphStyle("footer", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path


def save_pdf_report(audit_data, output_dir="."):
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"audit_report_{ts}.pdf"
    filepath = f"{output_dir}/{filename}"
    build_pdf_report(audit_data, filepath)
    return filepath
