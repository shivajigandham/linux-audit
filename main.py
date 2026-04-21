#!/usr/bin/env python3
"""
linux-audit — CLI entry point
Usage:
    python main.py              # runs full audit, generates HTML + PDF
    python main.py --html-only  # HTML report only
    python main.py --json       # also dump raw JSON
    python main.py --out /tmp   # custom output directory
"""

import argparse
import json
import os
import sys
from auditor    import run_audit
from html_report import save_html_report
from pdf_report  import save_pdf_report


def main():
    parser = argparse.ArgumentParser(
        description="Linux System Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Run full audit (HTML + PDF)
  python main.py --html-only        HTML report only
  python main.py --json             Also export raw JSON
  python main.py --out /tmp         Save reports to /tmp
  python main.py --scan /usr /home  Custom scan paths
        """
    )
    parser.add_argument("--html-only",  action="store_true", help="Generate HTML report only")
    parser.add_argument("--json",       action="store_true", help="Also export raw JSON data")
    parser.add_argument("--out",        default=".",         help="Output directory (default: .)")
    parser.add_argument("--scan",       nargs="+",           help="Paths to scan (overrides defaults)")
    parser.add_argument("--quiet",      action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # ── Run Audit ────────────────────────────
    audit_data = run_audit(verbose=not args.quiet)

    # ── Override scan paths if provided ──────
    if args.scan:
        from auditor import scan_suid_sgid, scan_world_writable
        suid_r, suid_e = scan_suid_sgid(args.scan)
        ww_r,   ww_e   = scan_world_writable(args.scan)
        audit_data["suid"]        = {"results": suid_r, "errors": suid_e}
        audit_data["world_write"] = {"results": ww_r,   "errors": ww_e}

    print()

    # ── HTML ─────────────────────────────────
    html_path = save_html_report(audit_data, args.out)
    print(f"[✓] HTML report → {html_path}")

    # ── PDF ──────────────────────────────────
    if not args.html_only:
        try:
            pdf_path = save_pdf_report(audit_data, args.out)
            print(f"[✓] PDF report  → {pdf_path}")
        except Exception as e:
            print(f"[!] PDF generation failed: {e}", file=sys.stderr)

    # ── JSON ─────────────────────────────────
    if args.json:
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{args.out}/audit_data_{ts}.json"
        # Make JSON-serialisable (convert sets/tuples)
        safe = json.loads(json.dumps(audit_data, default=str))
        with open(json_path, "w") as f:
            json.dump(safe, f, indent=2)
        print(f"[✓] JSON dump   → {json_path}")

    # ── Quick Summary ─────────────────────────
    suid_high = len([r for r in audit_data["suid"]["results"] if r["risk"] == "High"])
    ww_high   = len([r for r in audit_data["world_write"]["results"] if r["risk"] == "High"])
    fails     = audit_data["logins"]["total_failures"]
    brute     = len(audit_data["logins"]["brute_force_ips"])

    print()
    print("── Audit Summary ──────────────────────────")
    print(f"  Suspicious SUID bins : {suid_high}")
    print(f"  World-writable (high): {ww_high}")
    print(f"  Failed logins        : {fails}")
    print(f"  Brute-force IPs      : {brute}")
    print("───────────────────────────────────────────")


if __name__ == "__main__":
    main()
