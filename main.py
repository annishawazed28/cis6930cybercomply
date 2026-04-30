# This code may contain AI geneated content
#!/usr/bin/env python3
# main.py — STIG Hardening Agent orchestrator
#
# Usage:
#   python main.py --full                                           # scan + LLM + report
#   python main.py --scan                                           # scan only
#   python main.py --scan --llm --report                            # scan + LLM + report
#   python main.py --xml results/scan_X.xml --llm                   # analyze existing scan
#   python main.py --latest --llm --report                          # use most recent scan
#   python main.py --full --remediate                               # scan → fix → re-scan → report
#   python main.py --full --html                                    # scan + LLM + report → generate HTML report
#   python main.py --xml results/scan_X.xml --llm --report          # generate report from existing scan (no LLM)

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

def info(msg):   print(f"  {msg}")
def ok(msg):     print(f"  [OK] {msg}")
def err(msg):    print(f"  [ERROR] {msg}", file=sys.stderr)
def header(msg):
    print()
    print("=" * 55)
    print(f"  {msg}")
    print("=" * 55)

try:
    from agent.scanner    import run_scan
    from agent.remediator import run_remediation
    from agent.parser     import parse_results
    from agent.llm_agent  import analyze_findings
    from agent.reporter   import generate_report, generate_html_report
except ImportError as e:
    err(f"Could not import agent modules: {e}")
    err("Make sure you are running from the project root directory.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# Pipeline steps
# ─────────────────────────────────────────────────────────────

def step_scan() -> dict:
    header("Step 1 — Running OpenSCAP STIG Scan")
    try:
        result = run_scan()
        ok(f"XML  → {result['xml']}")
        return result
    except ConnectionError as e:
        err(str(e))
        err("Make sure the stig-target container is running:  docker compose up -d")
        sys.exit(1)
    except FileNotFoundError as e:
        err(str(e))
        sys.exit(1)
    except Exception as e:
        err(f"Scan failed: {e}")
        sys.exit(1)


def step_parse(xml_path: str) -> list:
    header("Step 2 — Parsing Scan Results")
    if not Path(xml_path).exists():
        err(f"XML file not found: {xml_path}")
        err("Run with --scan first to generate a result file.")
        sys.exit(1)
    try:
        findings = parse_results(xml_path)
        _print_findings_summary(findings)
        return findings
    except Exception as e:
        err(f"Parsing failed: {e}")
        sys.exit(1)


def step_llm(findings: list) -> list:
    header("Step 3 — AI Analysis with Ollama")
    high_count = sum(1 for f in findings if f.severity == "high")
    info(f"Sending {min(high_count, 10)} HIGH findings to llama3.2...")
    info("(This can take a few minutes depending on your machine)")
    try:
        enriched = analyze_findings(findings)
        ok("LLM analysis complete")
        return enriched
    except Exception as e:
        err(f"LLM analysis failed: {e}")
        err("Is Ollama running on your host machine?")
        err("Check: ollama list  (run in PowerShell)")
        return findings   # return unenriched — report still works


def step_report(findings: list, timestamp: str = "",
                xml_path: str = "", html: bool = False) -> str:
    header("Step 4 — Generating Report")
    ts        = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = f"reports/report_{ts}.md"
    html_path = f"reports/report_{ts}.html"
    try:
        generate_report(findings, output_path=out_path,
                        timestamp=ts, xml_path=xml_path)
        ok(f"Markdown → {out_path}")
        if html:
            generate_html_report(findings, output_path=html_path,
                                 timestamp=ts, xml_path=xml_path)
            ok(f"HTML     → {html_path}")
        return out_path
    except Exception as e:
        err(f"Report generation failed: {e}")
        sys.exit(1)


def step_remediate() -> None:
    header("Applying Automated Remediations")
    print()
    print("  WARNING: This modifies the target system configuration.")
    print("  Only run this on the Docker container or a VM.")
    print()
    confirm = input("  Continue? [y/N]: ").strip().lower()
    if confirm != "y":
        info("Remediation cancelled.")
        return
    try:
        run_remediation()
        ok("Remediations applied. Re-run --scan to measure improvement.")
    except Exception as e:
        err(f"Remediation failed: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _print_findings_summary(findings: list) -> None:
    highs  = sum(1 for f in findings if f.severity == "high")
    meds   = sum(1 for f in findings if f.severity == "medium")
    lows   = sum(1 for f in findings if f.severity == "low")
    total  = len(findings)
    if RICH:
        t = Table(show_header=True, header_style="bold")
        t.add_column("Severity", width=10)
        t.add_column("Count",    width=8)
        t.add_row("[red]HIGH[/red]",         str(highs))
        t.add_row("[yellow]MEDIUM[/yellow]", str(meds))
        t.add_row("[green]LOW[/green]",      str(lows))
        t.add_row("[bold]TOTAL[/bold]",      f"[bold]{total}[/bold]")
        console.print(t)
    else:
        print(f"  HIGH   : {highs}")
        print(f"  MEDIUM : {meds}")
        print(f"  LOW    : {lows}")
        print(f"  TOTAL  : {total}")


def _print_final_banner(report_path: str) -> None:
    msg = (f"\n  Pipeline complete!\n"
           f"  Report → {report_path}\n"
           f"\n  Open with VS Code:  code {report_path}")
    if RICH:
        console.print(Panel(msg, title="[bold green]Done[/bold green]", expand=False))
    else:
        print(msg)


# ─────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="AI-powered STIG hardening agent using OpenSCAP + Ollama",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python main.py --full
  python main.py --full --html
  python main.py --scan
  python main.py --xml results/scan_20240101_120000.xml --llm --report
  python main.py --latest --llm --report
  python main.py --full --remediate
        """
    )
    p.add_argument("--full",       action="store_true",
                   help="Run complete pipeline: scan → LLM → report")
    p.add_argument("--scan",       action="store_true",
                   help="Run OpenSCAP scan on target container")
    p.add_argument("--llm",        action="store_true",
                   help="Analyze findings with Ollama")
    p.add_argument("--report",     action="store_true",
                   help="Generate Markdown report")
    p.add_argument("--html",       action="store_true",
                   help="Also generate an HTML report")
    p.add_argument("--remediate",  action="store_true",
                   help="Apply automated STIG remediations on target")
    p.add_argument("--xml",        default=None, metavar="PATH",
                   help="Path to existing scan XML (skips --scan step)")
    p.add_argument("--latest",     action="store_true",
                   help="Use the most recent XML in results/ automatically")
    return p


def resolve_xml(args) -> str | None:
    if args.xml:
        return args.xml
    if args.latest:
        xmls = sorted(Path("results").glob("scan_*.xml"), reverse=True)
        if not xmls:
            err("No scan XML found in results/. Run --scan first.")
            sys.exit(1)
        info(f"Using latest scan: {xmls[0]}")
        return str(xmls[0])
    return None


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not any([args.full, args.scan, args.llm, args.report,
                args.remediate, args.xml, args.latest]):
        parser.print_help()
        sys.exit(0)

    if RICH:
        console.print(Panel(
            "[bold]STIG Hardening Agent[/bold]\n"
            "OpenSCAP + DISA STIG + Ollama (llama3.2)",
            expand=False
        ))
    else:
        header("STIG Hardening Agent")

    scan_result = None
    xml_path    = resolve_xml(args)
    timestamp   = ""

    # ── --full ────────────────────────────────────────────────
    if args.full:
        scan_result = step_scan()
        xml_path    = scan_result["xml"]
        timestamp   = scan_result["timestamp"]
        findings    = step_parse(xml_path)
        findings    = step_llm(findings)

        if args.remediate:
            step_remediate()
            info("Re-scanning after remediation...")
            scan_result = step_scan()
            xml_path    = scan_result["xml"]
            timestamp   = scan_result["timestamp"]
            findings    = step_parse(xml_path)
            findings    = step_llm(findings)

        report_path = step_report(findings, timestamp,
                                   xml_path=xml_path, html=args.html)
        _print_final_banner(report_path)
        return

    # ── Individual flags ──────────────────────────────────────
    if args.scan:
        scan_result = step_scan()
        xml_path    = scan_result["xml"]
        timestamp   = scan_result["timestamp"]

    if args.llm or args.report:
        if not xml_path:
            err("No XML file. Use --scan, --xml <path>, or --latest.")
            sys.exit(1)
        findings = step_parse(xml_path)

        if args.llm:
            findings = step_llm(findings)

        if args.report:
            report_path = step_report(findings, timestamp,
                                       xml_path=xml_path or "",
                                       html=args.html)
            _print_final_banner(report_path)
            return

    if args.remediate and not args.full:
        step_remediate()

    if args.scan and not args.llm and not args.report:
        print()
        info("Scan complete. Next steps:")
        info(f"  python main.py --xml {xml_path} --llm --report")
        info(f"  python main.py --latest --llm --report")


if __name__ == "__main__":
    main()