# This code may contain AI geneated content
#!/usr/bin/env python3
# evaluate.py  (project root, alongside main.py)
# Measures agent quality across 4 metrics.
#
# Usage:
#   python evaluate.py --latest                                             # evaluate most recent scan
#   python evaluate.py --latest --skip-llm                                  # evaluate most recent scan, skip LLM (cached advice only)
#   python evaluate.py --xml results/scan_X.xml                             # evaluate specific scan XML    
#   python evaluate.py --latest --after results/scan_after.xml              # evaluate before/after remediation (requires two XMLs)
#   python evaluate.py --xml results/before.xml --after results/after.xml   # evaluate specific before/after XMLs

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from agent.parser    import parse_results, get_stats, filter_by_severity
    from agent.llm_agent import analyze_findings, check_ollama
except ImportError as e:
    print(f"[ERROR] Could not import agent modules: {e}")
    sys.exit(1)

try:
    from rich.console import Console
    console = Console()
    RICH = True
except ImportError:
    RICH = False


# ─────────────────────────────────────────────────────────────
# Metric 1 — LLM Coverage
# ─────────────────────────────────────────────────────────────
def metric_coverage(findings) -> float:
    high = [f for f in findings if f.severity == "high"]
    if not high: return 1.0
    return sum(1 for f in high if f.llm_advice.strip()) / len(high)


# ─────────────────────────────────────────────────────────────
# Metric 2 — Relevance Score
# ─────────────────────────────────────────────────────────────
def metric_relevance(findings) -> float:
    scored = []
    for f in findings:
        if not f.llm_advice or not f.fix_script:
            continue
        fix_tokens    = {w.lower() for w in f.fix_script.split()
                         if len(w) > 3 and w.isalpha()}
        advice_tokens = set(f.llm_advice.lower().split())
        if not fix_tokens: continue
        scored.append(len(fix_tokens & advice_tokens) / len(fix_tokens))
    return sum(scored) / len(scored) if scored else 0.0


# ─────────────────────────────────────────────────────────────
# Metric 3 — Response Quality Rubric
# ─────────────────────────────────────────────────────────────
RUBRIC_CRITERIA = {
    "explains_risk":         lambda a: any(w in a.lower() for w in
                                 ["risk", "because", "security", "prevent",
                                  "attack", "exploit", "allow", "danger"]),
    "has_concrete_commands": lambda a: ("```" in a or "sudo" in a.lower()
                                        or "$ " in a or "systemctl" in a.lower()
                                        or "sed " in a.lower()),
    "has_verify_step":       lambda a: any(w in a.lower() for w in
                                 ["verify", "check", "confirm", "test",
                                  "ensure", "validate", "grep"]),
    "concise":               lambda a: len(a.split()) < 400,
}

def rubric_score(advice: str) -> dict:
    return {k: fn(advice) for k, fn in RUBRIC_CRITERIA.items()}

def metric_rubric_avg(findings) -> tuple[float, list[dict]]:
    results = []
    for f in findings:
        if f.severity != "high" or not f.llm_advice: continue
        scores = rubric_score(f.llm_advice)
        results.append({
            "title":    f.title[:60],
            "short_id": f.short_id,
            "scores":   scores,
            "total":    sum(scores.values()),
        })
    if not results: return 0.0, []
    return sum(r["total"] for r in results) / len(results), results


# ─────────────────────────────────────────────────────────────
# Metric 4 — Hardening Delta
# ─────────────────────────────────────────────────────────────
def metric_hardening_delta(before_xml: str, after_xml: str) -> dict:
    before    = parse_results(before_xml)
    after     = parse_results(after_xml)
    before_ids = {f.rule_id for f in before}
    after_ids  = {f.rule_id for f in after}
    fixed_ids  = before_ids - after_ids
    regressed  = after_ids  - before_ids

    fixed_by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in before:
        if f.rule_id in fixed_ids:
            fixed_by_sev[f.severity] = fixed_by_sev.get(f.severity, 0) + 1

    pct = round(len(fixed_ids) / len(before) * 100, 1) if before else 0.0
    return {
        "before_total":      len(before),
        "after_total":       len(after),
        "fixed":             len(fixed_ids),
        "regressed":         len(regressed),
        "pct_improvement":   pct,
        "fixed_by_severity": fixed_by_sev,
    }


# ─────────────────────────────────────────────────────────────
# Printer
# ─────────────────────────────────────────────────────────────
def _bar(value: float, width: int = 20) -> str:
    filled = int(value * width)
    return "█" * filled + "░" * (width - filled)

def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"

def print_results(findings, coverage, relevance, rubric_avg,
                  rubric_detail, delta, xml_path, after_xml):
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats = get_stats(findings)

    print()
    print("=" * 60)
    print("  STIG Hardening Agent — Evaluation Report")
    print(f"  {ts}")
    print("=" * 60)
    print(f"\n  Scan : {xml_path}")
    print(f"  Found: {stats['total']} findings  "
          f"({stats['high']} high, {stats['medium']} medium, {stats['low']} low)")

    # Metric 1
    cov_count = sum(1 for f in findings if f.severity == "high" and f.llm_advice)
    print(f"\n  [1] Coverage (HIGH findings analyzed by LLM)")
    print(f"      {cov_count} / {stats['high']}  {_bar(coverage)}  {_pct(coverage)}")
    print(f"      {'PASS' if coverage >= 0.9 else 'NEEDS IMPROVEMENT'}  (target: >= 90%)")

    # Metric 2
    print(f"\n  [2] Relevance (keyword overlap with SCAP fix scripts)")
    print(f"      {_bar(relevance)}  {_pct(relevance)}")
    print(f"      {'PASS' if relevance >= 0.5 else 'NEEDS IMPROVEMENT'}  (target: >= 50%)")

    # Metric 3
    print(f"\n  [3] Response quality rubric (avg across HIGH findings)")
    print(f"      {rubric_avg:.2f} / 4.0  {_bar(rubric_avg / 4)}")
    print(f"      {'PASS' if rubric_avg >= 3.0 else 'NEEDS IMPROVEMENT'}  (target: >= 3.0 / 4.0)")
    if rubric_detail:
        print()
        for r in rubric_detail[:5]:
            checks = "".join("✓" if v else "✗" for v in r["scores"].values())
            print(f"        [{checks}] {r['title']}")
        print(f"        Criteria: {' | '.join(RUBRIC_CRITERIA.keys())}")

    # Metric 4
    if delta:
        print(f"\n  [4] Hardening delta (before vs after remediation)")
        print(f"      Before : {delta['before_total']} failures")
        print(f"      After  : {delta['after_total']} failures")
        print(f"      Fixed  : {delta['fixed']} rules  ({delta['pct_improvement']}% improvement)")
        for sev, count in delta["fixed_by_severity"].items():
            print(f"               {sev.upper():6s}: {count} fixed")
        if delta["regressed"]:
            print(f"      WARNING: {delta['regressed']} new failures after remediation")
        print(f"      {'PASS' if delta['pct_improvement'] >= 30 else 'NEEDS IMPROVEMENT'}"
              f"  (target: >= 30% improvement)")
    else:
        print(f"\n  [4] Hardening delta")
        print(f"      Not measured. Run --remediate, re-scan, then pass --after <xml>")

    # Save JSON
    summary = {
        "timestamp":       ts,
        "xml_path":        xml_path,
        "after_xml":       after_xml or "",
        "stats":           stats,
        "coverage":        round(coverage,   3),
        "relevance":       round(relevance,  3),
        "rubric_avg":      round(rubric_avg, 3),
        "hardening_delta": delta,
    }
    Path("reports").mkdir(exist_ok=True)
    Path("reports/eval_summary.json").write_text(
        json.dumps(summary, indent=2)
    )
    print(f"\n  Summary saved → reports/eval_summary.json")
    print("=" * 60)
    print()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def resolve_xml(args) -> str:
    if args.xml:
        return args.xml
    if args.latest:
        files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
        if not files:
            print("[ERROR] No scan XML files in results/. Run: python main.py --scan")
            sys.exit(1)
        print(f"  Using latest scan: {files[0]}")
        return str(files[0])
    print("[ERROR] Provide --xml <path> or use --latest")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(
        description="Evaluate the STIG hardening agent output",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python evaluate.py --latest
  python evaluate.py --xml results/scan_20240101_120000.xml
  python evaluate.py --latest --after results/scan_after.xml
  python evaluate.py --latest --skip-llm
        """
    )
    ap.add_argument("--xml",      default=None,        help="Path to before-scan XML")
    ap.add_argument("--after",    default=None,        help="Path to after-remediation XML")
    ap.add_argument("--latest",   action="store_true", help="Use most recent scan in results/")
    ap.add_argument("--skip-llm", action="store_true", help="Skip LLM calls, use cached advice only")
    args = ap.parse_args()

    xml_path = resolve_xml(args)

    print()
    print("  Loading findings...")
    findings = parse_results(xml_path)

    if not args.skip_llm:
        print("  Running LLM analysis on HIGH findings...")
        if check_ollama():
            findings = analyze_findings(findings)
        else:
            print("  WARNING: Ollama not reachable — coverage will be 0%.")
            print("           Use --skip-llm to evaluate cached advice only.")
    else:
        print("  Skipping LLM — evaluating cached advice only.")

    coverage             = metric_coverage(findings)
    relevance            = metric_relevance(findings)
    rubric_avg, rubric_d = metric_rubric_avg(findings)
    delta                = metric_hardening_delta(xml_path, args.after) if args.after else None

    print_results(findings, coverage, relevance,
                  rubric_avg, rubric_d, delta,
                  xml_path, args.after)


if __name__ == "__main__":
    main()