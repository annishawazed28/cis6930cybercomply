# # This code may contain AI geneated content
# agent/reporter.py
from pathlib import Path
from datetime import datetime
from agent.parser import Finding, get_stats

SEV_ICON  = {"high": "🔴", "medium": "🟡", "low": "🟢", "unknown": "⚪"}
SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "unknown": "UNKNOWN"}

def _header(timestamp: str) -> str:
    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (f"# STIG Hardening Report\n"
            f"**Generated:** {ts}\n"
            f"**Standard:** DISA STIG for Red Hat Enterprise Linux 9\n"
            f"**Tool:** OpenSCAP + AI Agent (llama3.2 via Ollama)\n\n---\n")

def _executive_summary(findings, stats) -> str:
    ai_covered = stats["with_llm_advice"]
    ai_pct     = int(ai_covered / stats["high"] * 100) if stats["high"] else 0
    lines = [
        "## Executive Summary\n",
        "| Severity | Failed Rules |",
        "|----------|-------------|",
        f"| {SEV_ICON['high']} High    | {stats['high']} |",
        f"| {SEV_ICON['medium']} Medium  | {stats['medium']} |",
        f"| {SEV_ICON['low']} Low     | {stats['low']} |",
        f"| **Total**  | **{stats['total']}** |",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Rules with AI remediation advice | {ai_covered} / {stats['high']} HIGH ({ai_pct}%) |",
        f"| Rules with SCAP fix script       | {stats['with_fix_script']} / {stats['total']} |",
        "",
    ]
    if stats["high"] > 20:   risk = "**Critical posture** — large number of HIGH findings, not production-ready."
    elif stats["high"] > 5:  risk = "**Elevated risk** — several HIGH findings require immediate attention."
    elif stats["high"] > 0:  risk = "**Moderate risk** — a small number of HIGH findings detected."
    else:                    risk = "**Low risk** — no HIGH severity findings detected."
    lines += [f"> {risk}", "", "---", ""]
    return "\n".join(lines)

def _finding_block(f: Finding, index: int) -> str:
    icon  = SEV_ICON.get(f.severity, "⚪")
    label = SEV_LABEL.get(f.severity, "UNKNOWN")
    lines = [
        f"### {icon} {index}. {f.title}", "",
        f"| Field | Value |", f"|-------|-------|",
        f"| **Rule ID** | `{f.short_id}` |  |  **Severity** | {label} |",
    ]
    if f.references:
        lines.append(f"| **References** | {', '.join(f.references)} |")
    lines.append("")
    if f.description:
        lines += ["**What this rule checks:**", "", f"{f.description[:500]}", ""]
    if f.rationale:
        lines += ["**Why it matters:**", "", f"{f.rationale}", ""]
    if f.llm_advice:
        lines += ["**AI Remediation Advice:**", "", f"{f.llm_advice}", ""]
    elif f.fix_script:
        lines += ["**SCAP Fix Script:**", "", "```bash", f.fix_script.strip(), "```", ""]
    else:
        lines += ["> No automated fix available. Manual remediation required.", ""]
    lines += ["---", ""]
    return "\n".join(lines)

def _findings_section(findings, severity, start_index) -> tuple[str, int]:
    subset = [f for f in findings if f.severity == severity]
    if not subset: return "", start_index
    icon  = SEV_ICON[severity]
    label = SEV_LABEL[severity]
    lines = [f"## {icon} {label} Severity Findings\n"]
    idx   = start_index
    for f in subset:
        lines.append(_finding_block(f, idx))
        idx += 1
    return "\n".join(lines), idx

def _appendix(findings, xml_path="") -> str:
    lines = [
        "## Appendix\n",
        "### All Failed Rule IDs\n",
        "| # | Rule ID | Severity |",
        "|---|---------|----------|",
    ]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | `{f.short_id}` | {SEV_LABEL.get(f.severity,'?')} |")
    lines += [""]
    if xml_path:
        lines += ["### Raw Scan Data", "", f"XML result: `{xml_path}`", ""]
    return "\n".join(lines)

def generate_report(findings, output_path="reports/report.md",
                    timestamp="", xml_path="") -> str:
    Path("reports").mkdir(parents=True, exist_ok=True)
    stats    = get_stats(findings)
    sections = [_header(timestamp), _executive_summary(findings, stats)]

    high_md, next_i = _findings_section(findings, "high",   1)
    med_md,  next_i = _findings_section(findings, "medium", next_i)
    low_md,  _      = _findings_section(findings, "low",    next_i)

    if high_md: sections.append(high_md)
    if med_md:  sections.append(med_md)
    if low_md:  sections.append(low_md)
    sections.append(_appendix(findings, xml_path))

    report = "\n".join(sections)
    Path(output_path).write_text(report, encoding="utf-8")
    print(f"[reporter] Report written → {output_path}")
    print(f"[reporter] {stats['total']} findings | {stats['high']} high | "
          f"{stats['with_llm_advice']} with AI advice")
    return output_path

def generate_html_report(findings, output_path="reports/report.html",
                         timestamp="", xml_path="") -> str:
    try:
        import markdown as md_lib
    except ImportError:
        print("[reporter] 'markdown' package not installed — skipping HTML export")
        print("[reporter] Run: pip install markdown")
        return ""

    md_path = output_path.replace(".html", "_raw.md")
    generate_report(findings, md_path, timestamp, xml_path)
    md_text = Path(md_path).read_text(encoding="utf-8")
    body    = md_lib.markdown(md_text, extensions=["tables", "fenced_code"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>STIG Hardening Report</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; max-width: 960px;
             margin: 40px auto; padding: 0 24px; color: #1a1a1a; }}
    h1   {{ border-bottom: 2px solid #e53e3e; padding-bottom: 8px; }}
    h2   {{ border-bottom: 1px solid #ddd; padding-bottom: 4px; margin-top: 2em; }}
    table{{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
    th,td{{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
    th   {{ background: #f5f5f5; font-weight: 600; }}
    code {{ background: #f5f5f5; padding: 2px 5px; border-radius: 3px; font-size: .9em; }}
    pre  {{ background: #1e1e1e; color: #d4d4d4; padding: 16px;
             border-radius: 6px; overflow-x: auto; }}
    pre code {{ background: none; color: inherit; }}
    blockquote {{ border-left: 4px solid #e53e3e; margin: 0;
                   padding: 8px 16px; background: #fff5f5; }}
    hr   {{ border: none; border-top: 1px solid #eee; margin: 2em 0; }}
  </style>
</head>
<body>{body}</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[reporter] HTML report → {output_path}")
    return output_path