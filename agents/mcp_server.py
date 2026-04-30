# # This code may contain AI geneated content
# agent/mcp_server.py
import json, sys
from pathlib import Path
from mcp.server.fastmcp import FastMCP

from agent.scanner    import run_scan, check_target_running
from agent.parser     import parse_results, get_stats, filter_by_severity
from agent.llm_agent  import get_advice, check_ollama
from agent.reporter   import generate_report, generate_html_report
from agent.remediator import run_remediation

mcp = FastMCP(
    name="stig-hardening-agent",
    instructions=(
        "You are a STIG compliance expert. Use these tools to scan a Rocky Linux 9 "
        "system for DISA STIG compliance failures, analyze findings with AI, apply "
        "remediations, and generate reports. Always run check_status first, then "
        "scan_system, list_findings, analyze_finding for each HIGH finding, and "
        "finally generate_report_tool."
    ),
)

@mcp.tool()
def check_status() -> str:
    """Check whether the target container and Ollama are reachable. Call this first."""
    import subprocess, requests, yaml
    results = {}
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "stig-target"],
            capture_output=True, text=True, timeout=5
        )
        results["target_container"] = "running" if r.stdout.strip() == "true" else "stopped"
    except Exception as e:
        results["target_container"] = f"error: {e}"
    try:
        with open("config.yaml") as f: cfg = yaml.safe_load(f)
        url  = cfg["llm"]["ollama_url"].replace("/api/generate", "/api/tags")
        resp = requests.get(url, timeout=5)
        models = [m["name"] for m in resp.json().get("models", [])]
        results["ollama"] = "reachable"
        results["models"] = models
    except Exception as e:
        results["ollama"] = f"unreachable: {e}"
    try:
        r = subprocess.run(
            ["docker", "exec", "stig-target",
             "test", "-f", "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"],
            capture_output=True, timeout=5
        )
        results["scap_content"] = "present" if r.returncode == 0 else "missing"
    except Exception as e:
        results["scap_content"] = f"error: {e}"
    xml_files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
    results["existing_scans"] = [str(f) for f in xml_files[:5]]
    return json.dumps(results, indent=2)

@mcp.tool()
def scan_system(profile: str = "stig") -> str:
    """Run an OpenSCAP STIG scan on the Rocky Linux 9 target container (takes 3-8 min)."""
    import yaml
    profile_map = {
        "stig": "xccdf_org.ssgproject.content_profile_stig",
        "cis":  "xccdf_org.ssgproject.content_profile_cis",
        "ospp": "xccdf_org.ssgproject.content_profile_ospp",
    }
    full_profile = profile_map.get(profile.lower(),
                                   "xccdf_org.ssgproject.content_profile_stig")
    with open("config.yaml") as f: cfg = yaml.safe_load(f)
    original = cfg["scanner"]["profile"]
    cfg["scanner"]["profile"] = full_profile
    with open("config.yaml", "w") as f: yaml.dump(cfg, f)
    try:
        result = run_scan()
    finally:
        cfg["scanner"]["profile"] = original
        with open("config.yaml", "w") as f: yaml.dump(cfg, f)

    findings = parse_results(result["xml"])
    stats    = get_stats(findings)
    return json.dumps({
        "xml_path":  result["xml"],
        "timestamp": result["timestamp"],
        "profile":   profile,
        "summary":   stats,
        "next_step": f"Call list_findings with xml_path='{result['xml']}'"
    }, indent=2)

@mcp.tool()
def list_findings(xml_path: str = "", severity: str = "all", limit: int = 20) -> str:
    """Parse a scan XML result and return a list of failed STIG rules."""
    if not xml_path:
        files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
        if not files: return json.dumps({"error": "No scan results found. Run scan_system first."})
        xml_path = str(files[0])
    findings = parse_results(xml_path)
    stats    = get_stats(findings)
    if severity != "all": findings = filter_by_severity(findings, severity.lower())
    findings = findings[:limit]
    return json.dumps({
        "xml_path": xml_path, "stats": stats,
        "findings": [{"rule_id": f.short_id, "full_rule_id": f.rule_id,
                      "title": f.title, "severity": f.severity,
                      "has_fix": bool(f.fix_script)} for f in findings]
    }, indent=2)

@mcp.tool()
def get_finding_detail(rule_id: str, xml_path: str = "") -> str:
    """Get full details of one specific STIG finding including description and fix script."""
    if not xml_path:
        files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
        if not files: return json.dumps({"error": "No scan results found."})
        xml_path = str(files[0])
    findings = parse_results(xml_path)
    match    = next((f for f in findings if rule_id in f.rule_id or rule_id == f.short_id), None)
    if not match:
        return json.dumps({"error": f"Rule '{rule_id}' not found.", "hint": "Use list_findings."})
    return json.dumps({
        "rule_id": match.rule_id, "short_id": match.short_id,
        "title": match.title, "severity": match.severity,
        "description": match.description, "rationale": match.rationale,
        "fix_script": match.fix_script, "references": match.references,
        "llm_advice": match.llm_advice or "Not yet analyzed. Call analyze_finding.",
    }, indent=2)

@mcp.tool()
def analyze_finding(rule_id: str, xml_path: str = "") -> str:
    """Send a specific STIG finding to Ollama (llama3.2) for AI remediation advice."""
    if not xml_path:
        files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
        if not files: return json.dumps({"error": "No scan results found."})
        xml_path = str(files[0])
    findings = parse_results(xml_path)
    match    = next((f for f in findings if rule_id in f.rule_id or rule_id == f.short_id), None)
    if not match: return json.dumps({"error": f"Rule '{rule_id}' not found."})
    if not check_ollama(): return json.dumps({"error": "Ollama not reachable."})
    advice = get_advice(match)
    return json.dumps({"rule_id": match.short_id, "title": match.title,
                       "severity": match.severity, "advice": advice}, indent=2)

@mcp.tool()
def apply_remediation() -> str:
    """Apply automated STIG remediations on the target container via oscap --remediate."""
    try:
        run_remediation()
        return json.dumps({"status": "success",
                           "message": "Remediations applied. Run scan_system again."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

@mcp.tool()
def generate_report_tool(xml_path: str = "", html: bool = True) -> str:
    """Generate a Markdown (and optionally HTML) report from scan results."""
    if not xml_path:
        files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
        if not files: return json.dumps({"error": "No scan results found."})
        xml_path = str(files[0])
    from datetime import datetime
    findings  = parse_results(xml_path)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path   = f"reports/report_{ts}.md"
    html_path = f"reports/report_{ts}.html"
    generate_report(findings, output_path=md_path, timestamp=ts, xml_path=xml_path)
    result = {"markdown_report": md_path, "findings": get_stats(findings)}
    if html:
        generate_html_report(findings, output_path=html_path, timestamp=ts, xml_path=xml_path)
        result["html_report"] = html_path
    return json.dumps(result, indent=2)

@mcp.tool()
def list_scans() -> str:
    """List all available scan XML result files, sorted newest first."""
    files = sorted(Path("results").glob("scan_*.xml"), reverse=True)
    if not files:
        return json.dumps({"scans": [], "message": "No scans yet. Run scan_system first."})
    scans = []
    for f in files:
        try:
            findings = parse_results(str(f))
            scans.append({"path": str(f), "timestamp": f.stem.replace("scan_", ""),
                          "size_kb": round(f.stat().st_size / 1024, 1),
                          "stats": get_stats(findings)})
        except Exception:
            scans.append({"path": str(f), "error": "Could not parse"})
    return json.dumps({"scans": scans}, indent=2)

if __name__ == "__main__":
    transport = sys.argv[1] if len(sys.argv) > 1 else "sse"
    if transport == "stdio": mcp.run(transport="stdio")
    else: mcp.run(transport="sse", host="0.0.0.0", port=8000)