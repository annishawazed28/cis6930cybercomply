# This code may contain AI geneated content
# agent/kb_reporter.py
import argparse, json, sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

KB_DIR      = Path("knowledge_base")
CHROMA_DIR  = KB_DIR / "chroma"
SQLITE_PATH = KB_DIR / "index.db"
SEV_ICON    = {"high": "🔴", "medium": "🟡", "low": "🟢"}

@dataclass
class KBFinding:
    rule_id: str; short_id: str; title: str; severity: str
    description: str; rationale: str; fix_script: str
    llm_advice: str; references: list

def _get_db():
    if not SQLITE_PATH.exists():
        raise FileNotFoundError("Knowledge base not found. Run kb_ingester.py first.")
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def _get_chroma():
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    ef     = embedding_functions.DefaultEmbeddingFunction()
    return client.get_or_create_collection(name="stig_findings", embedding_function=ef)

def _row_to_finding(row) -> KBFinding:
    return KBFinding(
        rule_id=row["rule_id"], short_id=row["short_id"], title=row["title"],
        severity=row["severity"], description=row["description"] or "",
        rationale=row["rationale"] or "", fix_script=row["fix_script"] or "",
        llm_advice=row["llm_advice"] or "",
        references=json.loads(row["references"] or "[]"),
    )

def list_versions(product: str) -> list[dict]:
    db   = _get_db()
    rows = db.execute(
        "SELECT version, scan_date, total, high, medium, low FROM scans "
        "WHERE product=? ORDER BY created_at DESC", (product,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

def get_findings(product: str, version: str, severity="all") -> list[KBFinding]:
    db    = _get_db()
    query = "SELECT * FROM findings WHERE product=? AND version=?"
    args  = [product, version]
    if severity != "all": query += " AND severity=?"; args.append(severity)
    query += " ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"
    rows  = db.execute(query, args).fetchall()
    db.close()
    return [_row_to_finding(r) for r in rows]

def semantic_search(product: str, query: str, version="", n=10) -> list[dict]:
    collection = _get_chroma()
    where = {"product": product}
    if version: where = {"$and": [{"product": product}, {"version": version}]}
    results = collection.query(query_texts=[query], n_results=n, where=where)
    return [{"title": m["title"], "severity": m["severity"], "short_id": m["short_id"],
             "version": m["version"], "score": round(1 - results["distances"][0][i], 3)}
            for i, m in enumerate(results["metadatas"][0])]

def diff_versions(product, v_new, v_old) -> dict:
    old_ids      = {f.rule_id for f in get_findings(product, v_old)}
    new_findings = get_findings(product, v_new)
    new_ids      = {f.rule_id for f in new_findings}
    fixed_ids    = old_ids - new_ids
    old_findings = get_findings(product, v_old)
    return {
        "product": product, "old_version": v_old, "new_version": v_new,
        "new":        [f for f in new_findings if f.rule_id not in old_ids],
        "fixed":      [f for f in old_findings if f.rule_id in fixed_ids],
        "persisting": [f for f in new_findings if f.rule_id in (old_ids & new_ids)],
    }

def generate_version_report(product, version, output_dir="reports") -> str:
    findings = get_findings(product, version)
    if not findings: raise ValueError(f"No findings for '{product} {version}'")

    db   = _get_db()
    meta = db.execute("SELECT * FROM scans WHERE product=? AND version=?",
                      (product, version)).fetchone()
    db.close()

    highs = [f for f in findings if f.severity == "high"]
    meds  = [f for f in findings if f.severity == "medium"]
    lows  = [f for f in findings if f.severity == "low"]
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# Security Vulnerability Assessment Report", "",
        "| Field | Value |", "|-------|-------|",
        f"| **Product** | {product} |",
        f"| **Version** | {version} |",
        f"| **Scan Date** | {meta['scan_date'] if meta else 'N/A'} |",
        f"| **Report Generated** | {ts} |",
        f"| **Standard** | DISA STIG for Red Hat Enterprise Linux 9 |",
        "", "---", "",
        "## Executive Summary", "",
        "| Severity | Count |", "|----------|-------|",
        f"| 🔴 High   | {len(highs)} |",
        f"| 🟡 Medium | {len(meds)} |",
        f"| 🟢 Low    | {len(lows)} |",
        f"| **Total** | **{len(findings)}** |", "",
    ]
    if len(highs) > 10:
        lines.append(f"> **Critical:** {len(highs)} HIGH findings. Immediate remediation required.")
    elif len(highs) > 0:
        lines.append(f"> **Elevated Risk:** {len(highs)} HIGH findings require prompt attention.")
    else:
        lines.append("> **Low Risk:** No HIGH severity findings detected.")
    lines += ["", "---", ""]

    for sev, subset, label in [("high", highs, "HIGH"), ("medium", meds, "MEDIUM"), ("low", lows, "LOW")]:
        if not subset: continue
        lines += [f"## {SEV_ICON.get(sev,'')} {label} Severity Findings", ""]
        for i, f in enumerate(subset, 1):
            lines += [f"### {i}. {f.title}", "",
                      "| Field | Value |", "|-------|-------|",
                      f"| **Rule ID** | `{f.short_id}` |",
                      f"| **Severity** | {sev.upper()} |"]
            if f.references: lines.append(f"| **References** | {', '.join(f.references)} |")
            lines.append("")
            if f.description: lines += ["**Description:**", "", f.description[:600], ""]
            if f.llm_advice:  lines += ["**AI Remediation Advice:**", "", f.llm_advice, ""]
            elif f.fix_script: lines += ["**SCAP Fix Script:**", "", "```bash", f.fix_script.strip(), "```", ""]
            lines += ["---", ""]

    lines += ["## Appendix — All Failed Rules", "",
              "| # | Rule ID | Severity |", "|---|---------|----------|"]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | `{f.short_id}` | {f.severity.upper()} |")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    sv = version.replace("/", "-").replace(" ", "_")
    sp = product.replace(" ", "_")
    out = f"{output_dir}/report_{sp}_{sv}.md"
    Path(out).write_text("\n".join(lines), encoding="utf-8")
    print(f"[kb_reporter] Report → {out}")
    return out

def generate_remediation_script(product, version, output_dir="reports") -> str:
    findings = get_findings(product, version)
    fixable  = [f for f in findings if f.fix_script.strip()]
    lines = [
        "#!/usr/bin/env bash",
        f"# Remediation script for: {product} {version}",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Fixable rules: {len(fixable)} / {len(findings)}",
        "# WARNING: Review each fix before running on production.",
        "", "set -euo pipefail",
        f'echo "Starting STIG remediation for {product} {version}..."', "",
    ]
    for sev in ("high", "medium", "low"):
        subset = [f for f in fixable if f.severity == sev]
        if not subset: continue
        lines += [f"# {'='*50}", f"# {sev.upper()} SEVERITY FIXES ({len(subset)})", f"# {'='*50}", ""]
        for f in subset:
            lines += [f"# {f.short_id}: {f.title}",
                      f'echo "Applying: {f.title[:60]}"',
                      f.fix_script.strip(), ""]
    lines += ['echo ""', 'echo "Done. Re-run oscap scan to verify."']

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    sv  = version.replace("/", "-").replace(" ", "_")
    sp  = product.replace(" ", "_")
    out = f"{output_dir}/fix_{sp}_{sv}.sh"
    Path(out).write_text("\n".join(lines), encoding="utf-8")
    print(f"[kb_reporter] Script → {out}  ({len(fixable)} fixes)")
    return out

def generate_diff_report(product, v_new, v_old, output_dir="reports") -> str:
    d  = diff_versions(product, v_new, v_old)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Version Diff Report — {product}", "",
        f"**Comparing:** {v_old} → {v_new}  |  **Generated:** {ts}", "",
        "| Category | Count |", "|----------|-------|",
        f"| New findings (regressions) | {len(d['new'])} |",
        f"| Fixed findings | {len(d['fixed'])} |",
        f"| Persisting findings | {len(d['persisting'])} |",
        "", "---", "",
    ]
    if d["new"]:
        lines += [f"## New Findings in {v_new}", ""]
        for f in d["new"]:
            lines.append(f"- {SEV_ICON.get(f.severity,'')} **{f.title}** (`{f.short_id}`)")
        lines.append("")
    if d["fixed"]:
        lines += [f"## Fixed Since {v_old}", ""]
        for f in d["fixed"]:
            lines.append(f"- ✅ **{f.title}** (`{f.short_id}`)")
        lines.append("")
    if d["persisting"]:
        lines += [f"## Still Failing in {v_new}", ""]
        for f in d["persisting"][:20]:
            lines.append(f"- {SEV_ICON.get(f.severity,'')} **{f.title}** (`{f.short_id}`)")
        if len(d["persisting"]) > 20:
            lines.append(f"- ... and {len(d['persisting'])-20} more")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    sv  = v_new.replace("/", "-").replace(" ", "_")
    sv2 = v_old.replace("/", "-").replace(" ", "_")
    sp  = product.replace(" ", "_")
    out = f"{output_dir}/diff_{sp}_{sv2}_to_{sv}.md"
    Path(out).write_text("\n".join(lines), encoding="utf-8")
    print(f"[kb_reporter] Diff → {out}")
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--product",       required=True)
    ap.add_argument("--version",       default="")
    ap.add_argument("--list-versions", action="store_true")
    ap.add_argument("--diff-version",  default="")
    ap.add_argument("--search",        default="")
    ap.add_argument("--output-dir",    default="reports")
    args = ap.parse_args()

    if args.list_versions:
        versions = list_versions(args.product)
        if not versions: print(f"No versions found for '{args.product}'")
        else:
            print(f"\nVersions for '{args.product}':")
            for v in versions:
                print(f"  {v['version']:12s}  {v['scan_date']}  "
                      f"({v['high']} high, {v['medium']} med, {v['low']} low)")
        raise SystemExit

    if args.search:
        hits = semantic_search(args.product, args.search, args.version)
        print(f"\nSearch: '{args.search}'")
        for h in hits:
            print(f"  [{h['score']:.2f}] [{h['severity'].upper():6s}] "
                  f"{h['title'][:60]}  ({h['version']})")
        raise SystemExit

    if not args.version:
        ap.error("--version required unless using --list-versions or --search")

    generate_version_report(args.product, args.version, args.output_dir)
    generate_remediation_script(args.product, args.version, args.output_dir)
    if args.diff_version:
        generate_diff_report(args.product, args.version, args.diff_version, args.output_dir)