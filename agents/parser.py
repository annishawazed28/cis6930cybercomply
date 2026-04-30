# # This code may contain AI geneated content
# agent/parser.py
from dataclasses import dataclass, field
from pathlib import Path
from lxml import etree

NS = {
    "xccdf":   "http://checklists.nist.gov/xccdf/1.2",
    "xccdf11": "http://checklists.nist.gov/xccdf/1.1",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}

@dataclass
class Finding:
    rule_id:     str
    title:       str
    severity:    str
    result:      str
    description: str = ""
    fix_script:  str = ""
    rationale:   str = ""
    references:  list = field(default_factory=list)
    llm_advice:  str = ""

    @property
    def severity_label(self): return self.severity.upper()

    @property
    def short_id(self):
        parts = self.rule_id.split("content_rule_")
        return parts[-1] if len(parts) > 1 else self.rule_id

def _find(el, tag, ns_key="xccdf"):
    r = el.find(f"{ns_key}:{tag}", NS)
    return r if r is not None else el.find(f"xccdf11:{tag}", NS)

def _findall(el, tag, ns_key="xccdf"):
    r = el.findall(f"{ns_key}:{tag}", NS)
    return r if r else el.findall(f"xccdf11:{tag}", NS)

def _text(el) -> str:
    if el is None: return ""
    inner = etree.tostring(el, method="text", encoding="unicode")
    return " ".join(inner.split())

def _extract_references(rule_el) -> list[str]:
    refs = []
    for ident in _findall(rule_el, "ident"):
        system = ident.get("system", "")
        text   = (ident.text or "").strip()
        if text:
            if "cce"  in system.lower(): refs.append(f"CCE: {text}")
            elif "nist" in system.lower(): refs.append(f"NIST: {text}")
            else: refs.append(text)
    return refs[:5]

def parse_results(xml_path: str) -> list[Finding]:
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"Scan result not found: {xml_path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Scan result file is empty: {xml_path}")

    tree = etree.parse(str(path))
    root = tree.getroot()

    rule_defs = {}
    for rule_el in root.iter("{http://checklists.nist.gov/xccdf/1.2}Rule",
                              "{http://checklists.nist.gov/xccdf/1.1}Rule"):
        rid = rule_el.get("id")
        if rid: rule_defs[rid] = rule_el

    findings, seen = [], set()
    for rr in root.iter(
        "{http://checklists.nist.gov/xccdf/1.2}rule-result",
        "{http://checklists.nist.gov/xccdf/1.1}rule-result"
    ):
        result_el = (rr.find("{http://checklists.nist.gov/xccdf/1.2}result") or
                     rr.find("{http://checklists.nist.gov/xccdf/1.1}result"))
        if result_el is None or result_el.text is None: continue
        if result_el.text.strip().lower() != "fail": continue

        rule_id  = rr.get("idref", "").strip()
        severity = rr.get("severity", "unknown").strip().lower()
        if rule_id in seen: continue
        seen.add(rule_id)

        title = rule_id
        desc = fix = rat = ""
        refs = []
        rule_el = rule_defs.get(rule_id)
        if rule_el is not None:
            sev_attr = rule_el.get("severity")
            if sev_attr: severity = sev_attr.strip().lower()
            title = _text(_find(rule_el, "title")) or rule_id
            desc  = _text(_find(rule_el, "description"))[:1200]
            rat   = _text(_find(rule_el, "rationale"))[:600]
            fix_el = rule_el.find("xccdf:fix[@system='urn:xccdf:fix:script:sh']", NS)
            if fix_el is None: fix_el = _find(rule_el, "fix")
            fix = _text(fix_el)[:800] if fix_el is not None else ""
            refs = _extract_references(rule_el)

        findings.append(Finding(rule_id, title, severity, "fail",
                                desc, fix, rat, refs))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
    print(f"[parser] {len(findings)} failed rules "
          f"({sum(1 for f in findings if f.severity=='high')} high, "
          f"{sum(1 for f in findings if f.severity=='medium')} medium, "
          f"{sum(1 for f in findings if f.severity=='low')} low)")
    return findings

def filter_by_severity(findings, severity): return [f for f in findings if f.severity == severity]

def get_stats(findings) -> dict:
    return {
        "total":           len(findings),
        "high":            sum(1 for f in findings if f.severity == "high"),
        "medium":          sum(1 for f in findings if f.severity == "medium"),
        "low":             sum(1 for f in findings if f.severity == "low"),
        "with_llm_advice": sum(1 for f in findings if f.llm_advice),
        "with_fix_script": sum(1 for f in findings if f.fix_script),
    }