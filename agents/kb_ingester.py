# This code may contain AI geneated content
# agent/kb_ingester.py
import argparse, json, sqlite3, hashlib
from datetime import datetime
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

from agent.parser    import parse_results, get_stats
from agent.llm_agent import analyze_findings, check_ollama

KB_DIR      = Path("knowledge_base")
CHROMA_DIR  = KB_DIR / "chroma"
SQLITE_PATH = KB_DIR / "index.db"
KB_DIR.mkdir(parents=True, exist_ok=True)

def _get_chroma():
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    ef     = embedding_functions.DefaultEmbeddingFunction()
    return client.get_or_create_collection(
        name="stig_findings", embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

def _get_db():
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, product TEXT NOT NULL, version TEXT NOT NULL,
            scan_date TEXT NOT NULL, xml_path TEXT NOT NULL,
            total INTEGER, high INTEGER, medium INTEGER, low INTEGER,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL,
            product TEXT NOT NULL, version TEXT NOT NULL,
            rule_id TEXT NOT NULL, short_id TEXT NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL,
            description TEXT, rationale TEXT, fix_script TEXT,
            llm_advice TEXT, references TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    conn.commit()
    return conn

def _scan_id(product, version, scan_date):
    return hashlib.sha256(f"{product}:{version}:{scan_date}".encode()).hexdigest()[:16]

def ingest(xml_path: str, product: str, version: str, run_llm: bool = True) -> str:
    print(f"[kb] Ingesting  product='{product}'  version='{version}'")
    print(f"[kb] XML: {xml_path}")

    findings  = parse_results(xml_path)
    stats     = get_stats(findings)
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_id   = _scan_id(product, version, scan_date)

    if run_llm and check_ollama():
        print(f"[kb] Running LLM on {stats['high']} HIGH findings...")
        findings = analyze_findings(findings)
    else:
        print("[kb] Skipping LLM (Ollama not available or --no-llm set)")

    # SQLite
    db = _get_db()
    db.execute(
        "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)",
        (scan_id, product, version, scan_date, xml_path,
         stats["total"], stats["high"], stats["medium"], stats["low"],
         datetime.now().isoformat())
    )
    for f in findings:
        fid = hashlib.sha256(f"{scan_id}:{f.rule_id}".encode()).hexdigest()[:20]
        db.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, scan_id, product, version, f.rule_id, f.short_id,
             f.title, f.severity, f.description, f.rationale,
             f.fix_script, f.llm_advice, json.dumps(f.references))
        )
    db.commit()
    db.close()

    # ChromaDB
    collection = _get_chroma()
    docs, ids, metas = [], [], []
    for f in findings:
        fid = hashlib.sha256(f"{scan_id}:{f.rule_id}".encode()).hexdigest()[:20]
        docs.append(
            f"Title: {f.title}\n"
            f"Description: {f.description[:500]}\n"
            f"Advice: {f.llm_advice[:400] if f.llm_advice else ''}"
        )
        ids.append(fid)
        metas.append({
            "product": product, "version": version, "scan_id": scan_id,
            "rule_id": f.rule_id, "short_id": f.short_id,
            "title": f.title[:100], "severity": f.severity,
            "has_fix": str(bool(f.fix_script)),
        })
    if docs:
        collection.upsert(documents=docs, ids=ids, metadatas=metas)

    print(f"[kb] Stored {len(findings)} findings under '{product} {version}' (id: {scan_id})")
    return scan_id

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml",     required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--no-llm",  action="store_true")
    args = ap.parse_args()
    ingest(args.xml, args.product, args.version, run_llm=not args.no_llm)