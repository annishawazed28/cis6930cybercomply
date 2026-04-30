# # This code may contain AI geneated content
#  agent/llm_agent.py
import requests, time, yaml, os
from agent.parser import Finding

def _load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

_CFG       = _load_config()
OLLAMA_URL = os.environ.get("OLLAMA_URL",
             _CFG["llm"].get("ollama_url", "http://localhost:11434/api/generate"))
MODEL      = _CFG["llm"].get("model", "llama3.2")
TIMEOUT    = _CFG["llm"].get("timeout_seconds", 120)
MAX_HIGH   = _CFG["llm"].get("max_high_findings", 10)

SYSTEM_PROMPT = """You are a senior cybersecurity engineer specializing in DISA STIG 
compliance and Linux system hardening. You give clear, concise, actionable advice.
Always include exact bash commands. Be direct and practical."""

def build_prompt(f: Finding) -> str:
    fix_section = (
        f"SCAP Auto-Fix Script:\n{f.fix_script.strip()}"
        if f.fix_script else "No automated fix script provided."
    )
    rationale_section = f"Rationale: {f.rationale.strip()}" if f.rationale else ""
    refs_section = f"References: {', '.join(f.references)}" if f.references else ""

    return f"""A DISA STIG compliance scan found the following FAILED rule on a Rocky Linux 9 system.

=== FINDING ===
Rule ID:     {f.rule_id}
Title:       {f.title}
Severity:    {f.severity.upper()}
Description: {f.description[:800] if f.description else "Not provided."}
{rationale_section}
{refs_section}

{fix_section}

=== YOUR TASK ===
Respond with EXACTLY these four sections:

1. PLAIN ENGLISH
   Explain in 2-3 sentences what this rule checks and what misconfiguration was found.

2. SECURITY RISK
   What could an attacker do if this is left unremediated? Be specific.

3. REMEDIATION STEPS
   Provide numbered, copy-paste-ready bash commands to fix this on Rocky Linux 9.
   Include any config file edits, service restarts, or sysctl changes needed.

4. VERIFICATION
   Provide the exact command(s) to confirm the fix was applied successfully.

Keep the total response under 400 words. Use bash code blocks for all commands."""

def get_advice(finding: Finding, retries=3) -> str:
    payload = {
        "model":   MODEL,
        "prompt":  build_prompt(finding),
        "system":  SYSTEM_PROMPT,
        "stream":  False,
        "options": {"temperature": 0.2, "num_predict": 600},
    }
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            advice = resp.json().get("response", "").strip()
            if advice: return advice
            last_error = "Empty response from model"
        except requests.exceptions.ConnectionError:
            last_error = (f"Cannot connect to Ollama at {OLLAMA_URL}.\n"
                          "Make sure Ollama is running on your host machine.")
            break
        except requests.exceptions.Timeout:
            last_error = f"Ollama timed out (attempt {attempt}/{retries})"
            if attempt < retries:
                print(f"  [llm] Timeout — retrying ({attempt}/{retries})...")
                time.sleep(3)
        except Exception as e:
            last_error = str(e)
            if attempt < retries: time.sleep(2)

    print(f"  [llm] Warning: could not get advice for '{finding.title[:50]}': {last_error}")
    fallback = "AI analysis unavailable for this finding.\n\n**Manual review required.** "
    if finding.fix_script:
        fallback += "The SCAP fix script is available above — apply it and verify with the STIG guidance."
    else:
        fallback += f"Refer to the DISA STIG documentation for rule `{finding.short_id}`."
    return fallback

def analyze_findings(findings: list[Finding], max_high=MAX_HIGH) -> list[Finding]:
    high   = [f for f in findings if f.severity == "high"][:max_high]
    others = [f for f in findings if f.severity != "high"]

    if not high:
        print("[llm] No HIGH severity findings to analyze.")
        return findings

    print(f"[llm] Analyzing {len(high)} HIGH findings with {MODEL}...")
    print(f"[llm] Endpoint: {OLLAMA_URL}")

    for i, f in enumerate(high, 1):
        label = f.title[:55] + ("..." if len(f.title) > 55 else "")
        print(f"  [{i}/{len(high)}] {label}")
        f.llm_advice = get_advice(f)
        if i < len(high): time.sleep(1)

    success = sum(1 for f in high if "unavailable" not in f.llm_advice)
    print(f"\n[llm] Done — {success}/{len(high)} findings successfully analyzed.")
    return high + others

def check_ollama() -> bool:
    try:
        tags_url = OLLAMA_URL.replace("/api/generate", "/api/tags")
        resp = requests.get(tags_url, timeout=5)
        resp.raise_for_status()
        models     = [m["name"] for m in resp.json().get("models", [])]
        model_base = MODEL.split(":")[0]
        available  = any(model_base in m for m in models)
        if not available:
            print(f"[llm] Warning: '{MODEL}' not found. Run: ollama pull {MODEL}")
        return True
    except Exception as e:
        print(f"[llm] Ollama not reachable at {OLLAMA_URL}: {e}")
        return False