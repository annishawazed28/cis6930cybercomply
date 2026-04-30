# AI-Powered STIG Hardening Agent

An intelligent cybersecurity tool that automatically scans a Linux system for DISA STIG compliance failures, uses a local AI model to explain each finding in plain English, generates step-by-step remediation scripts, and tracks security posture across product versions over time.

---

## What It Does

- Scans a Rocky Linux 9 system against the DISA STIG ruleset using OpenSCAP
- Uses a locally hosted LLM (Ollama / llama3.2) to explain every HIGH severity finding and generate copy-paste bash fix commands — no security expertise required
- Applies automated remediations and re-scans to measure improvement
- Stores results in a versioned knowledge base (ChromaDB + SQLite) indexed by product name and version tag
- Exposes all capabilities as an MCP server so users can interact through natural language
- Generates Markdown and HTML reports with findings, AI advice, and ready-to-run fix scripts

---

## Architecture

```
Your machine (Windows host)
├── Ollama (llama3.2)          ← local LLM, no internet required
├── Docker Desktop
│   ├── stig-target            ← Rocky Linux 9 (the system being scanned)
│   ├── stig-agent             ← Python agent (scanner, parser, reporter)
│   └── stig-mcp               ← MCP server on port 8000
└── results/  reports/         ← output files on your Windows disk
    knowledge_base/            ← versioned scan database
```

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Docker Desktop | Latest | [docker.com/products/docker-desktop](https://docker.com/products/docker-desktop) |
| Ollama | Latest | [ollama.com/download/windows](https://ollama.com/download/windows) |
| Git | Any | [git-scm.com](https://git-scm.com) |

---

## Installation


### Create required folders

```powershell
mkdir results, reports, knowledge_base
New-Item agent\__init__.py -ItemType File
```

### Pull the LLM model

Open PowerShell (Ollama must be installed and running in the system tray):

```powershell
ollama pull llama3.2
```

Verify it worked:

```powershell
ollama list
# Should show: llama3.2
```

### Start Docker Desktop

Open Docker Desktop from the Start menu and wait for the whale icon in the system tray to stop animating (~30 seconds).

### Build and start all containers

```powershell
docker compose up --build -d
```

Verify all three containers are running:

```powershell
docker ps -a
# Should show: stig-target, stig-agent, stig-mcp
```

---

## Quick Start

Run the full pipeline in one command:

```powershell
# Usage:
#   python main.py --full                             # scan + LLM + report
#   python main.py --scan     			   # scan only
#   python main.py --scan --llm --report              # scan + LLM + report
#   python main.py --xml results/scan_X.xml --llm     # analyze existing scan
#   python main.py --full --remediate                 # scan → fix → re-scan → report

```

This will:
1. Scan the Rocky Linux 9 target with OpenSCAP (~5-8 minutes)
2. Analyze all HIGH severity findings with Ollama
3. Generate `reports/report_TIMESTAMP.md` and `reports/report_TIMESTAMP.html`

Open the HTML report in your browser:

```powershell
start reports\report_*.html
```


---

## User Guide

### Core Pipeline (`main.py`)

| Command | What it does |
|---------|-------------|
| `python main.py --full` | Full pipeline: scan → LLM → report |
| `python main.py --full --html` | Full pipeline + HTML report |
| `python main.py --full --remediate` | Scan → apply fixes → re-scan → report |
| `python main.py --scan` | Run OpenSCAP scan only |
| `python main.py --latest --llm --report` | Analyze most recent scan |
| `python main.py --xml results/scan_X.xml --llm --report` | Analyze a specific scan |

All commands are run inside the agent container:

```powershell
docker compose run agent python main.py --full --html
```

---

### Knowledge Base (`kb_ingester.py` + `kb_reporter.py`)

Store and retrieve scan results by product name and version tag.

**Store a scan result:**

```powershell
docker compose run agent python agent/kb_ingester.py \
  --xml results/scan_20240101_120000.xml \
  --product "MyApp" \
  --version "v1.0"
```

**Generate a versioned report + fix script:**

```powershell
docker compose run agent python agent/kb_reporter.py \
  --product "MyApp" \
  --version "v1.0"
```

This produces:
- `reports/report_MyApp_v1.0.md` — full security assessment report
- `reports/fix_MyApp_v1.0.sh` — ready-to-run bash remediation script

**Compare two versions:**

```powershell
docker compose run agent python agent/kb_reporter.py \
  --product "MyApp" \
  --version "v2.0" \
  --diff-version "v1.0"
```

Produces `reports/diff_MyApp_v1.0_to_v2.0.md` showing new findings, fixed findings, and persisting findings.

**List all stored versions:**

```powershell
docker compose run agent python agent/kb_reporter.py \
  --product "MyApp" \
  --list-versions
```

**Semantic search across all findings:**

```powershell
docker compose run agent python agent/kb_reporter.py \
  --product "MyApp" \
  --search "SSH root login"
```

---

### AI Agent Chat (`mcp_client.py`)

Instead of running commands manually, talk to the agent in plain English:

```powershell
docker compose run agent python agent/mcp_client.py
```

Example session:

```
You: scan
  [tool] check_status()
  [tool] scan_system()
  [tool] list_findings(severity=high)
  [tool] analyze_finding(rule_id=sshd_disable_root_login)
  ...

Agent: The scan found 14 HIGH severity findings on the Rocky Linux 9 system.
       The most critical issue is that SSH root login is enabled, which allows
       an attacker to directly brute-force the root account over the network...

You: apply the fixes and show me the improvement
  [tool] apply_remediation()
  [tool] scan_system()
  ...

Agent: After remediation, the system went from 198 failures down to 121 —
       a 38.9% improvement. The remaining failures require manual remediation...
```

Built-in shortcuts:

| Type | Does |
|------|------|
| `scan` | Full scan + analysis + report |
| `status` | Check environment health |
| `quit` | Exit |

---

### Evaluation (`evaluate.py`)

Measure how well the agent performed across four metrics.

**Evaluate most recent scan:**

```powershell
docker compose run agent python evaluate.py --latest
```

---

## Project Structure

```
stig-hardening-agent/
├── main.py                  ← CLI orchestrator
├── evaluate.py              ← evaluation metrics
├── config.yaml              ← all settings
├── requirements.txt         ← Python dependencies
├── docker-compose.yml       ← 3-service Docker setup
├── docker/
│   ├── Dockerfile.target    ← Rocky Linux 9 + OpenSCAP
│   └── Dockerfile.agent     ← Python 3.11 + Docker CLI
├── agent/
│   ├── scanner.py           ← runs oscap via docker exec
│   ├── parser.py            ← parses XCCDF XML
│   ├── llm_agent.py         ← calls Ollama for AI advice
│   ├── remediator.py        ← applies oscap --remediate
│   ├── reporter.py          ← generates MD + HTML reports
│   ├── mcp_server.py        ← MCP server (8 tools, port 8000)
│   ├── mcp_client.py        ← Ollama-powered agentic client
│   ├── kb_ingester.py       ← stores scans by product/version
│   └── kb_reporter.py       ← queries KB, generates reports
├── tests/
│   ├── conftest.py
│   ├── test_parser.py
│   ├── test_llm_agent.py
│   ├── test_reporter.py
│   └── test_integration.py
├── results/                 ← scan XML files
├── reports/                 ← generated reports
└── knowledge_base/          ← ChromaDB + SQLite store
```

---