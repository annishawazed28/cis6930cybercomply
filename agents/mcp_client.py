# # This code may contain AI geneated content
# agent/mcp_client.py
import requests, json, yaml, os

with open("config.yaml") as f:
    _CFG = yaml.safe_load(f)

OLLAMA_BASE  = _CFG["llm"]["ollama_url"].replace("/api/generate", "")
OLLAMA_CHAT  = f"{OLLAMA_BASE}/api/chat"
MODEL        = _CFG["llm"].get("model", "llama3.2")
MCP_URL      = os.environ.get("MCP_URL", "http://localhost:8000")

def mcp_list_tools() -> list[dict]:
    resp = requests.post(
        f"{MCP_URL}/mcp",
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("result", {}).get("tools", [])

def mcp_call_tool(name: str, arguments: dict) -> str:
    resp = requests.post(
        f"{MCP_URL}/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call",
              "params": {"name": name, "arguments": arguments}, "id": 2},
        timeout=600,
    )
    resp.raise_for_status()
    content = resp.json().get("result", {}).get("content", [])
    for block in content:
        if block.get("type") == "text": return block["text"]
    return json.dumps(resp.json().get("result", {}))

def mcp_tools_to_ollama(mcp_tools: list[dict]) -> list[dict]:
    return [{
        "type": "function",
        "function": {
            "name":        t["name"],
            "description": t.get("description", ""),
            "parameters":  t.get("inputSchema", {"type": "object", "properties": {}, "required": []}),
        }
    } for t in mcp_tools]

def ollama_chat(messages: list[dict], tools: list[dict]) -> dict:
    resp = requests.post(OLLAMA_CHAT, json={
        "model": MODEL, "messages": messages, "tools": tools,
        "stream": False, "options": {"temperature": 0.2},
    }, timeout=120)
    resp.raise_for_status()
    return resp.json().get("message", {})

def run_agent_turn(user_input, history, tools, ollama_tools) -> str:
    history.append({"role": "user", "content": user_input})
    while True:
        response   = ollama_chat(history, ollama_tools)
        content    = response.get("content", "")
        tool_calls = response.get("tool_calls", [])

        if not tool_calls:
            history.append({"role": response.get("role", "assistant"), "content": content})
            return content

        history.append({"role": response.get("role", "assistant"),
                        "content": content, "tool_calls": tool_calls})

        for tc in tool_calls:
            fn   = tc.get("function", {})
            name = fn.get("name", "")
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try: args = json.loads(args)
                except: args = {}

            print(f"\n  [tool] {name}({json.dumps(args) if args else ''})")
            try:
                result = mcp_call_tool(name, args)
                try:
                    parsed = json.loads(result)
                    print(f"  [result] {json.dumps(parsed, indent=2)[:400]}...")
                except Exception:
                    print(f"  [result] {result[:300]}")
            except Exception as e:
                result = json.dumps({"error": str(e)})
                print(f"  [error] {e}")

            history.append({"role": "tool", "content": result})

SYSTEM_PROMPT = """You are an expert cybersecurity engineer specializing in DISA STIG 
compliance and Linux system hardening. You have access to tools that let you scan a 
Rocky Linux 9 system, analyze findings, apply remediations, and generate reports.

Workflow: 1) check_status  2) scan_system  3) list_findings(severity=high)
4) analyze_finding for each HIGH rule  5) generate_report_tool

Always summarize tool results in plain English. Focus on HIGH severity findings first."""

SHORTCUTS = {
    "scan":   "Check system status, run a STIG scan, analyze all HIGH severity "
              "findings, and generate a full report with HTML output.",
    "status": "Check whether the target container and Ollama are ready.",
}

def main():
    print()
    print("╔══════════════════════════════════════════════╗")
    print("║   STIG Hardening Agent — Ollama MCP Client  ║")
    print(f"║   Model: {MODEL:<10s}  |  MCP: {MCP_URL:<20s}  ║")
    print("╚══════════════════════════════════════════════╝")
    print()

    print(f"  Connecting to MCP server at {MCP_URL}...")
    try:
        mcp_tools    = mcp_list_tools()
        ollama_tools = mcp_tools_to_ollama(mcp_tools)
        print(f"  Connected — {len(mcp_tools)} tools available:")
        for t in mcp_tools: print(f"    • {t['name']}")
    except Exception as e:
        print(f"  ERROR: Could not connect to MCP server: {e}")
        print("  Make sure it's running:  docker compose up mcp -d")
        return

    print()
    print("  Type your request, or:  'scan' | 'status' | 'quit'")
    print()

    history = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Goodbye!")
            break
        if not user_input: continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("  Goodbye!")
            break

        user_input = SHORTCUTS.get(user_input.lower(), user_input)
        print()
        try:
            response = run_agent_turn(user_input, history, mcp_tools, ollama_tools)
            print(f"\nAgent: {response}\n")
        except requests.exceptions.ConnectionError:
            print("  ERROR: Lost connection to Ollama or MCP server.")
        except Exception as e:
            print(f"  ERROR: {e}")

if __name__ == "__main__":
    main()