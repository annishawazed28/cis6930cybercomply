# # This code may contain AI geneated content
# agent/scanner.py
import subprocess, datetime, yaml, os
from pathlib import Path

def _load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

_CFG             = _load_config()
SCAP_CONTENT     = _CFG["scanner"]["scap_content"]
PROFILE          = _CFG["scanner"]["profile"]
TARGET_CONTAINER = os.environ.get("TARGET_CONTAINER",
                   _CFG["docker"].get("target_container", "stig-target"))
SHARED_RESULTS   = "/results"

def check_target_running() -> bool:
    r = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", TARGET_CONTAINER],
        capture_output=True, text=True
    )
    return r.stdout.strip() == "true"

def run_scan(output_dir="results") -> dict:
    if not check_target_running():
        raise RuntimeError(
            f"Container '{TARGET_CONTAINER}' is not running.\n"
            "Run:  docker compose up -d target"
        )
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_name = f"scan_{ts}.xml"
    xml_in_container = f"{SHARED_RESULTS}/{xml_name}"
    xml_local        = f"/results/{xml_name}"

    oscap_cmd = [
        "docker", "exec", TARGET_CONTAINER,
        "oscap", "xccdf", "eval",
        "--profile", PROFILE,
        "--results", xml_in_container,
        SCAP_CONTENT,
    ]
    print(f"[scanner] Running oscap inside '{TARGET_CONTAINER}'...")
    print(f"[scanner] This takes 3-8 minutes...")

    result = subprocess.run(oscap_cmd, capture_output=True, text=True, timeout=600)
    if result.returncode == 1:
        raise RuntimeError(f"oscap error:\n{result.stderr}")

    passes = result.stdout.count("pass")
    fails  = result.stdout.count("fail")
    print(f"[scanner] Done — {passes} passed, {fails} failed")
    print(f"[scanner] Results → {xml_local}")
    return {"xml": xml_local, "timestamp": ts}

if __name__ == "__main__":
    print(f"Checking Docker setup...")
    if check_target_running():
        print(f"  stig-target   RUNNING")
        r = subprocess.run(
            ["docker", "exec", TARGET_CONTAINER, "oscap", "--version"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            print(f"  oscap         OK  ({r.stdout.splitlines()[0]})")
    else:
        print(f"  stig-target   NOT RUNNING — run: docker compose up -d")