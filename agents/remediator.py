# # This code may contain AI geneated content
# agent/remediator.py
import subprocess, yaml, os
from pathlib import Path

def _load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

_CFG             = _load_config()
SCAP_CONTENT     = _CFG["scanner"]["scap_content"]
PROFILE          = _CFG["scanner"]["profile"]
TARGET_CONTAINER = os.environ.get("TARGET_CONTAINER",
                   _CFG["docker"].get("target_container", "stig-target"))

def run_remediation() -> None:
    """
    Run oscap --remediate inside the target container.
    Automatically applies all fixable STIG rules.

    WARNING: This modifies the target system's configuration.
    Only run against the Docker container or a VM — never your host machine.
    """
    print(f"[remediator] Applying STIG remediations on '{TARGET_CONTAINER}'...")
    print(f"[remediator] Profile: {PROFILE.split('_')[-1]}")

    cmd = [
        "docker", "exec", TARGET_CONTAINER,
        "oscap", "xccdf", "eval",
        "--remediate",
        "--profile", PROFILE,
        "--results", "/results/remediation_results.xml",
        SCAP_CONTENT,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)

    # Exit 2 = ran but some rules still fail (expected — not all are auto-fixable)
    if result.returncode == 1:
        raise RuntimeError(f"Remediation error:\n{result.stderr}")

    fixed = result.stdout.count("fixed")
    print(f"[remediator] Done — {fixed} rules remediated.")
    print(f"[remediator] Re-run --scan to measure improvement.")

if __name__ == "__main__":
    run_remediation()