# This may contain AI generated code
# tests/test_integration.py
# Live tests that require the stig-target container to be running.
#
# Run with:
#   docker compose run agent pytest tests/test_integration.py -v -m integration
#
# Skip in CI or when container is not running:
#   pytest tests/ -v -m "not integration"

import pytest
import subprocess
import tempfile
from pathlib import Path

pytestmark = pytest.mark.integration


# ── Helpers ───────────────────────────────────────────────────
def is_target_running() -> bool:
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "stig-target"],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip() == "true"
    except Exception:
        return False

def is_ollama_running() -> bool:
    try:
        import requests
        import yaml
        with open("config.yaml") as f:
            cfg = yaml.safe_load(f)
        url  = cfg["llm"]["ollama_url"].replace("/api/generate", "/api/tags")
        resp = requests.get(url, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False

def run_live_scan(tmp_dir: str) -> str:
    """Run an actual oscap scan inside the target container."""
    xml_out = f"{tmp_dir}/integration_scan.xml"
    cmd = [
        "docker", "exec", "stig-target",
        "oscap", "xccdf", "eval",
        "--profile", "xccdf_org.ssgproject.content_profile_stig",
        "--results", "/tmp/integration_scan.xml",
        "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    assert result.returncode in (0, 2), \
        f"oscap failed with code {result.returncode}:\n{result.stderr}"

    # Copy XML out of container
    subprocess.run(
        ["docker", "cp", "stig-target:/tmp/integration_scan.xml", xml_out],
        check=True
    )
    return xml_out


# ── Fixtures ──────────────────────────────────────────────────
@pytest.fixture(scope="module")
def live_xml(tmp_path_factory):
    if not is_target_running():
        pytest.skip("stig-target container not running")
    tmp_dir = str(tmp_path_factory.mktemp("integration"))
    return run_live_scan(tmp_dir)

@pytest.fixture(scope="module")
def live_findings(live_xml):
    from agent.parser import parse_results
    return parse_results(live_xml)


# ── Scanner integration ───────────────────────────────────────
class TestScannerIntegration:

    def test_target_container_is_running(self):
        assert is_target_running(), "stig-target container must be running"

    def test_oscap_installed_in_target(self):
        r = subprocess.run(
            ["docker", "exec", "stig-target", "oscap", "--version"],
            capture_output=True, text=True, timeout=10
        )
        assert r.returncode == 0
        assert "OpenSCAP" in r.stdout

    def test_scap_content_exists_in_target(self):
        r = subprocess.run(
            ["docker", "exec", "stig-target",
             "test", "-f", "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"],
            capture_output=True, timeout=10
        )
        assert r.returncode == 0, "SCAP content file missing in target container"

    def test_live_scan_produces_xml(self, live_xml):
        assert Path(live_xml).exists()
        assert Path(live_xml).stat().st_size > 1000

    def test_live_scan_xml_is_valid(self, live_xml):
        from lxml import etree
        tree = etree.parse(live_xml)
        assert tree.getroot() is not None


# ── Parser integration ────────────────────────────────────────
class TestParserIntegration:

    def test_live_scan_has_findings(self, live_findings):
        assert len(live_findings) > 0, \
            "A fresh Rocky 9 container should always have STIG failures"

    def test_live_scan_has_high_severity(self, live_findings):
        high = [f for f in live_findings if f.severity == "high"]
        assert len(high) > 0, "Expected at least one HIGH severity finding"

    def test_live_findings_have_titles(self, live_findings):
        assert all(f.title for f in live_findings)

    def test_live_findings_have_rule_ids(self, live_findings):
        assert all(f.rule_id for f in live_findings)

    def test_known_misconfiguration_detected(self, live_findings):
        # The Dockerfile.target deliberately sets PermitRootLogin yes
        ssh_rule = next(
            (f for f in live_findings if "sshd" in f.rule_id.lower() and
             "root" in f.rule_id.lower()), None
        )
        assert ssh_rule is not None, \
            "SSH root login finding should be present (intentional misconfiguration)"
        assert ssh_rule.severity == "high"

    def test_findings_sorted_by_severity(self, live_findings):
        order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
        for i in range(len(live_findings) - 1):
            assert order.get(live_findings[i].severity, 3) <= \
                   order.get(live_findings[i+1].severity, 3)


# ── Reporter integration ──────────────────────────────────────
class TestReporterIntegration:

    def test_report_generated_from_live_scan(self, live_findings, tmp_path):
        from agent.reporter import generate_report
        out     = str(tmp_path / "live_report.md")
        result  = generate_report(live_findings, output_path=out)
        assert Path(result).exists()
        content = Path(result).read_text()
        assert "STIG Hardening Report" in content
        assert len(live_findings) > 0

    def test_report_contains_high_findings(self, live_findings, tmp_path):
        from agent.reporter import generate_report
        out     = str(tmp_path / "live_report2.md")
        generate_report(live_findings, output_path=out)
        content = Path(out).read_text()
        assert "HIGH" in content


# ── LLM integration (optional — skipped if Ollama not running) ─
class TestLLMIntegration:

    def test_ollama_reachable(self):
        if not is_ollama_running():
            pytest.skip("Ollama not running on host")
        from agent.llm_agent import check_ollama
        assert check_ollama() is True

    def test_get_advice_returns_non_empty(self, live_findings):
        if not is_ollama_running():
            pytest.skip("Ollama not running on host")
        from agent.llm_agent import get_advice
        high = next((f for f in live_findings if f.severity == "high"), None)
        if not high:
            pytest.skip("No HIGH findings in live scan")
        advice = get_advice(high)
        assert isinstance(advice, str)
        assert len(advice) > 50

    def test_advice_contains_bash_commands(self, live_findings):
        if not is_ollama_running():
            pytest.skip("Ollama not running on host")
        from agent.llm_agent import get_advice
        high = next((f for f in live_findings if f.severity == "high"
                     and f.fix_script), None)
        if not high:
            pytest.skip("No HIGH findings with fix scripts")
        advice = get_advice(high)
        has_bash = "```" in advice or "sudo" in advice.lower() or "$ " in advice
        assert has_bash, "LLM advice should contain bash commands"
