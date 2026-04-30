# This may contain AI generated code
# tests/test_llm_agent.py
import pytest
from unittest.mock import patch, MagicMock
from agent.llm_agent import get_advice, analyze_findings, build_prompt, check_ollama


# ── Helpers ───────────────────────────────────────────────────
def _mock_ok(text="Apply the fix using sudo."):
    m = MagicMock()
    m.json.return_value = {"response": text}
    m.raise_for_status  = MagicMock()
    return m

def _mock_fail(exc=Exception("timeout")):
    return MagicMock(side_effect=exc)


# ── build_prompt ──────────────────────────────────────────────
class TestBuildPrompt:

    def test_contains_rule_id(self, sample_findings):
        prompt = build_prompt(sample_findings[0])
        assert sample_findings[0].rule_id in prompt

    def test_contains_title(self, sample_findings):
        prompt = build_prompt(sample_findings[0])
        assert sample_findings[0].title in prompt

    def test_contains_severity(self, sample_findings):
        prompt = build_prompt(sample_findings[0])
        assert "HIGH" in prompt

    def test_contains_description(self, sample_findings):
        prompt = build_prompt(sample_findings[0])
        assert sample_findings[0].description[:50] in prompt

    def test_contains_fix_script(self, sample_findings):
        prompt = build_prompt(sample_findings[0])
        assert sample_findings[0].fix_script[:30] in prompt

    def test_contains_four_sections(self, sample_findings):
        prompt = build_prompt(sample_findings[0])
        assert "PLAIN ENGLISH"      in prompt
        assert "SECURITY RISK"      in prompt
        assert "REMEDIATION STEPS"  in prompt
        assert "VERIFICATION"       in prompt

    def test_no_fix_script_handled(self, sample_findings):
        f = sample_findings[0]
        f.fix_script = ""
        prompt = build_prompt(f)
        assert "No automated fix script" in prompt


# ── get_advice ────────────────────────────────────────────────
class TestGetAdvice:

    def test_returns_string(self, sample_findings):
        with patch("agent.llm_agent.requests.post", return_value=_mock_ok()):
            advice = get_advice(sample_findings[0])
        assert isinstance(advice, str)
        assert len(advice) > 0

    def test_returns_model_response(self, sample_findings):
        with patch("agent.llm_agent.requests.post",
                   return_value=_mock_ok("Set PermitRootLogin to no.")):
            advice = get_advice(sample_findings[0])
        assert "PermitRootLogin" in advice

    def test_retries_on_timeout(self, sample_findings):
        ok = _mock_ok("Fixed.")
        with patch("agent.llm_agent.requests.post",
                   side_effect=[_mock_fail(), _mock_fail(), ok]):
            with patch("agent.llm_agent.time.sleep"):
                advice = get_advice(sample_findings[0], retries=3)
        assert advice == "Fixed."

    def test_fallback_on_connection_error(self, sample_findings):
        import requests as req
        with patch("agent.llm_agent.requests.post",
                   side_effect=req.exceptions.ConnectionError("down")):
            with patch("agent.llm_agent.time.sleep"):
                advice = get_advice(sample_findings[0], retries=3)
        assert "unavailable" in advice.lower() or "manual" in advice.lower()

    def test_fallback_when_all_retries_fail(self, sample_findings):
        with patch("agent.llm_agent.requests.post", side_effect=Exception("err")):
            with patch("agent.llm_agent.time.sleep"):
                advice = get_advice(sample_findings[0], retries=2)
        assert isinstance(advice, str)
        assert len(advice) > 0

    def test_fallback_mentions_fix_script_when_present(self, sample_findings):
        with patch("agent.llm_agent.requests.post", side_effect=Exception("err")):
            with patch("agent.llm_agent.time.sleep"):
                advice = get_advice(sample_findings[0], retries=1)
        assert "scap" in advice.lower() or "fix" in advice.lower()

    def test_empty_response_falls_back(self, sample_findings):
        m = MagicMock()
        m.json.return_value     = {"response": ""}
        m.raise_for_status      = MagicMock()
        with patch("agent.llm_agent.requests.post", return_value=m):
            with patch("agent.llm_agent.time.sleep"):
                advice = get_advice(sample_findings[0], retries=1)
        assert isinstance(advice, str)


# ── analyze_findings ──────────────────────────────────────────
class TestAnalyzeFindings:

    def test_enriches_high_findings(self, sample_findings):
        with patch("agent.llm_agent.requests.post", return_value=_mock_ok("Do this fix.")):
            enriched = analyze_findings(sample_findings, max_high=5)
        high = [f for f in enriched if f.severity == "high"]
        assert all(f.llm_advice != "" for f in high)

    def test_does_not_enrich_medium(self, sample_findings):
        with patch("agent.llm_agent.requests.post", return_value=_mock_ok("advice")):
            enriched = analyze_findings(sample_findings, max_high=5)
        medium = [f for f in enriched if f.severity == "medium"]
        assert all(f.llm_advice == "" for f in medium)

    def test_respects_max_high_cap(self, sample_findings):
        call_count = 0
        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _mock_ok("advice")
        with patch("agent.llm_agent.requests.post", side_effect=mock_post):
            with patch("agent.llm_agent.time.sleep"):
                analyze_findings(sample_findings, max_high=1)
        assert call_count == 1

    def test_returns_all_findings(self, sample_findings):
        with patch("agent.llm_agent.requests.post", return_value=_mock_ok("advice")):
            enriched = analyze_findings(sample_findings, max_high=5)
        assert len(enriched) == len(sample_findings)

    def test_no_high_findings_returns_unchanged(self, sample_findings):
        medium_only = [f for f in sample_findings if f.severity != "high"]
        result = analyze_findings(medium_only, max_high=5)
        assert result == medium_only


# ── check_ollama ──────────────────────────────────────────────
class TestCheckOllama:

    def test_returns_true_when_reachable(self):
        m = MagicMock()
        m.json.return_value = {"models": [{"name": "llama3.2"}]}
        m.raise_for_status  = MagicMock()
        with patch("agent.llm_agent.requests.get", return_value=m):
            assert check_ollama() is True

    def test_returns_false_when_unreachable(self):
        import requests as req
        with patch("agent.llm_agent.requests.get",
                   side_effect=req.exceptions.ConnectionError("down")):
            assert check_ollama() is False

    def test_warns_when_model_missing(self, capsys):
        m = MagicMock()
        m.json.return_value = {"models": [{"name": "mistral"}]}
        m.raise_for_status  = MagicMock()
        with patch("agent.llm_agent.requests.get", return_value=m):
            check_ollama()
        captured = capsys.readouterr()
        assert "not found" in captured.out or "Warning" in captured.out
