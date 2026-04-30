# This may contain AI generated code
# tests/test_parser.py
import pytest
from agent.parser import parse_results, get_stats, filter_by_severity, Finding


class TestParseResults:

    def test_returns_list(self, sample_xml):
        findings = parse_results(sample_xml)
        assert isinstance(findings, list)

    def test_correct_count(self, sample_xml):
        findings = parse_results(sample_xml)
        assert len(findings) == 4

    def test_only_failed_rules_returned(self, sample_xml):
        findings = parse_results(sample_xml)
        assert all(f.result == "fail" for f in findings)

    def test_sorted_high_first(self, sample_xml):
        findings = parse_results(sample_xml)
        severities = [f.severity for f in findings]
        assert severities[0] == "high"
        assert severities[-1] == "low"

    def test_high_findings_before_medium(self, sample_xml):
        findings = parse_results(sample_xml)
        high_indices   = [i for i, f in enumerate(findings) if f.severity == "high"]
        medium_indices = [i for i, f in enumerate(findings) if f.severity == "medium"]
        assert max(high_indices) < min(medium_indices)

    def test_title_populated(self, sample_xml):
        findings = parse_results(sample_xml)
        ssh_rule = next(f for f in findings if "sshd" in f.rule_id)
        assert ssh_rule.title == "Disable SSH Root Login"

    def test_severity_populated(self, sample_xml):
        findings = parse_results(sample_xml)
        ssh_rule = next(f for f in findings if "sshd" in f.rule_id)
        assert ssh_rule.severity == "high"

    def test_fix_script_populated(self, sample_xml):
        findings = parse_results(sample_xml)
        ssh_rule = next(f for f in findings if "sshd" in f.rule_id)
        assert "PermitRootLogin" in ssh_rule.fix_script

    def test_description_populated(self, sample_xml):
        findings = parse_results(sample_xml)
        ssh_rule = next(f for f in findings if "sshd" in f.rule_id)
        assert len(ssh_rule.description) > 0

    def test_rationale_populated(self, sample_xml):
        findings = parse_results(sample_xml)
        ssh_rule = next(f for f in findings if "sshd" in f.rule_id)
        assert "brute" in ssh_rule.rationale.lower() or len(ssh_rule.rationale) > 0

    def test_short_id_property(self, sample_xml):
        findings = parse_results(sample_xml)
        ssh_rule = next(f for f in findings if "sshd" in f.rule_id)
        assert ssh_rule.short_id == "sshd_disable_root_login"
        assert "xccdf" not in ssh_rule.short_id

    def test_references_extracted(self, sample_xml):
        findings  = parse_results(sample_xml)
        faillock  = next(f for f in findings if "faillock" in f.rule_id)
        assert any("CCE" in r for r in faillock.references)

    def test_empty_xml_returns_no_findings(self, empty_xml):
        findings = parse_results(empty_xml)
        assert findings == []

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_results("/nonexistent/path.xml")

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "empty.xml"
        f.write_text("")
        with pytest.raises(ValueError):
            parse_results(str(f))


class TestGetStats:

    def test_stats_keys(self, sample_findings):
        stats = get_stats(sample_findings)
        assert "total" in stats
        assert "high" in stats
        assert "medium" in stats
        assert "low" in stats
        assert "with_llm_advice" in stats
        assert "with_fix_script" in stats

    def test_stats_counts(self, sample_findings):
        stats = get_stats(sample_findings)
        assert stats["total"]  == 3
        assert stats["high"]   == 2
        assert stats["medium"] == 1
        assert stats["low"]    == 0

    def test_with_llm_advice_count(self, findings_with_advice):
        stats = get_stats(findings_with_advice)
        assert stats["with_llm_advice"] == 2

    def test_with_fix_script_count(self, sample_findings):
        stats = get_stats(sample_findings)
        assert stats["with_fix_script"] == 3

    def test_empty_findings(self):
        stats = get_stats([])
        assert stats["total"] == 0
        assert stats["high"]  == 0


class TestFilterBySeverity:

    def test_filter_high(self, sample_findings):
        high = filter_by_severity(sample_findings, "high")
        assert len(high) == 2
        assert all(f.severity == "high" for f in high)

    def test_filter_medium(self, sample_findings):
        medium = filter_by_severity(sample_findings, "medium")
        assert len(medium) == 1
        assert medium[0].severity == "medium"

    def test_filter_low_returns_empty(self, sample_findings):
        low = filter_by_severity(sample_findings, "low")
        assert low == []

    def test_filter_preserves_order(self, sample_findings):
        high = filter_by_severity(sample_findings, "high")
        titles = [f.title for f in high]
        assert titles == [f.title for f in sample_findings if f.severity == "high"]
