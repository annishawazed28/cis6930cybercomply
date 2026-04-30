# tests/test_reporter.py
import pytest
from pathlib import Path
from agent.reporter import generate_report, generate_html_report


class TestGenerateReport:

    def test_creates_file(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        assert Path(out).exists()

    def test_file_not_empty(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        assert Path(out).stat().st_size > 0

    def test_contains_header(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "STIG Hardening Report" in content

    def test_contains_executive_summary(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "Executive Summary" in content

    def test_contains_all_finding_titles(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        for f in sample_findings:
            assert f.title in content

    def test_contains_severity_counts(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "2" in content   # 2 HIGH findings
        assert "1" in content   # 1 MEDIUM finding

    def test_contains_llm_advice_when_present(self, findings_with_advice, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(findings_with_advice, output_path=out)
        content = Path(out).read_text()
        assert "PLAIN ENGLISH" in content
        assert "REMEDIATION STEPS" in content

    def test_contains_fix_script_for_medium(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "PASS_MAX_DAYS" in content

    def test_contains_appendix(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "Appendix" in content

    def test_contains_rule_ids_in_appendix(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        for f in sample_findings:
            assert f.short_id in content

    def test_timestamp_in_report(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out, timestamp="2024-01-01 12:00:00")
        content = Path(out).read_text()
        assert "2024-01-01" in content

    def test_xml_path_in_appendix(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out, xml_path="/results/scan_test.xml")
        content = Path(out).read_text()
        assert "scan_test.xml" in content

    def test_creates_reports_dir_if_missing(self, sample_findings, tmp_path):
        out = str(tmp_path / "new_dir" / "report.md")
        generate_report(sample_findings, output_path=out)
        assert Path(out).exists()

    def test_returns_output_path(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        result = generate_report(sample_findings, output_path=out)
        assert result == out

    def test_empty_findings_still_generates(self, tmp_path):
        out = str(tmp_path / "empty_report.md")
        generate_report([], output_path=out)
        content = Path(out).read_text()
        assert "STIG Hardening Report" in content
        assert "0" in content

    def test_high_section_before_medium(self, sample_findings, tmp_path):
        out = str(tmp_path / "report.md")
        generate_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        high_pos   = content.find("HIGH Severity Findings")
        medium_pos = content.find("MEDIUM Severity Findings")
        assert high_pos < medium_pos


class TestGenerateHtmlReport:

    def test_creates_html_file(self, sample_findings, tmp_path):
        pytest.importorskip("markdown", reason="markdown package not installed")
        out = str(tmp_path / "report.html")
        generate_html_report(sample_findings, output_path=out)
        assert Path(out).exists()

    def test_html_has_doctype(self, sample_findings, tmp_path):
        pytest.importorskip("markdown", reason="markdown package not installed")
        out = str(tmp_path / "report.html")
        generate_html_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "<!DOCTYPE html>" in content

    def test_html_contains_title(self, sample_findings, tmp_path):
        pytest.importorskip("markdown", reason="markdown package not installed")
        out = str(tmp_path / "report.html")
        generate_html_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        assert "STIG Hardening Report" in content

    def test_html_contains_findings(self, sample_findings, tmp_path):
        pytest.importorskip("markdown", reason="markdown package not installed")
        out = str(tmp_path / "report.html")
        generate_html_report(sample_findings, output_path=out)
        content = Path(out).read_text()
        for f in sample_findings:
            assert f.title in content