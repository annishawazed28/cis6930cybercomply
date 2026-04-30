# This may contain AI generated code

# tests/conftest.py
import pytest
from pathlib import Path
from agent.parser import Finding

# ── Sample XCCDF XML ─────────────────────────────────────────
SAMPLE_XCCDF_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_ssg_benchmark_rhel9">

  <Rule id="xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny"
        severity="high">
    <title>Lock Accounts After Failed Password Attempts</title>
    <description>Configure the number of failed attempts before lockout to prevent brute force.</description>
    <rationale>Locking accounts after failed attempts prevents brute force password attacks.</rationale>
    <ident system="https://nvd.nist.gov/cce/index.cfm">CCE-80667-3</ident>
    <fix system="urn:xccdf:fix:script:sh">
authselect enable-feature with-faillock
    </fix>
  </Rule>

  <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
        severity="high">
    <title>Disable SSH Root Login</title>
    <description>Root should not be able to log in via SSH directly.</description>
    <rationale>Disabling root SSH login forces use of a non-privileged account.</rationale>
    <fix system="urn:xccdf:fix:script:sh">
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
    </fix>
  </Rule>

  <Rule id="xccdf_org.ssgproject.content_rule_set_password_max_days"
        severity="medium">
    <title>Set Password Maximum Age</title>
    <description>Passwords should expire after a maximum of 60 days.</description>
    <rationale>Limiting password age reduces the window of opportunity for attackers.</rationale>
    <fix system="urn:xccdf:fix:script:sh">
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
    </fix>
  </Rule>

  <Rule id="xccdf_org.ssgproject.content_rule_audit_rules_login_events"
        severity="low">
    <title>Enable Auditing of Login Events</title>
    <description>The system should audit successful and unsuccessful login attempts.</description>
    <fix system="urn:xccdf:fix:script:sh">
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
    </fix>
  </Rule>

  <TestResult id="test1">
    <rule-result
      idref="xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny"
      severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result
      idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
      severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result
      idref="xccdf_org.ssgproject.content_rule_set_password_max_days"
      severity="medium">
      <result>fail</result>
    </rule-result>
    <rule-result
      idref="xccdf_org.ssgproject.content_rule_audit_rules_login_events"
      severity="low">
      <result>fail</result>
    </rule-result>
  </TestResult>

</Benchmark>
"""

# ── Fixtures ──────────────────────────────────────────────────
@pytest.fixture
def sample_xml(tmp_path):
    """Write sample XCCDF XML to a temp file and return its path."""
    f = tmp_path / "scan_results.xml"
    f.write_text(SAMPLE_XCCDF_XML)
    return str(f)

@pytest.fixture
def empty_xml(tmp_path):
    """A valid XML file with no findings."""
    f = tmp_path / "empty.xml"
    f.write_text(
        '<?xml version="1.0"?>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">'
        '<TestResult id="t"/></Benchmark>'
    )
    return str(f)

@pytest.fixture
def sample_findings():
    """Pre-built Finding objects for unit tests that don't need XML parsing."""
    return [
        Finding(
            rule_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            title="Disable SSH Root Login",
            severity="high",
            result="fail",
            description="Root should not be able to log in via SSH directly.",
            fix_script="sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\nsystemctl restart sshd",
            rationale="Disabling root SSH login forces use of a non-privileged account.",
            references=["CCE-80222-7"],
            llm_advice="",
        ),
        Finding(
            rule_id="xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny",
            title="Lock Accounts After Failed Password Attempts",
            severity="high",
            result="fail",
            description="Configure the number of failed attempts before lockout.",
            fix_script="authselect enable-feature with-faillock",
            rationale="Prevents brute force attacks.",
            references=["CCE-80667-3"],
            llm_advice="",
        ),
        Finding(
            rule_id="xccdf_org.ssgproject.content_rule_set_password_max_days",
            title="Set Password Maximum Age",
            severity="medium",
            result="fail",
            description="Passwords should expire after 60 days.",
            fix_script="sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs",
            rationale="Limits password age.",
            references=[],
            llm_advice="Set PASS_MAX_DAYS to 60 in /etc/login.defs using sudo.\n"
                       "```bash\nsudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs\n```\n"
                       "Verify with: grep PASS_MAX_DAYS /etc/login.defs",
        ),
    ]

@pytest.fixture
def findings_with_advice(sample_findings):
    """Same findings but with LLM advice populated on HIGH findings."""
    for f in sample_findings:
        if f.severity == "high":
            f.llm_advice = (
                "1. PLAIN ENGLISH\nThis rule checks whether root can log in over SSH.\n\n"
                "2. SECURITY RISK\nAn attacker could brute-force the root password directly.\n\n"
                "3. REMEDIATION STEPS\n```bash\n"
                "sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                "systemctl restart sshd\n```\n\n"
                "4. VERIFICATION\n```bash\ngrep PermitRootLogin /etc/ssh/sshd_config\n```"
            )
    return sample_findings
