from s3_auditor.severity import calculate_security_score


def test_calculate_security_score():
    findings = [
        {"status": "FAIL", "severity": "HIGH"},
        {"status": "FAIL", "severity": "MEDIUM"},
        {"status": "PASS", "severity": "LOW"},
    ]
    assert calculate_security_score(findings) == 70
