
from types import SimpleNamespace

from app.agents import security_analyzer


def test_security_analyzer(monkeypatch):
    sample_finding = {
        "resource_name": "teststorageaccount",
        "issue": "HTTPS-only traffic is disabled",
        "severity": "high",
        "compliance": [
            {
                "name": "ISO 27001",
                "control": "A.8.24"
            },
            {
                "name": "SOC 2",
                "control": "CC6.7"
            }
        ]
    }

    expected_analysis = (
        "Risk Explanation: HTTP traffic is not encrypted.\n"
        "Potential Impact: Data could be exposed.\n"
        "Recommended Remediation: Enable HTTPS-only traffic.\n"
        "Risk Priority: High."
    )

    class MockChatOpenAI:
        def __init__(self, **kwargs):
            pass

        def invoke(self, prompt):
            assert "teststorageaccount" in prompt
            return SimpleNamespace(content=expected_analysis)

    monkeypatch.setattr(
        security_analyzer,
        "ChatOpenAI",
        MockChatOpenAI
    )

    result = security_analyzer.security_analysis_graph.invoke({
        "finding": sample_finding,
        "analysis": ""
    })

    assert result["analysis"] == expected_analysis

    print("AI Security Analyzer test passed!")
    print("Mocked AI analysis verified successfully.")


if __name__ == "__main__":
    test_security_analyzer()
