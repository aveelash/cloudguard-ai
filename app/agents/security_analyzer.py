import logging
from typing import TypedDict

from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

from app.core.config import settings


class SecurityAnalysisState(TypedDict):
    finding: dict
    analysis: str


def analyze_security_finding(state: SecurityAnalysisState):
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        api_key=settings.OPENAI_API_KEY
    )

    prompt = f"""
    You are an experienced Azure cloud security analyst.

    Analyze the following Azure security finding.

    Security Finding:
    {state['finding']}

    Provide your response using these four sections:

    1. Risk Explanation
    Explain the security issue in simple and clear language.
    Describe why the configuration could be risky.

    2. Potential Impact
    Explain realistic security consequences, such as unauthorized
    access, privilege escalation, data exposure, or resource deletion.
    Only mention impacts relevant to the finding.

    3. Recommended Remediation
    Provide practical, step-by-step recommendations.

    For Azure RBAC findings:
    - Review the assigned principal and confirm whether access is required.
    - Remove unnecessary Owner role assignments.
    - Apply the principle of least privilege.
    - Prefer narrower built-in or custom roles where appropriate.
    - Consider Microsoft Entra Privileged Identity Management (PIM)
      for eligible, time-limited administrative access.
    - Regularly audit role assignments and access.

    Do not assume that Contributor is automatically safe.
    Do not recommend moving broad permissions to a higher scope.
    Do not suggest deleting legitimate access without reviewing
    business requirements.

    For Azure App Service findings:

    - If HTTPS-only traffic is disabled:
      Enable the HTTPS Only setting for the App Service.
      This redirects HTTP requests to HTTPS.

    - If a weak minimum TLS version is detected:
      Configure the App Service minimum inbound TLS version
      to TLS 1.2 or a stronger supported version.
      Verify application compatibility before changing the setting.

    - If unencrypted FTP access is enabled:
      Change the App Service FTP state from AllAllowed
      to FtpsOnly or Disabled.
      Prefer Disabled when FTP deployment is not required.
      Use encrypted FTPS instead of unencrypted FTP when
      file transfer access is necessary.

    For other Azure findings, provide remediation relevant
    to the affected resource and configuration.

    4. Risk Priority
    Explain the urgency based on the severity and potential impact.
    Avoid claiming that a finding is an active attack or confirmed
    compliance violation without supporting evidence.

    Important:
    - Keep recommendations clear and practical.
    - Avoid generic or unrelated suggestions.
    - Do not invent resource configurations.
    - Do not claim that remediation has already been performed.
    """

    try:
        response = llm.invoke(prompt)
    except Exception as exc:
        original_error = exc.__cause__ or exc

        logging.error(
            "OpenAI API request failed: type=%s, status=%s, details=%s",
            type(original_error).__name__,
            getattr(original_error, "status_code", None),
            getattr(original_error, "body", None)
        )

        raise

    return {
        "analysis": response.content
    }


def build_security_analysis_graph():
    graph = StateGraph(SecurityAnalysisState)

    graph.add_node(
        "analyze_security_finding",
        analyze_security_finding
    )

    graph.set_entry_point("analyze_security_finding")
    graph.add_edge("analyze_security_finding", END)

    return graph.compile()


security_analysis_graph = build_security_analysis_graph()
