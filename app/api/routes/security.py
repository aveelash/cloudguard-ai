import logging
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.azure.connection_service import get_azure_connection
from app.security.scanner import run_security_scan
from app.agents.security_analyzer import security_analysis_graph
from app.db import get_db
from app.db.models import SecurityScan, User
from app.auth.dependencies import get_current_user, require_roles

router = APIRouter(
    prefix="/api/security",
    tags=["Security Scanning"]
)


@router.get("/scan")
def scan_azure_resources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("owner", "admin"))
):
    try:
        azure_config = get_azure_connection(db, current_user.company_id)

        report = run_security_scan(azure_config)

        findings = report["findings"]

        critical_findings = sum(
            1 for finding in findings
            if finding.get("severity") == "critical"
        )

        high_findings = sum(
            1 for finding in findings
            if finding.get("severity") == "high"
        )

        medium_findings = sum(
            1 for finding in findings
            if finding.get("severity") == "medium"
        )

        low_findings = sum(
            1 for finding in findings
            if finding.get("severity") == "low"
        )

        scan_record = SecurityScan(
            company_id=current_user.company_id,
            total_resources_scanned=report["total_resources_scanned"],
            total_findings=len(findings),
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            critical_findings=critical_findings,
            findings=findings
        )

        db.add(scan_record)
        db.commit()

        return report

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while scanning Azure resources."
        )


@router.post("/analyze")
def analyze_security_finding(
    finding: dict,
    current_user: User = Depends(get_current_user)
):
    try:
        result = security_analysis_graph.invoke({
            "finding": finding,
            "analysis": ""
        })

        return {
            "resource_name": finding.get("resource_name"),
            "issue": finding.get("issue"),
            "severity": finding.get("severity"),
            "analysis": result["analysis"]
        }

    except Exception:
        logging.exception("AI security analysis failed")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while analyzing the security finding."
        )
