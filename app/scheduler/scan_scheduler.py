import logging
from apscheduler.schedulers.background import BackgroundScheduler
from app.security.finding_comparator import compare_findings
from app.security.scanner import run_security_scan
from app.db import SessionLocal
from app.db.models import Company, SecurityScan, SecurityAlert
from app.azure.connection_service import get_azure_connection


scheduler = BackgroundScheduler()



def run_scheduled_security_scan(company_id: int):
    db = SessionLocal()

    try:
        company = (
            db.query(Company)
            .filter(Company.id == company_id)
            .first()
        )

        if not company:
            raise ValueError("Company not found.")

        azure_config = get_azure_connection(db, company_id)

        report = run_security_scan(azure_config)
        findings = report["findings"]

        previous_scan = (
            db.query(SecurityScan)
            .filter(SecurityScan.company_id == company_id)
            .order_by(SecurityScan.scanned_at.desc())
            .first()
        )

        previous_findings = (
            previous_scan.findings
            if previous_scan else []
        )

        comparison = compare_findings(
            previous_findings,
            findings
        )

        for finding in comparison["new_findings"]:
            if finding.get("severity") in ("critical", "high"):
                alert = SecurityAlert(
                    company_id=company_id,
                    resource_name=finding.get(
                        "resource_name", "Unknown"
                    ),
                    issue=finding.get(
                        "issue", "Unknown security issue"
                    ),
                    severity="high",
                    alert_type="new_finding"
                )

                db.add(alert)

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
            company_id=company_id,
            total_resources_scanned=report["total_resources_scanned"],
            total_findings=len(findings),
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            findings=findings
        )

        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        return {
            "success": True,
            "scan_id": scan_record.id,
            "total_findings": len(findings),
            "new_findings": comparison["new_count"],
            "resolved_findings": comparison["resolved_count"],
            "existing_findings": comparison["existing_count"]
        }

    except Exception:
        db.rollback()
        logging.exception(
            "Scheduled security scan failed for company_id=%s",
            company_id
        )

        return {
            "success": False,
            "message": "An internal error occurred while running the security scan."
        }

    finally:
        db.close()




def start_scheduler():
    print(
        "Automatic security scanning is temporarily paused "
        "until company-specific Azure connections are configured."
    )



def trigger_manual_scan(company_id: int):
    return run_scheduled_security_scan(company_id)
