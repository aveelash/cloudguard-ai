from app.scheduler.scan_scheduler import trigger_manual_scan
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.scheduler.scan_scheduler import scheduler
from app.db import get_db
from app.db.models import SecurityScan, SecurityAlert, User
from app.auth.dependencies import get_current_user, require_roles


router = APIRouter(
    prefix="/api/history",
    tags=["Scan History"],
    dependencies=[Depends(get_current_user)]
)



@router.get("/scans")
def get_scan_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("owner", "admin"))
):
    try:
        scans = (
            db.query(SecurityScan)
            .filter(
                SecurityScan.company_id == current_user.company_id
            )
            .order_by(SecurityScan.scanned_at.desc())
            .all()
        )

        return {
            "total_scans": len(scans),
            "scans": [
                {
                    "id": scan.id,
                    "total_resources_scanned": scan.total_resources_scanned,
                    "total_findings": scan.total_findings,
                    "critical_findings": scan.critical_findings,
                    "high_findings": scan.high_findings,
                    "medium_findings": scan.medium_findings,
                    "low_findings": scan.low_findings,
                    "scanned_at": scan.scanned_at,
                    "findings": scan.findings
                }
                for scan in scans
            ]
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while retrieving scan history."
        )





@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        scans = (
            db.query(SecurityScan)
            .filter(
                SecurityScan.company_id == current_user.company_id
            )
            .all()
        )

        return {
            "total_scans": len(scans),
            "total_findings": sum(
                scan.total_findings for scan in scans
            ),
            "critical_findings": sum(
                scan.critical_findings for scan in scans
            ),
            "high_findings": sum(
                scan.high_findings for scan in scans
            ),
            "medium_findings": sum(
                scan.medium_findings for scan in scans
            ),
            "low_findings": sum(
                scan.low_findings for scan in scans
            ),
            "latest_scan": (
                max(
                    scans,
                    key=lambda scan: scan.scanned_at
                ).scanned_at
                if scans else None
            )
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while retrieving the dashboard summary."
        )




@router.get("/trends")
def get_security_trends(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        scans = (
            db.query(SecurityScan)
            .filter(
                SecurityScan.company_id == current_user.company_id
            )
            .order_by(SecurityScan.scanned_at.asc())
            .all()
        )

        return {
            "total_scans": len(scans),
            "trends": [
                {
                    "scan_id": scan.id,
                    "scanned_at": scan.scanned_at,
                    "total_findings": scan.total_findings,
                    "critical_findings": scan.critical_findings,
                    "high_findings": scan.high_findings,
                    "medium_findings": scan.medium_findings,
                    "low_findings": scan.low_findings
                }
                for scan in scans
            ]
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while retrieving security trends."
        )



@router.get("/scans/{scan_id}")
def get_scan_details(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = (
        db.query(SecurityScan)
        .filter(
            SecurityScan.id == scan_id,
            SecurityScan.company_id == current_user.company_id
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return {
        "id": scan.id,
        "total_resources_scanned": scan.total_resources_scanned,
        "total_findings": scan.total_findings,
        "critical_findings": scan.critical_findings,
        "high_findings": scan.high_findings,
        "medium_findings": scan.medium_findings,
        "low_findings": scan.low_findings,
        "scanned_at": scan.scanned_at,
        "findings": scan.findings
    }


@router.get("/scheduler/status")
def get_scheduler_status():
    job = scheduler.get_job("daily_security_scan")

    if not scheduler.running or job is None:
        return {
            "scheduler_running": False,
            "message": "Automatic security scanning is not active."
        }

    return {
        "scheduler_running": True,
        "job_id": job.id,
        "next_run_time": job.next_run_time,
        "message": "Automatic security scanning is active."
    }


@router.post("/scheduler/run-now")
def run_scan_now(
    current_user: User = Depends(get_current_user)
):
    result = trigger_manual_scan(current_user.company_id)

    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=result["message"]
        )

    return {
        "success": True,
        "scan_id": result["scan_id"],
        "total_findings": result["total_findings"],
        "new_findings": result["new_findings"],
        "resolved_findings": result["resolved_findings"],
        "existing_findings": result["existing_findings"],
        "message": "Manual security scan completed successfully."
    }



@router.get("/alerts")
def get_security_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.company_id == current_user.company_id
        )
        .order_by(SecurityAlert.created_at.desc())
        .all()
    )

    return [
        {
            "id": alert.id,
            "resource_name": alert.resource_name,
            "issue": alert.issue,
            "severity": alert.severity,
            "alert_type": alert.alert_type,
            "is_read": bool(alert.is_read),
            "created_at": alert.created_at
        }
        for alert in alerts
    ]



@router.patch("/alerts/{alert_id}/read")
def mark_alert_as_read(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.id == alert_id,
            SecurityAlert.company_id == current_user.company_id
        )
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found."
        )

    alert.is_read = 1
    db.commit()

    return {
        "success": True,
        "message": "Security alert marked as read.",
        "alert_id": alert.id
    }



@router.get("/alerts/unread-count")
def get_unread_alerts_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    unread_count = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.company_id == current_user.company_id,
            SecurityAlert.is_read == 0
        )
        .count()
    )

    return {
        "unread_count": unread_count
    }
