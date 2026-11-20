
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.security.scanner import run_security_scan
from app.reports.pdf_generator import generate_security_report
from app.agents.security_analyzer import security_analysis_graph

from app.auth.dependencies import get_current_user, require_roles
from app.azure.connection_service import get_azure_connection
from app.db import get_db
from app.db.models import User


router = APIRouter(
    prefix="/api/reports",
    tags=["Security Reports"]
)


@router.get("/security/pdf")
def download_security_report(
    current_user: User = Depends(require_roles("owner", "admin")),
    db: Session = Depends(get_db)
):
    try:
        # Get this company's Azure credentials.
        azure_config = get_azure_connection(
            db,
            current_user.company_id
        )

        # Run the company-specific Azure security scan.
        scan_report = run_security_scan(azure_config)

        # Generate AI analysis for each security finding.
        for finding in scan_report.get("findings", []):
            try:
                result = security_analysis_graph.invoke({
                    "finding": finding,
                    "analysis": ""
                })

                finding["analysis"] = result["analysis"]

            except Exception:
                finding["analysis"] = (
                    "AI analysis is currently unavailable."
                )

        # Generate the PDF report.
        pdf_buffer = generate_security_report(scan_report)

        # Return the PDF as a downloadable file.
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    "attachment; filename=cloudguard_security_report.pdf"
                )
            }
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to generate the security report."
        )
