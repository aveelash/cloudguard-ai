from fastapi import FastAPI
from app.db.init_db import create_tables
from app.core.config import settings
from app.api.routes.inventory import router as inventory_router
from app.api.routes.security import router as security_router
from app.api.routes.reports import router as reports_router
from app.api.routes.history import router as history_router
from pathlib import Path
from fastapi.responses import FileResponse
from app.scheduler.scan_scheduler import start_scheduler, scheduler
from app.api.routes.auth import router as auth_router
from app.api.routes.users import router as users_router
from app.api.routes.azure_connections import router as azure_connections_router


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered Azure Security and Compliance Platform",
    version="1.0.0",
    debug=settings.DEBUG
)

@app.on_event("startup")
def startup_event():
    create_tables()
    start_scheduler()

@app.on_event("shutdown")
def shutdown_event():
    if scheduler.running:
        scheduler.shutdown()

app.include_router(inventory_router)
app.include_router(security_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(azure_connections_router)


@app.get("/")
def root():
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "environment": settings.APP_ENV
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.get("/login", include_in_schema=False)
def login_page():
    login_file = (
        Path(__file__).parent / "app" / "static" / "login.html"
    )
    return FileResponse(login_file)

@app.get("/dashboard", include_in_schema=False)
def dashboard():
    dashboard_file = (
        Path(__file__).parent / "app" / "static" / "dashboard.html"
    )

    return FileResponse(dashboard_file)