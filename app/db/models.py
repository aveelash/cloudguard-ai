
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    JSON,
    String,
    Text,
    Boolean,
    ForeignKey
)
from sqlalchemy.orm import relationship

from app.db import Base


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(255), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    users = relationship("User", back_populates="company")
    scans = relationship("SecurityScan", back_populates="company")
    alerts = relationship("SecurityAlert", back_populates="company")


class AzureConnection(Base):
    __tablename__ = "azure_connections"

    id = Column(Integer, primary_key=True, index=True)

    company_id = Column(
        Integer,
        ForeignKey("companies.id"),
        nullable=False,
        unique=True,
        index=True
    )

    tenant_id = Column(String(255), nullable=False)
    client_id = Column(String(255), nullable=False)
    encrypted_client_secret = Column(Text, nullable=False)
    subscription_id = Column(String(255), nullable=False)

    is_active = Column(Boolean, default=True)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    company = relationship("Company")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

    company_name = Column(String(255), nullable=False)

    company_id = Column(
        Integer,
        ForeignKey("companies.id"),
        nullable=False,
        index=True
    )

    role = Column(String(50), nullable=False, default="analyst")

    is_active = Column(Boolean, default=True)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    company = relationship("Company", back_populates="users")


class SecurityScan(Base):
    __tablename__ = "security_scans"

    id = Column(Integer, primary_key=True, index=True)

    company_id = Column(
        Integer,
        ForeignKey("companies.id"),
        nullable=False,
        index=True
    )

    total_resources_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)

    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)

    findings = Column(JSON, default=list)

    scanned_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    company = relationship("Company", back_populates="scans")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    company_id = Column(
        Integer,
        ForeignKey("companies.id"),
        nullable=False,
        index=True
    )

    resource_name = Column(String(255), nullable=False)
    issue = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)

    alert_type = Column(String(50), nullable=False)

    is_read = Column(Integer, default=0)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    company = relationship("Company", back_populates="alerts")
