
from app.db import Base, engine

from app.db.models import (
    Company,
    User,
    SecurityScan,
    SecurityAlert,
    AzureConnection
)


def create_tables():
    Base.metadata.create_all(bind=engine)
