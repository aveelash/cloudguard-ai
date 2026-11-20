
from sqlalchemy import inspect
from app.db import Base, engine, SessionLocal
from app.db.models import (
    Company,
    User,
    SecurityScan,
    SecurityAlert,
    AzureConnection
)


def migrate_database():
    # Create the new companies table.
    Base.metadata.create_all(bind=engine)

    # Add missing columns to existing SQLite tables.
    with engine.begin() as connection:
        inspector = inspect(connection)

        migrations = {
            "users": {
                "company_id": (
                    "INTEGER REFERENCES companies(id)"
                ),
                "role": (
                    "VARCHAR(50) NOT NULL DEFAULT 'analyst'"
                )
            },
            "security_scans": {
                "company_id": (
                    "INTEGER REFERENCES companies(id)"
                )
            },
            "security_alerts": {
                "company_id": (
                    "INTEGER REFERENCES companies(id)"
                )
            }
        }

        for table_name, columns in migrations.items():
            existing_columns = {
                column["name"]
                for column in inspector.get_columns(table_name)
            }

            for column_name, column_definition in columns.items():
                if column_name not in existing_columns:
                    connection.exec_driver_sql(
                        f"ALTER TABLE {table_name} "
                        f"ADD COLUMN {column_name} {column_definition}"
                    )

    # Assign existing records to their company.
    db = SessionLocal()

    try:
        users = db.query(User).all()

        if not users:
            raise RuntimeError("No existing users found.")

        for user in users:
            company = (
                db.query(Company)
                .filter(Company.name == user.company_name)
                .first()
            )

            if not company:
                company = Company(name=user.company_name)
                db.add(company)
                db.flush()

            user.company_id = company.id

            # The first existing account becomes company owner.
            if user.id == min(u.id for u in users):
                user.role = "owner"

            db.query(SecurityScan).filter(
                SecurityScan.company_id.is_(None)
            ).update(
                {"company_id": company.id},
                synchronize_session=False
            )

            db.query(SecurityAlert).filter(
                SecurityAlert.company_id.is_(None)
            ).update(
                {"company_id": company.id},
                synchronize_session=False
            )

        db.commit()

        print("Database migration completed successfully.")

        print("Companies:", db.query(Company).count())
        print("Users:", db.query(User).count())
        print("Scans:", db.query(SecurityScan).count())
        print("Alerts:", db.query(SecurityAlert).count())

        for user in db.query(User).all():
            print(
                "User:", user.email,
                "| Company ID:", user.company_id,
                "| Role:", user.role
            )

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    migrate_database()
