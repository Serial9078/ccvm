from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.customer import Customer
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.job import Job


def count_findings_by_severity(db: Session, severity: str) -> int:
    return db.query(Finding).filter(Finding.severity == severity).count()


def count_findings_by_status(db: Session, status: str) -> int:
    return db.query(Finding).filter(Finding.status == status).count()


def get_dashboard_summary(db: Session) -> dict:
    return {
        "customers": db.query(Customer).count(),
        "domains": db.query(Domain).count(),
        "assets": db.query(Asset).count(),
        "jobs": db.query(Job).count(),
        "running_jobs": db.query(Job).filter(Job.status == "running").count(),
        "findings": db.query(Finding).count(),
        "critical": count_findings_by_severity(db, "critical"),
        "high": count_findings_by_severity(db, "high"),
        "medium": count_findings_by_severity(db, "medium"),
        "low": count_findings_by_severity(db, "low"),
        "info": count_findings_by_severity(db, "info"),
        "open": count_findings_by_status(db, "open"),
        "fixed": count_findings_by_status(db, "fixed"),
    }
