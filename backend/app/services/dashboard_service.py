from sqlalchemy import func
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


def get_latest_findings(db: Session):
    return db.query(Finding).order_by(Finding.id.desc()).limit(8).all()


def get_active_jobs(db: Session):
    return (
        db.query(Job)
        .filter(Job.status.in_(["queued", "running"]))
        .order_by(Job.id.desc())
        .limit(8)
        .all()
    )


def get_scanner_chart(db: Session):
    rows = (
        db.query(Finding.scanner, func.count(Finding.id))
        .group_by(Finding.scanner)
        .order_by(func.count(Finding.id).desc())
        .all()
    )

    return [{"label": scanner or "unknown", "value": count} for scanner, count in rows]


def get_dashboard_summary(db: Session) -> dict:
    critical = count_findings_by_severity(db, "critical")
    high = count_findings_by_severity(db, "high")
    medium = count_findings_by_severity(db, "medium")
    low = count_findings_by_severity(db, "low")
    info = count_findings_by_severity(db, "info")

    return {
        "customers": db.query(Customer).count(),
        "domains": db.query(Domain).count(),
        "assets": db.query(Asset).count(),
        "jobs": db.query(Job).count(),
        "running_jobs": db.query(Job).filter(Job.status == "running").count(),
        "findings": db.query(Finding).count(),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "open": count_findings_by_status(db, "open"),
        "fixed": count_findings_by_status(db, "fixed"),
        "latest_findings": get_latest_findings(db),
        "active_jobs": get_active_jobs(db),
        "severity_chart": [
            {"label": "Critical", "value": critical},
            {"label": "High", "value": high},
            {"label": "Medium", "value": medium},
            {"label": "Low", "value": low},
            {"label": "Info", "value": info},
        ],
        "scanner_chart": get_scanner_chart(db),
    }
