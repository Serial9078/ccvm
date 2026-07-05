from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.deps import get_db
from app.models.asset import Asset
from app.models.customer import Customer
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.dashboard import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)):
    return DashboardStats(
        customers=db.query(Customer).count(),
        assets=db.query(Asset).count(),
        scans=db.query(Scan).count(),
        findings=db.query(Finding).count(),
        critical=db.query(Finding).filter(Finding.severity == "critical").count(),
        high=db.query(Finding).filter(Finding.severity == "high").count(),
        medium=db.query(Finding).filter(Finding.severity == "medium").count(),
        low=db.query(Finding).filter(Finding.severity == "low").count(),
    )
