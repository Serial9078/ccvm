from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.host import Host
from app.schemas.host import HostCreate, HostOut

router = APIRouter(prefix="/hosts", tags=["Hosts"])


@router.get("", response_model=list[HostOut])
def list_hosts(db: Session = Depends(get_db)):
    return db.query(Host).order_by(Host.id.desc()).all()


@router.post("", response_model=HostOut)
def create_host(payload: HostCreate, db: Session = Depends(get_db)):
    host = Host(**payload.model_dump())
    db.add(host)
    db.commit()
    db.refresh(host)
    return host
