from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.port import Port
from app.schemas.port import PortCreate, PortOut

router = APIRouter(prefix="/ports", tags=["Ports"])


@router.get("", response_model=list[PortOut])
def list_ports(db: Session = Depends(get_db)):
    return db.query(Port).order_by(Port.id.desc()).all()


@router.post("", response_model=PortOut)
def create_port(payload: PortCreate, db: Session = Depends(get_db)):
    port = Port(**payload.model_dump())
    db.add(port)
    db.commit()
    db.refresh(port)
    return port
