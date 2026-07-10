from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.url import Url
from app.schemas.url import UrlCreate, UrlOut

router = APIRouter(
    prefix="/urls",
    tags=["URLs"],
)


@router.get("", response_model=list[UrlOut])
def list_urls(
    domain_id: int | None = None,
    host_id: int | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Url)

    if domain_id is not None:
        query = query.filter(Url.domain_id == domain_id)

    if host_id is not None:
        query = query.filter(Url.host_id == host_id)

    return query.order_by(Url.id.desc()).all()


@router.get("/{url_id}", response_model=UrlOut)
def get_url(
    url_id: int,
    db: Session = Depends(get_db),
):
    url = db.query(Url).filter(Url.id == url_id).first()

    if not url:
        raise HTTPException(
            status_code=404,
            detail="URL not found",
        )

    return url


@router.post("", response_model=UrlOut)
def create_url(
    payload: UrlCreate,
    db: Session = Depends(get_db),
):
    existing = (
        db.query(Url)
        .filter(
            Url.domain_id == payload.domain_id,
            Url.url == payload.url,
        )
        .first()
    )

    if existing:
        return existing

    url = Url(**payload.model_dump())

    db.add(url)
    db.commit()
    db.refresh(url)

    return url
