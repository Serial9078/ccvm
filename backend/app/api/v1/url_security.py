from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.url_security import UrlSecurity
from app.schemas.url_security import UrlSecurityOut

router = APIRouter(
    prefix="/url-security",
    tags=["URL Security"],
)


@router.get(
    "",
    response_model=list[UrlSecurityOut],
)
def list_url_security(
    url_id: int | None = None,
    minimum_score: int | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(UrlSecurity)

    if url_id is not None:
        query = query.filter(
            UrlSecurity.url_id == url_id,
        )

    if minimum_score is not None:
        query = query.filter(
            UrlSecurity.security_score >= minimum_score,
        )

    return query.order_by(
        UrlSecurity.security_score.asc(),
        UrlSecurity.id.desc(),
    ).all()


@router.get(
    "/{security_id}",
    response_model=UrlSecurityOut,
)
def get_url_security(
    security_id: int,
    db: Session = Depends(get_db),
):
    security = db.get(
        UrlSecurity,
        security_id,
    )

    if not security:
        raise HTTPException(
            status_code=404,
            detail="URL security record not found",
        )

    return security
