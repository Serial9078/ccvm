from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.database.deps import get_db
from app.models.url_detail import UrlDetail
from app.schemas.url_detail import UrlDetailOut

router = APIRouter(
    prefix="/url-details",
    tags=["URL Details"],
)


@router.get(
    "",
    response_model=list[UrlDetailOut],
)
def list_url_details(
    url_id: int | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(UrlDetail)

    if url_id is not None:
        query = query.filter(
            UrlDetail.url_id == url_id,
        )

    return query.order_by(UrlDetail.id.desc()).all()


@router.get(
    "/{detail_id}",
    response_model=UrlDetailOut,
)
def get_url_detail(
    detail_id: int,
    db: Session = Depends(get_db),
):
    detail = db.get(
        UrlDetail,
        detail_id,
    )

    if not detail:
        raise HTTPException(
            status_code=404,
            detail="URL detail not found",
        )

    return detail
