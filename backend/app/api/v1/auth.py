"""Same-origin local login; enrollment and recovery are local operator CLI tasks."""

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from app.services.auth_session import (
    ABSOLUTE_TIMEOUT,
    COOKIE_NAME,
    auth_policy,
    authenticate,
    principal_payload,
    require_session,
    revoke_session,
    session_principal,
)

router = APIRouter(prefix="/auth", tags=["Anmeldung"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128, repr=False)
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$", repr=False)


@router.get("/session")
def current_session(request: Request, response: Response):
    if auth_policy() is None:
        return {"mode": "legacy", "authenticated": False}
    principal = session_principal(request, required=False)
    if principal is None:
        if COOKIE_NAME in request.cookies:
            response.delete_cookie(
                COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict"
            )
        return {"mode": "local", "authenticated": False}
    return principal_payload(principal)


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response):
    raw_token, principal = authenticate(request, payload.username, payload.password, payload.code)
    response.set_cookie(
        COOKIE_NAME,
        raw_token,
        max_age=int(ABSOLUTE_TIMEOUT.total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    return principal_payload(principal)


@router.post("/logout", status_code=204)
def logout(request: Request):
    principal = require_session(request)
    revoke_session(principal)
    response = Response(status_code=204)
    response.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    return response
