from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from app.schemas.job import JobOut


class CredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    customer_id: int
    name: str = Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f]+$")
    kind: Literal["ssh_password", "ssh_key", "winrm"]
    username: str = Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x1f]+$")
    allowed_cidrs: list[str] = Field(min_length=1, max_length=32)
    password: SecretStr | None = None
    private_key: SecretStr | None = None
    passphrase: SecretStr | None = None

    @model_validator(mode="after")
    def valid_secrets(self):
        if not self.name.strip() or not self.username.strip():
            raise ValueError("Credential name and username must not be blank")
        if self.kind == "ssh_key":
            if not self.private_key or self.password:
                raise ValueError(
                    "SSH keys require private_key, optional passphrase, and no password"
                )
        elif not self.password or self.private_key or self.passphrase:
            raise ValueError("Password credentials require password only")
        for value in (self.password, self.private_key, self.passphrase):
            if value is not None and not 1 <= len(value.get_secret_value()) <= 32768:
                raise ValueError("Secret length must be 1–32768 characters")
        return self


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    customer_id: int
    name: str
    kind: str
    username: str
    allowed_cidrs: list[str]
    enabled: bool
    created_at: datetime


class HostAuditCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    customer_id: int
    credential_id: int
    target: str = Field(min_length=1, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)
    ssh_fingerprint: str | None = Field(default=None, pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")
    winrm_transport: Literal["https", "http_ntlm"] = "https"
    mode: Literal[
        "connection", "inventory", "windows_updates", "cim_connection", "cim_inventory"
    ] = "inventory"


class HostAuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    customer_id: int
    asset_id: int
    credential_id: int
    target: str
    port: int
    winrm_transport: Literal["https", "http_ntlm"]
    mode: str
    cancel_requested: bool
    created_at: datetime
    completed_at: datetime | None
    job: JobOut


class HostAuditDetail(HostAuditOut):
    inventory: dict | None
