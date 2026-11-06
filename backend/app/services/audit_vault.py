"""Small, deliberately separate operator boundary for the credentialed feature.

The existing application has no user authentication. These endpoints require TLS
and a separately provisioned operator token; this is not application-wide RBAC.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Header, HTTPException, Request

from app.services.network_scope import allowed_networks, network, verify_scanner_scope


def vault_key():
    try:
        key = base64.b64decode(os.environ.get("CCVM_AUDIT_VAULT_KEY", ""), validate=True)
        if len(key) != 32:
            raise ValueError
        return key
    except (ValueError, TypeError) as error:
        raise ValueError(
            "Configure CCVM_AUDIT_VAULT_KEY as a base64 encoded 32-byte key"
        ) from error


def operator_token():
    token = os.environ.get("CCVM_AUDIT_OPERATOR_TOKEN", "")
    if (
        len(token) < 32
        or len(token) > 512
        or not token.isascii()
        or any(c.isspace() for c in token)
    ):
        raise ValueError("Configure a separate CCVM_AUDIT_OPERATOR_TOKEN (32–512 characters)")
    return token


def require_operator(request: Request, authorization: str | None = Header(default=None)):
    # Uvicorn may accept Forwarded headers only from explicitly trusted proxies.
    # Never inspect X-Forwarded-Proto here: a client could supply it directly.
    if request.url.scheme != "https":
        raise HTTPException(status_code=403, detail="Host audit access requires HTTPS")
    try:
        expected = operator_token()
        vault_key()
    except ValueError as error:
        raise HTTPException(status_code=503, detail="Host audits are not configured") from error
    supplied = (authorization or "").removeprefix("Bearer ")
    if (
        not authorization
        or not authorization.startswith("Bearer ")
        or not hmac.compare_digest(supplied.encode(), expected.encode())
    ):
        raise HTTPException(status_code=401, detail="Operator token required")


def credential_scope(values):
    if not 1 <= len(values) <= 32:
        raise ValueError("Specify 1–32 credential CIDRs")
    allowed = allowed_networks()
    result = sorted({str(network(value)) for value in values})
    for value in result:
        net = network(value)
        if not any(net.version == parent.version and net.subnet_of(parent) for parent in allowed):
            raise ValueError("Credential CIDRs must be within the scanner's allowed networks")
    return result


def target_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("Host audits require a single literal IPv4/IPv6 address") from error
    network(str(address))
    verify_scanner_scope([str(address)])
    return str(address)


def verify_credential_target(credential, target, customer_id):
    target = target_address(target)
    if not credential.enabled or credential.ciphertext is None:
        raise ValueError("Credential has been revoked")
    if credential.customer_id != customer_id:
        raise ValueError("Credential belongs to another customer")
    address = ipaddress.ip_address(target)
    if not any(
        address.version == net.version and address in net
        for net in map(network, credential.allowed_cidrs)
    ):
        raise ValueError("Target is outside this credential's allowed CIDRs")
    return target


def identity(credential):
    # Authenticate metadata as well as the ciphertext: copying a credential to
    # another customer, changing its account, kind, or scope invalidates the tag.
    return json.dumps(
        [
            "ccvm-audit-v1",
            credential.uuid,
            credential.customer_id,
            credential.kind,
            credential.username,
            credential.allowed_cidrs,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def encrypt(credential, secrets):
    nonce = os.urandom(12)
    return nonce + AESGCM(vault_key()).encrypt(
        nonce, json.dumps(secrets).encode(), identity(credential)
    )


def decrypt(credential):
    ciphertext = credential.ciphertext or b""
    try:
        return json.loads(
            AESGCM(vault_key()).decrypt(ciphertext[:12], ciphertext[12:], identity(credential))
        )
    except (InvalidTag, ValueError, TypeError) as error:
        raise ValueError(
            "Credential cannot be decrypted with this vault key and identity"
        ) from error


def audit_hash(audit, credential):
    values = [
        "ccvm-host-inventory-v1",
        audit.customer_id,
        audit.asset_id,
        audit.job_id,
        credential.uuid,
        hashlib.sha256(identity(credential)).hexdigest(),
        hashlib.sha256(credential.ciphertext or b"").hexdigest(),
        audit.target,
        audit.port,
        audit.ssh_fingerprint,
        audit.mode,
    ]
    # The additive migration backfills existing runs to HTTPS. Preserve their
    # original frozen hashes, including queued SSH/HTTPS work; bind an explicit
    # opt-in to HTTP so changing either direction invalidates a frozen run.
    transport = getattr(audit, "winrm_transport", "https")
    if transport != "https":
        values.extend(["winrm_transport", transport])
    return hashlib.sha256(
        json.dumps(
            values,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
