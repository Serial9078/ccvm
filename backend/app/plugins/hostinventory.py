import hmac
import os
from datetime import UTC, datetime

from app.models.asset import Asset
from app.models.host_audit import AuditCredential, HostAudit
from app.services import host_inventory
from app.services.audit_vault import audit_hash, decrypt, verify_credential_target


def frozen_audit(db, job):
    audit = db.query(HostAudit).filter(HostAudit.job_id == job.id).one_or_none()
    if not audit:
        raise ValueError("No frozen host audit is attached to this job")
    credential = db.get(AuditCredential, audit.credential_id)
    asset = db.get(Asset, audit.asset_id)
    if (
        not credential
        or not asset
        or asset.customer_id != audit.customer_id
        or job.asset_id != asset.id
    ):
        raise ValueError("Host audit customer/asset identity changed")
    if asset.type != "ip" or asset.target != audit.target or job.plugin != "hostinventory":
        raise ValueError("Host audit target identity changed")
    if audit.mode not in {"connection", "inventory"} or not 1 <= audit.port <= 65535:
        raise ValueError("Invalid frozen host audit parameters")
    if credential.kind not in {"ssh_password", "ssh_key", "winrm"}:
        raise ValueError("Unsupported credential kind")
    verify_credential_target(credential, audit.target, audit.customer_id)
    if not hmac.compare_digest(audit_hash(audit, credential), audit.scope_sha256):
        raise ValueError("Frozen host audit parameters or credential changed")
    return audit, credential


def run_hostinventory(db, job):
    audit = None
    try:
        try:
            audit, credential = frozen_audit(db, job)
            secrets = decrypt(credential)
        except ValueError as error:
            # Only our explicit preflight errors are safe to expose. Unknown
            # exceptions from the transport, including ValueError, are private.
            raise host_inventory.CollectionError(str(error)) from None
        if audit.cancel_requested:
            raise host_inventory.CollectionCancelled("Host audit cancelled before authentication")
        payload = {
            "target": audit.target,
            "port": audit.port,
            "mode": audit.mode,
            "ssh_fingerprint": audit.ssh_fingerprint,
            "kind": credential.kind,
            "username": credential.username,
            "secrets": secrets,
            "ca_bundle": os.environ.get("CCVM_WINRM_CA_BUNDLE") or None,
        }
        job.progress = 10
        job.message = "Authenticating and collecting read-only host evidence"
        db.commit()

        def cancelled():
            db.expire_all()
            current = db.get(HostAudit, audit.id)
            cred = db.get(AuditCredential, credential.id)
            if not current or current.cancel_requested or not cred or not cred.enabled:
                return True
            try:
                frozen_audit(db, job)
            except ValueError:
                return True
            return False

        data = host_inventory.collect(payload, cancelled=cancelled)
        # Recheck after collection as well; revocation/scope changes must not be
        # missed between the final poll and publishing a completed inventory.
        audit = (
            db.query(HostAudit)
            .filter(HostAudit.id == audit.id)
            .with_for_update()
            .populate_existing()
            .one()
        )
        credential = (
            db.query(AuditCredential)
            .filter(AuditCredential.id == credential.id)
            .with_for_update()
            .populate_existing()
            .one()
        )
        if cancelled():
            raise host_inventory.CollectionCancelled("Host audit cancelled or credential revoked")
        audit.inventory = host_inventory.normalize_inventory(data, credential.kind, audit.mode)
        incomplete = any(
            audit.inventory[section]["status"] in {"unavailable", "truncated"}
            for section in ("packages", "hotfixes")
        )
        job.status = "failed" if incomplete else "finished"
        if audit.mode == "connection":
            job.message = "Authenticated connection test finished; OS identity read successfully"
        else:
            job.message = (
                (
                    "Authenticated inventory incomplete; partial evidence retained. "
                    if incomplete
                    else "Authenticated inventory finished. "
                )
                + f"Packages: {len(audit.inventory['packages']['items'])}. "
                + f"Hotfixes: {len(audit.inventory['hotfixes']['items'])}."
            )
    except host_inventory.CollectionCancelled as error:
        job.status = "cancelled"
        job.message = str(error)
    except host_inventory.CollectionError as error:
        job.status = "failed"
        job.message = str(error)[:1000]
    except Exception:
        # Unlike legacy plugins, never let a transport/DB exception (possibly
        # containing encrypted blobs or credentials) reach worker tracebacks.
        db.rollback()
        job.status = "failed"
        job.message = "Host inventory failed; no transport or credential details were logged"
    job.progress = 100
    if audit:
        audit.completed_at = datetime.now(UTC)
    db.commit()
