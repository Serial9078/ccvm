import json
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.domain import Domain
from app.models.finding import Finding
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.models.url_security import UrlSecurity


@dataclass(frozen=True)
class HeaderRule:
    key: str
    template_id: str
    name: str
    severity: str
    description: str
    remediation: str
    reference: str


HEADER_RULES = [
    HeaderRule(
        key="hsts",
        template_id="ccvm-missing-hsts",
        name="Missing HTTP Strict Transport Security",
        severity="medium",
        description=(
            "The HTTPS service does not send the "
            "Strict-Transport-Security header. "
            "Without HSTS, browsers may initially connect over HTTP "
            "and can be exposed to protocol downgrade attacks."
        ),
        remediation=(
            "Enable Strict-Transport-Security on the HTTPS virtual host. "
            "A common starting value is "
            "'max-age=31536000; includeSubDomains'. "
            "Only add 'preload' after validating all subdomains."
        ),
        reference=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/" "Headers/Strict-Transport-Security"
        ),
    ),
    HeaderRule(
        key="csp",
        template_id="ccvm-missing-csp",
        name="Missing Content Security Policy",
        severity="medium",
        description=(
            "The web application does not send a "
            "Content-Security-Policy header. "
            "A CSP can reduce the impact of cross-site scripting "
            "and other content-injection vulnerabilities."
        ),
        remediation=(
            "Define and deploy a restrictive Content-Security-Policy. "
            "Begin with Content-Security-Policy-Report-Only, "
            "review violations and then enforce the validated policy."
        ),
        reference=("https://developer.mozilla.org/en-US/docs/Web/HTTP/" "CSP"),
    ),
    HeaderRule(
        key="xfo",
        template_id="ccvm-missing-x-frame-options",
        name="Missing X-Frame-Options",
        severity="medium",
        description=(
            "The web application does not send the X-Frame-Options "
            "header. The application may therefore be embedded in "
            "another site and exposed to clickjacking attacks."
        ),
        remediation=(
            "Set X-Frame-Options to DENY or SAMEORIGIN. "
            "Prefer the CSP frame-ancestors directive for modern "
            "applications and keep X-Frame-Options for compatibility."
        ),
        reference=("https://developer.mozilla.org/en-US/docs/Web/HTTP/" "Headers/X-Frame-Options"),
    ),
    HeaderRule(
        key="xcto",
        template_id="ccvm-missing-x-content-type-options",
        name="Missing X-Content-Type-Options",
        severity="low",
        description=(
            "The X-Content-Type-Options header is missing. "
            "Browsers may attempt MIME-type sniffing instead of "
            "respecting the declared Content-Type."
        ),
        remediation=(
            "Set the response header " "'X-Content-Type-Options: nosniff' " "for all web responses."
        ),
        reference=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/" "Headers/X-Content-Type-Options"
        ),
    ),
    HeaderRule(
        key="referrer",
        template_id="ccvm-missing-referrer-policy",
        name="Missing Referrer Policy",
        severity="low",
        description=(
            "The web application does not define a Referrer-Policy. "
            "Sensitive path or query information may be disclosed "
            "to external destinations through the Referer header."
        ),
        remediation=(
            "Set a suitable Referrer-Policy, such as "
            "'strict-origin-when-cross-origin' or "
            "'no-referrer', according to application requirements."
        ),
        reference=("https://developer.mozilla.org/en-US/docs/Web/HTTP/" "Headers/Referrer-Policy"),
    ),
    HeaderRule(
        key="permissions",
        template_id="ccvm-missing-permissions-policy",
        name="Missing Permissions Policy",
        severity="low",
        description=(
            "The web application does not send a Permissions-Policy "
            "header. Browser capabilities such as camera, microphone "
            "or geolocation are therefore not explicitly restricted."
        ),
        remediation=(
            "Define a Permissions-Policy that disables unused browser "
            "features and explicitly allows only required capabilities."
        ),
        reference=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/" "Headers/Permissions-Policy"
        ),
    ),
]


def fail_job(
    db: Session,
    job: Job,
    message: str,
) -> None:
    db.rollback()

    current_job = db.get(Job, job.id)

    if not current_job:
        return

    current_job.status = "failed"
    current_job.progress = 100
    current_job.message = message[:1000]

    db.commit()


def finish_job(
    db: Session,
    job: Job,
    message: str,
) -> None:
    current_job = db.get(Job, job.id)

    if not current_job:
        return

    current_job.status = "finished"
    current_job.progress = 100
    current_job.message = message[:1000]

    db.commit()


def normalize_origin(
    value: str,
) -> str | None:
    parsed = urlparse(value)

    if not parsed.scheme or not parsed.hostname:
        return None

    hostname = parsed.hostname.lower()
    port = parsed.port

    default_port = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )

    if port and not default_port:
        return f"{parsed.scheme}://{hostname}:{port}"

    return f"{parsed.scheme}://{hostname}"


def missing_rule_keys(
    security: UrlSecurity,
    origin: str,
) -> set[str]:
    missing: set[str] = set()

    if origin.startswith("https://") and not security.hsts_present:
        missing.add("hsts")

    if not security.csp_present:
        missing.add("csp")

    if not security.xfo_present:
        missing.add("xfo")

    if not security.xcto_present:
        missing.add("xcto")

    if not security.referrer_policy_present:
        missing.add("referrer")

    if not security.permissions_policy_present:
        missing.add("permissions")

    return missing


def get_default_asset(
    db: Session,
    domain: Domain,
) -> Asset | None:
    return (
        db.query(Asset)
        .filter(
            Asset.customer_id == domain.customer_id,
        )
        .order_by(Asset.id.asc())
        .first()
    )


def run_headerfindings(
    db: Session,
    job: Job,
) -> None:
    domain = db.get(
        Domain,
        job.domain_id,
    )

    if not domain:
        fail_job(
            db,
            job,
            "Domain not found",
        )
        return

    asset = get_default_asset(
        db,
        domain,
    )

    if not asset:
        fail_job(
            db,
            job,
            ("No customer asset found for " "header findings"),
        )
        return

    rows = (
        db.query(
            Url,
            UrlDetail,
            UrlSecurity,
        )
        .join(
            UrlDetail,
            UrlDetail.url_id == Url.id,
        )
        .join(
            UrlSecurity,
            UrlSecurity.url_id == Url.id,
        )
        .filter(
            Url.domain_id == domain.id,
            UrlDetail.content_type.ilike("%text/html%"),
            UrlSecurity.error.is_(None),
            UrlSecurity.security_score.is_not(None),
        )
        .order_by(Url.id.asc())
        .all()
    )

    if not rows:
        fail_job(
            db,
            job,
            ("No successfully analysed HTML URLs " "found for HeaderFindings"),
        )
        return

    job.status = "running"
    job.progress = 10
    job.message = f"Correlating security headers for " f"{len(rows)} HTML URLs"
    db.commit()

    origin_data: dict[str, dict] = {}

    for url_record, detail, security in rows:
        checked_url = security.checked_url or detail.final_url or url_record.url

        origin = normalize_origin(checked_url)

        if not origin:
            continue

        current = origin_data.setdefault(
            origin,
            {
                "representative_url": checked_url,
                "missing": set(),
                "security_score": security.security_score,
                "server": (security.server or detail.webserver),
            },
        )

        current["missing"].update(
            missing_rule_keys(
                security,
                origin,
            )
        )

        if security.security_score < current["security_score"]:
            current["security_score"] = security.security_score
            current["representative_url"] = checked_url
            current["server"] = security.server or detail.webserver

    created = 0
    reopened = 0
    updated = 0
    fixed = 0

    rules_by_key = {rule.key: rule for rule in HEADER_RULES}

    total_origins = max(
        len(origin_data),
        1,
    )

    for index, (
        origin,
        data,
    ) in enumerate(
        origin_data.items(),
        start=1,
    ):
        active_template_ids: set[str] = set()

        for rule_key in data["missing"]:
            rule = rules_by_key[rule_key]

            active_template_ids.add(rule.template_id)

            existing = (
                db.query(Finding)
                .filter(
                    Finding.scanner == "headerprobe",
                    Finding.template_id == rule.template_id,
                    Finding.host == origin,
                )
                .order_by(Finding.id.desc())
                .first()
            )

            raw_data = {
                "origin": origin,
                "representative_url": (data["representative_url"]),
                "header": rule.name,
                "security_score": (data["security_score"]),
                "server": data["server"],
            }

            if existing:
                was_fixed = existing.status == "fixed"

                existing.asset_id = asset.id
                existing.job_id = job.id
                existing.severity = rule.severity
                existing.name = rule.name
                existing.description = rule.description
                existing.remediation = rule.remediation
                existing.reference = rule.reference
                existing.matched_at = data["representative_url"]
                existing.raw_json = json.dumps(raw_data)
                existing.status = "open"

                if was_fixed:
                    reopened += 1
                else:
                    updated += 1

            else:
                db.add(
                    Finding(
                        asset_id=asset.id,
                        job_id=job.id,
                        scanner="headerprobe",
                        template_id=(rule.template_id),
                        name=rule.name,
                        severity=(rule.severity),
                        host=origin,
                        matched_at=(data["representative_url"]),
                        description=(rule.description),
                        remediation=(rule.remediation),
                        reference=(rule.reference),
                        cve=None,
                        cvss_score=None,
                        raw_json=(json.dumps(raw_data)),
                        status="open",
                    )
                )

                created += 1

        existing_origin_findings = (
            db.query(Finding)
            .filter(
                Finding.scanner == "headerprobe",
                Finding.host == origin,
                Finding.status == "open",
            )
            .all()
        )

        for finding in existing_origin_findings:
            if finding.template_id not in active_template_ids:
                finding.status = "fixed"
                finding.job_id = job.id
                fixed += 1

        current_job = db.get(
            Job,
            job.id,
        )

        if current_job:
            current_job.progress = min(
                95,
                10 + int(index / total_origins * 85),
            )

            current_job.message = (
                f"HeaderFindings processed "
                f"{index}/{total_origins} "
                f"origins. Created: {created}, "
                f"reopened: {reopened}, "
                f"fixed: {fixed}"
            )

            db.commit()

    finish_job(
        db,
        job,
        (
            "HeaderFindings finished. "
            f"Origins analysed: "
            f"{len(origin_data)}. "
            f"Created: {created}. "
            f"Updated: {updated}. "
            f"Reopened: {reopened}. "
            f"Fixed: {fixed}"
        ),
    )
