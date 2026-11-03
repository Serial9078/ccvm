"""Customer-scoped TCP discovery and a fixed set of protocol configuration audits."""

import ipaddress
import json

from sqlalchemy import or_

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.host import Host
from app.models.network_scan import NetworkObservation, NetworkScan
from app.models.port import Port
from app.services import network_rules, nmap
from app.services.network_scope import build_scope, port_ranges, scope_hash, verify_scanner_scope


def frozen_scan(db, job, audit):
    column = NetworkScan.audit_job_id if audit else NetworkScan.discovery_job_id
    scan = db.query(NetworkScan).filter(column == job.id).one_or_none()
    if not scan:
        raise ValueError("Network scan snapshot not found for this job")
    root = db.get(Asset, scan.asset_id)
    if (
        not root
        or root.customer_id != scan.customer_id
        or job.asset_id != scan.asset_id
        or job.pipeline_id != scan.pipeline_id
        or job.domain_id is not None
        or job.parent_job_id != (scan.discovery_job_id if audit else None)
    ):
        raise ValueError("Network job/customer/pipeline identity changed")
    scope = build_scope(
        scan.target, scan.exclusions, scan.profile, scan.ports, scan.rate, scan.timeout_seconds
    )
    if scan.targets != scope.targets or scan.scope_sha256 != scope_hash(
        scope, scan.profile, scan.rate, scan.timeout_seconds, scan.customer_id
    ):
        raise ValueError("Frozen network scope changed; no probe started")
    verify_scanner_scope(scope.targets)
    if audit and scan.discovery_job.status != "finished":
        raise ValueError("Network discovery must finish before protocol audits")
    return scan, scope, root


def host_inventory(db, scan, root, address, services):
    host = (
        db.query(Host)
        .filter(
            Host.customer_id == scan.customer_id,
            Host.domain_id.is_(None),
            Host.source == "nmap-network",
            Host.ip_address == address,
        )
        .order_by(Host.id)
        .first()
    )
    if not host and not services:
        return None, None
    if not host:
        host = Host(
            customer_id=scan.customer_id,
            hostname=address,
            ip_address=address,
            alive=True,
            source="nmap-network",
        )
        db.add(host)
        db.flush()
    if services:
        host.alive = True  # Positive observations; silence never proves a host dead.
    asset = (
        db.query(Asset)
        .filter(
            Asset.customer_id == scan.customer_id,
            Asset.type.notin_(["url", "fqdn", "network"]),
            or_(Asset.target == address, Asset.ip_address == address),
        )
        .order_by(Asset.id)
        .first()
    )
    if not asset:
        asset = Asset(
            customer_id=scan.customer_id,
            target=address,
            ip_address=address,
            type="ip",
            name=address,
            exposure=root.exposure,
            environment=root.environment,
            criticality=root.criticality,
        )
        db.add(asset)
        db.flush()
    return host, asset


def update_ports(db, host, report_host, scanned):
    existing = db.query(Port).filter(Port.host_id == host.id, Port.protocol == "tcp").all()
    by_number = {port.port: port for port in existing}
    explicit = {item["port"]: item for item in report_host["ports"]}
    remaining = report_host["extraports"]
    implicit = remaining[0][0] if len(remaining) == 1 else "not_observed"
    for port in existing:
        if port.port in scanned:
            port.state = explicit.get(port.port, {}).get("state", implicit)
    for item in report_host["ports"]:
        if item["state"] != "open":
            continue
        port = by_number.get(item["port"])
        if not port:
            port = Port(host_id=host.id, port=item["port"], protocol="tcp")
            db.add(port)
        port.state = "open"
        port.service = (item["service"] or "unknown")[:100]
        port.product, port.version, port.tunnel = item["product"], item["version"], item["tunnel"]
        port.cpe, port.source = item["cpe"], "nmap-network"
        port.banner = (
            " ".join(
                str(item.get(key) or "") for key in ("product", "version", "extra_info")
            ).strip()[:500]
            or None
        )


def import_discovery(db, scan, root, report):
    positive = set()
    for address, item in report["hosts"].items():
        services = [port for port in item["ports"] if port["state"] == "open"]
        host, asset = host_inventory(db, scan, root, address, services)
        if host:
            update_ports(db, host, item, report["ports"])
        if not services:
            continue
        positive.add(address)
        observation = (
            db.query(NetworkObservation).filter_by(scan_id=scan.id, ip_address=address).first()
        )
        if not observation:
            observation = NetworkObservation(
                scan_id=scan.id,
                host_id=host.id,
                asset_id=asset.id,
                ip_address=address,
                services=services,
            )
            db.add(observation)
        else:
            observation.services = services
    if not report["errors"]:
        for observation in db.query(NetworkObservation).filter_by(scan_id=scan.id).all():
            if observation.ip_address not in positive:
                db.delete(observation)
    scan.hosts_checked = len(report["hosts"])
    scan.open_services = sum(
        port["state"] == "open" for host in report["hosts"].values() for port in host["ports"]
    )
    scan.scanner_version = report["version"]
    scan.scanned_ports = sorted(report["ports"])


def store_finding(db, scan, job, observation, service, item):
    address = observation.ip_address
    host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    matched = f"tcp://{host}:{service['port']}"
    key = "nmap:" + item["key"]
    finding = (
        db.query(Finding)
        .filter_by(
            asset_id=observation.asset_id,
            scanner="network-audit",
            template_id=key,
            matched_at=matched,
        )
        .order_by(Finding.id)
        .first()
    )
    created = finding is None
    if created:
        finding = Finding(
            asset_id=observation.asset_id,
            scanner="network-audit",
            template_id=key,
            matched_at=matched,
            name=item["name"],
        )
        db.add(finding)
    finding.job_id, finding.host = job.id, address
    finding.name, finding.severity = item["name"], item["severity"]
    finding.description, finding.remediation = item["description"], item["remediation"]
    finding.reference = "https://nmap.org/nsedoc/scripts/" + item["script"]["id"] + ".html"
    finding.raw_json = json.dumps(
        {
            "scan_id": scan.id,
            "pipeline_id": scan.pipeline_id,
            "ip": address,
            "service": service,
            "evidence": item["script"],
        }
    )
    finding.status = "open"
    db.flush()  # The real worker uses autoflush=False; duplicate evidence stays idempotent.
    return created


def import_audit(db, scan, job, report):
    created = updated = 0
    completed_checks = unavailable_checks = unaudited_services = 0
    for observation in db.query(NetworkObservation).filter_by(scan_id=scan.id).all():
        asset, host = db.get(Asset, observation.asset_id), db.get(Host, observation.host_id)
        if (
            not asset
            or not host
            or asset.customer_id != scan.customer_id
            or host.customer_id != scan.customer_id
        ):
            raise ValueError("Observed host/customer identity changed")
        item = report["hosts"].get(observation.ip_address)
        if not item:
            continue
        update_ports(db, host, item, report["ports"])
        services = [port for port in item["ports"] if port["state"] == "open"]
        smb = next(
            (
                p["port"]
                for p in sorted(services, key=lambda p: p["port"] != 445)
                if p["service"] in {"microsoft-ds", "netbios-ssn"} or p["port"] in {139, 445}
            ),
            None,
        )
        for service in services:
            scripts = list(service["scripts"])
            if service["port"] == smb:
                scripts += item["scripts"]
            scripts = [s for s in scripts if s["id"] in nmap.AUDIT_SCRIPTS]
            available = {s["id"] for s in scripts if network_rules.completed(s)}
            expected = set(network_rules.checks_for(service)) | {
                script["id"]
                for script in scripts
                if script["id"]
                in {"ssh2-enum-algos", "ssl-enum-ciphers", "smb-protocols", "rdp-enum-encryption"}
            }
            if any(script["id"] == "ssl-cert" for script in scripts):
                expected.add("ssl-enum-ciphers")
            service["checks"] = [
                {
                    "check": check,
                    "status": "completed" if check in available else "unavailable",
                    "output": next(
                        (script["output"] for script in scripts if script["id"] == check),
                        "No enumeration result returned",
                    ),
                }
                for check in sorted(expected)
            ]
            completed_checks += len(expected & available)
            unavailable_checks += len(expected - available)
            unaudited_services += not expected
            missing = [
                check["check"] for check in service["checks"] if check["status"] == "unavailable"
            ]
            if missing:
                report["errors"].append(
                    f"{observation.ip_address}:{service['port']}: checks unavailable: "
                    + ", ".join(missing)
                )
            for finding in network_rules.findings(service, scripts):
                if store_finding(db, scan, job, observation, service, finding):
                    created += 1
                else:
                    updated += 1
        observation.services = services
    scan.findings_created, scan.findings_updated = created, updated
    scan.open_services = sum(
        len(obs.services) for obs in db.query(NetworkObservation).filter_by(scan_id=scan.id)
    )
    report["audit_summary"] = (
        f"Checks completed: {completed_checks}. "
        f"Unavailable: {unavailable_checks}. "
        f"Services without an applicable audit: {unaudited_services}"
    )
    return created, updated


def execute(db, job, *, audit):
    scan, scope, root = frozen_scan(db, job, audit)
    if scan.cancel_requested:
        job.status, job.progress, job.message = "cancelled", 100, "Network scan cancelled"
        db.commit()
        return
    targets, ports, expected_count = scope.targets, scan.ports, scope.port_count
    if audit:
        observations = db.query(NetworkObservation).filter_by(scan_id=scan.id).all()
        targets = sorted(observation.ip_address for observation in observations)
        if any(address not in scope.targets for address in targets):
            raise ValueError("Network audit observations escaped the frozen scope")
        selected = sorted(
            {
                int(service["port"])
                for observation in observations
                for service in observation.services
            }
        )
        if not targets or not selected:
            job.status, job.progress = "finished", 100
            job.message = "Network audit finished: no open TCP services in the selected profile"
            db.commit()
            return
        ports, checked = port_ranges(",".join(map(str, selected)))
        if not scan.scanned_ports or not checked <= set(scan.scanned_ports):
            raise ValueError("Network audit ports escaped the discovery profile")
        expected_count = len(checked)
    label = "Network audit" if audit else "Network discovery"
    job.progress, job.message = 5, label + f" starting for {len(targets)} addresses"
    db.commit()

    def update(elapsed, directory):
        db.refresh(scan)
        if scan.cancel_requested:
            return True
        value, line = nmap.progress(directory)
        job.progress = max(job.progress, value)
        job.message = f"{label} running. Addresses: {len(targets)}. Elapsed: {elapsed}s. {line}"
        db.commit()
        return False

    execution = nmap.run(
        scan.id,
        job.id,
        targets,
        profile=scan.profile,
        ports=ports,
        rate=scan.rate,
        timeout_seconds=scan.timeout_seconds,
        audit=audit,
        update=update,
    )
    errors = []
    if execution.returncode:
        errors.append(f"Nmap exit code {execution.returncode}")
    if execution.timedout:
        errors.append(f"execution timeout after {scan.timeout_seconds}s")
    try:
        expected_ports = port_ranges(ports)[1] if ports else None
        report = nmap.parse(
            execution.directory / "results.xml",
            targets,
            expected_ports=expected_ports,
            expected_count=expected_count,
        )
        if audit:
            created, updated = import_audit(db, scan, job, report)
            summary = f"Created: {created}. Updated: {updated}. {report['audit_summary']}"
        else:
            import_discovery(db, scan, root, report)
            summary = (
                f"Hosts checked: {scan.hosts_checked}/{len(targets)}. "
                f"Open TCP services: {scan.open_services}"
            )
        errors.extend(report["errors"])
    except ValueError as error:
        summary = "No complete import"
        errors.append(str(error))
    job.status = "cancelled" if execution.cancelled else "failed" if errors else "finished"
    job.progress = 100
    job.message = (f"{label} {job.status}. {summary}. " + "; ".join(errors[:3]))[:1000]
    print(
        f"Network scan {scan.id}, job {job.id}: evidence retained at {execution.directory}",
        flush=True,
    )
    db.commit()


def run_networkdiscovery(db, job):
    execute(db, job, audit=False)


def run_networkaudit(db, job):
    execute(db, job, audit=True)
