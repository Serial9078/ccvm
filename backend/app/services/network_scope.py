"""Canonical literal-address scopes; expansion is bounded after exclusions."""

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass

MAX_TARGETS = 4096
PROFILE_PORTS = {"fast": 100, "standard": 1000, "full": 65535}


def allowed_networks():
    values = re.split(r"[,\s]+", os.environ.get("CCVM_NETWORK_ALLOWED_CIDRS", "").strip())
    return [network(value) for value in values if value]


def verify_scanner_scope(targets):
    allowed = allowed_networks()
    if not allowed:
        raise ValueError("Network scanning is disabled: configure this scanner's allowed CIDRs")
    for value in targets:
        address = ipaddress.ip_address(value)
        if not any(address.version == net.version and address in net for net in allowed):
            raise ValueError(f"Target {address} is outside this scanner's configured networks")


def network(value: str):
    if "%" in value:
        raise ValueError("Scoped IPv6 addresses are not supported")
    try:
        result = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise ValueError("Use a literal IPv4/IPv6 address or CIDR network") from error
    if result.is_multicast or result.network_address.is_unspecified:
        raise ValueError("Multicast and unspecified targets are not supported")
    if result.version == 6 and result.is_link_local:
        raise ValueError("IPv6 link-local targets require an interface and are not supported")
    return result


def port_ranges(value: str) -> tuple[str, frozenset[int]]:
    ports = set()
    if not value or len(value) > 2000:
        raise ValueError("Specify TCP ports or ranges, for example 22,443,445,3389")
    for item in value.split(","):
        if not re.fullmatch(r"\s*\d{1,5}(?:-\d{1,5})?\s*", item):
            raise ValueError("Ports must be comma-separated numbers or ranges")
        numbers = item.strip().split("-")
        start, end = int(numbers[0]), int(numbers[-1])
        if not 1 <= start <= end <= 65535:
            raise ValueError("TCP ports must be between 1 and 65535")
        ports.update(range(start, end + 1))
    ranges = []
    start = previous = None
    for port in sorted(ports):
        if previous is not None and port != previous + 1:
            ranges.append(str(start) if start == previous else f"{start}-{previous}")
            start = None
        if start is None:
            start = port
        previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges), frozenset(ports)


@dataclass(frozen=True)
class Scope:
    target: str
    targets: list[str]
    exclusions: list[str]
    version: int
    ports: str | None
    port_count: int
    minimum_seconds: int


def build_scope(target, exclusions, profile, ports, rate, timeout_seconds) -> Scope:
    net = network(target)
    if len(exclusions) > 256:
        raise ValueError("At most 256 exclusions are supported")
    first, last = int(net.network_address), int(net.broadcast_address)
    if net.version == 4 and net.prefixlen < 31:
        first, last = first + 1, last - 1
    elif net.version == 6 and net.prefixlen < 127:
        first += 1
    intervals, normalized = [(first, last)], []
    for value in exclusions:
        excluded = network(value)
        if excluded.version != net.version:
            raise ValueError("Targets and exclusions must use the same IP version")
        normalized.append(str(excluded))
        lo, hi = int(excluded.network_address), int(excluded.broadcast_address)
        updated = []
        for start, end in intervals:
            if hi < start or lo > end:
                updated.append((start, end))
            else:
                if start < lo:
                    updated.append((start, lo - 1))
                if hi < end:
                    updated.append((hi + 1, end))
        intervals = updated
    count = sum(end - start + 1 for start, end in intervals)
    if not 0 < count <= MAX_TARGETS:
        raise ValueError(f"Select between 1 and {MAX_TARGETS} addresses after exclusions")
    if profile == "custom":
        canonical_ports, selected_ports = port_ranges(ports or "")
        port_count = len(selected_ports)
    elif profile in PROFILE_PORTS and not ports:
        canonical_ports, port_count = None, PROFILE_PORTS[profile]
    else:
        raise ValueError("Choose fast, standard, full, or custom with explicit TCP ports")
    if not 10 <= rate <= 1000 or not 60 <= timeout_seconds <= 86400:
        raise ValueError("Portscan rate must be 10–1000/s and timeout 60–86400 seconds")
    minimum = (count * port_count + rate - 1) // rate
    if minimum > timeout_seconds:
        raise ValueError(
            "The portscan alone exceeds this budget; reduce scope/ports or increase time"
        )
    address = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
    targets = [str(address(number)) for start, end in intervals for number in range(start, end + 1)]
    return Scope(
        str(net),
        targets,
        sorted(set(normalized)),
        net.version,
        canonical_ports,
        port_count,
        minimum,
    )


def scope_hash(scope: Scope, profile, rate, timeout_seconds, customer_id):
    payload = {
        "customer_id": customer_id,
        "target": scope.target,
        "targets": scope.targets,
        "exclusions": scope.exclusions,
        "profile": profile,
        "ports": scope.ports,
        "rate": rate,
        "timeout": timeout_seconds,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
