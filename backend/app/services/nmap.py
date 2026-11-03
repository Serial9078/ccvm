"""Fixed Nmap commands, bounded private evidence, and strict XML scope checks."""

import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from app.services.network_scope import port_ranges

DATA_ROOT = Path(__file__).resolve().parents[2] / ".scanner-data" / "network-runs"
AUDIT_SCRIPTS = (
    "ssh2-enum-algos",
    "ssl-enum-ciphers",
    "ssl-cert",
    "smb-protocols",
    "smb2-security-mode",
    "rdp-enum-encryption",
)


def command(directory, targets, *, profile, ports, rate, timeout_seconds, audit=False):
    target_file = directory / "targets.txt"
    target_file.write_text("\n".join(targets) + "\n")
    selected = ["-p", ports] if ports else ["--top-ports", "100" if profile == "fast" else "1000"]
    if profile == "full" and not ports:
        selected = ["-p", "1-65535"]
    port_count = len(port_ranges(selected[1])[1]) if selected[0] == "-p" else int(selected[1])
    host_timeout = min(timeout_seconds, max(180, 120 + (port_count * 2 + rate - 1) // rate))
    args = [
        "nmap",
        "--unprivileged",
        "--noninteractive",
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "-n",
        "--max-retries",
        "1",
        "--max-rate",
        str(rate),
        "--max-parallelism",
        "10",
        "--host-timeout",
        f"{host_timeout}s",
        "--stats-every",
        "5s",
        *selected,
        "-oX",
        str(directory / "results.xml"),
        "-iL",
        str(target_file),
    ]
    if ipaddress.ip_address(targets[0]).version == 6:
        args.append("-6")
    if audit:
        args.extend(["-v", "--script", ",".join(AUDIT_SCRIPTS), "--script-timeout", "30s"])
    return args


@dataclass
class Execution:
    directory: Path
    returncode: int
    cancelled: bool = False
    timedout: bool = False


def run(scan_id, job_id, targets, *, profile, ports, rate, timeout_seconds, audit, update):
    root = Path(os.environ.get("CCVM_NETWORK_LOG_DIR", str(DATA_ROOT)))
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=f"scan-{scan_id}-job-{job_id}-", dir=root))
    args = command(
        directory,
        targets,
        profile=profile,
        ports=ports,
        rate=rate,
        timeout_seconds=timeout_seconds,
        audit=audit,
    )
    (directory / "command.json").write_text(json.dumps(args, indent=2))
    started, process = time.monotonic(), None
    execution = Execution(directory, 1)
    try:
        with (
            (directory / "stdout.log").open("w") as stdout,
            (directory / "stderr.log").open("w") as stderr,
        ):
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                text=True,
                start_new_session=True,
            )
            while process.poll() is None:
                elapsed = int(time.monotonic() - started)
                if update(elapsed, directory):
                    execution.cancelled = True
                    break
                if elapsed >= timeout_seconds:
                    execution.timedout = True
                    break
                time.sleep(2)
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            execution.returncode = process.returncode
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process is not None and process.returncode is not None:
            execution.returncode = process.returncode
        (directory / "execution.json").write_text(
            json.dumps(
                {
                    "returncode": execution.returncode,
                    "cancelled": execution.cancelled,
                    "timedout": execution.timedout,
                    "elapsed_seconds": int(time.monotonic() - started),
                },
                indent=2,
            )
        )
    return execution


def progress(directory):
    path = directory / "stdout.log"
    with path.open("rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(0, handle.tell() - 4096))
        lines = handle.read().decode(errors="replace").splitlines()
    for line in reversed(lines):
        match = re.search(r"About (\d+(?:\.\d+)?)% done", line)
        if match:
            return min(85, 10 + int(float(match[1]) * 0.75)), line.strip()[:300]
    return 10, "Port/service probes in progress"


def script_data(node):
    return {
        "id": node.get("id", ""),
        "output": node.get("output", ""),
        "xml": ET.tostring(node, encoding="unicode"),
    }


def partial_xml(data):
    parser = ET.XMLPullParser(events=("start", "end"))
    root, completed, stack = None, [], []
    try:
        for offset in range(0, len(data), 4096):
            parser.feed(data[offset : offset + 4096])
            for event, node in parser.read_events():
                if root is None and event == "start":
                    root = ET.Element(node.tag, node.attrib)
                if event == "start":
                    stack.append(node.tag)
                else:
                    if len(stack) == 2 and node.tag in {"scaninfo", "host"}:
                        completed.append(node)
                    stack.pop()
    except ET.ParseError:
        pass
    if root is None:
        raise ValueError("Nmap XML is incomplete; raw evidence retained")
    root.extend(completed)
    return root


def parse(path, targets, expected_ports=None, expected_count=None):
    if not path.exists() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Nmap XML is missing or exceeds the 64 MiB evidence limit")
    data = path.read_bytes()
    if b"<!ENTITY" in data.upper():
        raise ValueError("Nmap XML entity declarations are not allowed")
    incomplete = False
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        root = partial_xml(data)
        incomplete = True
    if root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise ValueError("Unexpected scanner XML")
    infos = root.findall("scaninfo")
    if len(infos) != 1 or infos[0].get("protocol") != "tcp":
        raise ValueError("Expected a single TCP scan")
    _, scanned = port_ranges(infos[0].get("services", ""))
    if (expected_ports is not None and scanned != set(expected_ports)) or (
        expected_count is not None and len(scanned) != expected_count
    ):
        raise ValueError("Nmap scanned ports do not match the frozen profile")
    allowed, hosts, errors = set(targets), {}, []
    if incomplete:
        errors.append("Nmap XML is incomplete; completed host records retained")
    for host in root.findall("host"):
        addresses = [
            str(ipaddress.ip_address(n.get("addr", "")))
            for n in host.findall("address")
            if n.get("addrtype") in {"ipv4", "ipv6"}
        ]
        if len(addresses) != 1 or addresses[0] not in allowed or addresses[0] in hosts:
            raise ValueError("Nmap returned an out-of-scope or duplicate host")
        address = addresses[0]
        entries = []
        seen_ports = set()
        for port in host.findall("./ports/port"):
            number = int(port.get("portid", "0"))
            if port.get("protocol") != "tcp" or number not in scanned or number in seen_ports:
                raise ValueError("Nmap returned an out-of-profile port")
            seen_ports.add(number)
            service = port.find("service")
            attributes = service.attrib if service is not None else {}
            state = port.find("state")
            entries.append(
                {
                    "port": number,
                    "protocol": "tcp",
                    "state": state.get("state", "unknown") if state is not None else "unknown",
                    "service": attributes.get("name"),
                    "product": attributes.get("product"),
                    "version": attributes.get("version"),
                    "extra_info": attributes.get("extrainfo"),
                    "tunnel": attributes.get("tunnel"),
                    "method": attributes.get("method"),
                    "confidence": int(attributes.get("conf", "0")),
                    "cpe": (
                        [n.text or "" for n in service.findall("cpe")]
                        if service is not None
                        else []
                    ),
                    "scripts": [script_data(n) for n in port.findall("script")],
                }
            )
        extras = [
            (n.get("state", "unknown"), int(n.get("count", "0")))
            for n in host.findall("./ports/extraports")
        ]
        if any(count < 0 for _, count in extras):
            raise ValueError("Nmap returned an invalid port count")
        tested = len(entries) + sum(count for _, count in extras)
        if host.get("timedout") == "true" or tested != len(scanned):
            errors.append(f"{address}: incomplete TCP coverage ({tested}/{len(scanned)})")
        hosts[address] = {
            "ip": address,
            "ports": entries,
            "extraports": extras,
            "scripts": [script_data(n) for n in host.findall("./hostscript/script")],
        }
    for address in sorted(allowed - hosts.keys()):
        errors.append(f"{address}: no completed host record")
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("exit") != "success":
        errors.append("Nmap did not report successful completion")
    for host in hosts.values():
        for item in host["scripts"] + [script for p in host["ports"] for script in p["scripts"]]:
            if "ERROR:" in item["output"]:
                errors.append(f"{host['ip']}: {item['id']} returned an error")
    return {
        "hosts": hosts,
        "ports": scanned,
        "errors": errors,
        "version": root.get("version", "unknown")[:100],
    }
