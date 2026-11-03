"""Findings require protocol evidence; banners/CPEs alone never create CVEs."""

import re
import xml.etree.ElementTree as ET


def completed(script):
    if "ERROR:" in script["output"]:
        return False
    node = ET.fromstring(script["xml"])
    if script["id"] == "ssh2-enum-algos":
        return any(
            (table.get("key") or "").startswith("kex_algorithms")
            and any(n.text for n in table.findall("elem"))
            for table in node.iter("table")
        )
    if script["id"] == "ssl-enum-ciphers":
        return any(
            (table.get("key") or "").startswith(("TLS", "SSL"))
            and table.find("table[@key='ciphers']") is not None
            and len(table.find("table[@key='ciphers']")) > 0
            for table in node.findall("table")
        )
    if script["id"] == "smb-protocols":
        return bool(node.findall("table[@key='dialects']/elem"))
    if script["id"] == "smb2-security-mode":
        return bool(
            re.search(
                r"Message signing (?:enabled (?:and required|but not required)|(?:is )?disabled)",
                script["output"],
            )
        )
    if script["id"] == "rdp-enum-encryption":
        return bool(re.search(r":\s*SUCCESS", script["output"]))
    return bool(script["output"])


def smb2_advertised(scripts):
    return any(
        re.fullmatch(r"[23](?:\.\d+)+", (node.text or "").strip())
        for script in scripts
        if script["id"] == "smb-protocols"
        for node in ET.fromstring(script["xml"]).findall("table[@key='dialects']/elem")
    )


def checks_for(service):
    if service.get("method") != "probed":
        return []
    name = service.get("service") or ""
    result = []
    if name == "ssh":
        result.append("ssh2-enum-algos")
    if service.get("tunnel") == "ssl" or name in {"https", "ssl"}:
        result.append("ssl-enum-ciphers")
    if name in {"microsoft-ds", "netbios-ssn"}:
        result.append("smb-protocols")
    if name == "ms-wbt-server":
        result.append("rdp-enum-encryption")
    return result


def coverage_for(service, audit_status):
    checks = service.get("checks") or []
    if checks:
        if any(check.get("status") not in {"completed", "host-level"} for check in checks):
            return "unavailable"
        return (
            "shared"
            if any(check.get("status") == "host-level" for check in checks)
            else "completed"
        )
    if not checks_for(service):
        return "no_rule"
    if audit_status in {"queued", "running"}:
        return "pending"
    if audit_status in {"cancelled", "skipped"}:
        return "not_run"
    return "unavailable"


def findings(service, scripts):
    result = []

    def add(key, name, severity, detail, remediation, script):
        result.append(
            {
                "key": key,
                "name": name,
                "severity": severity,
                "description": detail,
                "remediation": remediation,
                "script": script,
            }
        )

    for script in scripts:
        if "ERROR:" in script["output"]:
            continue
        identifier, output = script["id"], script["output"]
        node = ET.fromstring(script["xml"])
        if identifier == "ssh2-enum-algos":
            kex = {
                n.text.strip()
                for table in node.iter("table")
                if (table.get("key") or "").startswith("kex_algorithms")
                for n in table.findall("elem")
                if n.text
            }
            ciphers = {
                n.text.strip()
                for table in node.iter("table")
                if (table.get("key") or "").startswith("encryption_algorithms")
                for n in table.findall("elem")
                if n.text
            }
            weak_kex = kex & {
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1",
            }
            weak_cipher = ciphers & {
                "arcfour",
                "arcfour128",
                "arcfour256",
                "3des-cbc",
                "blowfish-cbc",
                "cast128-cbc",
                "des-cbc",
            }
            if weak_kex:
                add(
                    "ssh-legacy-kex",
                    "Legacy SSH key exchange offered",
                    "low",
                    "The SSH server advertised: " + ", ".join(sorted(weak_kex)),
                    "Disable SHA-1 key exchange and prefer current SHA-2/ECDH algorithms.",
                    script,
                )
            if weak_cipher:
                add(
                    "ssh-weak-ciphers",
                    "Weak SSH ciphers offered",
                    "medium",
                    "The SSH server advertised: " + ", ".join(sorted(weak_cipher)),
                    "Disable RC4, DES and other obsolete SSH ciphers.",
                    script,
                )
        elif identifier == "ssl-enum-ciphers":
            legacy = [
                n.get("key")
                for n in node.findall("table")
                if n.get("key") in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
                and n.find("table[@key='ciphers']") is not None
                and len(n.find("table[@key='ciphers']")) > 0
            ]
            if legacy:
                add(
                    "tls-legacy-protocol",
                    "Legacy TLS/SSL protocols accepted",
                    "medium",
                    "The endpoint completed cipher enumeration for: " + ", ".join(legacy),
                    "Disable SSL and TLS 1.0/1.1; use TLS 1.2 or TLS 1.3.",
                    script,
                )
        elif identifier == "smb-protocols":
            dialects = [n.text or "" for n in node.findall("table[@key='dialects']/elem")]
            if any(
                re.fullmatch(r"NT LM 0\.12(?: \(SMBv1\))?(?: \[[^\]]+\])?", value)
                for value in dialects
            ):
                add(
                    "smb1-enabled",
                    "SMBv1 dialect accepted",
                    "high",
                    "The SMB server accepted the legacy SMBv1 dialect.",
                    "Disable SMBv1 and use SMB2/SMB3 after checking client compatibility.",
                    script,
                )
        elif identifier == "smb2-security-mode":
            if re.search(r"Message signing (?:enabled but not required|(?:is )?disabled)", output):
                add(
                    "smb-signing-optional",
                    "SMB signing is not required",
                    "medium",
                    "SMB negotiation reported that message signing is optional or disabled.",
                    "Require SMB signing on servers and clients where supported.",
                    script,
                )
        elif identifier == "rdp-enum-encryption":
            if re.search(r"(?:Native RDP|SSL)\s*:\s*SUCCESS", output):
                add(
                    "rdp-without-nla",
                    "RDP accepts a security layer without NLA",
                    "medium",
                    "RDP negotiation accepted a native RDP or SSL security layer without CredSSP.",
                    "Require Network Level Authentication and restrict RDP reachability.",
                    script,
                )
    return result
