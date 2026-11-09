"""Fixed read-only WMI enumeration over WS-Man, without any remote shell.

This module uses only the standard library so the isolated transport can load
its reviewed sibling without importing application configuration or credentials.
"""

import ipaddress
import re
import uuid
import xml.etree.ElementTree as ET
from time import monotonic
from urllib.parse import urlsplit

SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDR = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
ENUM = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
MS_WSMAN = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
WMI = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/"
OS_CLASS = "Win32_OperatingSystem"
QFE_CLASS = "Win32_QuickFixEngineering"
MAX_RESPONSE = 256 * 1024
MAX_TOTAL_RESPONSE = 8 * 1024 * 1024
MAX_HOTFIXES = 10000
MAX_PAGES = 128
COLLECTION_METHOD = "cim"
OS_FIELDS = (
    "Caption",
    "Version",
    "BuildNumber",
    "OSArchitecture",
    "CSName",
    "ProductType",
    "OperatingSystemSKU",
)


class CimError(ValueError):
    def __init__(self, code="cim_invalid_response"):
        self.code = code
        super().__init__(code)


class CimLimit(CimError):
    def __init__(self):
        super().__init__("cim_incomplete_response")


def _element(parent, namespace, name, value=None, **attributes):
    child = ET.SubElement(parent, "{" + namespace + "}" + name, attributes)
    if value is not None:
        child.text = str(value)
    return child


def _endpoint(value):
    try:
        parsed = urlsplit(value)
        ipaddress.ip_address(parsed.hostname)
        if (
            parsed.scheme not in {"http", "https"}
            or "%" in parsed.hostname
            or parsed.username
            or parsed.password
            or not 1 <= parsed.port <= 65535
            or parsed.path != "/wsman"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise CimError("invalid_request") from None
    return value


def _parse(response, operation, message_id):
    if not isinstance(response, bytes) or len(response) > MAX_RESPONSE:
        raise CimError()
    try:
        document = response.decode("utf-8", errors="strict")
        if (
            any(value in document.upper() for value in ("<!DOCTYPE", "<!ENTITY"))
            or "\x00" in document
        ):
            raise ValueError
        root = ET.fromstring(document)
    except (ValueError, UnicodeDecodeError, ET.ParseError):
        raise CimError() from None
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 32 or count > 20000:
            raise CimError()
        pending.extend((child, depth + 1) for child in node)
    headers = root.findall("{" + SOAP + "}Header")
    bodies = root.findall("{" + SOAP + "}Body")
    if root.tag != "{" + SOAP + "}Envelope" or len(headers) != 1 or len(bodies) != 1:
        raise CimError()
    actions = headers[0].findall("{" + ADDR + "}Action")
    relates = headers[0].findall("{" + ADDR + "}RelatesTo")
    expected = ENUM + "/" + operation + "Response"
    if (
        len(actions) != 1
        or actions[0].text != expected
        or len(relates) != 1
        or relates[0].text != message_id
        or len(bodies[0]) != 1
        or bodies[0][0].tag != "{" + ENUM + "}" + operation + "Response"
    ):
        raise CimError()
    return bodies[0][0]


def _metadata(body):
    metadata_tags = {"{" + ENUM + "}Expires", "{" + WSMAN + "}TotalItemsCountEstimate"}
    allowed = {
        "{" + ENUM + "}EnumerationContext",
        "{" + ENUM + "}Items",
        "{" + WSMAN + "}Items",
        "{" + ENUM + "}EndOfSequence",
        "{" + WSMAN + "}EndOfSequence",
    } | metadata_tags
    if any(node.tag not in allowed for node in body):
        raise CimError()
    for tag in metadata_tags:
        values = body.findall(tag)
        if len(values) > 1:
            raise CimError()
        for node in values:
            value = (node.text or "").strip()
            if (
                len(node)
                or not value
                or len(value) > 128
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
            ):
                raise CimError()
            if tag.endswith("}TotalItemsCountEstimate"):
                if not re.fullmatch(r"[0-9]{1,20}", value) or int(value) > 18446744073709551615:
                    raise CimError()
            elif not (
                re.fullmatch(
                    r"-?P(?=.*[0-9])(?:[0-9]+Y)?(?:[0-9]+M)?(?:[0-9]+D)?"
                    r"(?:T(?=.+)(?:[0-9]+H)?(?:[0-9]+M)?(?:[0-9]+(?:\.[0-9]+)?S)?)?",
                    value,
                )
                or re.fullmatch(
                    r"-?[0-9]{4,10}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
                    r"[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?",
                    value,
                )
            ):
                raise CimError()
    # Expiration and count estimates are bounded metadata, never completion or
    # patch evidence. Only the explicit EndOfSequence closes an enumeration.
    contexts = body.findall("{" + ENUM + "}EnumerationContext")
    endings = [
        node
        for node in body
        if node.tag
        in {
            "{" + ENUM + "}EndOfSequence",
            "{" + WSMAN + "}EndOfSequence",
        }
    ]
    groups = [
        node
        for node in body
        if node.tag
        in {
            "{" + ENUM + "}Items",
            "{" + WSMAN + "}Items",
        }
    ]
    if len(contexts) > 1 or len(endings) > 1 or len(groups) > 1:
        raise CimError()
    complete = bool(endings)
    context = (contexts[0].text or None) if contexts else None
    if (
        contexts
        and len(contexts[0])
        or context
        and (len(context) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in context))
        or not complete
        and context is None
    ):
        raise CimError()
    return context, complete, list(groups[0]) if groups else []


def _field(row, class_name, name, *, allow_empty=False):
    values = row.findall("{" + WMI + class_name + "}" + name)
    if len(values) != 1 or len(values[0]):
        raise CimError()
    value = values[0].text or ""
    if (
        not allow_empty
        and not value
        or len(value) > 500
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
    ):
        raise CimError()
    return value


def _row(row, class_name):
    if row.tag != "{" + WMI + class_name + "}" + class_name:
        raise CimError()
    if class_name == QFE_CLASS:
        return {
            "id": _field(row, class_name, "HotFixID"),
            "description": _field(row, class_name, "Description", allow_empty=True),
        }
    values = {key: _field(row, class_name, key) for key in OS_FIELDS}
    if values["ProductType"] not in {"1", "2", "3"} or any(
        not re.fullmatch(r"[0-9]{1,10}", values[key]) or int(values[key]) > 4294967295
        for key in ("BuildNumber", "OperatingSystemSKU")
    ):
        raise CimError()
    version = re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.([0-9]{1,10})", values["Version"])
    if version is None or int(version.group(1)) != int(values["BuildNumber"]):
        raise CimError()
    return {
        "family": "Windows",
        "name": values["Caption"],
        "version": values["Version"],
        "kernel": values["BuildNumber"],
        "architecture": values["OSArchitecture"],
        "hostname": values["CSName"],
        "product_type": values["ProductType"],
        "sku": values["OperatingSystemSKU"],
    }


class Enumeration:
    def __init__(self, protocol, endpoint, deadline):
        self.protocol = protocol
        self.endpoint = _endpoint(endpoint)
        self.deadline = deadline
        self.total_bytes = 0

    def send(self, class_name, operation, context=None, count=1):
        if class_name not in {OS_CLASS, QFE_CLASS} or operation not in {
            "Enumerate",
            "Pull",
            "Release",
        }:
            raise CimError("invalid_request")
        remaining = self.deadline - monotonic()
        if remaining <= 2:
            raise CimLimit()
        message_id = "uuid:" + str(uuid.uuid4())
        envelope = ET.Element("{" + SOAP + "}Envelope")
        header = _element(envelope, SOAP, "Header")
        _element(header, ADDR, "To", self.endpoint)
        reply = _element(header, ADDR, "ReplyTo")
        _element(reply, ADDR, "Address", ADDR + "/role/anonymous")
        _element(header, ADDR, "MessageID", message_id)
        _element(header, ADDR, "Action", ENUM + "/" + operation)
        _element(header, WSMAN, "ResourceURI", WMI + class_name)
        _element(header, WSMAN, "MaxEnvelopeSize", 153600)
        _element(
            header, WSMAN, "OperationTimeout", "PT" + str(min(15, max(1, int(remaining) - 2))) + "S"
        )
        _element(
            header,
            MS_WSMAN,
            "DataLocale",
            **{"{http://www.w3.org/XML/1998/namespace}lang": "en-US"},
        )
        body = _element(_element(envelope, SOAP, "Body"), ENUM, operation)
        if operation == "Enumerate":
            _element(body, WSMAN, "OptimizeEnumeration")
            _element(body, WSMAN, "MaxElements", count)
        else:
            _element(body, ENUM, "EnumerationContext", context)
            if operation == "Pull":
                _element(body, ENUM, "MaxElements", count)
        transport = self.protocol.transport
        old_timeout = transport.read_timeout_sec
        transport.read_timeout_sec = min(old_timeout, max(1, remaining - 1))
        try:
            response = self.protocol.send_message(ET.tostring(envelope, encoding="unicode"))
        finally:
            transport.read_timeout_sec = old_timeout
        if not isinstance(response, bytes):
            raise CimError()
        self.total_bytes += len(response)
        if self.total_bytes > MAX_TOTAL_RESPONSE:
            raise CimLimit()
        return _parse(response, operation, message_id)

    def collect(self, class_name, limit, pages):
        rows, context, complete = [], None, False
        try:
            for page in range(pages):
                count = min(100, limit - len(rows))
                if class_name == OS_CLASS and len(rows) == 1:
                    # One confirmation Pull may establish EndOfSequence without
                    # silently accepting a second operating-system identity.
                    count = 1
                if not count:
                    return rows, "truncated"
                body = self.send(class_name, "Enumerate" if page == 0 else "Pull", context, count)
                next_context, complete, items = _metadata(body)
                context = next_context or context
                if len(items) > count:
                    raise CimError()
                rows.extend(_row(item, class_name) for item in items)
                if len(rows) > limit:
                    raise CimError()
                if complete:
                    return rows, "complete"
            return rows, "truncated"
        except CimLimit:
            return rows, "truncated"
        finally:
            if context and not complete and self.deadline - monotonic() > 2:
                try:
                    self.send(class_name, "Release", context)
                except Exception:
                    pass


def collect(protocol, endpoint, mode, *, deadline=None):
    if mode not in {"cim_connection", "cim_inventory"}:
        raise CimError("invalid_request")
    collector = Enumeration(
        protocol,
        endpoint,
        (
            deadline
            if deadline is not None
            else monotonic() + (35 if mode == "cim_connection" else 155)
        ),
    )
    rows, status = collector.collect(OS_CLASS, 1, 3)
    if status != "complete" or len(rows) != 1:
        raise CimError("cim_incomplete_response")
    result = {
        "schema_version": 1,
        "collection_method": COLLECTION_METHOD,
        "os": rows[0],
        "packages": {"status": "not_requested", "source": "none", "items": []},
        "hotfixes": {"status": "not_requested", "source": QFE_CLASS, "items": []},
    }
    if mode == "cim_inventory":
        try:
            rows, status = collector.collect(QFE_CLASS, MAX_HOTFIXES, MAX_PAGES)
        except Exception:
            rows, status = [], "unavailable"
        result["hotfixes"] = {"status": status, "source": QFE_CLASS, "items": rows}
    return result
