import copy
import json
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest

from app.services import host_audit_transport as transport
from app.services import windows_cim as cim

ENDPOINT = "http://192.0.2.1:5985/wsman"
OS = {
    "Caption": "Microsoft Windows 11 Pro",
    "Version": "10.0.26300",
    "BuildNumber": "26300",
    "OSArchitecture": "64-bit",
    "CSName": "fixture-client",
    "ProductType": "1",
    "OperatingSystemSKU": "48",
}
QFE = {"HotFixID": "KB1234567", "Description": "Security Update"}


def response(operation, message_id, class_name, *, rows=(), context=None, complete=True):
    root = ET.Element("{" + cim.SOAP + "}Envelope")
    header = ET.SubElement(root, "{" + cim.SOAP + "}Header")
    ET.SubElement(header, "{" + cim.ADDR + "}Action").text = cim.ENUM + "/" + operation + "Response"
    ET.SubElement(header, "{" + cim.ADDR + "}RelatesTo").text = message_id
    body = ET.SubElement(
        ET.SubElement(root, "{" + cim.SOAP + "}Body"), "{" + cim.ENUM + "}" + operation + "Response"
    )
    if context is not None:
        ET.SubElement(body, "{" + cim.ENUM + "}EnumerationContext").text = context
    if rows:
        namespace = cim.WSMAN if operation == "Enumerate" else cim.ENUM
        items = ET.SubElement(body, "{" + namespace + "}Items")
        for fields in rows:
            item = ET.SubElement(items, "{" + cim.WMI + class_name + "}" + class_name)
            for name, value in fields.items():
                ET.SubElement(item, "{" + cim.WMI + class_name + "}" + name).text = value
    if complete:
        ET.SubElement(body, "{" + cim.WSMAN + "}EndOfSequence")
    return ET.tostring(root, encoding="utf-8")


class Protocol:
    def __init__(self, replies):
        self.replies = list(replies)
        self.messages = []
        self.transport = SimpleNamespace(read_timeout_sec=20)

    def send_message(self, document):
        root = ET.fromstring(document)
        header = root.find("{" + cim.SOAP + "}Header")
        assert header.findtext("{" + cim.ADDR + "}To") == ENDPOINT
        uri = header.findtext("{" + cim.WSMAN + "}ResourceURI")
        assert uri in {cim.WMI + cim.OS_CLASS, cim.WMI + cim.QFE_CLASS}
        action = header.findtext("{" + cim.ADDR + "}Action")
        operation = action.removeprefix(cim.ENUM + "/")
        assert operation in {"Enumerate", "Pull", "Release"}
        body = root.find("{" + cim.SOAP + "}Body")[0]
        assert body.tag == "{" + cim.ENUM + "}" + operation
        count = body.findtext(
            "{" + (cim.WSMAN if operation == "Enumerate" else cim.ENUM) + "}MaxElements"
        )
        if operation != "Release":
            assert 1 <= int(count) <= 100
        self.messages.append((operation, uri, body))
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        message_id = header.findtext("{" + cim.ADDR + "}MessageID")
        if callable(item):
            return item(operation, message_id, uri.removeprefix(cim.WMI))
        return response(operation, message_id, uri.removeprefix(cim.WMI), **item)

    def open_shell(self, *args, **kwargs):
        pytest.fail("CIM must never open a shell")

    run_command = open_shell
    get_command_output = open_shell
    cleanup_command = open_shell
    close_shell = open_shell


def test_os_only_connection_uses_one_correlated_fixed_enumeration():
    protocol = Protocol([{"rows": [OS], "context": ""}])
    data = cim.collect(protocol, ENDPOINT, "cim_connection")
    assert data["collection_method"] == "cim"
    assert data["os"]["kernel"] == "26300"
    assert data["os"]["product_type"] == "1" and data["os"]["sku"] == "48"
    assert "native_architecture" not in data["os"] and "edition_id" not in data["os"]
    assert data["packages"] == {"status": "not_requested", "source": "none", "items": []}
    assert data["hotfixes"]["status"] == "not_requested"
    assert len(protocol.messages) == 1
    assert protocol.transport.read_timeout_sec == 20


def test_cim_inventory_pages_qfe_without_any_shell_or_software():
    protocol = Protocol(
        [
            {"rows": [OS]},
            {"complete": False, "context": "page-one"},
            {"rows": [QFE], "complete": False, "context": "page-two"},
            {"rows": [{**QFE, "HotFixID": "KB7654321"}]},
        ]
    )
    data = cim.collect(protocol, ENDPOINT, "cim_inventory")
    assert data["hotfixes"] == {
        "status": "complete",
        "source": cim.QFE_CLASS,
        "items": [
            {"id": "KB1234567", "description": "Security Update"},
            {"id": "KB7654321", "description": "Security Update"},
        ],
    }
    assert [row[0] for row in protocol.messages] == ["Enumerate", "Enumerate", "Pull", "Pull"]
    assert data["packages"]["status"] == "not_requested"
    assert "windows_updates" not in data


def test_singleton_confirmation_pull_rejects_second_os_identity():
    protocol = Protocol(
        [
            {"rows": [OS], "complete": False, "context": "os-context"},
            {"rows": [OS], "complete": False, "context": "os-context"},
            {},
        ]
    )
    with pytest.raises(cim.CimError):
        cim.collect(protocol, ENDPOINT, "cim_connection")
    assert [row[0] for row in protocol.messages] == ["Enumerate", "Pull", "Release"]


def test_singleton_confirmation_pull_accepts_empty_end_of_sequence():
    protocol = Protocol(
        [
            {"rows": [OS], "complete": False, "context": "os-context"},
            {},
        ]
    )
    assert cim.collect(protocol, ENDPOINT, "cim_connection")["os"]["hostname"] == "fixture-client"


def test_nonoptimized_os_enumeration_reads_one_identity_then_confirms_completion():
    protocol = Protocol(
        [
            {"complete": False, "context": "os-context"},
            {"rows": [OS], "complete": False, "context": "os-context"},
            {},
        ]
    )
    data = cim.collect(protocol, ENDPOINT, "cim_connection")
    assert data["os"]["hostname"] == "fixture-client"
    assert [entry[0] for entry in protocol.messages] == ["Enumerate", "Pull", "Pull"]


def test_nonoptimized_os_cannot_return_a_second_identity_on_confirmation_pull():
    protocol = Protocol(
        [
            {"complete": False, "context": "os-context"},
            {"rows": [OS], "complete": False, "context": "os-context"},
            {"rows": [OS], "complete": False, "context": "os-context"},
            {},
        ]
    )
    with pytest.raises(cim.CimError, match="^cim_invalid_response$"):
        cim.collect(protocol, ENDPOINT, "cim_connection")
    assert [entry[0] for entry in protocol.messages] == ["Enumerate", "Pull", "Pull", "Release"]


def with_metadata(tag, value, *, nested=False, duplicate=False):
    def modified(operation, message_id, class_name):
        root = ET.fromstring(response(operation, message_id, class_name, rows=[OS]))
        body = root.find("{" + cim.SOAP + "}Body")[0]
        node = ET.SubElement(body, tag)
        node.text = value
        if nested:
            ET.SubElement(node, "{urn:foreign}value").text = "hidden"
        if duplicate:
            body.append(copy.deepcopy(node))
        return ET.tostring(root, encoding="utf-8")

    return modified


@pytest.mark.parametrize(
    "tag,value",
    [
        ("{" + cim.ENUM + "}Expires", "PT59.5S"),
        ("{" + cim.ENUM + "}Expires", "2026-11-09T12:00:00Z"),
        ("{" + cim.WSMAN + "}TotalItemsCountEstimate", "0"),
        ("{" + cim.WSMAN + "}TotalItemsCountEstimate", "18446744073709551615"),
    ],
)
def test_standard_leaf_metadata_is_accepted_but_not_returned_as_inventory(tag, value):
    data = cim.collect(Protocol([with_metadata(tag, value)]), ENDPOINT, "cim_connection")
    assert data["os"]["kernel"] == "26300"
    assert "Expires" not in json.dumps(data) and "TotalItemsCountEstimate" not in json.dumps(data)


@pytest.mark.parametrize(
    "tag,value,nested,duplicate",
    [
        ("{" + cim.ENUM + "}Expires", "PT1S", True, False),
        ("{" + cim.ENUM + "}Expires", "PT1S", False, True),
        ("{" + cim.ENUM + "}Expires", "x" * 129, False, False),
        ("{" + cim.ENUM + "}Expires", "not-an-expiration", False, False),
        ("{" + cim.WSMAN + "}TotalItemsCountEstimate", "18446744073709551616", False, False),
        ("{" + cim.WSMAN + "}TotalItemsCountEstimate", "-1", False, False),
        ("{urn:foreign}Expires", "PT1S", False, False),
        ("{urn:foreign}TotalItemsCountEstimate", "1", False, False),
    ],
)
def test_metadata_remains_exact_bounded_scalar_data(tag, value, nested, duplicate):
    protocol = Protocol([with_metadata(tag, value, nested=nested, duplicate=duplicate)])
    with pytest.raises(cim.CimError, match="^cim_invalid_response$"):
        cim.collect(protocol, ENDPOINT, "cim_connection")


@pytest.mark.parametrize("fault", [RuntimeError("synthetic-secret-raw-fault"), cim.CimError()])
def test_qfe_failure_retains_os_without_exposing_raw_fault(fault):
    protocol = Protocol([{"rows": [OS]}, fault])
    data = cim.collect(protocol, ENDPOINT, "cim_inventory")
    assert data["os"]["kernel"] == "26300"
    assert data["hotfixes"] == {"status": "unavailable", "source": cim.QFE_CLASS, "items": []}
    assert "synthetic-secret" not in json.dumps(data)


def foreign_items(operation, message_id, class_name):
    fields = OS if class_name == cim.OS_CLASS else QFE
    root = ET.fromstring(response(operation, message_id, class_name, rows=[fields]))
    root.find(".//{" + cim.WSMAN + "}Items").tag = "{urn:foreign}Items"
    return ET.tostring(root, encoding="utf-8")


def test_foreign_items_cannot_turn_qfe_evidence_into_complete_empty_inventory():
    data = cim.collect(Protocol([{"rows": [OS]}, foreign_items]), ENDPOINT, "cim_inventory")
    assert data["os"]["kernel"] == "26300"
    assert data["hotfixes"] == {"status": "unavailable", "source": cim.QFE_CLASS, "items": []}


def test_foreign_items_cannot_supply_os_identity():
    with pytest.raises(cim.CimError, match="^cim_invalid_response$"):
        cim.collect(Protocol([foreign_items]), ENDPOINT, "cim_connection")


@pytest.mark.parametrize("name", ["EnumerationContext", "EndOfSequence", "Unexpected"])
def test_unknown_direct_response_children_are_rejected(name):
    def invalid(operation, message_id, class_name):
        root = ET.fromstring(response(operation, message_id, class_name, rows=[OS]))
        body = root.find("{" + cim.SOAP + "}Body")[0]
        ET.SubElement(body, "{urn:foreign}" + name).text = "ignored-data"
        return ET.tostring(root, encoding="utf-8")

    with pytest.raises(cim.CimError, match="^cim_invalid_response$"):
        cim.collect(Protocol([invalid]), ENDPOINT, "cim_connection")


def test_qfe_limit_returns_retained_rows_as_truncated_and_releases(monkeypatch):
    monkeypatch.setattr(cim, "MAX_HOTFIXES", 1)
    protocol = Protocol(
        [
            {"rows": [OS]},
            {"rows": [QFE], "complete": False, "context": "qfe-context"},
            RuntimeError("cleanup failure must not replace partial evidence"),
        ]
    )
    data = cim.collect(protocol, ENDPOINT, "cim_inventory")
    assert data["hotfixes"]["status"] == "truncated"
    assert len(data["hotfixes"]["items"]) == 1
    assert protocol.messages[-1][0] == "Release"


def test_malformed_os_preserves_primary_error_when_release_also_fails():
    protocol = Protocol(
        [
            {"rows": [{**OS, "ProductType": "99"}], "complete": False, "context": "ctx"},
            RuntimeError("cleanup-secret"),
        ]
    )
    with pytest.raises(cim.CimError, match="^cim_invalid_response$"):
        cim.collect(protocol, ENDPOINT, "cim_connection")
    assert protocol.messages[-1][0] == "Release"


@pytest.mark.parametrize(
    "mutation", ["relates", "action", "body_namespace", "row_namespace", "duplicate"]
)
def test_rejects_mismatched_or_ambiguous_xml(mutation):
    def invalid(operation, message_id, class_name):
        root = ET.fromstring(response(operation, message_id, class_name, rows=[OS]))
        if mutation == "relates":
            root.find("{" + cim.SOAP + "}Header/{" + cim.ADDR + "}RelatesTo").text = "uuid:other"
        elif mutation == "action":
            root.find("{" + cim.SOAP + "}Header/{" + cim.ADDR + "}Action").text = (
                cim.ENUM + "/PullResponse"
            )
        elif mutation == "body_namespace":
            root.find("{" + cim.SOAP + "}Body")[0].tag = "{urn:other}EnumerateResponse"
        else:
            row = root.find(".//{" + cim.WMI + class_name + "}" + class_name)
            if mutation == "row_namespace":
                row.tag = "{urn:other}" + class_name
            else:
                row.append(copy.deepcopy(row[0]))
        return ET.tostring(root, encoding="utf-8")

    with pytest.raises(cim.CimError):
        cim.collect(Protocol([invalid]), ENDPOINT, "cim_connection")


@pytest.mark.parametrize(
    "payload",
    [
        b"<!DOCTYPE x [<!ENTITY a 'value'>]><x>&a;</x>",
        "<x/>".encode("utf-16"),
        b"x" * (cim.MAX_RESPONSE + 1),
    ],
)
def test_rejects_unsafe_xml_encodings_entities_and_size(payload):
    with pytest.raises(cim.CimError):
        cim.collect(Protocol([lambda *_: payload]), ENDPOINT, "cim_connection")


@pytest.mark.parametrize(
    "key,value",
    [
        ("ProductType", "0"),
        ("OperatingSystemSKU", "4294967296"),
        ("BuildNumber", "26300.1234"),
        ("Version", "10.0.22631"),
        ("Caption", "bad\ncaption"),
    ],
)
def test_rejects_unread_or_malformed_os_identity(key, value):
    with pytest.raises(cim.CimError):
        cim.collect(Protocol([{"rows": [{**OS, key: value}]}]), ENDPOINT, "cim_connection")


def test_deadline_and_byte_budget_are_honest_limits(monkeypatch):
    with pytest.raises(cim.CimError, match="cim_incomplete_response"):
        cim.collect(Protocol([]), ENDPOINT, "cim_connection", deadline=cim.monotonic() - 1)
    monkeypatch.setattr(cim, "MAX_TOTAL_RESPONSE", 1)
    with pytest.raises(cim.CimError, match="cim_incomplete_response"):
        cim.collect(Protocol([{"rows": [OS]}]), ENDPOINT, "cim_connection")


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://host.example:5985/wsman",
        "http://user:secret@192.0.2.1:5985/wsman",
        "http://192.0.2.1:5985/other",
        "http://192.0.2.1:5985/wsman?redirect=yes",
        "http://[fe80::1%eth0]:5985/wsman",
    ],
)
def test_rejects_unapproved_endpoint_forms(endpoint):
    with pytest.raises(cim.CimError, match="invalid_request"):
        cim.collect(Protocol([]), endpoint, "cim_connection")


def test_real_cim_transport_uses_existing_hardened_session_and_never_shell(monkeypatch):
    protocol = Protocol([{"rows": [OS]}])
    seen = []
    monkeypatch.setattr(transport, "winrm_protocol", lambda payload: (protocol, ENDPOINT))
    monkeypatch.setattr(
        transport,
        "winrm_session",
        lambda *args: SimpleNamespace(close=lambda: seen.append("close")),
    )
    data = transport.cim_collect({"kind": "winrm", "mode": "cim_connection"})
    assert data["collection_method"] == "cim" and seen == ["close"]


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "ssh_password", "mode": "cim_inventory"},
        {"kind": "winrm", "mode": "inventory"},
    ],
)
def test_cim_transport_rejects_invalid_kind_or_mode_before_authentication(payload, monkeypatch):
    monkeypatch.setattr(transport, "winrm_protocol", lambda *_: pytest.fail("authenticated"))
    with pytest.raises(transport.TransportFailure, match="invalid_request"):
        transport.cim_collect(payload)
