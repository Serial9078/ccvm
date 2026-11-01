import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.plugins import katana, registry
from app.worker import main as worker


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        (
            {"url": " https://example.test/a ", "method": "post", "status-code": "201"},
            ("https://example.test/a", "POST", 201, None),
        ),
        (
            {
                "request": {"endpoint": "https://example.test/b", "method": "get"},
                "response": {"status_code": 200, "content_type": "text/html"},
            },
            ("https://example.test/b", "GET", 200, "text/html"),
        ),
        (
            {"endpoint": "https://example.test/c", "status_code": "invalid"},
            ("https://example.test/c", "GET", None, None),
        ),
        ({}, (None, "GET", None, None)),
    ],
)
def test_extract_katana_url(item, expected):
    assert katana.extract_katana_url(item) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.test/page", True),
        ("https://sub.example.test/page", True),
        ("https://EXAMPLE.TEST/page", True),
        ("https://other.test", False),
        ("https://example.test.other.test", False),
        ("https://other-example.test", False),
        ("https://example.test@other.test", False),
        ("//example.test/page", False),
        ("/relative", False),
    ],
)
def test_katana_domain_boundary(url, expected):
    assert katana.is_domain_url(url, "Example.Test") is expected


def test_katana_ignores_noise_and_external_urls_and_deduplicates(monkeypatch):
    item = {"url": " https://example.test/page ", "status_code": 200}
    output = "\n".join(
        ["scanner output", "{invalid json", json.dumps({"url": "https://other.test"})]
        + [json.dumps(item)] * 2
    )
    run = Mock(return_value=SimpleNamespace(stdout=output, returncode=0))
    monkeypatch.setattr(katana.subprocess, "run", run)
    rows, failures = katana.collect_host_urls(
        SimpleNamespace(hostname="example.test"), SimpleNamespace(name="example.test")
    )
    assert failures == 0
    assert rows == [
        {
            "hostname": "example.test",
            "url": "https://example.test/page",
            "method": "GET",
            "status_code": 200,
            "content_type": None,
        }
    ]
    run.assert_called_once()
    assert run.call_args.kwargs["timeout"] == katana.KATANA_TIMEOUT_SECONDS
    assert run.call_args.args[0][:3] == ["katana", "-u", "https://example.test"]


def test_katana_falls_back_to_http_after_https_timeout(monkeypatch):
    run = Mock(
        side_effect=[
            subprocess.TimeoutExpired("katana", 45),
            SimpleNamespace(stdout=json.dumps({"url": "http://example.test"}), returncode=0),
        ]
    )
    monkeypatch.setattr(katana.subprocess, "run", run)
    rows, failures = katana.collect_host_urls(
        SimpleNamespace(hostname="example.test"), SimpleNamespace(name="example.test")
    )
    assert failures == 1
    assert [row["url"] for row in rows] == ["http://example.test"]
    assert [call.args[0][2] for call in run.call_args_list] == [
        "https://example.test",
        "http://example.test",
    ]


@pytest.mark.parametrize("name", ["subfinder", "dnsx", "httpx", "naabu", "nuclei", "dummy"])
def test_registry_resolves_existing_worker_handlers(name):
    assert registry.get_plugin(f" {name.upper()} ") is getattr(worker, f"run_{name}")


def test_registry_keeps_hardened_katana_and_handles_unknown_plugins():
    assert registry.get_plugin("katana") is katana.run_katana
    assert registry.get_plugin("unknown") is None
    assert registry.list_plugins() == [
        "dnsx",
        "dummy",
        "httpx",
        "katana",
        "naabu",
        "nuclei",
        "subfinder",
    ]
