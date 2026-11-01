"""Exercise built frontend/nginx against a synthetic backend in disposable containers."""

import base64
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PNG = b"\x89PNG\r\n\x1a\nCCVM synthetic screenshot"
STUB = """from http.server import BaseHTTPRequestHandler, HTTPServer
import base64

class Handler(BaseHTTPRequestHandler):
    def respond(self, body=True):
        routes = {
            "/api/v1/urls": ("application/json", b'[{"url":"https://example.test/"}]'),
            "/api/v1/screenshots/ci.png": ("image/png", base64.b64decode("PNG_DATA")),
        }
        if self.path not in routes:
            self.send_error(404)
            return
        content_type, data = routes[self.path]
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body:
            self.wfile.write(data)
    def do_GET(self):
        self.respond()
    def do_HEAD(self):
        self.respond(False)

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
""".replace("PNG_DATA", base64.b64encode(PNG).decode())


def docker(*args, check=True):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=180, check=False
    )
    if check and result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr}")
    return result.stdout.strip()


def check_routes(base):
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"{base}/api/v1/urls", timeout=3) as response:
                assert json.load(response) == [{"url": "https://example.test/"}]
            break
        except (urllib.error.URLError, TimeoutError):
            time.sleep(1)
    else:
        raise AssertionError("nginx/backend did not become ready")
    with urllib.request.urlopen(f"{base}/urls", timeout=3) as response:
        assert response.headers.get_content_type() == "text/html"
        assert b'<div id="root"></div>' in response.read()
    for method in ("GET", "HEAD"):
        request = urllib.request.Request(f"{base}/api/v1/screenshots/ci.png", method=method)
        with urllib.request.urlopen(request, timeout=3) as response:
            assert response.headers.get_content_type() == "image/png"
            assert int(response.headers["Content-Length"]) == len(PNG)
            assert response.read() == (PNG if method == "GET" else b"")


def main():
    # Validate the checked-in example without starting any application service.
    compose = json.loads(
        docker("compose", "-f", str(ROOT / "docker-compose.yml"), "config", "--format", "json")
    )
    services = compose["services"]
    storage = {
        name: next(
            volume
            for volume in services[name]["volumes"]
            if volume["target"] == "/data/screenshots"
        )
        for name in ("backend", "screenshot-service")
    }
    assert storage["backend"]["source"] == storage["screenshot-service"]["source"]
    assert storage["backend"]["read_only"]
    prefix = f"ccvm-routing-{uuid.uuid4().hex[:12]}"
    backend, frontend = f"{prefix}-backend", f"{prefix}-frontend"
    image = f"{prefix}:ci"
    try:
        with tempfile.TemporaryDirectory(prefix="ccvm-routing-") as directory:
            stub = Path(directory) / "backend.py"
            stub.write_text(STUB)
            docker("build", "-t", image, str(ROOT / "frontend"))
            docker("network", "create", "--internal", prefix)
            docker(
                "run",
                "-d",
                "--name",
                backend,
                "--network",
                prefix,
                "--network-alias",
                "backend",
                "-v",
                f"{stub}:/fixture.py:ro",
                "python:3.12-alpine",
                "python",
                "/fixture.py",
            )
            docker(
                "run",
                "-d",
                "--name",
                frontend,
                "--network",
                prefix,
                "-p",
                "127.0.0.1::80",
                image,
            )
            address = docker("port", frontend, "80/tcp")
            assert address.startswith("127.0.0.1:"), address
            check_routes(f"http://{address}")
            print("nginx smoke check passed: API JSON, SPA fallback, screenshot GET/HEAD")
    except Exception:
        for name in (backend, frontend):
            print(docker("logs", "--tail", "50", name, check=False))
        raise
    finally:
        for name in (frontend, backend):
            docker("rm", "-f", name, check=False)
        docker("network", "rm", prefix, check=False)
        docker("image", "rm", image, check=False)


if __name__ == "__main__":
    main()
