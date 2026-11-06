"""Pure configuration helpers for the scoped authenticated-inventory rollout.

Operational addresses, image IDs, certificate choices and credentials are supplied
locally, never embedded in this public repository. No network or writes on import.
"""

import hashlib
import ipaddress
import json
import re

BEGIN = "# BEGIN CCVM AUTHENTICATED INGRESS"
END = "# END CCVM AUTHENTICATED INGRESS"
SOCKET_DIRECTORY = ".ccvm-audit"
SOCKET_NAME = "gateway.sock"


def selection(hostname, clients):
    hostname = hostname.lower()
    if not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", hostname
    ):
        raise ValueError("Use a DNS hostname without scheme, port or path")
    if not 1 <= len(clients) <= 32:
        raise ValueError("Select 1–32 browser/VPN CIDRs")
    networks = sorted({str(ipaddress.ip_network(value, strict=True)) for value in clients})
    if any(not ipaddress.ip_network(value).is_private for value in networks):
        raise ValueError("This rollout requires internal/VPN client networks")
    for value in networks:
        net = ipaddress.ip_network(value)
        if (
            net.is_multicast
            or net.network_address.is_unspecified
            or net.is_link_local
            or net.network_address.is_loopback
        ):
            raise ValueError(
                "Unspecified, multicast and link-local client networks are not supported"
            )
    return hostname, networks


def sections(source):
    """Retain exact original text; refuse ambiguous/unsupported ingress layouts."""
    lines = source.splitlines(keepends=True)
    boundaries = []
    pattern = (
        r"^(global|defaults|frontend|backend|listen|resolvers|userlist|peers|program|ring|"
        r"http-errors|mailers|cache|fcgi-app|crt-store)(?:\s+(\S+))?\s*(?:#.*)?$"
    )
    for index, line in enumerate(lines):
        match = re.match(pattern, line.rstrip("\r\n"))
        if match:
            boundaries.append((index, match[1], match[2]))
    return lines, [
        (start, boundaries[i + 1][0] if i + 1 < len(boundaries) else len(lines), kind, name)
        for i, (start, kind, name) in enumerate(boundaries)
    ]


def ingress_frontends(source):
    lines, blocks = sections(source)
    result = {}
    if re.search(r"^\s*chroot\s+", source, re.M):
        raise ValueError("HAProxy chroot needs a separately reviewed socket mount")
    if BEGIN in source or re.search(r"\bccvm_audit_", source):
        raise ValueError("Existing CCVM ingress retained; use its deployment journal")
    for start, end, kind, name in blocks:
        if kind not in {"frontend", "listen"}:
            continue
        block = "".join(lines[start:end])
        for port in (80, 443):
            binds = [line for line in lines[start:end] if re.match(r"\s*bind\s+", line)]
            public = [
                line
                for line in binds
                if re.search(rf"(?:\*|0\.0\.0\.0|::|\[::\]):{port}(?:\s|$)", line)
            ]
            if not public:
                continue
            if port in result or len(public) != 1:
                raise ValueError("Ambiguous public HTTP/TLS frontend")
            if port == 443:
                if re.search(r"\b(?:ssl|accept-proxy)\b", public[0]):
                    raise ValueError("Public TLS frontend must be the existing TCP SNI router")
                if (
                    not re.search(r"tcp-request\s+inspect-delay\s+", block)
                    or "req.ssl_hello_type" not in block
                ):
                    raise ValueError("Existing TLS ClientHello inspection could not be verified")
            result[port] = (start, end, name)
    if set(result) != {80, 443}:
        raise ValueError("Expected one public HTTP frontend and one TCP TLS SNI frontend")
    return lines, result


def free_tls_port(source):
    used = {int(value) for value in re.findall(r"\bbind\s+[^\n]*?:(\d+)\b", source)}
    return next((port for port in range(4448, 4465) if port not in used), None)


def render_haproxy(source, hostname, clients, certificate, socket_path, port, marker):
    hostname, clients = selection(hostname, clients)
    for value in (certificate, socket_path):
        if not re.fullmatch(r"/[a-zA-Z0-9_./-]+", value) or ".." in value.split("/"):
            raise ValueError("Unsupported HAProxy file path")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("Invalid internal TLS listener port")
    if not re.fullmatch(r"[a-f0-9]{12,40}", marker):
        raise ValueError("Invalid deployment marker")
    if re.search(rf"(?<![\w.-]){re.escape(hostname)}(?![\w.-])", source, re.I):
        raise ValueError("Selected hostname already appears in HAProxy configuration")
    lines, fronts = ingress_frontends(source)
    insertions = {}
    start, end, _ = fronts[443]
    position = next(
        (
            i
            for i in range(start + 1, end)
            if re.match(r"\s*(use_backend|default_backend)\b", lines[i])
        ),
        end,
    )
    insertions[position] = (
        f"    {BEGIN} SNI\n"
        f"    acl ccvm_audit_sni req.ssl_sni -i {hostname}\n"
        "    use_backend ccvm_audit_tls if ccvm_audit_sni\n"
        f"    {END} SNI\n"
    )
    start, end, _ = fronts[80]
    insertions[start + 1] = (
        f"    {BEGIN} HTTP\n"
        "    http-request redirect scheme https code 308 if "
        f"{{ hdr(host),lower -m str {hostname} {hostname}:80 }}\n"
        f"    {END} HTTP\n"
    )
    rendered = "".join(insertions.get(i, "") + line for i, line in enumerate(lines))
    rendered += insertions.get(len(lines), "")
    if rendered and not rendered.endswith("\n"):
        rendered += "\n"
    # Named defaults prevent policies from the last unrelated application from
    # being inherited by the added frontend/backends.
    rendered += f"""
{BEGIN} SECTIONS
defaults ccvm_audit_defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s

backend ccvm_audit_tls
    mode tcp
    server ccvm_audit_loop 127.0.0.1:{port} send-proxy-v2

frontend ccvm_audit_https
    bind 127.0.0.1:{port} ssl crt {certificate} accept-proxy ssl-min-ver TLSv1.2 alpn h2,http/1.1
    mode http
    no log
    acl ccvm_audit_clients src {' '.join(clients)}
    acl ccvm_audit_host hdr(host),lower -m str {hostname} {hostname}:443
    http-request deny deny_status 403 unless ccvm_audit_clients
    http-request deny deny_status 421 unless ccvm_audit_host
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-For %[src]
    http-after-response set-header X-CCVM-Route {marker}
    default_backend ccvm_audit_application

backend ccvm_audit_application
    mode http
    no log
    server ccvm_audit_gateway {socket_path} send-proxy-v2
{END} SECTIONS
"""
    return rendered


def render_gateway(hostname, clients, backend_host="backend"):
    hostname, clients = selection(hostname, clients)
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", backend_host):
        raise ValueError("Invalid backend service alias")
    acl = "\n".join(f"    allow {value};" for value in clients)
    return f"""server {{
    listen unix:/run/ccvm/gateway.sock proxy_protocol;
    server_name {hostname};
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;
{acl}
    deny all;
    if ($host != {hostname}) {{ return 421; }}
    access_log off;
    server_tokens off;
    client_max_body_size 1m;
    root /usr/share/nginx/html;
    index index.html;
    resolver 127.0.0.11 valid=5s ipv6=off;
    set $ccvm_backend {backend_host}:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_protocol_addr;
    proxy_set_header X-Real-IP $proxy_protocol_addr;
    proxy_connect_timeout 5s;
    proxy_read_timeout 30s;
    location /api/ {{ proxy_pass http://$ccvm_backend$request_uri; }}
    location = /health {{ proxy_pass http://$ccvm_backend/health; }}
    location / {{ try_files $uri $uri/ /index.html; }}
}}
"""


def gateway_address(network):
    configs = network.get("IPAM", {}).get("Config", [])
    candidates = [item for item in configs if ":" not in item.get("Subnet", ":")]
    if len(candidates) != 1:
        raise ValueError("Expected one IPv4 application subnet")
    net = ipaddress.ip_network(candidates[0]["Subnet"])
    used = {
        str(ipaddress.ip_interface(item["IPv4Address"]).ip)
        for item in network.get("Containers", {}).values()
        if item.get("IPv4Address")
    }
    used.add(candidates[0].get("Gateway", ""))
    for number in range(
        int(net.broadcast_address) - 1,
        max(int(net.network_address), int(net.broadcast_address) - 33),
        -1,
    ):
        value = str(ipaddress.ip_address(number))
        if value not in used:
            return value
    raise ValueError("No free static gateway address in the application subnet")


def render_override(
    images, private, socket_dir, address, frontend_dir, gateway_name="ccvm-audit-gateway"
):
    """Compose !override is essential: appending leaves the public ports open."""
    backend, worker, frontend = images["backend"], images["worker"], images["frontend"]
    services = {
        "backend": {
            "image": backend,
            "pull_policy": "never",
            "command": [
                "uvicorn",
                "app.main:app",
                "--host",
                "0.0.0.0",
                "--port",
                "8000",
                "--proxy-headers",
                "--forwarded-allow-ips",
                address,
            ],
            "env_file": [private + "/vault.env", private + "/operator.env"],
            "ports": [
                {"target": 8000, "published": "8088", "host_ip": "127.0.0.1", "protocol": "tcp"}
            ],
        },
        "worker": {"image": worker, "pull_policy": "never", "env_file": [private + "/vault.env"]},
        "frontend": {
            "image": frontend,
            "pull_policy": "never",
            "ports": [
                {"target": 80, "published": "8090", "host_ip": "127.0.0.1", "protocol": "tcp"}
            ],
        },
        "audit-gateway": {
            "image": frontend,
            "pull_policy": "never",
            "container_name": gateway_name,
            "restart": "unless-stopped",
            "read_only": True,
            "networks": {"default": {"ipv4_address": address}},
            "tmpfs": ["/var/cache/nginx", "/var/run", "/tmp"],
            "volumes": [
                {
                    "type": "bind",
                    "source": private + "/gateway.conf",
                    "target": "/etc/nginx/conf.d/default.conf",
                    "read_only": True,
                },
                {
                    "type": "bind",
                    "source": frontend_dir,
                    "target": "/usr/share/nginx/html",
                    "read_only": True,
                },
                # Match the literal parent of the PID tmpfs. Older Docker/runc
                # mounts /var/run (a symlink to /run) after /run/ccvm otherwise,
                # hiding the socket bind. nginx can still listen on /run/ccvm.
                {"type": "bind", "source": socket_dir, "target": "/var/run/ccvm"},
            ],
        },
    }
    lines = ["services:"]
    for name, values in services.items():
        lines.append(f"  {name}:")
        for key, value in values.items():
            tag = "!override " if key == "ports" else ""
            lines.append(f"    {key}: {tag}{json.dumps(value)}")
    return "\n".join(lines) + "\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


ROOT_IO = r"""
import base64, fcntl, hashlib, json, os, stat, sys
p = json.load(sys.stdin)
path = p['path']
action = p['action']
if action == 'read':
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode): raise RuntimeError('Not a regular file')
        data = stream.read()
    print(json.dumps({'data':base64.b64encode(data).decode(), 'ino':s.st_ino,
        'dev':s.st_dev, 'mode':stat.S_IMODE(s.st_mode), 'uid':s.st_uid, 'gid':s.st_gid}))
elif action == 'inplace':
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or (s.st_ino,s.st_dev) != (p['ino'],p['dev']):
            raise RuntimeError('Configuration inode changed')
        if hashlib.sha256(stream.read()).hexdigest() != p['before']:
            raise RuntimeError('Configuration bytes changed')
        data = base64.b64decode(p['data'],validate=True)
        stream.seek(0)
        stream.write(data)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())
elif action == 'socket-dir':
    if os.path.lexists(path):
        s = os.lstat(path)
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_gid != p['gid']
                or stat.S_IMODE(s.st_mode) != 0o2750):
            raise RuntimeError('Existing socket directory differs')
    else:
        os.mkdir(path,0o700)
        os.chown(path,0,p['gid'])
        os.chmod(path,0o2750)
else:
    raise RuntimeError('Unknown privileged operation')
"""
