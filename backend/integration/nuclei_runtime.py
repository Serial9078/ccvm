"""Real Nuclei v3.11.0: persistent catalog and a scan on an isolated HTTP fixture."""

import json
import os
import textwrap
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
SMOKE_TEMPLATE = """id: ccvm-ci-smoke
info:
  name: CCVM isolated HTTP fixture
  author: ccvm-ci
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "CCVM-INTERNAL-CI-ONLY"
"""


def assert_nuclei_runtime(command, image, root):
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    # Docker needs an existing mountpoint beneath a read-only parent bind.
    # The production operator creates this same host directory before the helper.
    (BACKEND / ".scanner-data").mkdir(exist_ok=True)
    cache = root / "scanner-data"
    cache.mkdir()
    mount = f"type=bind,src={cache},dst=/app/.scanner-data"

    def prepare(code):
        # The real worker runs as root. Return ownership of only this disposable
        # cache to the CI user so host assertions and TemporaryDirectory cleanup
        # can inspect the installer-created private directories.
        wrapped = (
            "import os\ntry:\n" + textwrap.indent(code, "    ") + "\nfinally:\n"
            "    for directory, subdirs, files in os.walk('/app/.scanner-data'):\n"
            "        for path in [directory, *(os.path.join(directory, f) for f in files)]:\n"
            f"            os.chown(path, {os.getuid()}, {os.getgid()}, follow_symlinks=False)\n"
        )
        return command(
            "docker",
            "run",
            "--rm",
            "--mount",
            f"type=bind,src={BACKEND},dst=/app,readonly",
            "--mount",
            mount,
            "--entrypoint",
            "python",
            image,
            "-B",
            "-c",
            wrapped,
            timeout=300,
        )

    result = json.loads(
        prepare(
            "import json; from app.plugins.nuclei_templates import "
            "prepare_templates, yaml_count, selected_template_count; "
            "from app.plugins.nucleiurl import NUCLEI_TAGS, NUCLEI_SEVERITIES; "
            "directory=prepare_templates(); "
            "print(json.dumps({'directory': str(directory), 'count': yaml_count(directory), "
            "'selected': selected_template_count(directory, NUCLEI_TAGS, NUCLEI_SEVERITIES)}))"
        )
    )
    assert result["directory"] == "/app/.scanner-data/nuclei-templates"
    assert result["count"] > 0 and (cache / "nuclei-templates/http").is_dir()
    assert result["selected"] > 0
    assert (
        json.loads(
            prepare(
                "import json, subprocess; "
                "from app.plugins.nuclei_templates import prepare_templates, yaml_count; "
                "original_run=subprocess.run; "
                "subprocess.run=lambda *a, **k: "
                "original_run(*a, **k) if a[0]==['nuclei', '-version'] else "
                "(_ for _ in ()).throw(AssertionError('Unexpected download')); "
                "print(json.dumps({'count': yaml_count(prepare_templates())}))"
            )
        )["count"]
        == result["count"]
    )
    print(
        f"Real Nuclei catalog: {result['count']} YAML files installed and reused after container "
        "replacement without another download",
        flush=True,
    )

    suffix = f"{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    network = f"ccvm-nuclei-smoke-{suffix}"
    server = f"ccvm-nuclei-http-{suffix}"
    web = root / "web"
    web.mkdir()
    (web / "index.html").write_text("CCVM-INTERNAL-CI-ONLY")
    catalog = root / "synthetic-catalog"
    catalog.mkdir()
    (catalog / "smoke.yaml").write_text(SMOKE_TEMPLATE)
    (catalog / ".nuclei-ignore").write_bytes(
        (cache / "nuclei-templates/.nuclei-ignore").read_bytes()
    )
    command("docker", "network", "create", "--internal", network)
    try:
        command(
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            server,
            "--network",
            network,
            "--network-alias",
            "nuclei-ci.example.test",
            "--mount",
            f"type=bind,src={web},dst=/site,readonly",
            "--entrypoint",
            "python",
            image,
            "-m",
            "http.server",
            "8000",
            "--directory",
            "/site",
        )
        result = command(
            "docker",
            "run",
            "--rm",
            "--network",
            network,
            "--mount",
            f"type=bind,src={BACKEND},dst=/app,readonly",
            "--mount",
            f"type=bind,src={catalog},dst=/synthetic-catalog,readonly",
            "--mount",
            mount,
            "--env",
            "DATABASE_URL=sqlite://",
            "--env",
            "NUCLEI_TEMPLATES_DIR=/synthetic-catalog",
            "--entrypoint",
            "python",
            image,
            "-B",
            "-c",
            r"""
import copy, hashlib, json, subprocess, tempfile, time, urllib.request
from pathlib import Path
import sqlalchemy as sa
from sqlalchemy.orm import Session
import app.models
from app.database.session import Base, engine
from app.models.customer import Customer
from app.models.domain import Domain
from app.models.asset import Asset
from app.models.job import Job
from app.models.url import Url
from app.models.url_detail import UrlDetail
from app.models.finding import Finding
from app.plugins.nucleiurl import run_nucleiurl
from app.plugins import nucleiurl, nuclei_control
for attempt in range(20):
    try:
        with urllib.request.urlopen('http://nuclei-ci.example.test:8000/', timeout=2) as response:
            assert b'CCVM-INTERNAL-CI-ONLY' in response.read()
        break
    except OSError:
        time.sleep(0.2)
else:
    raise AssertionError('Isolated HTTP fixture did not become ready')
@sa.event.listens_for(engine, 'connect')
def sqlite_functions(connection, record):
    connection.create_function('sha256', 1, lambda value: hashlib.sha256(value).digest(),
                               deterministic=True)
Base.metadata.create_all(engine)
with Session(engine, autoflush=False) as db:
    customer = Customer(name='Isolated Nuclei CI')
    db.add(customer)
    db.flush()
    domain = Domain(customer_id=customer.id, name='nuclei-ci.example.test')
    db.add(domain)
    db.flush()
    target = 'http://nuclei-ci.example.test:8000/'
    asset = Asset(customer_id=customer.id, target=target)
    url = Url(customer_id=customer.id, domain_id=domain.id, url=target)
    job = Job(domain_id=domain.id, plugin='nucleiurl', status='running')
    db.add_all([asset, url, job])
    db.flush()
    db.add(UrlDetail(url_id=url.id, status_code=200, content_type='text/html'))
    db.commit()
    native_popen = subprocess.Popen
    launched = []
    def capture(command, **kwargs):
        if '-l' in command and '-stats' in command:
            launched.append(command)
        return native_popen(command, **kwargs)
    subprocess.Popen = capture
    try:
        run_nucleiurl(db, job)
    finally:
        subprocess.Popen = native_popen
    assert job.status == 'finished' and job.progress == 100, job.message
    finding = db.query(Finding).one()
    assert finding.template_id == 'ccvm-ci-smoke' and finding.matched_at == target
    attempts = list(Path('/app/.scanner-data/nuclei-runs').glob('job-*'))
    assert len(attempts) == 1
    stderr = (attempts[0] / 'nuclei.stderr.log').read_text()
    assert 'Could not read nuclei-ignore' not in stderr
    assert 'Could not parse nuclei-ignore' not in stderr
    assert (Path('/root/.config/nuclei') / '.nuclei-ignore').is_file()
    assert (attempts[0] / 'execution.json').is_file()
    # Exercise the real same-namespace PID handle and Nuclei SIGINT handler.
    # The database snapshot here is synthetic; locked PostgreSQL retry behavior
    # is checked separately by assert_header_resume_transaction(mode='nuclei').
    control_catalog = Path('/app/.scanner-data/control-catalog')
    control_catalog.mkdir()
    text = Path('/synthetic-catalog/smoke.yaml').read_text()
    paths = '\n'.join('      - "{{BaseURL}}/?request-%d"' % i for i in range(2000))
    (control_catalog / 'slow.yaml').write_text(text.replace('      - "{{BaseURL}}/"', paths))
    nuclei_control.DEFAULT_DIRECTORY = control_catalog
    attempt = Path(tempfile.mkdtemp(prefix='job-125-', dir='/app/.scanner-data/nuclei-runs'))
    identity = '11111111-1111-4111-8111-111111111111'
    (attempt / 'identity.json').write_text(json.dumps({'job_id': 125, 'uuid': identity}))
    (attempt / 'targets.txt').write_text(target + '\n')
    command = list(launched[0])
    for flag, value in {'-t': control_catalog, '-update-template-dir': control_catalog,
                        '-l': attempt / 'targets.txt', '-o': attempt / 'results.jsonl'}.items():
        command[command.index(flag) + 1] = str(value)
    with ((attempt / 'nuclei.stdout.log').open('w') as stdout,
          (attempt / 'nuclei.stderr.log').open('w') as stderr):
        child = native_popen(command, stdin=subprocess.DEVNULL,
                             stdout=stdout, stderr=stderr, text=True)
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                assert child.poll() is None, (attempt / 'nuclei.stderr.log').read_text()
                stats = nucleiurl.read_scan_stats(attempt / 'nuclei.stderr.log')
                if stats and stats['requests'] > 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError('No active native scan statistics before interruption')
            nucleiurl.write_diagnostic(attempt / 'progress.json', {
                'elapsed_seconds': 5, 'timeout_seconds': 7200, 'last_stats': stats})
            rows = [{'id': i, 'status': 'finished', 'progress': 100} for i in range(9)]
            rows.append({'id': 125, 'uuid': identity, 'pipeline_id': 'isolated-control',
                         'plugin': 'nucleiurl', 'worker': 'ccvm-worker-01',
                         'status': 'running', 'progress': 11,
                         'message': 'Nuclei URL scan running. Targets: 37. Elapsed: 445s. '
                                    'Limit: 7200s. Requests: 24919/671217. Results: 0'})
            expected = copy.deepcopy(rows)
            def snapshot(pipeline):
                code = child.poll()
                if code is not None:
                    assert code == 1, code
                    rows[9].update(status='failed', progress=100, message=(
                        'Nuclei URL scan incomplete: exit code 1. Partial findings retained.'))
                return copy.deepcopy(rows), [] if code is not None else [125]
            nuclei_control.snapshot = snapshot
            record = nuclei_control.interrupt_two_hour_scan(expected)
            assert record['phase'] == 'stopped' and child.wait(timeout=10) == 1
            assert nuclei_control.interrupt_two_hour_scan(expected) == record
            assert (attempt / 'results.jsonl').stat().st_size > 0
            assert 'Creating resume file:' in (attempt / 'nuclei.stderr.log').read_text()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    print(json.dumps({'job_status': job.status, 'findings': 1}))
""",
            timeout=120,
        )
        assert json.loads(result) == {"job_status": "finished", "findings": 1}
        print(
            "Real Nuclei URL plugin finished and imported one finding against the isolated "
            "HTTP fixture; scanner network had no external route",
            flush=True,
        )
        print(
            "Real Nuclei budget control: exact child interrupted using a PID handle; "
            "partial raw results retained and repeated control sent no second signal",
            flush=True,
        )
    finally:
        command("docker", "rm", "--force", server, check=False)
        command("docker", "network", "rm", network, check=False)
        prepare("pass")  # Return ownership of retained diagnostics to the CI user.
