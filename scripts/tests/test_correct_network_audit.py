"""Selection, evidence preservation and availability during offline correction."""

import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "smb_audit_operator", Path(__file__).parents[1] / "correct-network-audit.py"
)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)
SELECTION = {
    "scan_id": 1,
    "customer_id": 2,
    "customer_uuid": "11111111-1111-4111-8111-111111111111",
    "cidr": "192.0.2.0/24",
}


def snapshot():
    return {
        "identity": {"database": "fixture"},
        "transactions": [],
        "active": [],
        "tables": {
            name: {"count": 7, "sha256": "unchanged"}
            for name in ("jobs", "network_observations", "findings", "ports", "network_scans")
        },
        "others": {"jobs": "other jobs unchanged", "network_observations": "other hosts unchanged"},
        "selection": {
            "scan": {
                "id": 1,
                "customer_id": 2,
                "target": SELECTION["cidr"],
                "cancel_requested": False,
                "pipeline_id": "pipeline",
                "discovery_job_id": 11,
                "audit_job_id": 12,
            },
            "customer": {"id": 2, "uuid": SELECTION["customer_uuid"]},
            "jobs": [
                {
                    "id": 11,
                    "uuid": "discovery-identity",
                    "plugin": "networkdiscovery",
                    "pipeline_id": "pipeline",
                    "status": "finished",
                    "progress": 100,
                    "parent_job_id": None,
                    "message": "discovery finished",
                },
                {
                    "id": 12,
                    "uuid": "audit-identity",
                    "plugin": "networkaudit",
                    "pipeline_id": "pipeline",
                    "status": "failed",
                    "progress": 100,
                    "parent_job_id": 11,
                    "message": "Network audit failed. missing SMB duplicate",
                },
            ],
        },
    }


class SavedAuditCorrection(unittest.TestCase):
    def test_selection_and_unrelated_evidence_cannot_change(self):
        before = snapshot()
        operator.validate_selection(before, SELECTION)
        for field in ("customer_id", "cidr", "customer_uuid", "scan_id"):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                operator.validate_selection(before, {**SELECTION, field: "different"})
        after = copy.deepcopy(before)
        after["tables"]["jobs"]["sha256"] = "corrected selected job"
        after["tables"]["network_observations"]["sha256"] = "corrected selected checks"
        operator.assert_unchanged(before, after, corrected=True)
        for table in ("findings", "ports", "network_scans"):
            bad = copy.deepcopy(after)
            bad["tables"][table]["sha256"] = "changed"
            with self.subTest(table=table), self.assertRaises(RuntimeError):
                operator.assert_unchanged(before, bad, corrected=True)
        after["others"]["jobs"] = "another job changed"
        with self.assertRaises(RuntimeError):
            operator.assert_unchanged(before, after, corrected=True)

    def test_backup_precedes_correction_and_findings_are_preserved(self):
        self.exercise()

    def test_rejected_evidence_restores_services_and_keeps_the_failed_job(self):
        self.exercise("refused")

    def test_lost_correction_response_restores_verified_coherent_services(self):
        self.exercise("lost-response")

    def exercise(self, fail=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".git").mkdir()
            (root / "docker-compose.yml").write_text("private config")
            actions = []

            def git(root, *args):
                if args[0] == "rev-parse":
                    return str(root / ".git")
                actions.append("source")
                return ""

            plan = operator.BASE, ["backend/app/plugins/network.py"]
            module = SimpleNamespace(
                git=git,
                CONFIGS=("docker-compose.yml",),
                source_plan=lambda *a: plan,
                validate_state=lambda state: operator.validate_selection(state, SELECTION),
            )

            class Runtime:
                def __init__(self):
                    self.snapshot = snapshot()
                    self.worker_info = {"Config": {"Env": []}}
                    self.maintenance_args = ["run", "--workdir", "/app"]
                    self.started = 1

                def preflight(self, root):
                    return copy.deepcopy(self.snapshot)

                def state(self):
                    return copy.deepcopy(self.snapshot)

                def prepare_maintenance(self, backup):
                    actions.append("helper")

                def freeze(self):
                    actions.append("pause")

                def resume(self):
                    actions.append("resume")

                def database_backup(self, path):
                    assert "pause" in actions and "stop" in actions and "source" not in actions
                    actions.append("backup")
                    path.write_bytes(b"valid dump")

                def docker(self, *args):
                    if args[0] == "inspect":
                        return json.dumps({"Running": True, "StartedAt": str(self.started)})
                    actions.append(args[0])
                    if args[0] == "restart":
                        self.started += 1
                    return ""

                def maintenance_python(self, code):
                    assert "backup" in actions and "source" in actions
                    assert "saved_audit_report" in code and "correct_saved_audit" in code
                    actions.append("correct")
                    if fail == "refused":
                        raise RuntimeError("Original evidence not eligible")
                    self.snapshot["tables"]["jobs"]["sha256"] = "one corrected job"
                    self.snapshot["tables"]["network_observations"][
                        "sha256"
                    ] = "corrected references"
                    self.snapshot["selection"]["jobs"][1].update(
                        status="finished", message="finished. " + operator.MARKER
                    )
                    if fail == "lost-response":
                        raise RuntimeError("Result lost after commit")
                    return json.dumps({"unavailable": 0})

            runtime = Runtime()
            with (
                patch.object(operator, "verify") as verify,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                if fail:
                    with self.assertRaises(RuntimeError):
                        operator.apply(module, runtime, root, "d" * 40, plan, SELECTION)
                else:
                    operator.apply(module, runtime, root, "d" * 40, plan, SELECTION)
                    verify.assert_called_once()
            self.assertEqual(
                actions,
                [
                    "helper",
                    "stop",
                    "pause",
                    "backup",
                    "source",
                    "correct",
                    "resume",
                    "restart",
                    "start",
                ],
            )
            self.assertEqual(
                runtime.snapshot["tables"]["findings"], snapshot()["tables"]["findings"]
            )
            self.assertEqual((root / "docker-compose.yml").read_text(), "private config")


if __name__ == "__main__":
    unittest.main()
