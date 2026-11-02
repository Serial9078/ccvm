"""Catalog installation must complete before a scan can launch."""

import subprocess
from pathlib import Path

import pytest

from app.plugins import nuclei_templates

native_config_directory = nuclei_templates.config_directory


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    directory = tmp_path / "config"
    directory.mkdir()
    monkeypatch.setattr(nuclei_templates, "config_directory", lambda: directory)
    return directory


def test_missing_catalog_is_installed_once_and_published_atomically(tmp_path, monkeypatch):
    directory = tmp_path / "persistent" / "nuclei-templates"
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(directory))
    launches = []

    def download(command, **kwargs):
        launches.append(command)
        assert command[:2] == ["nuclei", "-update-templates"]
        assert "-disable-update-check" not in command
        assert "-l" not in command and "-u" not in command
        staging = Path(command[command.index("-update-template-dir") + 1])
        assert staging != directory and not directory.exists()
        staging.mkdir(parents=True)
        (staging / "synthetic.yaml").write_text("id: ci-template\n")
        (nuclei_templates.config_directory() / ".nuclei-ignore").write_text("tags: [dos]\n")
        return subprocess.CompletedProcess(command, 0, "Templates installed", "")

    monkeypatch.setattr(nuclei_templates.subprocess, "run", download)
    assert nuclei_templates.prepare_templates() == directory
    assert nuclei_templates.prepare_templates() == directory
    assert len(launches) == 1
    assert (directory / "synthetic.yaml").is_file()
    assert (directory / ".ccvm-catalog.json").is_file()
    assert (directory / ".nuclei-ignore").read_text() == "tags: [dos]\n"


@pytest.mark.parametrize("failure", ["exit", "empty-success", "timeout"])
def test_failed_download_never_becomes_an_active_catalog(tmp_path, monkeypatch, failure):
    directory = tmp_path / "nuclei-templates"
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(directory))

    def download(command, **kwargs):
        staging = Path(command[command.index("-update-template-dir") + 1])
        staging.mkdir(parents=True)
        if failure == "timeout":
            (staging / "partial.yaml").write_text("partial")
            raise subprocess.TimeoutExpired(command, 120)
        return subprocess.CompletedProcess(
            command, 1 if failure == "exit" else 0, "", "[FTL] controlled install failure"
        )

    monkeypatch.setattr(nuclei_templates.subprocess, "run", download)
    with pytest.raises(RuntimeError):
        nuclei_templates.prepare_templates()
    assert not directory.exists()
    assert not list(tmp_path.glob(".nuclei-download-*"))


def test_existing_empty_directory_is_preserved_and_rejected(tmp_path, monkeypatch):
    directory = tmp_path / "empty"
    directory.mkdir()
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(directory))
    with pytest.raises(RuntimeError, match="contains no YAML"):
        nuclei_templates.prepare_templates()
    assert directory.is_dir()


def test_fatal_error_is_visible_even_when_followed_by_many_statistics_lines():
    stderr = "[FTL] Could not run nuclei: no templates provided for scan\n"
    stderr += '{"requests":"0","templates":"n/a"}\n' * 1000
    assert "no templates provided for scan" in nuclei_templates.error_summary("", stderr)
    assert "requests" not in nuclei_templates.error_summary("", stderr)
    assert len(nuclei_templates.error_summary("", "[ERR] " + "x" * 2000)) <= 450


def test_default_catalog_lives_in_the_persistent_backend_bind():
    assert nuclei_templates.DEFAULT_DIRECTORY == (
        Path(nuclei_templates.__file__).resolve().parents[2] / ".scanner-data/nuclei-templates"
    )


def test_legacy_catalog_recovers_policy_without_changing_existing_templates(tmp_path, monkeypatch):
    directory = tmp_path / "catalog"
    directory.mkdir()
    original = directory / "existing.yaml"
    original.write_text("id: preserved-existing-template\n")
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(directory))

    def download(command, **kwargs):
        staging = Path(command[command.index("-update-template-dir") + 1])
        staging.mkdir(parents=True)
        (staging / "new-release.yaml").write_text("id: new-release-template\n")
        (nuclei_templates.config_directory() / ".nuclei-ignore").write_text("tags: [dos, fuzz]\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(nuclei_templates.subprocess, "run", download)
    assert nuclei_templates.prepare_templates() == directory
    assert original.read_text() == "id: preserved-existing-template\n"
    assert not (directory / "new-release.yaml").exists()
    assert (directory / ".nuclei-ignore").read_text() == "tags: [dos, fuzz]\n"

    replacement_config = tmp_path / "replacement-container-config"
    monkeypatch.setattr(nuclei_templates, "config_directory", lambda: replacement_config)
    monkeypatch.setattr(
        nuclei_templates.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("Existing catalog must not redownload"),
    )
    nuclei_templates.prepare_templates()
    assert (replacement_config / ".nuclei-ignore").read_text() == "tags: [dos, fuzz]\n"


def test_existing_user_ignore_policy_is_preserved(tmp_path, monkeypatch, isolated_config):
    directory = tmp_path / "catalog"
    directory.mkdir()
    (directory / "one.yaml").write_text("id: example\n")
    (directory / ".nuclei-ignore").write_text("tags: [dos]\n")
    policy = isolated_config / ".nuclei-ignore"
    policy.write_text("tags: [custom-user-policy]\n")
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(directory))
    nuclei_templates.prepare_templates()
    assert policy.read_text() == "tags: [custom-user-policy]\n"


def test_template_listing_rejects_missing_policy_even_when_engine_returns_success(monkeypatch):
    monkeypatch.setattr(
        nuclei_templates.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "/catalog/one.yaml\n", "[ERR] Could not read nuclei-ignore file"
        ),
    )
    with pytest.raises(RuntimeError, match="Could not read nuclei-ignore"):
        nuclei_templates.selected_template_count(Path("/catalog"), "tech", "info")


def test_config_directory_comes_from_the_running_engine(monkeypatch):
    monkeypatch.setattr(
        nuclei_templates.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "", "[INF] Nuclei Config Directory: /custom/nuclei-config\n"
        ),
    )
    assert native_config_directory() == Path("/custom/nuclei-config")
