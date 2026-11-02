"""Catalog installation must complete before a scan can launch."""

import subprocess
from pathlib import Path

import pytest

from app.plugins import nuclei_templates


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
        return subprocess.CompletedProcess(command, 0, "Templates installed", "")

    monkeypatch.setattr(nuclei_templates.subprocess, "run", download)
    assert nuclei_templates.prepare_templates() == directory
    assert nuclei_templates.prepare_templates() == directory
    assert len(launches) == 1
    assert (directory / "synthetic.yaml").is_file()
    assert (directory / ".ccvm-catalog.json").is_file()


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
