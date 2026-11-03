"""Offline project detection, lockfile parsing, and environment selection."""

import json
from pathlib import Path

import pytest

from depscan.models import ReadyRequirement, UnscannedRequirement
from depscan.project import read_project


def write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        (
            "uv.lock",
            """version = 1
[[package]]
name = "root"
source = { virtual = "." }
[[package]]
name = "Demo_Package"
version = "1.2"
source = { registry = "https://pypi.org/simple" }
""",
        ),
        (
            "poetry.lock",
            """[[package]]
name = "Demo_Package"
version = "1.2"
""",
        ),
        (
            "Pipfile.lock",
            json.dumps(
                {"default": {"Demo_Package": {"version": "==1.2"}}, "develop": {}}
            ),
        ),
        ("pyproject.toml", '[project]\ndependencies = ["Demo_Package==1.2"]'),
        ("requirements.txt", "Demo_Package==1.2"),
    ],
)
def test_supported_files(tmp_path: Path, filename: str, content: str) -> None:
    path = write(tmp_path / filename, content)
    for target in (path, tmp_path):
        selected, results = read_project(target)
        assert selected == path
        assert len(results) == 1
        result = results[0]
        assert isinstance(result, ReadyRequirement)
        assert result.package.name == "demo-package"
        assert result.package.version == "1.2"
        assert result.source.path == path


def test_detection_precedence_and_explicit_override(tmp_path: Path) -> None:
    for name in (
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "pyproject.toml",
        "requirements.txt",
    ):
        write(tmp_path / name, "invalid")
    for name in (
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "pyproject.toml",
        "requirements.txt",
    ):
        selected, results = read_project(tmp_path)
        assert selected.name == name
        assert isinstance(results[0], UnscannedRequirement)
        (tmp_path / name).unlink()
    path = write(tmp_path / "custom.txt", "demo==1")
    assert isinstance(read_project(path)[1][0], ReadyRequirement)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("uv.lock", "not toml"),
        ("uv.lock", 'package = "wrong"'),
        ("uv.lock", "package = [1]"),
        ("uv.lock", '[[package]]\nname = "demo"\nsource = []'),
        ("uv.lock", '[[package]]\nname = "demo"\nsource = {registry="url"}'),
        (
            "uv.lock",
            '[[package]]\nname = "demo"\nversion = "1; x"\nsource = {registry="url"}',
        ),
        ("poetry.lock", '[[package]]\nname = "demo; x"\nversion = "1"'),
        ("Pipfile.lock", "[]"),
        ("Pipfile.lock", "{}"),
        ("Pipfile.lock", '{"default":{"demo":1},"develop":{}}'),
        ("Pipfile.lock", '{"default":{"demo":{"version":"==1; x"}},"develop":{}}'),
        ("pyproject.toml", '[project]\ndependencies = "demo"'),
        ("pyproject.toml", "[project]\ndependencies = [1]"),
        ("pyproject.toml", "project = []"),
        ("pyproject.toml", '[project]\ndynamic = ["dependencies"]'),
        ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.14"'),
    ],
)
def test_invalid_manifests_are_incomplete(
    tmp_path: Path, filename: str, content: str
) -> None:
    path = write(tmp_path / filename, content)
    results = read_project(path)[1]
    assert len(results) == 1
    assert isinstance(results[0], UnscannedRequirement)
    assert results[0].reason


@pytest.mark.parametrize("filename", ["uv.lock", "poetry.lock", "Pipfile.lock"])
def test_non_registry_sources_are_unscanned(tmp_path: Path, filename: str) -> None:
    content = (
        '{"default":{"demo":{"git":"https://example.invalid/repo"}},"develop":{}}'
        if filename == "Pipfile.lock"
        else '[[package]]\nname="demo"\nsource={git="url"}\n'
    )
    results = read_project(write(tmp_path / filename, content))[1]
    assert isinstance(results[0], UnscannedRequirement)


def test_no_file_is_not_a_clean_scan(tmp_path: Path) -> None:
    assert isinstance(read_project(tmp_path)[1][0], UnscannedRequirement)


def test_project_never_uses_scanner_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("depscan.requirements.metadata.version", lambda name: "2")
    path = write(tmp_path / "requirements.txt", "demo>=1")
    assert isinstance(read_project(path)[1][0], ReadyRequirement)
    result = read_project(tmp_path)[1][0]
    assert isinstance(result, UnscannedRequirement)
    assert "--venv" in result.reason


def test_manifest_does_not_use_scanner_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("depscan.requirements.metadata.version", lambda name: "2")
    path = write(tmp_path / "pyproject.toml", '[project]\ndependencies=["demo>=1"]')
    assert isinstance(read_project(path)[1][0], UnscannedRequirement)


@pytest.mark.parametrize("site", ["lib/python3.14/site-packages", "Lib/site-packages"])
def test_selected_venv_metadata(tmp_path: Path, site: str) -> None:
    venv = tmp_path / "env"
    venv.mkdir()
    write(venv / "pyvenv.cfg", "include-system-site-packages = false\n")
    info = venv / site / "demo_package-2.0.dist-info"
    info.mkdir(parents=True)
    write(
        info / "METADATA", "Metadata-Version: 2.1\nName: Demo_Package\nVersion: 2.0\n"
    )
    path = write(
        tmp_path / "requirements.txt", "demo-package>=1,<3\nmissing>=1\ndemo-package<2"
    )
    results = read_project(path, venv=venv)[1]
    assert isinstance(results[0], ReadyRequirement)
    assert results[0].package.version == "2.0"
    assert isinstance(results[1], UnscannedRequirement)
    assert isinstance(results[2], UnscannedRequirement)
    assert "does not satisfy" in results[2].reason


def test_invalid_venv(tmp_path: Path) -> None:
    path = write(tmp_path / "requirements.txt", "demo==1")
    assert isinstance(read_project(path, venv=tmp_path)[1][0], UnscannedRequirement)


def test_lock_audits_all_groups_and_ignores_platform_markers(tmp_path: Path) -> None:
    content = json.dumps(
        {
            "default": {"demo": {"version": "==1", "markers": "python_version < '0'"}},
            "develop": {"transitive": {"version": "==2"}},
        }
    )
    results = read_project(write(tmp_path / "Pipfile.lock", content))[1]
    assert len(results) == 2
    assert all(isinstance(result, ReadyRequirement) for result in results)


def test_manifest_markers_are_evaluated(tmp_path: Path) -> None:
    path = write(
        tmp_path / "pyproject.toml",
        """[project]
dependencies = ["demo==1; python_version < '0'"]
""",
    )
    assert read_project(path)[1][0].status == "non_applicable"


def test_empty_manifest_is_allowed(tmp_path: Path) -> None:
    path = write(tmp_path / "pyproject.toml", "[project]\ndependencies=[]")
    assert read_project(path)[1] == []


def test_real_repository_lockfile() -> None:
    lock = Path(__file__).resolve().parents[1] / "uv.lock"
    results = read_project(lock)[1]
    assert results
    assert all(isinstance(result, ReadyRequirement) for result in results)
    names = {
        result.package.name
        for result in results
        if isinstance(result, ReadyRequirement)
    }
    assert "requests" in names
    assert "pytest" in names
    assert "depscan" not in names


def test_selected_venv_applies_to_includes(tmp_path: Path) -> None:
    venv = tmp_path / "env"
    venv.mkdir()
    write(venv / "pyvenv.cfg", "")
    (venv / "Lib/site-packages").mkdir(parents=True)
    path = write(tmp_path / "requirements.txt", "-r base.txt")
    write(tmp_path / "base.txt", "pytest>=1")
    assert isinstance(read_project(path, venv=venv)[1][0], UnscannedRequirement)


def test_pipfile_custom_categories_are_scanned(tmp_path: Path) -> None:
    path = write(
        tmp_path / "Pipfile.lock",
        json.dumps(
            {
                "_meta": {"pipfile-spec": 6},
                "default": {},
                "develop": {},
                "production": {"requests": {"version": "==2.31.0"}},
                "tests": {"pytest": {"version": "==9.2.0"}},
            }
        ),
    )

    results = read_project(path)[1]

    assert len(results) == 2
    assert all(isinstance(result, ReadyRequirement) for result in results)
    assert {
        result.package.name
        for result in results
        if isinstance(result, ReadyRequirement)
    } == {"requests", "pytest"}


def test_invalid_pipfile_custom_category_is_incomplete(tmp_path: Path) -> None:
    path = write(
        tmp_path / "Pipfile.lock",
        json.dumps({"default": {}, "develop": {}, "production": []}),
    )

    assert isinstance(read_project(path)[1][0], UnscannedRequirement)
