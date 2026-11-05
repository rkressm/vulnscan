"""Offline tests for declarations, version selection, and file traversal."""

from importlib import metadata
from pathlib import Path

import pytest
from packaging.markers import default_environment

from depscan.models import (
    NonApplicableRequirement,
    ReadyRequirement,
    RequirementResult,
    ScanError,
    UnscannedRequirement,
)
from depscan.requirements import read_requirements


@pytest.fixture(autouse=True)
def installed_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never depend on packages installed on the machine running the tests."""

    def lookup(name: str) -> str:
        versions = {"requests": "2.31.0", "demo": "1.5", "preview": "2.0rc1"}
        if name not in versions:
            raise metadata.PackageNotFoundError(name)
        return versions[name]

    monkeypatch.setattr(metadata, "version", lookup)


def read_text(tmp_path: Path, text: str) -> list[RequirementResult]:
    path = tmp_path / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    return read_requirements(path)


def test_root_read_failure_has_explicit_python_context(tmp_path: Path) -> None:
    path = tmp_path / "missing.txt"
    errors: list[ScanError] = []
    inputs: set[Path] = set()
    results = read_requirements(path, source_errors=errors, input_paths=inputs)
    assert len(errors) == 1
    assert errors[0].ecosystem == "PyPI"
    assert errors[0].source == results[0].source
    assert isinstance(results[0], UnscannedRequirement)
    assert results[0].ecosystem == "PyPI"
    assert path in inputs


def test_empty_and_entry_errors_are_not_failed_documents(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    errors: list[ScanError] = []
    path.write_text("", encoding="utf-8")
    assert read_requirements(path, source_errors=errors) == []
    path.write_text("-r missing.txt\n-e ./local\n", encoding="utf-8")
    results = read_requirements(path, source_errors=errors)
    assert len(results) == 2
    assert all(
        isinstance(item, UnscannedRequirement) and item.ecosystem == "PyPI"
        for item in results
    )
    assert errors == []


@pytest.mark.parametrize(
    ("text", "name", "version"),
    [
        ("Requests==2.30.0", "requests", "2.30.0"),
        ("absent==1.0", "absent", "1.0"),
        ("My_Package.Name==1.0", "my-package-name", "1.0"),
        ("requests>=2.28,<3", "requests", "2.31.0"),
        ("requests", "requests", "2.31.0"),
        ("requests[socks,security]==2.30.0", "requests", "2.30.0"),
        ("requests==2.*", "requests", "2.31.0"),
        ("demo~=1.0", "demo", "1.5"),
        ("preview>=1.0", "preview", "2.0rc1"),
        ("absent==1.0rc1", "absent", "1.0rc1"),
        ("absent===1.0", "absent", "1.0"),
        ("absent==v1.0", "absent", "v1.0"),
    ],
)
def test_version_selection(tmp_path: Path, text: str, name: str, version: str) -> None:
    results = read_text(tmp_path, text)

    assert len(results) == 1
    result = results[0]
    assert isinstance(result, ReadyRequirement)
    assert result.package.name == name
    assert result.package.version == version


def test_pins_do_not_query_installed_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_lookup(name: str) -> str:
        pytest.fail(f"Unexpected installed-version lookup: {name}")

    monkeypatch.setattr(metadata, "version", unexpected_lookup)
    assert isinstance(read_text(tmp_path, "requests==2.31.0")[0], ReadyRequirement)


def test_comments_blank_lines_and_locations(tmp_path: Path) -> None:
    results = read_text(
        tmp_path, "\ufeff# comment\n\n  requests==2.31.0 # note\n\t# comment\nabsent\n"
    )

    assert len(results) == 2
    assert isinstance(results[0], ReadyRequirement)
    result = results[1]
    assert isinstance(result, UnscannedRequirement)
    assert result.source.path == tmp_path / "requirements.txt"
    assert result.source.line == 5
    assert result.source.text == "absent"
    assert result.name == "absent"
    assert "not installed" in result.reason


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("absent", "not installed"),
        ("absent>=1", "not installed"),
        ("requests>=3", "Installed version 2.31.0 does not satisfy"),
        ("requests!=2.31.0", "does not satisfy"),
        ("requests==1.0,>=2", "Declared version 1.0 does not satisfy"),
        ("requests==1.0,==2.0", "does not satisfy"),
        ("requests===not-a-version", "Invalid package version"),
        ("-e .", "unsupported"),
        ("git+https://example.com/repo.git", "unsupported"),
        ("./local-package", "unsupported"),
        ("https://example.com/demo.whl", "unsupported"),
        ("demo @ https://example.com/demo.whl#sha256=abc", "unsupported"),
        ("demo @ file:///local/demo", "unsupported"),
        ("--index-url https://example.com", "unsupported"),
        ("requests==2.31.0 --hash=sha256:abc", "unsupported"),
        ("not a valid requirement", "Invalid or unsupported"),
    ],
)
def test_unscanned_declarations(tmp_path: Path, text: str, reason: str) -> None:
    result = read_text(tmp_path, text)[0]

    assert isinstance(result, UnscannedRequirement)
    assert reason in result.reason
    assert result.source.line == 1
    assert result.source.text == text


def test_invalid_installed_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(metadata, "version", lambda name: "not-a-version")
    result = read_text(tmp_path, "demo")[0]

    assert isinstance(result, UnscannedRequirement)
    assert "Invalid package version" in result.reason


def test_markers_use_current_environment(tmp_path: Path) -> None:
    python_version = default_environment()["python_version"]
    results = read_text(
        tmp_path,
        f'requests==2.31.0; python_version == "{python_version}"\n'
        'absent; python_version < "0"\n',
    )

    assert isinstance(results[0], ReadyRequirement)
    assert isinstance(results[1], NonApplicableRequirement)
    assert results[1].name == "absent"
    assert "marker does not match" in results[1].reason


def test_hash_inside_quoted_marker_is_not_a_comment(tmp_path: Path) -> None:
    result = read_text(
        tmp_path, 'requests==2.31.0; os_name == " # not a comment" # actual comment'
    )[0]

    assert isinstance(result, NonApplicableRequirement)


def test_marker_excludes_requirement_before_version_lookup(tmp_path: Path) -> None:
    results = read_text(
        tmp_path,
        'absent>=3; python_version < "0"\n'
        'demo @ https://example.com/demo.whl ; python_version < "0"',
    )

    assert all(isinstance(result, NonApplicableRequirement) for result in results)


def test_undefined_marker_comparison(tmp_path: Path) -> None:
    result = read_text(tmp_path, 'requests; os_name ~= "not-a-version"')[0]

    assert isinstance(result, UnscannedRequirement)
    assert "Cannot evaluate environment marker" in result.reason


def test_extras_do_not_trigger_additional_lookups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    looked_up: list[str] = []

    def lookup(name: str) -> str:
        looked_up.append(name)
        return "2.31.0"

    monkeypatch.setattr(metadata, "version", lookup)
    results = read_text(tmp_path, "requests[socks]>=2")

    assert len(results) == 1
    assert isinstance(results[0], ReadyRequirement)
    assert looked_up == ["requests"]


def test_lookup_uses_declared_name_but_result_uses_canonical_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    looked_up: list[str] = []

    def lookup(name: str) -> str:
        looked_up.append(name)
        return "v1.5"

    monkeypatch.setattr(metadata, "version", lookup)
    result = read_text(tmp_path, "My_Package.Name>=1")[0]

    assert looked_up == ["My_Package.Name"]
    assert isinstance(result, ReadyRequirement)
    assert result.package.name == "my-package-name"
    assert result.package.version == "v1.5"


@pytest.mark.parametrize(
    ("text", "name", "reason"),
    [
        (
            "requests==2.0,==10.0",
            "requests",
            "Declared version 10.0 does not satisfy ==10.0,==2.0.",
        ),
        (
            "requests>=3",
            "requests",
            "Installed version 2.31.0 does not satisfy >=3.",
        ),
        (
            "demo @ https://example.com/demo.whl",
            "demo",
            "Direct URL and local path dependencies are unsupported.",
        ),
        (
            "--requirement=",
            None,
            "Requirements include must specify one local file path.",
        ),
    ],
)
def test_failure_details(
    tmp_path: Path, text: str, name: str | None, reason: str
) -> None:
    result = read_text(tmp_path, text)[0]

    assert isinstance(result, UnscannedRequirement)
    assert result.name == name
    assert result.reason == reason
    assert result.source.path == tmp_path / "requirements.txt"
    assert result.source.line == 1
    assert result.source.text == text


@pytest.mark.parametrize("directive", ["-r", "-r ", "--requirement=", "--requirement "])
def test_nested_includes_relative_to_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directive: str
) -> None:
    (tmp_path / "nested").mkdir()
    root = tmp_path / "requirements.txt"
    root.write_text(f"{directive}nested/dev.txt\nrequests==2.31.0\n")
    (tmp_path / "nested/dev.txt").write_text('-r "base file.txt"\n')
    (tmp_path / "nested/base file.txt").write_text("demo==1.0\n")
    monkeypatch.chdir(tmp_path.parent)

    results = read_requirements(root)

    assert len(results) == 2
    assert isinstance(results[0], ReadyRequirement)
    assert results[0].package.name == "demo"
    assert results[0].source.path == tmp_path / "nested/base file.txt"
    assert isinstance(results[1], ReadyRequirement)
    assert results[1].package.name == "requests"


def test_cycle_reports_include_and_continues(tmp_path: Path) -> None:
    root = tmp_path / "requirements.txt"
    root.write_text("-r other.txt\nrequests==2.31.0\n")
    (tmp_path / "other.txt").write_text("# comment\n-r requirements.txt\n")

    results = read_requirements(root)

    assert len(results) == 2
    assert isinstance(results[0], UnscannedRequirement)
    assert "Circular" in results[0].reason
    assert results[0].source.path == tmp_path / "other.txt"
    assert results[0].source.line == 2
    assert isinstance(results[1], ReadyRequirement)


def test_symlink_cycle(tmp_path: Path) -> None:
    (tmp_path / "alias.txt").symlink_to(tmp_path / "requirements.txt")
    result = read_text(tmp_path, "-r alias.txt")[0]

    assert isinstance(result, UnscannedRequirement)
    assert "Circular" in result.reason


def test_repeated_includes_are_not_cycles(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("requests==2.31.0\n")
    results = read_text(tmp_path, "-r base.txt\n-r base.txt\nrequests==2.31.0\n")

    assert len(results) == 3
    assert all(isinstance(result, ReadyRequirement) for result in results)


@pytest.mark.parametrize(
    "text",
    ["-r", "--requirement", '-r "broken', "-r a.txt b.txt", "-r https://example.com"],
)
def test_invalid_includes(tmp_path: Path, text: str) -> None:
    result = read_text(tmp_path, text)[0]

    assert isinstance(result, UnscannedRequirement)
    assert "include" in result.reason.lower()


def test_missing_include_reports_parent_location(tmp_path: Path) -> None:
    results = read_text(tmp_path, "# comment\n-r missing.txt\nrequests==2.31.0")

    assert len(results) == 2
    assert isinstance(results[0], UnscannedRequirement)
    assert "missing.txt" in results[0].reason
    assert results[0].source.path == tmp_path / "requirements.txt"
    assert results[0].source.line == 2
    assert isinstance(results[1], ReadyRequirement)


def test_missing_root_file(tmp_path: Path) -> None:
    path = tmp_path / "missing.txt"
    result = read_requirements(str(path))[0]

    assert isinstance(result, UnscannedRequirement)
    assert "Cannot read" in result.reason
    assert result.source.path == path
    assert result.source.line == 1


def test_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\xff")

    result = read_requirements(path)[0]

    assert isinstance(result, UnscannedRequirement)
    assert "Cannot read" in result.reason


def test_directory_is_not_a_requirements_file(tmp_path: Path) -> None:
    assert isinstance(read_requirements(tmp_path)[0], UnscannedRequirement)


def test_empty_file(tmp_path: Path) -> None:
    assert read_text(tmp_path, "# just a comment\n\n") == []


def test_excessive_include_depth(tmp_path: Path) -> None:
    for index in range(101):
        (tmp_path / f"{index}.txt").write_text(f"-r {index + 1}.txt\n")

    result = read_requirements(tmp_path / "0.txt")[0]

    assert isinstance(result, UnscannedRequirement)
    assert "depth exceeds" in result.reason


def test_exactly_one_hundred_files_are_allowed(tmp_path: Path) -> None:
    for index in range(99):
        (tmp_path / f"{index}.txt").write_text(f"-r {index + 1}.txt\n")
    (tmp_path / "99.txt").write_text("demo==1.0\n")

    results = read_requirements(tmp_path / "0.txt")

    assert len(results) == 1
    assert isinstance(results[0], ReadyRequirement)
    assert results[0].source.path == tmp_path / "99.txt"


def test_example_requirements() -> None:
    example = Path(__file__).resolve().parents[1] / "examples/requirements.txt"

    results = read_requirements(example)

    assert [result.status for result in results] == [
        "ready",
        "ready",
        "unscanned",
        "non_applicable",
        "unscanned",
    ]
    assert isinstance(results[0], ReadyRequirement)
    assert results[0].package.version == "2.31.0"
