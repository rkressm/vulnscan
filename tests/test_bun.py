"""Offline Bun reader coverage; fixtures are inert and require no JS executables."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from depscan.javascript.bun import read_bun_lock
from depscan.models import ReadyRequirement, SourceReadResult, UnscannedRequirement

FIXTURES = Path(__file__).parent / "fixtures" / "bun"


def _read(tmp_path: Path, **fields: Any) -> SourceReadResult:
    path = tmp_path / "bun.lock"
    document = {"lockfileVersion": 1, "workspaces": {"": {}}, **fields}
    path.write_text(json.dumps(document), encoding="utf-8")
    return read_bun_lock(path)


def _ready(result: SourceReadResult) -> list[ReadyRequirement]:
    return [item for item in result.requirements if isinstance(item, ReadyRequirement)]


def test_verified_upstream_fixture() -> None:
    path = FIXTURES / "upstream-v1.lock"
    result = read_bun_lock(path)
    assert result.status == "success"
    assert not result.errors
    assert [(item.package.name, item.package.version) for item in _ready(result)] == [
        ("@esbuild/aix-ppc64", "0.21.5"),
        ("@wolfy1339/lru-cache", "11.0.2-patch.1"),
        ("@octokit/types", "13.10.0"),
        ("@octokit/types", "12.6.0"),
        ("@octokit/types", "12.6.0"),
    ]
    assert len(result.requirements) == 8
    assert all(item.ecosystem == "npm" for item in result.requirements)
    assert all(item.source.line == 1 for item in result.requirements)
    assert result.input_paths == (path.absolute(),)
    assert 'packages["lru-cache"]' in _ready(result)[1].source.text
    assert _ready(result)[-1].source != _ready(result)[-2].source


def test_synthetic_coverage_fixture() -> None:
    result = read_bun_lock(FIXTURES / "coverage-v1.lock")
    assert result.status == "success"
    ready = _ready(result)
    assert [(item.package.name, item.package.version) for item in ready] == [
        ("@scope/pkg", "1.2.3-beta.1+build.2"),
        ("optional", "2.0.0"),
    ]
    unscanned = [
        item for item in result.requirements if isinstance(item, UnscannedRequirement)
    ]
    patch = next(item for item in unscanned if "patch" in item.reason)
    assert patch.source == ready[0].source
    assert "https://registry.example.test//npm/" in ready[0].source.text
    assert len(unscanned) == 6
    assert len(result.errors) == 1
    assert result.errors[0].ecosystem == "npm"
    assert result.errors[0].source is not None
    assert 'packages["broken"]' in result.errors[0].source.text


@pytest.mark.parametrize("packages", [None, {}])
def test_valid_empty_inventory(tmp_path: Path, packages: Any) -> None:
    result = _read(tmp_path, **({} if packages is None else {"packages": packages}))
    assert result.status == "success"
    assert not result.requirements
    assert not result.errors


@pytest.mark.parametrize("version", [None, 0, 2, -1, True, False, "1", 1.0])
def test_unknown_versions_fail(tmp_path: Path, version: Any) -> None:
    result = _read(tmp_path, lockfileVersion=version)
    assert result.status == "failed"
    assert not result.requirements
    assert "integer 1" in result.errors[0].reason


@pytest.mark.parametrize(
    "fields",
    [
        {"workspaces": None},
        {"workspaces": {}},
        {"workspaces": {"": []}},
        {"workspaces": {"": {"name": 1}}},
        {"workspaces": {"": {"dependencies": []}}},
        {"workspaces": {"": {"dependencies": {"a": 1}}}},
        {"workspaces": {"": {}, "packages/a": {}}},
        {"workspaces": {"": {}, "packages/a": {"name": "a", "version": 1}}},
        {"packages": []},
        {"packages": None},
        {"patchedDependencies": []},
        {"patchedDependencies": {"a@1.0.0": None}},
        {"patchedDependencies": {"a@1.0.0": ""}},
    ],
)
def test_overall_shape_failures(tmp_path: Path, fields: dict[str, Any]) -> None:
    result = _read(tmp_path, **fields)
    assert result.status == "failed"
    assert result.errors
    assert not result.requirements


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        [],
        [1],
        ["a@1.0.0"],
        ["a@1.0.0", "", {}],
        ["a@1.0.0", 1, {}, ""],
        ["a@1.0.0", "", [], ""],
        ["a@1.0.0", "", {}, None],
        ["a@1.0.0", "", {}, "", "extra"],
        ["a@1.0.0", "", {"dependencies": []}, ""],
        ["a@workspace:pkg", {}],
        ["a@file:pkg"],
        ["a@link:pkg", None],
        ["a@root:", None],
    ],
)
def test_bad_tuple_preserves_siblings(tmp_path: Path, record: Any) -> None:
    result = _read(
        tmp_path, packages={"broken": record, "good": ["good@1.0.0", "", {}, ""]}
    )
    assert result.status == "success"
    assert len(result.errors) == 1
    assert [item.package.name for item in _ready(result)] == ["good"]


@pytest.mark.parametrize(
    "locator",
    [
        "a@^1.2.3",
        "a@latest",
        "a@1.0",
        "a@01.0.0",
        "a@1.0.0-01",
        "a@npm:target@1.0.0",
        "a@https://example.test/a.tgz",
        "a@git+https://example.test/repo#abc",
        "a@github:owner/repo#abc",
        "a@../a.tgz",
        "@scope/a@workspace:packages/a",
        "not-a-locator",
        "bad name@1.0.0",
        "a@patch:target@1.0.0",
    ],
)
def test_untrustworthy_identity_is_never_queried(tmp_path: Path, locator: str) -> None:
    record = [locator] if "workspace:" in locator else [locator, "", {}, ""]
    result = _read(tmp_path, packages={"plausible-name": record})
    assert result.status == "success"
    assert not _ready(result)
    assert len(result.requirements) == 1
    assert result.requirements[0].status == "unscanned"


def test_alias_identity_and_exact_semver_come_from_tuple(tmp_path: Path) -> None:
    result = _read(
        tmp_path,
        packages={"alias": ["@scope/a_b.c@v1.2.3-pre.1+build", "", {}, ""]},
    )
    package = _ready(result)[0].package
    assert package.identity == ("npm", "@scope/a_b.c", "1.2.3-pre.1+build")


def test_missing_inventory_and_workspace_coverage(tmp_path: Path) -> None:
    result = _read(
        tmp_path,
        workspaces={
            "": {"name": "root"},
            "packages/a": {"name": "a", "dependencies": {"external": "^1"}},
        },
    )
    assert result.status == "success"
    assert not _ready(result)
    assert len(result.requirements) == 2
    assert result.input_paths == (tmp_path / "bun.lock",)


def test_untrustworthy_patch_target_remains_visible(tmp_path: Path) -> None:
    result = _read(tmp_path, patchedDependencies={"a@^1": "a.patch"})
    assert result.status == "success"
    assert not _ready(result)
    assert result.requirements[0].status == "unscanned"


def test_patch_target_without_tuple_remains_visible(tmp_path: Path) -> None:
    result = _read(tmp_path, patchedDependencies={"a@1.0.0": "a.patch"})
    assert result.status == "success"
    assert not _ready(result)
    assert result.requirements[0].status == "unscanned"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        "null",
        '{"lockfileVersion":1,',
        '{"lockfileVersion":1,"lockfileVersion":1,"workspaces":{"":{}}}',
        '{"lockfileVersion":1,"workspaces":{"":{}},"packages":{"a":[],"a":[]}}',
        '{"lockfileVersion":1,"workspaces":{"":{}}} trailing',
    ],
)
def test_invalid_text_is_failed(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bun.lock"
    path.write_text(text, encoding="utf-8")
    result = read_bun_lock(path)
    assert result.status == "failed"
    assert not result.requirements
    assert result.input_paths == (path,)


def test_json5_permissiveness_and_escaped_comment_strings(tmp_path: Path) -> None:
    path = tmp_path / "bun.lock"
    path.write_text(
        r"""{lockfileVersion:1, workspaces:{'':{name:'a \' // /* literal */'}},
        packages:{alias:['real@1.2.3','','', '']}}""",
        encoding="utf-8",
    )
    result = read_bun_lock(path)
    assert result.status == "success"
    assert len(result.errors) == 1  # metadata string, not object


@pytest.mark.parametrize("mode", ["missing", "directory", "unicode"])
def test_unreadable_inputs(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "bun.lock"
    if mode == "directory":
        path.mkdir()
    elif mode == "unicode":
        path.write_bytes(b"\xff")
    result = read_bun_lock(path)
    assert result.status == "failed"
    assert result.input_paths == (path,)
    assert result.errors[0].ecosystem == "npm"


def test_deep_input_is_contextual_failure(tmp_path: Path) -> None:
    path = tmp_path / "bun.lock"
    path.write_text("[" * 1500 + "]" * 1500, encoding="utf-8")
    assert read_bun_lock(path).status == "failed"


def test_binary_guidance_without_open_or_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Bun reader must not open binary files or execute commands")

    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    path = tmp_path / "bun.lockb"
    result = read_bun_lock(path)
    assert result.status == "failed"
    assert result.source.kind == "bun_binary"
    assert result.input_paths == (path,)
    reason = result.errors[0].reason
    assert (
        "bun install --save-text-lockfile --frozen-lockfile --lockfile-only" in reason
    )
    assert "cache" in reason and "manually verify" in reason
    assert not result.requirements


def test_text_does_not_execute_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("No subprocess permitted")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setenv("PATH", "")
    result = _read(tmp_path, packages={"a": ["a@1.0.0", "", {}, ""]})
    assert len(_ready(result)) == 1


def test_symlink_spelling_is_preserved(tmp_path: Path) -> None:
    _read(tmp_path)
    link = tmp_path / "alias.lock"
    link.symlink_to(tmp_path / "bun.lock")
    result = read_bun_lock(link)
    assert result.source.path == link
    assert result.input_paths == (link,)
