"""Offline source selection, input protection, and contextual failure evidence."""

import json
from pathlib import Path

import pytest

from depscan.discovery import discover_sources


def _files(root: Path, *names: str) -> None:
    for name in names:
        (root / name).write_text("not a valid lock or manifest", encoding="utf-8")


def _manifest(root: Path, hint: object) -> None:
    (root / "package.json").write_text(
        json.dumps({"packageManager": hint}), encoding="utf-8"
    )


def test_no_sources_and_nested_projects_are_absent(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    _files(nested, "uv.lock", "package-lock.json", "package.json")
    result = discover_sources(tmp_path)
    assert [(s.ecosystem, s.status) for s in result.selections] == [
        ("PyPI", "absent"),
        ("npm", "absent"),
    ]
    assert result.input_paths == ()


def test_ecosystems_independent_all_candidates_protected(tmp_path: Path) -> None:
    names = (
        "requirements.txt",
        "pyproject.toml",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
    )
    _files(tmp_path, *names)
    result = discover_sources(tmp_path)
    python, javascript = result.selections
    assert python.source is not None and python.source.kind == "uv"
    assert [c.path.name for c in python.candidates] == list(reversed(names[:5]))
    assert javascript.source is not None
    assert javascript.source.path.name == "npm-shrinkwrap.json"
    assert [c.path.name for c in javascript.candidates] == [
        "npm-shrinkwrap.json",
        "package-lock.json",
        "package.json",
    ]
    assert result.input_paths == tuple(sorted(tmp_path / name for name in names))


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("uv.lock", "uv"),
        ("poetry.lock", "poetry"),
        ("Pipfile.lock", "pipfile"),
        ("pyproject.toml", "pyproject"),
        ("requirements.txt", "requirements"),
        ("package.json", "package_json"),
        ("npm-shrinkwrap.json", "npm"),
        ("package-lock.json", "npm"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun_binary"),
    ],
)
def test_each_source_without_companion_manifest(
    tmp_path: Path, name: str, kind: str
) -> None:
    _files(tmp_path, name)
    result = discover_sources(tmp_path)
    selection = next(s for s in result.selections if s.status != "absent")
    assert selection.status == "selected"
    assert selection.source is not None and selection.source.kind == kind
    assert result.input_paths == (tmp_path / name,)


@pytest.mark.parametrize(
    ("names", "selected"),
    [
        (("uv.lock", "poetry.lock"), "uv.lock"),
        (("poetry.lock", "Pipfile.lock"), "poetry.lock"),
        (("Pipfile.lock", "pyproject.toml"), "Pipfile.lock"),
        (("pyproject.toml", "requirements.txt"), "pyproject.toml"),
        (("npm-shrinkwrap.json", "package-lock.json"), "npm-shrinkwrap.json"),
        (("bun.lock", "bun.lockb"), "bun.lock"),
    ],
)
def test_precedence_does_not_parse_or_fall_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    names: tuple[str, ...],
    selected: str,
) -> None:
    _files(tmp_path, *names, "package.json")

    def no_reads(self: Path, *args: object, **kwargs: object) -> str:
        pytest.fail(f"Discovery must not read selected inputs: {self}")

    monkeypatch.setattr(Path, "read_text", no_reads)
    result = discover_sources(tmp_path)
    assert any(s.source and s.source.path.name == selected for s in result.selections)
    assert all(s.status in {"selected", "absent"} for s in result.selections)


@pytest.mark.parametrize(
    ("hint", "selected"),
    [
        ("npm@10.2.3", "npm-shrinkwrap.json"),
        ("npm@1.2.3+shared.1", "npm-shrinkwrap.json"),
        ("npm@1.2.3+shadow", "npm-shrinkwrap.json"),
        ("npm@1.2.3+sha224extra", "npm-shrinkwrap.json"),
        ("yarn@v4.2.1", "yarn.lock"),
        ("pnpm@9.0.0-rc.1+build.5", "pnpm-lock.yaml"),
        ("bun@1.2.3", "bun.lock"),
        *[
            (f"npm@10.2.3+{algorithm}.{'aB' * (length // 2)}", "npm-shrinkwrap.json")
            for algorithm, length in [
                ("sha224", 56),
                ("sha256", 64),
                ("sha384", 96),
                ("sha512", 128),
            ]
        ],
        (f"npm@10.2.3+build+sha224.{'a' * 56}", "npm-shrinkwrap.json"),
        (f"npm@1.2.3+shared.1+sha224.{'a' * 56}", "npm-shrinkwrap.json"),
    ],
)
def test_valid_cross_manager_hints(tmp_path: Path, hint: str, selected: str) -> None:
    names = (
        "npm-shrinkwrap.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "package.json",
    )
    _files(tmp_path, *names)
    _manifest(tmp_path, hint)
    result = discover_sources(tmp_path)
    selection = result.selections[1]
    assert selection.status == "selected"
    assert selection.source is not None and selection.source.path.name == selected
    assert [c.path.name for c in selection.candidates] == list(names)
    assert result.input_paths == tuple(sorted(tmp_path / name for name in names))


@pytest.mark.parametrize(
    "hint",
    [
        None,
        False,
        123,
        {},
        "",
        "npm",
        "npm@",
        "npm@latest",
        "npm@^10.2.3",
        "npm@10.2",
        "npm@01.2.3",
        "npm@1.2.3-01",
        "npm@9007199254740992.2.3",
        "npm@https://example.com/npm.tgz",
        "deno@1.2.3",
        "pnpm@9.2.3",  # Valid but conflicts with the available managers.
        "NPM@10.2.3",
        " npm@10.2.3",
        "npm@10.2.3 ",
        "npm@10.2.3+sha224.abc",
        "npm@10.2.3+sha224",
        "npm@10.2.3+sha224.",
        f"npm@10.2.3+sha256.{'g' * 64}",
        f"npm@10.2.3+sha1.{'a' * 40}",
        f"npm@+sha224.{'a' * 56}",
        f"npm@^10.2.3+sha224.{'a' * 56}",
    ],
)
def test_invalid_absent_or_conflicting_hints_are_ambiguous(
    tmp_path: Path, hint: object
) -> None:
    _files(tmp_path, "package-lock.json", "yarn.lock", "uv.lock")
    _manifest(tmp_path, hint)
    result = discover_sources(tmp_path)
    assert result.selections[0].status == "selected"
    selection = result.selections[1]
    assert selection.status == "ambiguous"
    assert selection.source is None
    assert selection.errors[0].ecosystem == "npm"
    assert "explicitly" in selection.errors[0].reason
    assert tmp_path / "package.json" in result.input_paths


@pytest.mark.parametrize("manifest", [None, "{}"])
def test_multiple_managers_without_hint(tmp_path: Path, manifest: str | None) -> None:
    _files(tmp_path, "yarn.lock", "pnpm-lock.yaml")
    if manifest is not None:
        (tmp_path / "package.json").write_text(manifest, encoding="utf-8")
    assert discover_sources(tmp_path).selections[1].status == "ambiguous"


@pytest.mark.parametrize(
    "text",
    [
        "not JSON",
        "[]",
        "null",
        '{"packageManager":"npm@1.2.3","invalid":NaN}',
        '{"packageManager":"npm@1.2.3","invalid":Infinity}',
        '{"packageManager":"npm@1.2.3","packageManager":"yarn@1.2.3"}',
    ],
)
def test_malformed_hint_manifest_fails_only_npm(tmp_path: Path, text: str) -> None:
    _files(tmp_path, "requirements.txt", "package-lock.json", "yarn.lock")
    manifest = tmp_path / "package.json"
    manifest.write_text(text, encoding="utf-8")
    result = discover_sources(tmp_path)
    assert result.selections[0].status == "selected"
    selection = result.selections[1]
    assert selection.status == "failed"
    assert selection.source is None
    assert selection.errors[0].ecosystem == "npm"
    assert selection.errors[0].source is not None
    assert selection.errors[0].source.path == manifest
    assert manifest in result.input_paths
    assert len(selection.candidates) == 3


@pytest.mark.parametrize("failure", [PermissionError("denied"), UnicodeError("decode")])
def test_hint_read_attempt_protected_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    _files(tmp_path, "package.json", "yarn.lock", "bun.lock")
    attempted: list[Path] = []

    def fail(self: Path, *args: object, **kwargs: object) -> str:
        attempted.append(self)
        raise failure

    monkeypatch.setattr(Path, "read_text", fail)
    result = discover_sources(tmp_path)
    assert attempted == [tmp_path / "package.json"]
    assert result.selections[1].status == "failed"
    assert attempted[0] in result.input_paths


@pytest.mark.parametrize(
    ("name", "ecosystem", "kind"),
    [
        ("package.json", "npm", "package_json"),
        ("package-lock.json", "npm", "npm"),
        ("npm-shrinkwrap.json", "npm", "npm"),
        ("yarn.lock", "npm", "yarn"),
        ("pnpm-lock.yaml", "npm", "pnpm"),
        ("bun.lock", "npm", "bun"),
        ("bun.lockb", "npm", "bun_binary"),
        ("uv.lock", "PyPI", "uv"),
        ("poetry.lock", "PyPI", "poetry"),
        ("Pipfile.lock", "PyPI", "pipfile"),
        ("pyproject.toml", "PyPI", "pyproject"),
        ("requirements.txt", "PyPI", "requirements"),
        ("custom.in", "PyPI", "requirements"),
    ],
)
def test_explicit_files_ignore_siblings_and_manifest_hint(
    tmp_path: Path, name: str, ecosystem: str, kind: str
) -> None:
    _files(tmp_path, "uv.lock", "yarn.lock", "pnpm-lock.yaml", "package.json", name)
    path = tmp_path / name
    result = discover_sources(path)
    assert len(result.selections) == 1
    selection = result.selections[0]
    assert selection.ecosystem == ecosystem
    assert selection.status == "selected"
    assert selection.source is not None and selection.source.kind == kind
    assert selection.candidates == (selection.source,)
    assert result.input_paths == (path,)


def test_relative_paths_are_absolute_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _files(tmp_path, "requirements.txt", "package-lock.json", "package.json")
    monkeypatch.chdir(tmp_path.parent)
    result = discover_sources(Path(tmp_path.name))
    assert result == discover_sources(Path(tmp_path.name))
    assert result.input_paths == tuple(
        sorted(
            tmp_path / name
            for name in ["requirements.txt", "package-lock.json", "package.json"]
        )
    )
    assert all(p.is_absolute() for p in result.input_paths)


def test_symlink_spelling_not_replaced_with_target(tmp_path: Path) -> None:
    target = tmp_path / "original"
    target.write_text("broken lock", encoding="utf-8")
    link = tmp_path / "yarn.lock"
    link.symlink_to(target)
    for path in (tmp_path, link):
        result = discover_sources(path)
        selection = result.selections[-1]
        assert selection.source is not None and selection.source.path == link
        assert result.input_paths == (link,)


@pytest.mark.parametrize("loop", [False, True])
def test_broken_symlink_fails_affected_ecosystem_with_evidence(
    tmp_path: Path, loop: bool
) -> None:
    link = tmp_path / "yarn.lock"
    link.symlink_to(link if loop else tmp_path / "missing")
    _files(tmp_path, "uv.lock")
    result = discover_sources(tmp_path)
    assert result.selections[0].status == "selected"
    selection = result.selections[1]
    assert selection.status == "failed"
    assert selection.candidates[0].path == link
    assert selection.errors[0].ecosystem == "npm"
    assert link in result.input_paths


def test_resolution_error_retains_attempted_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _files(tmp_path, "yarn.lock")

    def fail(self: Path, strict: bool = False) -> Path:
        raise OSError("resolution denied")

    monkeypatch.setattr(Path, "resolve", fail)
    result = discover_sources(tmp_path)
    assert result.selections[1].status == "failed"
    assert result.input_paths == (tmp_path / "yarn.lock",)


def test_candidate_stat_permission_failure_not_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _files(tmp_path, "requirements.txt", "package-lock.json")
    original = Path.lstat

    def fail(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "package-lock.json":
            raise PermissionError("permission denied")
        return original(self)

    monkeypatch.setattr(Path, "lstat", fail)
    result = discover_sources(tmp_path)
    assert result.selections[0].status == "selected"
    assert result.selections[1].status == "failed"
    assert tmp_path / "package-lock.json" in result.input_paths


@pytest.mark.parametrize("name", ["package.json", "custom.in"])
def test_missing_explicit_file_has_contextual_failure(
    tmp_path: Path, name: str
) -> None:
    path = tmp_path / name
    result = discover_sources(path)
    selection = result.selections[0]
    assert selection.status == "failed"
    assert selection.candidates[0].path == path
    assert selection.errors[0].ecosystem == selection.ecosystem
    assert result.input_paths == (path,)


def test_named_directory_is_not_a_dependency_file(tmp_path: Path) -> None:
    (tmp_path / "package.json").mkdir()
    assert discover_sources(tmp_path).selections[1].status == "absent"


def test_only_selection_manifest_contents_are_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _files(tmp_path, "yarn.lock", "bun.lock", "package.json", "uv.lock")
    _manifest(tmp_path, "bun@1.2.3")
    original = Path.read_text
    reads: list[Path] = []

    def track(self: Path, *args: object, **kwargs: object) -> str:
        reads.append(self)
        assert self.name == "package.json"
        return original(self, encoding="utf-8-sig")

    monkeypatch.setattr(Path, "read_text", track)
    result = discover_sources(tmp_path)
    assert reads == [tmp_path / "package.json"]
    assert result.selections[1].source is not None
    assert result.selections[1].source.kind == "bun"


@pytest.mark.parametrize("contents", [b"\xff", b"[" * 2000])
def test_decode_and_excessive_nesting_are_contextual_failures(
    tmp_path: Path, contents: bytes
) -> None:
    _files(tmp_path, "package-lock.json", "bun.lock")
    manifest = tmp_path / "package.json"
    manifest.write_bytes(contents)
    result = discover_sources(tmp_path)
    assert result.selections[1].status == "failed"
    assert manifest in result.input_paths


def test_directory_symlink_preserves_supplied_root_spelling(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _files(root, "package-lock.json")
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    result = discover_sources(link)
    assert result.input_paths == (link / "package-lock.json",)


def test_explicit_resolution_failure_retains_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _files(tmp_path, "package.json")
    path = tmp_path / "package.json"

    def fail(self: Path, strict: bool = False) -> Path:
        raise OSError("resolution denied")

    monkeypatch.setattr(Path, "resolve", fail)
    result = discover_sources(path)
    assert result.selections[0].status == "failed"
    assert result.selections[0].errors[0].ecosystem == "npm"
    assert result.input_paths == (path,)


def test_nonregular_candidate_is_failed_not_opened(tmp_path: Path) -> None:
    import os

    path = tmp_path / "yarn.lock"
    os.mkfifo(path)
    result = discover_sources(tmp_path)
    assert result.selections[1].status == "failed"
    assert result.input_paths == (path,)
    explicit = discover_sources(path)
    assert explicit.selections[0].status == "failed"
