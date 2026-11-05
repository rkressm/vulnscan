import json
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from depscan.javascript.npm import read_npm_lock, read_package_json
from depscan.models import ReadyRequirement, SourceReadResult

FIXTURES = Path(__file__).parent / "fixtures" / "npm"


def write(path: Path, document: Any) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def identities(result: SourceReadResult) -> list[tuple[str, str, str]]:
    return [
        r.package.identity
        for r in result.requirements
        if isinstance(r, ReadyRequirement)
    ]


def test_upstream_v1_nested_inventory() -> None:
    result = read_npm_lock(FIXTURES / "upstream-v1.json")
    assert result.status == "success" and not result.errors
    assert identities(result) == [
        ("npm", "@babel/core", "7.12.9"),
        ("npm", "@babel/code-frame", "7.18.6"),
    ]
    assert ".dependencies[" in result.requirements[1].source.text


def test_upstream_v2_does_not_double_count_legacy_tree() -> None:
    result = read_npm_lock(FIXTURES / "upstream-v2.json")
    assert result.status == "success" and not result.errors
    assert identities(result) == [
        ("npm", "@isaacs/dedupe-tests-a", "1.0.1"),
        ("npm", "@isaacs/dedupe-tests-b", "1.0.0"),
        ("npm", "@isaacs/dedupe-tests-b", "2.0.0"),
    ]


def test_upstream_v3_real_alias_and_workspace_gaps() -> None:
    result = read_npm_lock(FIXTURES / "upstream-v3.json")
    assert identities(result) == [("npm", "string-width", "4.2.3")]
    assert len(result.requirements) == 3
    assert all(r.status == "unscanned" for r in result.requirements[:2])


def test_manifest_four_groups_aliases_duplicates_and_provenance(tmp_path: Path) -> None:
    path = write(
        tmp_path / "package.json",
        {
            "dependencies": {
                "alias": "npm:@scope/real@1.2.3-beta.1",
                "range": "^1.0.0",
            },
            "devDependencies": {"@scope/real": "1.2.3-beta.1"},
            "optionalDependencies": {"alias": "npm:@scope/real@1.2.3-beta.1"},
            "peerDependencies": {"peer": "v2.0.0"},
        },
    )
    result = read_package_json(path)
    assert result.status == "success" and not result.errors
    assert identities(result) == [("npm", "@scope/real", "1.2.3-beta.1")] * 3 + [
        ("npm", "peer", "2.0.0")
    ]
    assert len({r.source.text for r in result.requirements}) == 5
    assert all(
        r.source.path == path and r.source.line == 1 for r in result.requirements
    )
    assert result.source.kind == "package_json" and result.input_paths == (path,)


@pytest.mark.parametrize(
    "group",
    ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"],
)
@pytest.mark.parametrize("bad", [None, [], 3, "bad", True])
def test_manifest_bad_group_is_failed(tmp_path: Path, group: str, bad: Any) -> None:
    result = read_package_json(write(tmp_path / "package.json", {group: bad}))
    assert result.status == "failed" and result.errors and not result.requirements


def test_manifest_bad_entry_preserves_usable_sibling(tmp_path: Path) -> None:
    result = read_package_json(
        write(
            tmp_path / "package.json", {"dependencies": {"good": "1.0.0", "bad": 123}}
        )
    )
    assert result.status == "success"
    assert identities(result) == [("npm", "good", "1.0.0")]
    assert len(result.errors) == 1
    assert result.errors[0].source is not None and "bad" in result.errors[0].source.text


@pytest.mark.parametrize("version", [None, True, False, "1", 1.0, 0, 4, -1])
def test_unknown_or_invalid_versions_fail(tmp_path: Path, version: Any) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json", {"lockfileVersion": version, "packages": {}}
        )
    )
    assert result.status == "failed" and not result.requirements
    assert "lockfileVersion" in result.errors[0].reason


@pytest.mark.parametrize("version", [1, 2, 3])
@pytest.mark.parametrize("filename", ["package-lock.json", "npm-shrinkwrap.json"])
def test_empty_locks(tmp_path: Path, version: int, filename: str) -> None:
    doc: dict[str, Any] = {"lockfileVersion": version}
    if version != 1:
        doc["packages"] = {"": {"name": "root", "version": "1.0.0"}}
    path = write(tmp_path / filename, doc)
    result = read_npm_lock(path)
    assert result.status == "success" and not result.errors and not result.requirements
    assert result.input_paths == (path,) and result.source.kind == "npm"


def test_empty_manifest(tmp_path: Path) -> None:
    result = read_package_json(write(tmp_path / "package.json", {}))
    assert result.status == "success" and not result.requirements and not result.errors


@pytest.mark.parametrize("version", [1, 2, 3])
def test_inventory_all_flags_duplicates_distinct_versions_and_aliases(
    tmp_path: Path, version: int
) -> None:
    records = {
        "a": {"version": "1.0.0", "dev": True},
        "b": {
            "name": "a",
            "version": "1.0.0",
            "optional": True,
            "os": ["impossible"],
            "cpu": ["other"],
        },
        "c": {"version": "npm:@scope/real@2.0.0-rc.1"},
        "d": {
            "version": "3.0.0",
            "resolved": "https://registry.npmjs.org/@scope/real/-/real-3.0.0.tgz",
        },
        "e": {"version": "v4.0.0", "inBundle": True},
    }
    doc: dict[str, Any] = {"lockfileVersion": version}
    if version == 1:
        doc["dependencies"] = records
    else:
        doc["packages"] = {"node_modules/" + k: v for k, v in records.items()}
        doc["dependencies"] = {"legacy-only": {"version": "9.9.9"}}
    result = read_npm_lock(write(tmp_path / "package-lock.json", doc))
    assert result.status == "success" and not result.errors
    assert identities(result) == [
        ("npm", "a", "1.0.0"),
        ("npm", "a", "1.0.0"),
        ("npm", "@scope/real", "2.0.0-rc.1"),
        ("npm", "@scope/real", "3.0.0"),
        ("npm", "e", "4.0.0"),
    ]
    assert len({r.source.text for r in result.requirements}) == 5


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"version": 1},
        {"version": "^1.0.0"},
        {"version": "file:../pkg"},
        {"version": "git+https://example.org/repo#abc"},
        {"version": "https://example.org/pkg.tgz"},
        {"version": "1.0.0", "resolved": "file:../pkg"},
        {"version": "1.0.0", "resolved": "git+ssh://example.org/pkg#abc"},
        {"version": "1.0.0", "resolved": "https://example.org/pkg.tgz"},
        {"version": "1.0.0", "resolved": 123},
        {"version": "1.0.0", "resolved": None},
        {"version": "1.0.0", "name": 123},
        {"version": "1.0.0", "name": "bad/name"},
        {"version": "1.0.0", "link": "true"},
        {"version": "1.0.0", "link": True},
        {"version": "npm:other@1.0.0", "name": "real"},
        {
            "version": "npm:other@1.0.0",
            "resolved": "https://registry.npmjs.org/real/-/real-1.0.0.tgz",
        },
        {
            "version": "1.0.0",
            "name": "other",
            "resolved": "https://registry.npmjs.org/real/-/real-1.0.0.tgz",
        },
    ],
)
def test_untrustworthy_records_never_become_ready(
    tmp_path: Path, record: dict[str, Any]
) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {"lockfileVersion": 3, "packages": {"node_modules/alias": record}},
        )
    )
    assert result.status == "success" and not identities(result)
    assert (
        len(result.requirements) == 1 and result.requirements[0].status == "unscanned"
    )


def test_links_workspace_containers_and_workspace_external_inventory(
    tmp_path: Path,
) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "packages/member": {"name": "member", "version": "1.0.0"},
                    "node_modules/member": {
                        "link": True,
                        "resolved": "packages/member",
                    },
                    "packages/member/node_modules/external": {"version": "1.2.3"},
                },
            },
        )
    )
    assert identities(result) == [("npm", "external", "1.2.3")]
    assert len(result.requirements) == 3 and len(result.input_paths) == 1


def test_manifest_workspaces_not_opened(tmp_path: Path) -> None:
    result = read_package_json(
        write(
            tmp_path / "package.json",
            {"workspaces": ["packages/*"], "dependencies": {"a": "1.0.0"}},
        )
    )
    assert identities(result) == [("npm", "a", "1.0.0")]
    assert result.requirements[0].status == "unscanned"
    assert len(result.input_paths) == 1


@pytest.mark.parametrize(
    "doc",
    [
        {"lockfileVersion": 1, "dependencies": []},
        {"lockfileVersion": 2},
        {"lockfileVersion": 3, "packages": []},
        {"lockfileVersion": 3, "packages": {}, "workspaces": {}},
    ],
)
def test_bad_inventory_shapes_are_failed(tmp_path: Path, doc: dict[str, Any]) -> None:
    result = read_npm_lock(write(tmp_path / "package-lock.json", doc))
    assert result.status == "failed" and result.errors and not result.requirements


@pytest.mark.parametrize("version", [1, 2, 3])
def test_malformed_entry_is_recoverable(tmp_path: Path, version: int) -> None:
    key = "dependencies" if version == 1 else "packages"
    prefix = "" if version == 1 else "node_modules/"
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": version,
                key: {prefix + "bad": [], prefix + "good": {"version": "1.0.0"}},
            },
        )
    )
    assert result.status == "success" and len(result.errors) == 1
    assert identities(result) == [("npm", "good", "1.0.0")]


def test_invalid_nested_dependencies_preserve_parent_and_siblings(
    tmp_path: Path,
) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "a": {"version": "1.0.0", "dependencies": []},
                    "b": {"version": "2.0.0"},
                },
            },
        )
    )
    assert len(identities(result)) == 2 and len(result.errors) == 1


@pytest.mark.parametrize(
    "text",
    [
        "",
        "{",
        "[]",
        "null",
        '{"dependencies":{},"dependencies":{}}',
        '{"x": NaN}',
        "[" * 2000,
        "\ud800",
    ],
)
@pytest.mark.parametrize("manifest", [True, False])
def test_malformed_documents_contextual_failure(
    tmp_path: Path, text: str, manifest: bool
) -> None:
    path = tmp_path / ("package.json" if manifest else "package-lock.json")
    path.write_bytes(text.encode("utf-8", errors="surrogatepass"))
    result = (read_package_json if manifest else read_npm_lock)(path)
    assert result.status == "failed" and not result.requirements
    assert result.errors[0].ecosystem == "npm"
    assert result.errors[0].source is not None and result.errors[0].source.path == path
    assert result.input_paths == (path,)


@pytest.mark.parametrize("manifest", [True, False])
def test_unreadable_registers_attempted_path(tmp_path: Path, manifest: bool) -> None:
    path = tmp_path / "missing.json"
    result = (read_package_json if manifest else read_npm_lock)(path)
    assert result.status == "failed" and result.input_paths == (path,)


def test_relative_and_symlink_spelling_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "real.json", {})
    (tmp_path / "package.json").symlink_to("real.json")
    monkeypatch.chdir(tmp_path)
    result = read_package_json(Path("package.json"))
    assert result.status == "success" and result.input_paths == (
        tmp_path / "package.json",
    )


@pytest.mark.parametrize("version", [2, 3])
def test_alias_declarations_recover_target_not_install_path(
    tmp_path: Path, version: int
) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": version,
                "packages": {
                    "": {"dependencies": {"alias": "npm:@scope/real@^1.0.0"}},
                    "node_modules/alias": {"version": "1.2.3"},
                    "node_modules/parent": {
                        "version": "2.0.0",
                        "optionalDependencies": {"nested-alias": "npm:actual@latest"},
                    },
                    "node_modules/parent/node_modules/nested-alias": {
                        "version": "3.0.0"
                    },
                },
            },
        )
    )
    assert identities(result) == [
        ("npm", "@scope/real", "1.2.3"),
        ("npm", "parent", "2.0.0"),
        ("npm", "actual", "3.0.0"),
    ]


@pytest.mark.parametrize(
    "declaration, record",
    [
        ("npm:other@^1", {"name": "real", "version": "1.0.0"}),
        ("npm:other@^1", {"version": "npm:real@1.0.0"}),
        ("npm:@broken", {"version": "1.0.0"}),
    ],
)
def test_conflicting_or_invalid_alias_evidence_is_not_guessed(
    tmp_path: Path, declaration: str, record: dict[str, Any]
) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"alias": declaration}},
                    "node_modules/alias": record,
                },
            },
        )
    )
    assert not identities(result) and result.requirements[0].status == "unscanned"


def test_nested_v1_alias_requires_target(tmp_path: Path) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "parent": {
                        "version": "1.0.0",
                        "requires": {"alias": "npm:@scope/real@^2"},
                        "dependencies": {"alias": {"version": "2.1.0"}},
                    },
                },
            },
        )
    )
    assert identities(result) == [
        ("npm", "parent", "1.0.0"),
        ("npm", "@scope/real", "2.1.0"),
    ]


@pytest.mark.parametrize("name", ["real", "@scope/real"])
def test_registry_relative_and_encoded_scoped_sources(
    tmp_path: Path, name: str
) -> None:
    result = read_npm_lock(
        write(
            tmp_path / "package-lock.json",
            {
                "lockfileVersion": 1,
                "dependencies": {
                    name: {"version": "1.0.0", "resolved": f"{name}/-/real-1.0.0.tgz"},
                    "alias": {
                        "version": "2.0.0",
                        "resolved": (
                            f"https://registry.npmjs.org/{name.replace('/', '%2f')}"
                            "/-/real-2.0.0.tgz"
                        ),
                    },
                },
            },
        )
    )
    assert identities(result) == [("npm", name, "1.0.0"), ("npm", name, "2.0.0")]


def test_readers_do_not_execute_or_resolve_externally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(
            "Reader must not execute programs or open network connections"
        )

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    manifest = write(
        tmp_path / "package.json",
        {"dependencies": {"alias": "npm:real@1.0.0", "range": "^1.0.0"}},
    )
    assert identities(read_package_json(manifest)) == [("npm", "real", "1.0.0")]
    assert read_npm_lock(FIXTURES / "upstream-v2.json").status == "success"
