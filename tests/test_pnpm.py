"""Offline inventory/coverage tests; fixtures never execute package managers."""

from pathlib import Path

import pytest

from depscan.javascript.pnpm import read_pnpm_lock
from depscan.models import ReadyRequirement, SourceReadResult, UnscannedRequirement

FIXTURES = Path(__file__).parent / "fixtures" / "pnpm"


def read_text(tmp_path: Path, text: str) -> SourceReadResult:
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text(text, encoding="utf-8")
    return read_pnpm_lock(path)


def identities(result: SourceReadResult) -> set[tuple[str, str, str]]:
    return {
        item.package.identity
        for item in result.requirements
        if isinstance(item, ReadyRequirement)
    }


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (
            "v6.yaml",
            {
                ("npm", "@ampproject/remapping", "2.2.0"),
                ("npm", "@babel/plugin-proposal-dynamic-import", "7.18.6"),
                ("npm", "@babel/core", "7.21.0"),
            },
        ),
        (
            "v9.yaml",
            {
                ("npm", "@ampproject/remapping", "2.3.0"),
                ("npm", "@jridgewell/gen-mapping", "0.3.8"),
                ("npm", "@jridgewell/trace-mapping", "0.3.25"),
            },
        ),
    ],
)
def test_verified_format_excerpts(
    fixture: str, expected: set[tuple[str, str, str]]
) -> None:
    path = (FIXTURES / fixture).absolute()
    result = read_pnpm_lock(path)
    assert result.status == "success"
    assert not result.errors
    assert identities(result) == expected
    assert all(isinstance(item, ReadyRequirement) for item in result.requirements)
    assert result.input_paths == (path,)
    assert result.source.ecosystem == "npm"
    assert result.source.kind == "pnpm"
    assert all(
        item.source.path == path and item.source.line == 1
        for item in result.requirements
    )


def test_aliases_peers_patches_workspaces_and_nonregistry_inventory() -> None:
    result = read_pnpm_lock(FIXTURES / "contexts.yaml")
    assert result.status == "success"
    assert not result.errors
    assert identities(result) == {
        ("npm", "real", "1.2.3"),
        ("npm", "real", "1.2.4"),
        ("npm", "@scope/real", "2.0.0"),
        ("npm", "peer", "3.0.0"),
        ("npm", "foo", "1.2.3-beta.1+build.2"),
    }
    ready = [item for item in result.requirements if isinstance(item, ReadyRequirement)]
    scoped = [item for item in ready if item.package.name == "@scope/real"]
    assert len(scoped) == 4  # metadata, alias, and two peer-context snapshots
    assert any("scoped-alias" in item.source.text for item in scoped)
    assert any("packages/member" in item.source.text for item in ready)
    unscanned = [
        item for item in result.requirements if isinstance(item, UnscannedRequirement)
    ]
    patch_locations = [
        item.source for item in unscanned if "applied patch" in item.reason
    ]
    assert len(patch_locations) == 3
    assert len(set(item.text for item in patch_locations)) == 3
    assert all(item.ecosystem == "npm" for item in unscanned)
    assert any("workspace" in item.reason.lower() for item in unscanned)
    assert any("tarball" in item.reason for item in unscanned)
    assert any("matching package metadata" in item.reason for item in unscanned)
    for item in ready:
        if item.package.name == "real" and item.package.version == "1.2.3":
            assert any(
                other.source == item.source and "patch" in other.reason
                for other in unscanned
            )


@pytest.mark.parametrize("version", ["'6.0'", "'9.0'", "6", "9", "6.0", "9.0"])
def test_accepted_empty_inventories(tmp_path: Path, version: str) -> None:
    result = read_text(tmp_path, f"lockfileVersion: {version}\n")
    assert result.status == "success"
    assert not result.errors and not result.requirements


@pytest.mark.parametrize(
    "version",
    [
        "'6'",
        "'9'",
        "'06.0'",
        "'6.00'",
        "6.1",
        "9.1",
        "5.4",
        "10",
        "true",
        "false",
        "null",
        "[]",
        "{}",
    ],
)
def test_unknown_versions_fail(tmp_path: Path, version: str) -> None:
    result = read_text(tmp_path, f"lockfileVersion: {version}\n")
    assert result.status == "failed"
    assert not result.requirements
    assert "Unsupported lockfileVersion" in result.errors[0].reason
    assert result.errors[0].ecosystem == "npm"


@pytest.mark.parametrize(
    "document",
    [
        "",
        "[]",
        "null",
        "{}",
        "lockfileVersion: [",
        "lockfileVersion: '9.0'\nlockfileVersion: '6.0'",
        "!!python/object/apply:os.system ['echo unsafe']",
        "lockfileVersion: '9.0'\npackages: []",
        "lockfileVersion: '9.0'\nimporters: null",
        "lockfileVersion: '9.0'\nsnapshots: true",
        "lockfileVersion: '9.0'\npatchedDependencies: []",
        "lockfileVersion: '9.0'\npackages: {1: {}}",
        "lockfileVersion: '6.0'\nsnapshots: {foo: {}}",
        "lockfileVersion: '9.0'\nrecursive: &x [*x]",
        "lockfileVersion: '9.0'\npackages: {foo@1.0.0: {}, foo@1.0.0: {}}",
    ],
)
def test_malformed_document_fails_contextually(tmp_path: Path, document: str) -> None:
    result = read_text(tmp_path, document)
    assert result.status == "failed"
    assert not result.requirements
    assert result.errors and result.errors[0].ecosystem == "npm"
    assert result.errors[0].source is not None
    assert result.input_paths == ((tmp_path / "pnpm-lock.yaml").absolute(),)


def test_io_and_unicode_failures_register_attempted_input(tmp_path: Path) -> None:
    path = tmp_path / "missing.yaml"
    for content in (None, b"\xff"):
        if content is not None:
            path.write_bytes(content)
        result = read_pnpm_lock(path)
        assert result.status == "failed"
        assert result.input_paths == (path.absolute(),)
        assert result.errors[0].ecosystem == "npm"


@pytest.mark.parametrize("v6", [True, False])
def test_entry_errors_retain_usable_siblings(tmp_path: Path, v6: bool) -> None:
    slash = "/" if v6 else ""
    result = read_text(
        tmp_path,
        f"""
lockfileVersion: '{"6.0" if v6 else "9.0"}'
packages:
  {slash}good@1.0.0:
    resolution: {{integrity: synthetic}}
    dependencies: {{broken: []}}
  {slash}bad@1.0.0: []
importers:
  .:
    dependencies:
      good: {{specifier: ^1, version: 1.0.0}}
      bad: {{specifier: ^1, version: []}}
      other: 1.0.0
    optionalDependencies: []
  broken: []
""",
    )
    assert result.status == "success"
    assert identities(result) == {("npm", "good", "1.0.0")}
    assert result.errors
    assert all(
        error.ecosystem == "npm" and error.source is not None for error in result.errors
    )


@pytest.mark.parametrize(
    "key",
    [
        "foo@1.0.0(unknown)",
        "foo@1.0.0(peer@^1)",
        "foo@1.0.0(peer@1.0.0",
        "foo@1.0.0()",
        "foo@1.0.0(peer@1.0.0)junk",
        "foo@latest",
        "foo@1.0.0_patchhash",
    ],
)
def test_unknown_contexts_never_become_versions(tmp_path: Path, key: str) -> None:
    result = read_text(
        tmp_path,
        f"lockfileVersion: '9.0'\npackages:\n"
        f"  '{key}': {{resolution: {{integrity: synthetic}}}}\n",
    )
    assert result.status == "success"
    assert not identities(result)
    assert len(result.requirements) == 1
    assert isinstance(result.requirements[0], UnscannedRequirement)


def test_v6_root_importer_alias_and_nested_peer_context(tmp_path: Path) -> None:
    result = read_text(
        tmp_path,
        """
lockfileVersion: 6.0
dependencies:
  alias:
    specifier: 'npm:@scope/real@^1'
    version: '@scope/real@1.0.0(peer@2.0.0(other@3.0.0))'
packages:
  /@scope/real@1.0.0(peer@2.0.0(other@3.0.0)):
    resolution: {integrity: synthetic}
""",
    )
    assert not result.errors
    assert len(result.requirements) == 2
    assert identities(result) == {("npm", "@scope/real", "1.0.0")}
    assert "alias" in result.requirements[1].source.text


@pytest.mark.parametrize(
    "metadata",
    [
        "{}",
        "{resolution: []}",
        "{resolution: {integrity: 12}}",
        "{resolution: {integrity: x}, name: other}",
        "{resolution: {integrity: x}, version: 2.0.0}",
        "{resolution: {integrity: x}, patched: yes}",
        "{resolution: {integrity: x, directory: ../local}}",
    ],
)
def test_untrusted_metadata_blocks_snapshot_and_importer(
    tmp_path: Path, metadata: str
) -> None:
    result = read_text(
        tmp_path,
        f"""
lockfileVersion: '9.0'
packages:
  foo@1.0.0: {metadata}
snapshots:
  foo@1.0.0(peer@1.0.0): {{}}
importers:
  .:
    dependencies:
      foo: {{specifier: ^1, version: 1.0.0}}
""",
    )
    assert result.status == "success"
    assert not identities(result)
    assert all(isinstance(item, UnscannedRequirement) for item in result.requirements)


def test_missing_references_patches_and_snapshot_errors_are_visible(
    tmp_path: Path,
) -> None:
    result = read_text(
        tmp_path,
        """
lockfileVersion: '9.0'
patchedDependencies:
  missing@1.0.0: {path: patches/a.patch, hash: abcd}
  broken: []
snapshots:
  missing@1.0.0: {dependencies: {also-missing: 2.0.0}}
  bad@1.0.0: []
  other@1.0.0: {patched: 'true'}
""",
    )
    assert result.status == "success"
    assert not identities(result)
    assert len(result.errors) == 3
    assert len(result.requirements) == 4


@pytest.mark.parametrize(
    ("name", "specifier", "version"),
    [
        ("alias", "npm:other@^1", "real@1.0.0"),
        ("alias", "npm:real@^1", "1.0.0"),
        ("real", "file:../real", "1.0.0"),
        ("alias", "^1", "real@1.0.0"),
        ("bad/name", "npm:real@^1", "real@1.0.0"),
    ],
)
def test_conflicting_importer_targets_are_not_queried_as_aliases(
    tmp_path: Path, name: str, specifier: str, version: str
) -> None:
    result = read_text(
        tmp_path,
        f"""
lockfileVersion: '9.0'
packages:
  real@1.0.0: {{resolution: {{integrity: synthetic}}}}
importers:
  .:
    dependencies:
      {name}: {{specifier: '{specifier}', version: '{version}'}}
""",
    )
    assert identities(result) == {("npm", "real", "1.0.0")}
    assert isinstance(result.requirements[-1], UnscannedRequirement)


def test_yaml_12_names_and_nonrecursive_aliases(tmp_path: Path) -> None:
    result = read_text(
        tmp_path,
        """
lockfileVersion: '9.0'
packages:
  on@1.0.0: &metadata {resolution: {integrity: synthetic}}
  off@1.0.0: *metadata
""",
    )
    assert not result.errors
    assert identities(result) == {("npm", "on", "1.0.0"), ("npm", "off", "1.0.0")}


def test_v6_peer_variants_patch_and_multiple_versions(tmp_path: Path) -> None:
    result = read_text(
        tmp_path,
        """
lockfileVersion: '6.0'
name: root-project
version: 9.9.9
packages:
  /a_b.foo@1.0.0(peer@2.0.0):
    resolution: {integrity: synthetic}
    optional: true
  /a_b.foo@1.0.0(peer@3.0.0):
    resolution: {integrity: synthetic}
    dev: true
  /a_b.foo@2.0.0(patch_hash=abcd):
    resolution: {integrity: synthetic}
    patched: true
""",
    )
    assert not result.errors
    assert identities(result) == {
        ("npm", "a_b.foo", "1.0.0"),
        ("npm", "a_b.foo", "2.0.0"),
    }
    ready = [item for item in result.requirements if isinstance(item, ReadyRequirement)]
    assert len(ready) == 3
    assert len({item.source.text for item in ready}) == 3
    assert isinstance(result.requirements[-1], UnscannedRequirement)
    assert "patch" in result.requirements[-1].reason


@pytest.mark.parametrize("selector", ["foo@v1.0.0", "foo@1.0.0(peer@2.0.0)"])
def test_patch_selectors_join_by_canonical_upstream_identity(
    tmp_path: Path, selector: str
) -> None:
    result = read_text(
        tmp_path,
        f"""
lockfileVersion: '9.0'
patchedDependencies:
  {selector}: {{path: patches/foo.patch, hash: abcd}}
packages:
  foo@1.0.0: {{resolution: {{integrity: synthetic}}}}
""",
    )
    assert not result.errors
    assert identities(result) == {("npm", "foo", "1.0.0")}
    assert len(result.requirements) == 2
    assert isinstance(result.requirements[-1], UnscannedRequirement)
    assert "applied patch" in result.requirements[-1].reason


def test_snapshot_patch_flag_without_other_patch_markers(tmp_path: Path) -> None:
    result = read_text(
        tmp_path,
        """
lockfileVersion: '9.0'
packages:
  foo@1.0.0: {resolution: {integrity: synthetic}}
snapshots:
  foo@1.0.0: {patched: true}
""",
    )
    assert not result.errors
    assert identities(result) == {("npm", "foo", "1.0.0")}
    assert len(result.requirements) == 3
    assert isinstance(result.requirements[-1], UnscannedRequirement)
    assert "applied patch" in result.requirements[-1].reason
