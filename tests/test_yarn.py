from pathlib import Path

import pytest

from depscan.javascript.yarn import read_yarn_lock
from depscan.models import ReadyRequirement, SourceReadResult, UnscannedRequirement

FIXTURES = Path(__file__).parent / "fixtures" / "yarn"


def identities(result: SourceReadResult) -> list[tuple[str, str, str]]:
    return [
        item.package.identity
        for item in result.requirements
        if isinstance(item, ReadyRequirement)
    ]


def read_text(tmp_path: Path, text: str) -> SourceReadResult:
    path = tmp_path / "yarn.lock"
    path.write_text(text, encoding="utf-8")
    return read_yarn_lock(path)


def modern(body: str, version: str = "8") -> str:
    return f"__metadata:\n  version: {version}\n\n{body}"


def test_classic_inventory_and_group_provenance() -> None:
    result = read_yarn_lock(FIXTURES / "classic.lock")
    assert result.status == "success"
    assert not result.errors
    assert identities(result) == [
        ("npm", "acorn", "5.7.1"),
        ("npm", "acorn", "5.7.1"),
        ("npm", "acorn", "5.7.1"),
        ("npm", "@babel/code-frame", "7.0.0-beta.55"),
        ("npm", "@scope/real", "1.2.3"),
        ("npm", "acorn", "8.0.1"),
    ]
    assert len({item.source.text for item in result.requirements}) == 6


@pytest.mark.parametrize(
    "version,name,package_version",
    [
        (4, "@algolia/cache-browser-local-storage", "4.2.0"),
        (6, "@actions/core", "1.2.6"),
        (8, "@aashutoshrathi/word-wrap", "1.2.6"),
        (10, "@aashutoshrathi/word-wrap", "1.2.6"),
    ],
)
def test_verified_modern_versions(
    version: int, name: str, package_version: str
) -> None:
    path = (FIXTURES / f"modern-{version}.lock").absolute()
    result = read_yarn_lock(path)
    assert result.status == "success"
    assert identities(result) == [("npm", name, package_version)]
    assert result.input_paths == (path,)
    assert result.source.path == path
    assert result.source.kind == "yarn"
    assert all(item.source.line == 1 for item in result.requirements)


def test_wrappers_aliases_and_workspace_coverage() -> None:
    result = read_yarn_lock(FIXTURES / "wrappers.lock")
    assert result.status == "success"
    assert identities(result) == [
        ("npm", "@scope/real", "1.2.3"),
        ("npm", "virtual-example", "2.0.0"),
        ("npm", "@strictsoftware/typedoc-plugin-monorepo", "0.2.2"),
        ("npm", "nested", "1.0.0"),
    ]
    unscanned = [i for i in result.requirements if isinstance(i, UnscannedRequirement)]
    assert len(unscanned) == 3
    assert sum("Upstream-only" in i.reason for i in unscanned) == 2
    assert "workspace" in unscanned[-1].reason
    assert "alias" in result.requirements[0].source.text


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        "foo: {}",
        "# yarn lockfile v2\n",
        "# yarn lockfile v0\n",
        "# yarn lockfile v1\n__metadata:\n  version 8\n",
        "# yarn lockfile v1\nfoo@1:\n version 1\n",
        "# yarn lockfile v1\nfoo@1:\n    version 1\n",
        '# yarn lockfile v1\nfoo@1:\n  version "unterminated\n',
        "# yarn lockfile v1\nfoo@1:\n  version '1.2.3'\n",
        "# yarn lockfile v1\nfoo@1:\n  version [1,2,3]\n",
        '# yarn lockfile v1\nfoo@1:\n  version "1.2.3" extra\n',
        '# yarn lockfile v1\nfoo@1:\n  version "1.2.3"\n  version "2.0.0"\n',
        "# yarn lockfile v1\n<<<<<<< HEAD\n",
        modern("foo: [unterminated"),
        modern("foo: !!python/object:danger {}"),
        modern("foo: {}\nfoo: {}"),
        modern("foo:\n  version: 1\n  version: 2"),
        modern("? [a, {b: c}]\n: value"),
        '# yarn lockfile v1\nfoo@1:\n  version "1.0.0"\nfoo@1:\n  version "1.0.0"',
        'foo@1:\n  version "1.0.0"\n# yarn lockfile v1\n',
        '# yarn lockfile v1\n@scope/name@^1:\n  version "1.2.3"\n',
        '# yarn lockfile v1\n123@^1:\n  version "1.2.3"\n',
    ],
)
def test_bad_documents_fail(tmp_path: Path, text: str) -> None:
    result = read_text(tmp_path, text)
    assert result.status == "failed"
    assert not result.requirements
    assert result.errors
    assert result.errors[0].ecosystem == "npm"
    assert result.input_paths == ((tmp_path / "yarn.lock").absolute(),)


@pytest.mark.parametrize(
    "version", ["0", "1", "5", "7", "9", "11", "true", '"8"', "8.0", "null"]
)
def test_unknown_or_wrong_typed_versions_fail(tmp_path: Path, version: str) -> None:
    result = read_text(tmp_path, modern("", version))
    assert result.status == "failed"
    assert "__metadata.version" in result.errors[0].reason


@pytest.mark.parametrize("text", ["# yarn lockfile v1\n", modern("")])
def test_empty_supported_inventory(tmp_path: Path, text: str) -> None:
    result = read_text(tmp_path, text)
    assert result.status == "success"
    assert not result.requirements and not result.errors


def test_classic_quotes_comments_crlf_bom_and_nested_maps(tmp_path: Path) -> None:
    text = (
        '\ufeff# yarn lockfile v1\r\n"f\\u006fo@^1", foo@~1: # group\r\n'
        '  version "v1.2.3-beta.1+build" # exact\r\n'
        '  dependencies:\r\n    "@scope/name" "^2"\r\n'
        '  optionalDependencies:\r\n    other "^3"\r\n'
    )
    result = read_text(tmp_path, text)
    assert result.status == "success"
    assert identities(result) == [("npm", "foo", "1.2.3-beta.1+build")] * 2


@pytest.mark.parametrize("name", ["123", "@scope/name"])
def test_classic_names_requiring_quotes(tmp_path: Path, name: str) -> None:
    result = read_text(tmp_path, f'# yarn lockfile v1\n"{name}@^1":\n  version "1.2.3"')
    assert identities(result) == [("npm", name, "1.2.3")]


@pytest.mark.parametrize(
    "selector,fields",
    [
        ("foo@file:../foo", 'version "1.2.3"'),
        ("foo@foo.tgz", 'version "1.2.3"'),
        ("foo@", 'version "1.2.3"'),
        ("alias@npm:real@https://example.com/real.tgz", 'version "1.2.3"'),
        ("foo@https://example.com/foo.tgz", 'version "1.2.3"'),
        ("foo@^1", 'version "1.2.3"\n  resolved "https://evil.example/foo/-/foo.tgz"'),
        (
            "alias@npm:real@^1",
            'version "1.2.3"\n  resolved "https://registry.npmjs.org/wrong/-/wrong.tgz"',
        ),
        ("foo@^1", "version true"),
        ("foo@^1", 'integrity "hash"'),
        ("foo@^1", 'version "^1.2.3"'),
    ],
)
def test_classic_untrustworthy_entries_are_unscanned(
    tmp_path: Path, selector: str, fields: str
) -> None:
    result = read_text(tmp_path, f'# yarn lockfile v1\n"{selector}":\n  {fields}\n')
    assert result.status == "success"
    assert not identities(result)
    assert isinstance(result.requirements[0], UnscannedRequirement)


@pytest.mark.parametrize(
    "locator,version",
    [
        ("foo@npm:^1.0.0", "1.0.0"),
        ("foo@npm:1.0.0", "2.0.0"),
        ("alias@npm:real@1.0.0", "1.0.0"),
        ("alias@npm:@scope/real@1.0.0", "1.0.0"),
        ("alias@virtual:hash#npm:real@1.0.0", "1.0.0"),
        ("foo@npm:1.0.0::__archiveUrl=https%3A%2F%2Fexample.com%2Ffoo.tgz", "1.0.0"),
        ("foo@file:../foo", "1.0.0"),
        ("foo@https://example.com/foo.tgz", "1.0.0"),
        ("foo@virtual:#npm:1.0.0", "1.0.0"),
        ("foo@patch:bar@npm%3A1.0.0#patch", "1.0.0"),
        ("foo@patch:foo@npm%253A1.0.0#patch", "1.0.0"),
        ("foo@patch:foo@npm%3A1.0.0", "1.0.0"),
        ("foo@" + "virtual:hash#" * 17 + "npm:1.0.0", "1.0.0"),
    ],
)
def test_untrustworthy_modern_entries(
    tmp_path: Path, locator: str, version: str
) -> None:
    result = read_text(
        tmp_path,
        modern(f'"foo@npm:*":\n  version: "{version}"\n  resolution: "{locator}"\n'),
    )
    assert result.status == "success"
    assert not identities(result)
    assert any(isinstance(i, UnscannedRequirement) for i in result.requirements)


def test_malformed_entry_keeps_good_siblings(tmp_path: Path) -> None:
    result = read_text(
        tmp_path,
        modern(
            "bad: []\nmissing: {}\nwrong:\n  version: 1\n  resolution: true\n"
            'good:\n  version: 1.2.3\n  resolution: "foo@npm:1.2.3"\n'
        ),
    )
    assert result.status == "success"
    assert identities(result) == [("npm", "foo", "1.2.3")]
    assert len(result.errors) == 1
    assert len(result.requirements) == 3


def test_sixteen_virtual_wrappers_are_supported(tmp_path: Path) -> None:
    locator = "foo@" + "virtual:hash#" * 16 + "npm:1.0.0"
    result = read_text(
        tmp_path,
        modern(f'foo:\n  version: 1.0.0\n  resolution: "{locator}"\n'),
    )
    assert identities(result) == [("npm", "foo", "1.0.0")]


def test_modern_keeps_versions_and_duplicate_identity_provenance(
    tmp_path: Path,
) -> None:
    result = read_text(
        tmp_path,
        modern(
            '"foo@npm:^1":\n  version: 1.0.0\n  resolution: "foo@npm:1.0.0"\n'
            '"alias@npm:foo@1":\n  version: 1.0.0\n  resolution: "foo@npm:1.0.0"\n'
            '"foo@npm:^2":\n  version: 2.0.0\n  resolution: "foo@npm:2.0.0"\n'
        ),
    )
    assert identities(result) == [
        ("npm", "foo", "1.0.0"),
        ("npm", "foo", "1.0.0"),
        ("npm", "foo", "2.0.0"),
    ]
    assert len({i.source.text for i in result.requirements}) == 3


def test_reads_without_package_manager_executables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "")
    for name in ("classic.lock", "modern-8.lock", "wrappers.lock"):
        result = read_yarn_lock(FIXTURES / name)
        assert result.status == "success"
        assert identities(result)


@pytest.mark.parametrize(
    "locator",
    [
        "foo@patch:foo@virtual%3Ahash%23npm%3A1.2.3#patch",
        "foo@patch:foo@patch%3Afoo@npm%253A1.2.3%23patch#patch",
    ],
)
def test_patch_decodes_only_its_source_once(tmp_path: Path, locator: str) -> None:
    result = read_text(
        tmp_path,
        modern(f'foo:\n  version: 1.2.3\n  resolution: "{locator}"\n'),
    )
    assert identities(result) == [("npm", "foo", "1.2.3")]
    unscanned = [i for i in result.requirements if isinstance(i, UnscannedRequirement)]
    assert len(unscanned) == 1
    assert "Upstream-only" in unscanned[0].reason


def test_unresolved_patch_has_only_one_coverage_outcome(tmp_path: Path) -> None:
    result = read_text(
        tmp_path,
        modern('foo:\n  version: 1.2.3\n  resolution: "foo@patch:foo@npm%3A%5E1#p"'),
    )
    assert len(result.requirements) == 1
    assert isinstance(result.requirements[0], UnscannedRequirement)
    assert "Upstream-only" not in result.requirements[0].reason


@pytest.mark.parametrize("protocol", ["workspace", "portal", "link"])
def test_workspace_protocols_have_visible_coverage(
    tmp_path: Path, protocol: str
) -> None:
    result = read_text(
        tmp_path,
        modern(f'foo:\n  version: 1.2.3\n  resolution: "foo@{protocol}:../foo"'),
    )
    assert not identities(result)
    assert isinstance(result.requirements[0], UnscannedRequirement)
    assert result.requirements[0].name == "foo"
    assert "external workspace coverage" in result.requirements[0].reason


@pytest.mark.parametrize("comment", ["# yarn lockfile v1", "  # yarn lockfile v1"])
def test_modern_body_comments_are_not_format_headers(
    tmp_path: Path, comment: str
) -> None:
    result = read_text(
        tmp_path,
        modern(f'foo:\n{comment}\n  version: 1.2.3\n  resolution: "foo@npm:1.2.3"'),
    )
    assert identities(result) == [("npm", "foo", "1.2.3")]


@pytest.mark.parametrize(
    "root",
    [
        '  version: 0.0.0-use.local\n  resolution: "project@workspace:."\n'
        '  dependencies:\n    missing: "npm:^1"\n',
        '  version: 0.0.0-use.local\n  resolution: "project@workspace:."\n'
        "  dependencies: []\n",
        '  resolution: "project@workspace:."\n  dependencies: true\n',
        "  dependencies:\n    missing: {}\n",
        "  dependencies: null\n",
    ],
)
def test_workspace_root_never_claims_complete_inventory(
    tmp_path: Path, root: str
) -> None:
    result = read_text(
        tmp_path,
        modern(
            f'"project@workspace:.":\n{root}'
            '"present@npm:1":\n  version: 1.0.0\n'
            '  resolution: "present@npm:1.0.0"\n'
        ),
    )
    assert result.status == "success"
    assert identities(result) == [("npm", "present", "1.0.0")]
    assert isinstance(result.requirements[0], UnscannedRequirement)
    assert "project@workspace:." in result.requirements[0].source.text


@pytest.mark.parametrize("root", ["[]", "null", "true", '"broken"', "{}"])
def test_malformed_root_container_cannot_be_clean_empty(
    tmp_path: Path, root: str
) -> None:
    result = read_text(tmp_path, modern(f'"project@workspace:.": {root}\n'))
    assert not identities(result)
    assert result.errors or any(
        isinstance(item, UnscannedRequirement) for item in result.requirements
    )


def test_read_failures_track_input(tmp_path: Path) -> None:
    path = tmp_path / "yarn.lock"
    for contents in (None, b"\xff"):
        if contents is not None:
            path.write_bytes(contents)
        result = read_yarn_lock(path)
        assert result.status == "failed"
        assert result.input_paths == (path.absolute(),)
        assert result.errors[0].source is not None


def test_recursive_yaml_does_not_recurse_through_entries(tmp_path: Path) -> None:
    result = read_text(
        tmp_path, modern("foo: &loop\n  resolution: *loop\n  version: 1.2.3\n")
    )
    assert result.status == "success"
    assert not identities(result)


def test_excessively_nested_yaml_fails_contextually(tmp_path: Path) -> None:
    result = read_text(tmp_path, modern("junk: " + "[" * 1200 + "0" + "]" * 1200))
    assert result.status == "failed"
    assert result.errors[0].ecosystem == "npm"
    assert not result.requirements
