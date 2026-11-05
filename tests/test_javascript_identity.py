from pathlib import Path

import pytest

from depscan.javascript.identity import exact_npm_version, resolve_npm_declaration
from depscan.models import PackageVersion, ReadyRequirement, SourceLocation

LOCATION = SourceLocation(path=Path("package.json"), line=1, text="dependencies.alias")


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        ("0.0.0-dev.0+build.01", "0.0.0-dev.0+build.01"),
        ("9007199254740991.0.0", "9007199254740991.0.0"),
        ("9007199254740992.0.0", None),
        ("1.0.0-01", None),
        ("01.2.3", None),
        ("1.2.3-", None),
        ("1.2.3-α", None),
        ("1.2.3+a..b", None),
        ("1.2.3+" + "x" * 256, None),
        ("=1.2.3", None),
        ("^1.2.3", None),
        ("1.2", None),
        ("latest", None),
        (" 1.2.3", None),
    ],
)
def test_exact_version_uses_shared_validation(value: str, expected: str | None) -> None:
    assert exact_npm_version(value) == expected
    if expected is not None:
        assert (
            PackageVersion(ecosystem="npm", name="x", version=value).version == expected
        )


@pytest.mark.parametrize(
    "name, declaration, target, version",
    [
        ("a_b.c", "1.2.3", "a_b.c", "1.2.3"),
        ("@Scope/Name", "v1.0.0-rc.2+build", "@Scope/Name", "1.0.0-rc.2+build"),
        ("alias", "npm:real@1.2.3", "real", "1.2.3"),
        ("@scope/alias", "npm:@other/real@1.0.0-beta.1", "@other/real", "1.0.0-beta.1"),
    ],
)
def test_exact_declarations(
    name: str, declaration: str, target: str, version: str
) -> None:
    result = resolve_npm_declaration(name, declaration, LOCATION)
    assert isinstance(result, ReadyRequirement)
    assert result.package.identity == ("npm", target, version)
    assert result.source == LOCATION


@pytest.mark.parametrize(
    "declaration",
    [
        "*",
        "",
        "latest",
        "^1.2.3",
        "~1.0.0",
        ">=1.0.0",
        "1 || 2",
        "1.x",
        "npm:real@^1.0.0",
        "npm:@scope/real@latest",
        "npm:@scope/real",
        "npm:real",
        "npm:bad/name@1.2.3",
        "file:../pkg",
        "./pkg",
        "../pkg",
        "/pkg",
        "~/pkg",
        "link:../pkg",
        "workspace:*",
        "portal:pkg",
        "https://example.org/pkg.tgz",
        "git+https://example.org/a.git#abc",
        "github:owner/repo",
        "owner/repo",
    ],
)
def test_unresolved_and_non_registry_declarations(declaration: str) -> None:
    result = resolve_npm_declaration("alias", declaration, LOCATION)
    assert result.status == "unscanned"
    assert result.ecosystem == "npm"
    assert result.source == LOCATION
    assert result.reason


@pytest.mark.parametrize("name", ["", "_private", ".bad", "@scope", "bad/name", "a b"])
def test_invalid_declared_alias_name_is_not_hidden(name: str) -> None:
    assert (
        resolve_npm_declaration(name, "npm:real@1.2.3", LOCATION).status == "unscanned"
    )
