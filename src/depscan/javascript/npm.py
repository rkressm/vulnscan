"""Read package.json and npm lockfile v1/v2/v3 inventories without npm."""

import json
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from pydantic import ValidationError

from depscan.javascript.identity import resolve_npm_declaration
from depscan.models import (
    DependencySource,
    PackageVersion,
    ReadyRequirement,
    RequirementResult,
    ScanError,
    SourceLocation,
    SourceReadResult,
    UnscannedRequirement,
)

_GROUPS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
_INSTALL_PATH = re.compile(r"(?:[^/]+/)*node_modules/((?:@[^/]+/)?[^/]+)$")
_WORKSPACE_REASON = (
    "Workspace/local container or link excluded; external workspace dependency "
    "coverage is unavailable (nested manifests are not read)."
)


def _location(path: Path, text: str) -> SourceLocation:
    return SourceLocation(path=path, line=1, text=text)


def _error(path: Path, text: str, reason: str) -> ScanError:
    return ScanError(ecosystem="npm", source=_location(path, text), reason=reason)


def _unscanned(
    source: SourceLocation, reason: str, name: str | None = None
) -> UnscannedRequirement:
    return UnscannedRequirement(
        ecosystem="npm", source=source, name=name, reason=reason
    )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"Non-JSON constant: {value}")


def _read(path: Path, kind: Literal["package_json", "npm"]) -> SourceReadResult:
    # absolute(), unlike resolve(), preserves symlink spelling and is registered
    # before opening. No other manifest, node_modules or environment file is read.
    path = path.absolute()
    source = DependencySource(ecosystem="npm", path=path, kind=kind)
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
        if not isinstance(document, dict):
            raise ValueError("Expected a JSON object.")
        if kind == "package_json":
            requirements, errors = _manifest(path, document)
        else:
            requirements, errors = _lock(path, document)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        return SourceReadResult(
            source=source,
            status="failed",
            errors=(_error(path, path.name, f"Cannot read {path.name}: {exc}"),),
            input_paths=(path,),
        )
    return SourceReadResult(
        source=source,
        status="success",
        requirements=tuple(requirements),
        errors=tuple(errors),
        input_paths=(path,),
    )


def read_package_json(path: Path) -> SourceReadResult:
    """Read all four dependency groups; preserve exact-pin declaration provenance."""
    return _read(path, "package_json")


def read_npm_lock(path: Path) -> SourceReadResult:
    """Read package-lock.json or npm-shrinkwrap.json, integer versions 1, 2, 3."""
    return _read(path, "npm")


def _workspaces(document: dict[str, Any]) -> bool:
    if "workspaces" not in document:
        return False
    value = document["workspaces"]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("workspaces must be an array of strings.")
    return bool(value)


def _manifest(
    path: Path, document: dict[str, Any]
) -> tuple[list[RequirementResult], list[ScanError]]:
    requirements: list[RequirementResult] = []
    errors: list[ScanError] = []
    # A broken group is an overall shape failure, not a clean empty inventory.
    for group in _GROUPS:
        if group in document and not isinstance(document[group], dict):
            raise ValueError(f"{group} must be an object of dependency declarations.")
    if _workspaces(document):
        requirements.append(
            _unscanned(_location(path, "workspaces"), _WORKSPACE_REASON)
        )
    for group in _GROUPS:
        for name, declaration in document.get(group, {}).items():
            text = f"{group}.{name} = {declaration}"
            if not isinstance(declaration, str):
                errors.append(
                    _error(path, text, "Dependency declaration must be a string.")
                )
                continue
            requirements.append(
                resolve_npm_declaration(name, declaration, _location(path, text))
            )
    return requirements, errors


def _lock(
    path: Path, document: dict[str, Any]
) -> tuple[list[RequirementResult], list[ScanError]]:
    version = document.get("lockfileVersion")
    if type(version) is not int or version not in (1, 2, 3):
        raise ValueError("Unsupported lockfileVersion; expected integer 1, 2 or 3.")
    requirements: list[RequirementResult] = []
    errors: list[ScanError] = []
    if _workspaces(document):
        requirements.append(
            _unscanned(_location(path, "workspaces"), _WORKSPACE_REASON)
        )
    if version == 1:
        tree = document.get("dependencies", {})
        if not isinstance(tree, dict):
            raise ValueError("dependencies must be an object.")
        # Iterative traversal does not impose a Python recursion limit on the tree.
        pending = [(tree, "dependencies", document)]
        while pending:
            entries, prefix, parent = pending.pop()
            for name, record in entries.items():
                text = f"{prefix}[{json.dumps(name)}]"
                location = _location(path, text)
                if not isinstance(record, dict):
                    errors.append(
                        _error(path, text, "Dependency record must be an object.")
                    )
                    continue
                requirements.append(
                    _record(name, record, location, _aliases(parent, name))
                )
                if "dependencies" in record:
                    nested = record["dependencies"]
                    if isinstance(nested, dict):
                        pending.append((nested, f"{text}.dependencies", record))
                    else:
                        errors.append(
                            _error(path, text, "Nested dependencies must be an object.")
                        )
    else:
        packages = document.get("packages")
        if not isinstance(packages, dict):
            raise ValueError("packages must be an object for lockfileVersion 2/3.")
        # The legacy dependencies tree in v2 is intentionally never inventoried.
        for install_path, record in packages.items():
            text = f"packages[{json.dumps(install_path)}]"
            location = _location(path, text)
            if not isinstance(record, dict):
                errors.append(_error(path, text, "Package record must be an object."))
                continue
            if install_path == "":
                if _workspaces(record):
                    requirements.append(_unscanned(location, _WORKSPACE_REASON))
                continue
            match = _INSTALL_PATH.fullmatch(install_path)
            if match is None:
                requirements.append(_unscanned(location, _WORKSPACE_REASON))
                continue
            install_name = match.group(1)
            parent_path = install_path.rsplit("node_modules/", 1)[0].rstrip("/")
            parent = packages.get(parent_path, {})
            aliases = _aliases(parent, install_name) if isinstance(parent, dict) else []
            requirements.append(_record(install_name, record, location, aliases))
    return requirements, errors


def _aliases(parent: dict[str, Any], name: str) -> list[str]:
    aliases = []
    for group in (*_GROUPS, "requires"):
        declarations = parent.get(group)
        if isinstance(declarations, dict):
            declaration = declarations.get(name)
            if isinstance(declaration, str) and declaration.startswith("npm:"):
                aliases.append(declaration)
    return aliases


def _registry_name(resolved: str) -> str | None:
    """Recognize public-registry tarball identity, not arbitrary URL filenames."""
    url = urlsplit(resolved)
    if url.scheme not in ("https", "http") or url.hostname not in (
        "registry.npmjs.org",
        "registry.yarnpkg.com",
    ):
        return None
    package, separator, artifact = unquote(url.path).lstrip("/").partition("/-/")
    if not separator or not artifact or "/" in artifact:
        return None
    return package


def _record(
    install_name: str,
    record: dict[str, Any],
    source: SourceLocation,
    aliases: list[str] | None = None,
) -> RequirementResult:
    if "link" in record and type(record["link"]) is not bool:
        return _unscanned(source, "Invalid link flag.", install_name)
    if record.get("link") is True:
        return _unscanned(source, _WORKSPACE_REASON, install_name)
    version = record.get("version")
    if not isinstance(version, str):
        return _unscanned(
            source, "Missing or invalid exact package version.", install_name
        )
    name = record.get("name", install_name)
    if not isinstance(name, str):
        return _unscanned(source, "Invalid package name field.", install_name)
    resolved = record.get("resolved")
    registry_name = None
    if "resolved" in record:
        if not isinstance(resolved, str):
            return _unscanned(source, "Invalid resolved source field.", install_name)
        try:
            registry_name = _registry_name(resolved)
        except ValueError:
            registry_name = None
        if registry_name is not None:
            # Aliases may differ from their installation path. The explicit name
            # or registry URL supplies the real identity; never query the alias.
            if "name" in record and name != registry_name:
                return _unscanned(
                    source, "Conflicting registry package identities.", install_name
                )
            name = registry_name
        elif ":" in resolved or resolved.startswith(("/", ".")):
            return _unscanned(
                source,
                "Non-registry or unverified tarball source; "
                "registry identity is not trustworthy.",
                install_name,
            )
        elif not resolved.startswith(f"{name}/-/"):
            return _unscanned(
                source, "Unrecognized registry-relative source.", install_name
            )
    if aliases:
        targets = set()
        for alias in aliases:
            target, separator, _ = alias[4:].rpartition("@")
            try:
                if not separator:
                    raise ValueError("Missing alias version separator")
                PackageVersion(ecosystem="npm", name=target, version="0.0.0")
            except ValidationError, ValueError:
                return _unscanned(
                    source, "Untrustworthy declared alias target.", install_name
                )
            targets.add(target)
        if len(targets) != 1:
            return _unscanned(
                source, "Conflicting declared alias targets.", install_name
            )
        target = targets.pop()
        if ("name" in record or registry_name is not None) and name != target:
            return _unscanned(
                source, "Conflicting declared/locked alias identities.", install_name
            )
        name = target
    result = resolve_npm_declaration(name, version, source)
    if isinstance(result, ReadyRequirement):
        if (
            "name" in record or registry_name is not None or aliases
        ) and result.package.name != name:
            return _unscanned(
                source, "Conflicting alias target identities.", install_name
            )
    # PackageVersion validation above deliberately rejects local/git/range versions.
    return result
