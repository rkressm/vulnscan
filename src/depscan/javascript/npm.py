"""Read package.json and npm lockfile v1/v2/v3 inventories without npm."""

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from pydantic import ValidationError

from depscan.javascript.identity import resolve_npm_declaration
from depscan.models import (
    DependencySource,
    PackageVersion,
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
        pending = [(tree, "dependencies", "")]
        inventory: dict[str, Any] = {"": document}
        locations = []
        while pending:
            entries, prefix, parent_path = pending.pop()
            for name, record in entries.items():
                text = f"{prefix}[{json.dumps(name)}]"
                location = _location(path, text)
                install_path = f"{parent_path}/node_modules/{name}".lstrip("/")
                inventory[install_path] = record
                if not isinstance(record, dict):
                    errors.append(
                        _error(path, text, "Dependency record must be an object.")
                    )
                    continue
                locations.append((install_path, name, record, location))
                if "dependencies" in record:
                    nested = record["dependencies"]
                    if isinstance(nested, dict):
                        pending.append((nested, f"{text}.dependencies", install_path))
                    else:
                        errors.append(
                            _error(path, text, "Nested dependencies must be an object.")
                        )
        declarations = _requesters(inventory)
        for install_path, name, record, location in locations:
            requirements.append(
                _record(name, record, location, declarations.get(install_path, []))
            )
    else:
        packages = document.get("packages")
        if not isinstance(packages, dict):
            raise ValueError("packages must be an object for lockfileVersion 2/3.")
        declarations = _requesters(packages)
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
            requirements.append(
                _record(
                    install_name, record, location, declarations.get(install_path, [])
                )
            )
    return requirements, errors


def _requesters(inventory: dict[str, Any]) -> dict[str, list[str]]:
    """Associate declarations with the nearest recorded install, including hoists.

    This is a lexical inventory join, not range resolution or an active install
    reconstruction. A nested record shadows its hoisted namesake even if broken.
    """
    result: dict[str, list[str]] = {}
    for requester, record in inventory.items():
        if not isinstance(record, dict):
            continue
        directory = PurePosixPath(requester)
        ancestors = (directory, *directory.parents)
        for group in (*_GROUPS, "requires"):
            declarations = record.get(group)
            if not isinstance(declarations, dict):
                continue
            for name, declaration in declarations.items():
                if not isinstance(declaration, str):
                    continue
                for ancestor in ancestors:
                    if ancestor.name == "node_modules":
                        continue
                    candidate = str(ancestor / "node_modules" / name)
                    if candidate in inventory:
                        result.setdefault(candidate, []).append(declaration)
                        break
    return result


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


def _ordinary_registry_spec(value: str) -> bool:
    """Classify plain pins/ranges/tags without validating or resolving ranges."""
    value = value.strip()
    return (
        value not in (".", "..")
        and not any(delimiter in value for delimiter in (":", "/", "\\"))
        and not value.endswith((".tgz", ".tar.gz", ".tar"))
    )


def _record(
    install_name: str,
    record: dict[str, Any],
    source: SourceLocation,
    declarations: list[str],
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
    targets = {name} if "name" in record else set()
    aliases = [value for value in declarations if value.startswith("npm:")]
    if version.startswith("npm:"):
        aliases.append(version)
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
    # Plain registry requests assert the install name even when another source
    # (explicit name or tarball URL, not just an npm: alias) suggests a target.
    if any(_ordinary_registry_spec(value) for value in declarations):
        targets.add(install_name)
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
            targets.add(registry_name)
        elif ":" in resolved or resolved.startswith(("/", ".")):
            return _unscanned(
                source,
                "Non-registry or unverified tarball source; "
                "registry identity is not trustworthy.",
                install_name,
            )
    if len(targets) > 1:
        return _unscanned(
            source, "Conflicting registry/alias identities.", install_name
        )
    if targets:
        name = targets.pop()
    if isinstance(resolved, str) and registry_name is None:
        relative_name, separator, artifact = resolved.partition("/-/")
        if relative_name != name or not separator or not artifact or "/" in artifact:
            return _unscanned(
                source, "Unrecognized registry-relative source.", install_name
            )
    return resolve_npm_declaration(name, version, source)
