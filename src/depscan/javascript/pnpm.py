"""Read pnpm 6.0/9.0 recorded inventories, without invoking pnpm or Node."""

import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from depscan.javascript.identity import exact_npm_version, resolve_npm_declaration
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

_GROUPS = ("dependencies", "devDependencies", "optionalDependencies")
_WORKSPACE = (
    "Workspace/local importer or link excluded; external workspace dependency "
    "coverage is unavailable (nested manifests are not read)."
)
_PATCH = (
    "Upstream advisories do not assess the applied patch; patch coverage unavailable."
)


def _location(path: Path, text: str) -> SourceLocation:
    return SourceLocation(path=path, line=1, text=text)


def _unscanned(source: SourceLocation, reason: str) -> UnscannedRequirement:
    return UnscannedRequirement(ecosystem="npm", source=source, reason=reason)


def _mapping(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{description} must be a mapping with string keys.")
    return value


def _acyclic(document: Any) -> None:
    # Safe YAML still permits recursive aliases. Reject cycles before walking any
    # records, and avoid Python recursion even for deeply nested inert metadata.
    active: set[int] = set()
    visited: set[int] = set()
    pending = [(document, False)]
    while pending:
        node, exiting = pending.pop()
        if not isinstance(node, (dict, list)):
            continue
        identity = id(node)
        if exiting:
            active.remove(identity)
            visited.add(identity)
        elif identity in active:
            raise ValueError("Recursive YAML aliases are unsupported.")
        elif identity not in visited:
            active.add(identity)
            pending.append((node, True))
            children = node.values() if isinstance(node, dict) else node
            pending.extend((child, False) for child in children)


def read_pnpm_lock(path: Path) -> SourceReadResult:
    """Read exactly YAML lockfileVersion 6.0 or 9.0 (string or numeric)."""
    path = path.absolute()
    source = DependencySource(ecosystem="npm", path=path, kind="pnpm")
    try:
        yaml = YAML(typ="safe", pure=True)
        yaml.allow_duplicate_keys = False
        document = yaml.load(path.read_text(encoding="utf-8"))
        _acyclic(document)
        document = _mapping(document, "Lockfile")
        version = document.get("lockfileVersion")
        if not (
            (type(version) is str and version in ("6.0", "9.0"))
            or (type(version) in (int, float) and version in (6, 9))
        ):
            raise ValueError("Unsupported lockfileVersion; expected 6.0 or 9.0.")
        requirements, errors = _inventory(path, document, str(version).startswith("6"))
    except (OSError, UnicodeError, ValueError, YAMLError, RecursionError) as exc:
        return SourceReadResult(
            source=source,
            status="failed",
            errors=(
                ScanError(
                    ecosystem="npm",
                    source=_location(path, path.name),
                    reason=f"Cannot read {path.name}: {exc}",
                ),
            ),
            input_paths=(path,),
        )
    return SourceReadResult(
        source=source,
        status="success",
        requirements=tuple(requirements),
        errors=tuple(errors),
        input_paths=(path,),
    )


def _locator(value: str, *, depth: int = 0) -> tuple[str, str, bool] | None:
    """Recognize exact identities with balanced peer/patch contexts only."""
    if depth > 20:
        return None
    base, _, context = value.partition("(")
    name, separator, version = base.rpartition("@")
    if not separator or exact_npm_version(version) is None:
        return None
    patched = False
    if context:
        remaining = "(" + context
        while remaining:
            if not remaining.startswith("("):
                return None
            balance = 0
            end = 0
            for index, char in enumerate(remaining):
                balance += (char == "(") - (char == ")")
                if balance == 0:
                    end = index
                    break
            if balance:
                return None
            inner = remaining[1:end]
            if re.fullmatch(r"patch_hash=[A-Za-z0-9_-]+", inner):
                patched = True
            else:
                peer = _locator(inner, depth=depth + 1)
                if peer is None:
                    return None
                patched |= peer[2]
            remaining = remaining[end + 1 :]
    elif "(" in value:
        return None
    try:
        package = PackageVersion(ecosystem="npm", name=name, version=version)
    except ValidationError:
        return None
    return package.name, package.version, patched


def _package(
    key: str, record: dict[str, Any], source: SourceLocation, v6: bool
) -> tuple[RequirementResult, bool]:
    locator = _locator(key[1:] if v6 and key.startswith("/") else key)
    if v6 and not key.startswith("/"):
        locator = None
    if locator is None:
        return _unscanned(
            source, "Non-registry or unrecognized package locator."
        ), False
    name, version, patched = locator
    resolution = record.get("resolution")
    if not isinstance(resolution, dict):
        return _unscanned(source, "Missing or malformed package resolution."), False
    # Integrity is evidence for a registry-keyed record, not proof that an
    # arbitrary tarball/directory/git source is the registry package in the key.
    if any(
        field in resolution
        for field in ("tarball", "directory", "repo", "commit", "type")
    ):
        return _unscanned(
            source, "Non-registry or unverified tarball resolution."
        ), False
    if not isinstance(resolution.get("integrity"), str) or not resolution["integrity"]:
        return _unscanned(
            source, "Missing registry integrity; identity is unverified."
        ), False
    for field, expected in (("name", name), ("version", version)):
        if field in record and record[field] != expected:
            return _unscanned(source, "Conflicting package identity metadata."), False
    if "patched" in record and type(record["patched"]) is not bool:
        return _unscanned(source, "Malformed patched flag."), False
    return resolve_npm_declaration(name, version, source), patched or record.get(
        "patched"
    ) is True


def _inventory(
    path: Path, document: dict[str, Any], v6: bool
) -> tuple[list[RequirementResult], list[ScanError]]:
    packages = _mapping(document.get("packages", {}), "packages")
    importers = _mapping(document.get("importers", {}), "importers")
    snapshots = _mapping(document.get("snapshots", {}), "snapshots")
    patches = _mapping(document.get("patchedDependencies", {}), "patchedDependencies")
    if v6 and snapshots:
        raise ValueError("snapshots are not part of lockfileVersion 6.0.")
    requirements: list[RequirementResult] = []
    errors: list[ScanError] = []
    patched_identities = set()
    for key in patches:
        locator = _locator(key)
        if locator is not None:
            patched_identities.add((locator[0], locator[1]))
    # Index the complete inventory before references, including failed records so
    # a broken peer variant cannot silently fall back to a good namesake.
    indexed: dict[tuple[str, str], list[tuple[RequirementResult, bool]]] = {}

    def error(source: SourceLocation, reason: str) -> None:
        errors.append(ScanError(ecosystem="npm", source=source, reason=reason))

    def emit(result: RequirementResult, patched: bool = False) -> None:
        requirements.append(result)
        if isinstance(result, ReadyRequirement) and patched:
            requirements.append(_unscanned(result.source, _PATCH))

    for key, record in packages.items():
        source = _location(path, f"packages[{key!r}]")
        locator = _locator(key.removeprefix("/") if v6 else key)
        if not isinstance(record, dict):
            error(source, "Package record must be a mapping.")
            result: RequirementResult = _unscanned(source, "Malformed package record.")
            patched = False
        else:
            result, patched = _package(key, record, source, v6)
        if locator:
            name, version, _ = locator
            patched |= (name, version) in patched_identities
            indexed.setdefault((name, version), []).append((result, patched))
        emit(result, patched)

    def reference(
        name: str,
        value: str,
        source: SourceLocation,
        specifier: str | None = None,
        *,
        force_patch: bool = False,
    ) -> None:
        declared_name = resolve_npm_declaration(name, "0.0.0", source)
        if not isinstance(declared_name, ReadyRequirement):
            emit(declared_name)
            return
        raw = value.removeprefix("/").removeprefix("npm:")
        # Aliases serialize their real target in the resolved reference, while
        # ordinary dependency references contain just the resolved version.
        locator = _locator(f"{name}@{raw}") or _locator(raw)
        if locator is None:
            result = resolve_npm_declaration(name, value, source)
            if isinstance(result, ReadyRequirement):
                result = _unscanned(
                    source, "Resolved reference has no matching package metadata."
                )
            emit(result)
            return
        target, version, patched = locator
        if specifier is not None:
            if specifier.startswith("npm:"):
                declared_target, separator, _ = specifier[4:].rpartition("@")
                if not separator or declared_target != target:
                    emit(
                        _unscanned(
                            source, "Conflicting or malformed importer alias target."
                        )
                    )
                    return
            elif any(char in specifier for char in (":", "/", "\\")):
                emit(
                    _unscanned(
                        source,
                        "Non-registry importer declaration; "
                        "registry identity is unverified.",
                    )
                )
                return
            elif target != name:
                emit(_unscanned(source, "Conflicting importer registry name."))
                return
        matches = indexed.get((target, version), [])
        if not matches or any(
            not isinstance(item, ReadyRequirement) for item, _ in matches
        ):
            emit(
                _unscanned(
                    source, "Missing or untrustworthy matching package metadata."
                )
            )
            return
        emit(
            resolve_npm_declaration(target, version, source),
            patched or force_patch or any(flag for _, flag in matches),
        )

    def dependencies(record: dict[str, Any], prefix: str, *, importer: bool) -> None:
        for group in _GROUPS:
            entries = record.get(group, {})
            source = _location(path, f"{prefix}.{group}")
            if not isinstance(entries, dict):
                error(source, "Dependency group must be a mapping.")
                continue
            for name, entry in entries.items():
                source = _location(path, f"{prefix}.{group}[{name!r}] = {entry!r}")
                if not isinstance(name, str):
                    error(source, "Dependency name must be a string.")
                    continue
                if importer:
                    if not isinstance(entry, dict) or not isinstance(
                        entry.get("specifier"), str
                    ):
                        error(
                            source,
                            "Importer dependency must have string "
                            "specifier and version.",
                        )
                        continue
                    value = entry.get("version")
                else:
                    value = entry
                if not isinstance(value, str):
                    error(source, "Resolved dependency version must be a string.")
                    continue
                reference(name, value, source, entry["specifier"] if importer else None)

    # The single-project v6 form stores importer groups at the document root.
    dependencies(document, "root", importer=True)
    for key, record in importers.items():
        prefix = f"importers[{key!r}]"
        source = _location(path, prefix)
        if not isinstance(record, dict):
            error(source, "Importer must be a mapping.")
            continue
        if key != ".":
            emit(_unscanned(source, _WORKSPACE))
        dependencies(record, prefix, importer=True)
    for key, record in (packages if v6 else snapshots).items():
        prefix = f"{'packages' if v6 else 'snapshots'}[{key!r}]"
        source = _location(path, prefix)
        if not isinstance(record, dict):
            if not v6:
                error(source, "Snapshot must be a mapping.")
            continue
        if not v6:
            locator = _locator(key)
            if locator is None:
                emit(
                    _unscanned(source, "Non-registry or unrecognized snapshot locator.")
                )
            elif "patched" in record and type(record["patched"]) is not bool:
                error(source, "Malformed patched flag.")
            else:
                reference(
                    locator[0], key, source, force_patch=record.get("patched") is True
                )
        dependencies(record, prefix, importer=False)
    for key, patch in patches.items():
        source = _location(path, f"patchedDependencies[{key!r}]")
        if (
            not isinstance(patch, dict)
            or not isinstance(patch.get("path"), str)
            or not isinstance(patch.get("hash"), str)
        ):
            error(source, "Patch metadata must contain string path and hash.")
        locator = _locator(key)
        matches = indexed.get((locator[0], locator[1]), []) if locator else []
        if not any(isinstance(item, ReadyRequirement) for item, _ in matches):
            emit(
                _unscanned(
                    source,
                    "Patch has no trustworthy matching upstream package metadata.",
                )
            )
    return requirements, errors
