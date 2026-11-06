"""Read Bun text lockfile v1 inventories, never executing Bun or project code."""

import json
from pathlib import Path
from typing import Any

import json5
from pydantic import ValidationError

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
_WORKSPACE_REASON = (
    "Workspace/local container or link excluded; external workspace dependency "
    "coverage is unavailable (nested manifests are not read)."
)
_PATCH_REASON = "Upstream advisories do not assess the applied Bun patch."
_BINARY_REASON = (
    "Legacy binary bun.lockb is unsupported. Migrate externally with "
    "`bun install --save-text-lockfile --frozen-lockfile --lockfile-only`, "
    "then manually verify bun.lock and remove the binary lock if appropriate. "
    "This external command can populate Bun's cache; depscan never invokes it."
)


def _location(path: Path, text: str) -> SourceLocation:
    return SourceLocation(path=path, line=1, text=text)


def _unscanned(
    source: SourceLocation, reason: str, name: str | None = None
) -> UnscannedRequirement:
    return UnscannedRequirement(
        ecosystem="npm", source=source, reason=reason, name=name
    )


def read_bun_lock(path: Path) -> SourceReadResult:
    """Read text v1 or return detection-only diagnostics for legacy bun.lockb.

    json5 supplies safe JSONC parsing (comments/trailing commas), with a documented
    JSON5 lexical superset. No regex comment stripping or JavaScript evaluation.
    """
    path = path.absolute()
    binary = path.name == "bun.lockb"
    source = DependencySource(
        ecosystem="npm", path=path, kind="bun_binary" if binary else "bun"
    )
    try:
        if binary:
            raise ValueError(_BINARY_REASON)
        document = json5.loads(
            path.read_text(encoding="utf-8"), allow_duplicate_keys=False
        )
        requirements, errors = _inventory(path, document)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
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


def _info(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Package/workspace metadata must be an object.")
    for field in ("name", "version"):
        if field in value and not isinstance(value[field], str):
            raise ValueError(f"{field} must be a string.")
    for group in _GROUPS:
        if group in value:
            declarations = value[group]
            if not isinstance(declarations, dict) or any(
                not isinstance(spec, str) for spec in declarations.values()
            ):
                raise ValueError(f"{group} must be an object of string declarations.")


def _package(locator: str) -> PackageVersion | None:
    name, separator, version = locator.rpartition("@")
    if not separator:
        return None
    try:
        return PackageVersion(ecosystem="npm", name=name, version=version)
    except ValidationError:
        return None


def _inventory(
    path: Path, document: Any
) -> tuple[list[RequirementResult], list[ScanError]]:
    if not isinstance(document, dict):
        raise ValueError("Expected a Bun lockfile object.")
    version = document.get("lockfileVersion")
    if type(version) is not int or version != 1:
        raise ValueError("Unsupported lockfileVersion; expected integer 1.")
    workspaces = document.get("workspaces")
    if not isinstance(workspaces, dict) or "" not in workspaces:
        raise ValueError('workspaces must be an object containing the root "".')
    requirements: list[RequirementResult] = []
    errors: list[ScanError] = []
    for key, workspace in workspaces.items():
        _info(workspace)
        if key:
            if not isinstance(workspace.get("name"), str):
                raise ValueError("Non-root workspace must have a string name.")
            requirements.append(
                _unscanned(
                    _location(path, f"workspaces[{json.dumps(key)}]"),
                    _WORKSPACE_REASON,
                    workspace["name"],
                )
            )
    packages = document.get("packages", {})
    if not isinstance(packages, dict):
        raise ValueError("packages must be an object.")
    patches = document.get("patchedDependencies", {})
    if not isinstance(patches, dict) or any(
        not isinstance(value, str) or not value for value in patches.values()
    ):
        raise ValueError(
            "patchedDependencies must map package locators to patch paths."
        )
    patched: set[PackageVersion] = set()
    for locator in patches:
        package = _package(locator)
        if package is None:
            requirements.append(
                _unscanned(
                    _location(path, f"patchedDependencies[{json.dumps(locator)}]"),
                    "Untrustworthy patch target; patch coverage is unavailable.",
                )
            )
        else:
            patched.add(package)
    for key, record in packages.items():
        location = _location(path, f"packages[{json.dumps(key)}] = {record!r}")
        try:
            requirements.extend(_record(record, location, patched))
        except ValueError as exc:
            errors.append(ScanError(ecosystem="npm", source=location, reason=str(exc)))
    recorded = {
        item.package for item in requirements if isinstance(item, ReadyRequirement)
    }
    for locator in patches:
        package = _package(locator)
        if package is not None and package not in recorded:
            requirements.append(
                _unscanned(
                    _location(path, f"patchedDependencies[{json.dumps(locator)}]"),
                    "Patch target has no trustworthy recorded registry tuple; "
                    "upstream and patch coverage are unavailable.",
                    package.name,
                )
            )
    # Root declarations resolve at their declared install keys, including aliases.
    # Existing broken/non-registry tuples already have entry diagnostics above.
    # This presence check neither resolves ranges nor reconstructs workspace or
    # transitive dependency graphs; non-root workspaces retain their coverage gap.
    for group in _GROUPS:
        for name, declaration in workspaces[""].get(group, {}).items():
            if name in packages:
                continue
            requirements.append(
                _unscanned(
                    _location(
                        path,
                        f'workspaces[""].{group}[{json.dumps(name)}] = {declaration}',
                    ),
                    "Root dependency declaration has no recorded package tuple at "
                    "its install key; dependency coverage is unavailable. "
                    "No version is inferred from the declaration.",
                    name,
                )
            )
    return requirements, errors


def _record(
    record: Any, source: SourceLocation, patched: set[PackageVersion]
) -> list[RequirementResult]:
    if not isinstance(record, list) or not record or not isinstance(record[0], str):
        raise ValueError("Package tuple must start with a string resolved locator.")
    locator = record[0]
    # Split at the first non-scope @, not the last @ in a git URL or local path.
    separator = locator.find("@", 1)
    if separator < 1:
        return [_unscanned(source, "Missing trustworthy resolved package identity.")]
    name, resolution = locator[:separator], locator[separator + 1 :]
    if resolution.startswith("workspace:"):
        if len(record) != 1:
            raise ValueError("Workspace tuple must contain only its locator.")
        return [_unscanned(source, _WORKSPACE_REASON, name)]
    if resolution.startswith(("root:", "file:", "link:")):
        if len(record) != 2:
            raise ValueError("Root/local tuple must contain locator and metadata.")
        _info(record[1])
        return [_unscanned(source, _WORKSPACE_REASON, name)]
    package = _package(locator)
    if package is None:
        return [
            _unscanned(
                source,
                "Non-registry or unresolved package locator; no trustworthy exact "
                "registry identity/version.",
                name,
            )
        ]
    if (
        len(record) != 4
        or not isinstance(record[1], str)
        or not isinstance(record[3], str)
    ):
        raise ValueError(
            "Registry tuple must contain locator, registry string, metadata, "
            "and integrity string."
        )
    _info(record[2])
    results: list[RequirementResult] = [
        ReadyRequirement(source=source, package=package)
    ]
    if package in patched:
        results.append(_unscanned(source, _PATCH_REASON, package.name))
    return results
