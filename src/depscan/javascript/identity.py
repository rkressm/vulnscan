"""Pure exact-pin recognition; no environment inspection or range resolution."""

from pydantic import ValidationError

from depscan.models import (
    PackageVersion,
    ReadyRequirement,
    RequirementResult,
    SourceLocation,
    UnscannedRequirement,
)


def exact_npm_version(value: str) -> str | None:
    """Return the shared model's canonical exact npm version, or None."""
    try:
        return PackageVersion(
            ecosystem="npm", name="version-check", version=value
        ).version
    except ValidationError:
        return None


def resolve_npm_declaration(
    name: str, declaration: str, source: SourceLocation
) -> RequirementResult:
    """Resolve only exact registry pins and npm aliases, retaining the source."""
    try:
        # Validate the declared name too, even when an alias supplies another name.
        PackageVersion(ecosystem="npm", name=name, version="0.0.0")
    except ValidationError:
        return _unscanned(name, source, "Invalid npm dependency name.")

    target, version = name, declaration
    if declaration.startswith("npm:"):
        target, separator, version = declaration[4:].rpartition("@")
        if not separator or not target:
            return _unscanned(
                name, source, "Unresolved npm alias; supply a supported lockfile."
            )
    try:
        package = PackageVersion(ecosystem="npm", name=target, version=version)
    except ValidationError:
        if declaration.startswith("npm:"):
            reason = (
                "Invalid or unresolved npm alias target; supply a supported lockfile."
            )
        elif declaration.startswith(("workspace:", "link:", "portal:")):
            reason = (
                "Workspace/link dependency; external workspace coverage is unavailable."
            )
        elif declaration.startswith(("file:", "./", "../", "/", "~/")):
            reason = "Local dependency is not a registry package version."
        elif ":" in declaration or "/" in declaration:
            reason = "Git/URL dependency is not a registry package version."
        else:
            reason = (
                "Unresolved npm range, tag or invalid version; "
                "supply a supported lockfile."
            )
        return _unscanned(name, source, reason)
    return ReadyRequirement(source=source, package=package)


def _unscanned(name: str, source: SourceLocation, reason: str) -> UnscannedRequirement:
    return UnscannedRequirement(
        ecosystem="npm", name=name, source=source, reason=reason
    )
