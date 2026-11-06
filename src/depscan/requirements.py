"""Read declared dependencies without installing or discovering dependencies."""

import re
import shlex
from collections.abc import Mapping
from importlib import metadata
from os import PathLike
from pathlib import Path

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from depscan.models import (
    NonApplicableRequirement,
    PackageVersion,
    ReadyRequirement,
    RequirementResult,
    ScanError,
    SourceLocation,
    UnscannedRequirement,
)

# Bound recursive expansion as well as checking for actual cycles.
_MAX_INCLUDE_DEPTH = 100


class _TrackedDistribution(metadata.PathDistribution):
    """Register metadata paths before importlib attempts to open them."""

    def __init__(self, path: Path, input_paths: set[Path]) -> None:
        super().__init__(path)
        self.metadata_path = path
        self.input_paths = input_paths

    def read_text(self, filename: str | PathLike[str]) -> str | None:
        path = self.metadata_path / filename
        self.input_paths.add(path.absolute())
        self.input_paths.add(path.resolve())
        return super().read_text(filename)


def track_distribution(
    distribution: metadata.Distribution, input_paths: set[Path] | None
) -> metadata.Distribution:
    """Track filesystem metadata only, never distribution modules or RECORD files."""
    # importlib exposes no public metadata-root accessor. Non-filesystem providers
    # (such as zip archives) cannot be overwritten through an internal file path.
    path = getattr(distribution, "_path", None)
    if input_paths is not None and isinstance(path, Path):
        return _TrackedDistribution(path, input_paths)
    return distribution


def read_requirements(
    path: str | Path,
    *,
    installed_versions: Mapping[str, str] | None = None,
    input_paths: set[Path] | None = None,
    source_errors: list[ScanError] | None = None,
) -> list[RequirementResult]:
    """Read a UTF-8 requirements file and its relative includes in source order.

    File errors are unscanned results, not exceptions. Included-file errors point
    to the include directive; a root-file error uses line 1. Duplicate declarations
    are preserved. Extras do not expand into additional dependencies. If provided,
    input_paths collects resolved paths, even for files without declarations.
    source_errors optionally collects fatal root read errors; entry/include errors
    remain unscanned declarations in a successfully read root document.
    """
    source = SourceLocation(path=Path(path).absolute(), line=1, text="")
    return _read_file(
        Path(path), (), source, installed_versions, input_paths, source_errors
    )


def _read_file(
    path: Path,
    include_chain: tuple[Path, ...],
    origin: SourceLocation,
    installed_versions: Mapping[str, str] | None,
    input_paths: set[Path] | None,
    source_errors: list[ScanError] | None,
) -> list[RequirementResult]:
    try:
        if input_paths is not None:
            input_paths.add(path.absolute())
        path = path.resolve()
        if input_paths is not None:
            input_paths.add(path)
        if path in include_chain:
            chain = " -> ".join(str(item) for item in (*include_chain, path))
            return [
                UnscannedRequirement(
                    ecosystem="PyPI",
                    source=origin,
                    reason=f"Circular requirements include: {chain}",
                )
            ]
        if len(include_chain) >= _MAX_INCLUDE_DEPTH:
            return [
                UnscannedRequirement(
                    ecosystem="PyPI",
                    source=origin,
                    reason="Requirements include depth exceeds 100 files.",
                )
            ]
        content = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError, ValueError) as exc:
        if not include_chain and source_errors is not None:
            source_errors.append(
                ScanError(
                    ecosystem="PyPI",
                    source=origin,
                    reason=f"Cannot read requirements file {path}: {exc}",
                )
            )
        return [
            UnscannedRequirement(
                ecosystem="PyPI",
                source=origin,
                reason=f"Cannot read requirements file {path}: {exc}",
            )
        ]

    results: list[RequirementResult] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        text = _strip_comment(raw_line).strip()
        if not text or text.startswith("#"):
            continue
        source = SourceLocation(path=path, line=line_number, text=raw_line)
        if text.startswith("-r") or re.match(r"^--requirement(?:\s|=|$)", text):
            try:
                target = _include_target(text)
            except ValueError as exc:
                results.append(
                    UnscannedRequirement(
                        ecosystem="PyPI", source=source, reason=str(exc)
                    )
                )
                continue
            results.extend(
                _read_file(
                    path.parent / target,
                    (*include_chain, path),
                    source,
                    installed_versions,
                    input_paths,
                    source_errors,
                )
            )
        else:
            results.append(
                resolve_requirement(
                    text,
                    source,
                    installed_versions=installed_versions,
                    input_paths=input_paths,
                )
            )
    return results


def _strip_comment(text: str) -> str:
    """Preserve URL fragments and hashes inside quoted environment markers."""
    quote: str | None = None
    for index, char in enumerate(text):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index]
    return text


def _include_target(text: str) -> str:
    if text.startswith("--requirement"):
        target = text[len("--requirement") :].removeprefix("=").strip()
    else:
        target = text[2:].strip()
    try:
        parts = shlex.split(target)
    except ValueError as exc:
        raise ValueError(f"Invalid requirements include: {exc}") from exc
    if len(parts) != 1 or not parts[0]:
        raise ValueError("Requirements include must specify one local file path.")
    if "://" in parts[0]:
        raise ValueError(
            "Remote requirements includes are unsupported; use a local file."
        )
    return parts[0]


def resolve_requirement(
    text: str,
    source: SourceLocation,
    *,
    installed_versions: Mapping[str, str] | None = None,
    input_paths: set[Path] | None = None,
) -> RequirementResult:
    """Resolve a declaration, optionally using an explicitly selected environment."""
    try:
        requirement = Requirement(text)
    except InvalidRequirement as exc:
        return UnscannedRequirement(
            ecosystem="PyPI",
            source=source,
            reason=(
                "Invalid or unsupported requirement (editable dependencies, URLs, "
                f"local paths, and pip options are unsupported): {exc}"
            ),
        )

    name = canonicalize_name(requirement.name)
    try:
        if requirement.marker is not None and not requirement.marker.evaluate():
            return NonApplicableRequirement(
                ecosystem="PyPI",
                source=source,
                name=name,
                reason=f"Environment marker does not match: {requirement.marker}",
            )
    except (UndefinedComparison, UndefinedEnvironmentName) as exc:
        return UnscannedRequirement(
            ecosystem="PyPI",
            source=source,
            reason=f"Cannot evaluate environment marker: {exc}",
            name=name,
        )

    if requirement.url is not None:
        return UnscannedRequirement(
            ecosystem="PyPI",
            source=source,
            reason="Direct URL and local path dependencies are unsupported.",
            name=name,
        )

    pinned_versions = sorted(
        specifier.version
        for specifier in requirement.specifier
        if specifier.operator in {"==", "==="} and "*" not in specifier.version
    )
    if pinned_versions:
        selected_version = pinned_versions[0]
    else:
        try:
            if installed_versions is None and input_paths is not None:
                try:
                    distribution = metadata.distribution(requirement.name)
                except metadata.PackageNotFoundError:
                    pass
                else:
                    # Preflight the same metadata reads before the legacy version
                    # API, retaining compatibility with callers that replace it.
                    _ = track_distribution(distribution, input_paths).metadata
            selected_version = (
                metadata.version(requirement.name)
                if installed_versions is None
                else installed_versions[name]
            )
        except metadata.PackageNotFoundError, KeyError:
            return UnscannedRequirement(
                ecosystem="PyPI",
                source=source,
                reason=(
                    "Package is not installed; ranges and unpinned requirements need "
                    "an installed version in the selected Python environment. "
                    "For project scans, select one with --venv PATH."
                ),
                name=name,
            )
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            return UnscannedRequirement(
                ecosystem="PyPI",
                source=source,
                reason=f"Cannot read installed metadata for {name}: {exc}",
                name=name,
            )

    try:
        parsed_version = Version(selected_version)
    except InvalidVersion:
        return UnscannedRequirement(
            ecosystem="PyPI",
            source=source,
            reason=f"Invalid package version: {selected_version!r}.",
            name=name,
        )

    # Installed prereleases may satisfy a range; exact prerelease pins work too.
    if not requirement.specifier.contains(parsed_version, prereleases=True):
        version_origin = "Declared" if pinned_versions else "Installed"
        return UnscannedRequirement(
            ecosystem="PyPI",
            source=source,
            reason=(
                f"{version_origin} version {selected_version} "
                f"does not satisfy {requirement.specifier}."
            ),
            name=name,
        )
    return ReadyRequirement(
        source=source,
        package=PackageVersion(ecosystem="PyPI", name=name, version=selected_version),
    )
