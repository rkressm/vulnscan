"""Detect Python manifests and read locked versions without resolving or installing."""

import json
import tomllib
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import Version

from depscan.models import (
    RequirementResult,
    ScanError,
    SourceLocation,
    UnscannedRequirement,
)
from depscan.requirements import (
    read_requirements,
    resolve_requirement,
    track_distribution,
    track_metadata_archive_candidates,
)

_FILES = (
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "requirements.txt",
)


def read_project(
    path: Path,
    *,
    venv: Path | None = None,
    input_paths: set[Path] | None = None,
    source_errors: list[ScanError] | None = None,
) -> tuple[Path, list[RequirementResult]]:
    """Prefer a lockfile; never silently fall back from a broken selected manifest.

    Directory scans never inspect the scanner's installed packages. Explicit
    requirements-file scans preserve their original behavior unless --venv is used.
    source_errors optionally collects fatal source errors without changing the
    legacy list of requirement results returned to existing callers.
    """
    is_project = path.is_dir()
    selected = (
        next((path / name for name in _FILES if (path / name).is_file()), path)
        if is_project
        else path
    )
    source = SourceLocation(path=selected.absolute(), line=1, text="")
    try:
        if input_paths is not None and not selected.is_dir():
            input_paths.add(selected.absolute())
            input_paths.add(selected.resolve())
        installed = (
            _installed_versions(venv, input_paths=input_paths)
            if venv is not None
            else None
        )
        if is_project and installed is None:
            installed = {}
        if selected.is_dir():
            raise ValueError(f"No supported Python dependency file found in {path}.")
        if selected.name not in _FILES or selected.name == "requirements.txt":
            return selected, read_requirements(
                selected,
                installed_versions=installed,
                input_paths=input_paths,
                source_errors=source_errors,
            )
        text = selected.read_text(encoding="utf-8-sig")
        data = (
            json.loads(text) if selected.name == "Pipfile.lock" else tomllib.loads(text)
        )
        if not isinstance(data, dict):
            raise ValueError("Dependency file must contain an object.")
        results = _read_manifest(selected, data, installed or {})
        return selected, results
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
    ) as exc:
        if source_errors is not None:
            source_errors.append(
                ScanError(ecosystem="PyPI", source=source, reason=str(exc))
            )
        return selected, [
            UnscannedRequirement(ecosystem="PyPI", source=source, reason=str(exc))
        ]


def _installed_versions(
    venv: Path, *, input_paths: set[Path] | None = None
) -> dict[str, str]:
    if not (venv / "pyvenv.cfg").is_file():
        raise ValueError(f"Not a virtual environment: {venv}")
    paths = sorted(set(venv.glob("lib/python*/site-packages")))
    windows = venv / "Lib/site-packages"
    if windows.is_dir():
        paths.append(windows)
    if not paths:
        raise ValueError(f"No site-packages directory found in {venv}.")
    versions: dict[str, str] = {}
    track_metadata_archive_candidates(paths, input_paths)
    for distribution in metadata.distributions(path=[str(path) for path in paths]):
        distribution = track_distribution(distribution, input_paths)
        name = canonicalize_name(distribution.metadata["Name"])
        if name in versions and versions[name] != distribution.version:
            raise ValueError(f"Conflicting installed versions for {name} in {venv}.")
        versions[name] = distribution.version
    return versions


def _read_manifest(
    path: Path, data: dict[str, Any], installed: dict[str, str]
) -> list[RequirementResult]:
    results: list[RequirementResult] = []

    def declaration(text: str, *, unsupported: str | None = None) -> None:
        # TOML/JSON parsers don't expose line locations: line 1 denotes the document.
        source = SourceLocation(path=path.absolute(), line=1, text=text)
        results.append(
            UnscannedRequirement(ecosystem="PyPI", source=source, reason=unsupported)
            if unsupported
            else resolve_requirement(text, source, installed_versions=installed)
        )

    if path.name == "pyproject.toml":
        project = data.get("project", {})
        if not isinstance(project, dict):
            raise ValueError("project must be a TOML table.")
        dependencies = project.get("dependencies")
        dynamic = project.get("dynamic", [])
        if not isinstance(dynamic, list):
            raise ValueError("project.dynamic must be an array.")
        if dependencies is None or "dependencies" in dynamic:
            raise ValueError(
                "No static [project].dependencies; "
                "provide a lockfile or requirements file."
            )
        if not isinstance(dependencies, list):
            raise ValueError("project.dependencies must be an array of strings.")
        for item in dependencies:
            if not isinstance(item, str):
                raise ValueError("project.dependencies must contain strings.")
            declaration(item)
        return results

    if path.name == "Pipfile.lock":
        for group in ("default", "develop"):
            if group not in data:
                raise ValueError(f"Pipfile.lock needs a {group!r} object.")
        for group, packages in data.items():
            if group == "_meta":
                continue
            if not isinstance(packages, dict):
                raise ValueError(f"Pipfile.lock needs a {group!r} object.")
            for name, entry in packages.items():
                canonicalize_name(name, validate=True)
                if not isinstance(entry, dict):
                    raise ValueError(f"Invalid lock entry for {name}.")
                version = entry.get("version", "")
                supported = (
                    isinstance(version, str)
                    and version.startswith("==")
                    and "*" not in version
                    and not any(
                        key in entry for key in ("git", "path", "file", "editable")
                    )
                )
                if supported:
                    Version(version[2:])
                declaration(
                    f"{name}{version}",
                    unsupported=None
                    if supported
                    else "Unsupported or unpinned lock entry.",
                )
        return results

    packages = data.get("package")
    if not isinstance(packages, list):
        raise ValueError("Lockfile needs a package array.")
    for entry in packages:
        if not isinstance(entry, dict):
            raise ValueError("Invalid lockfile package entry.")
        source = entry.get("source", {})
        if not isinstance(source, dict):
            raise ValueError("Invalid lockfile source.")
        # uv records the project/workspace itself; it isn't a registry dependency.
        if path.name == "uv.lock" and (
            "virtual" in source or source.get("editable") == "."
        ):
            continue
        name, version = entry.get("name"), entry.get("version")
        if not isinstance(name, str):
            raise ValueError("Each locked package needs a name.")
        canonicalize_name(name, validate=True)
        registry = (
            set(source) == {"registry"} and isinstance(source["registry"], str)
            if path.name == "uv.lock"
            else not source or source.get("type") == "legacy"
        )
        if registry:
            if not isinstance(version, str):
                raise ValueError(f"Missing exact version for {name}.")
            Version(version)
        declaration(
            f"{name}=={version}" if registry else name,
            unsupported=None
            if registry
            else "Non-registry lock sources are unsupported.",
        )
    return results
