"""Select root dependency sources without parsing locks or invoking readers."""

import json
import re
import stat
from pathlib import Path

from pydantic import ValidationError

from depscan.models import (
    DependencySource,
    DiscoveryResult,
    Ecosystem,
    PackageVersion,
    ScanError,
    SourceKind,
    SourceLocation,
    SourceSelection,
)

_PYTHON_FILES: tuple[tuple[str, SourceKind], ...] = (
    ("uv.lock", "uv"),
    ("poetry.lock", "poetry"),
    ("Pipfile.lock", "pipfile"),
    ("pyproject.toml", "pyproject"),
    ("requirements.txt", "requirements"),
)
_JS_FILES: tuple[tuple[str, SourceKind], ...] = (
    ("npm-shrinkwrap.json", "npm"),
    ("package-lock.json", "npm"),
    ("yarn.lock", "yarn"),
    ("pnpm-lock.yaml", "pnpm"),
    ("bun.lock", "bun"),
    ("bun.lockb", "bun_binary"),
    ("package.json", "package_json"),
)
_FILE_GROUPS: tuple[tuple[Ecosystem, tuple[tuple[str, SourceKind], ...]], ...] = (
    ("PyPI", _PYTHON_FILES),
    ("npm", _JS_FILES),
)
_HASH_LENGTHS = {"sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}


def _error(ecosystem: Ecosystem, path: Path, reason: str) -> ScanError:
    return ScanError(
        ecosystem=ecosystem,
        source=SourceLocation(path=path, line=1, text=""),
        reason=reason,
    )


def _explicit_source(path: Path) -> DependencySource:
    for ecosystem, files in _FILE_GROUPS:
        for name, kind in files:
            if path.name == name:
                return DependencySource(ecosystem=ecosystem, path=path, kind=kind)
    return DependencySource(ecosystem="PyPI", path=path, kind="requirements")


def _selected(
    source: DependencySource, candidates: tuple[DependencySource, ...]
) -> SourceSelection:
    return SourceSelection(
        ecosystem=source.ecosystem,
        status="selected",
        source=source,
        candidates=candidates,
    )


def _hint_manager(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    manager, separator, version = value.partition("@")
    if not separator or manager not in {"npm", "yarn", "pnpm", "bun"}:
        return None
    # Integrity metadata is distinct from SemVer build metadata. In particular,
    # a malformed sha suffix must not pass as an otherwise valid build string.
    before_hash, plus, suffix = version.rpartition("+")
    if plus and suffix.startswith("sha"):
        algorithm, dot, digest = suffix.partition(".")
        length = _HASH_LENGTHS.get(algorithm)
        if (
            not dot
            or length is None
            or len(digest) != length
            or re.fullmatch(r"[0-9a-fA-F]+", digest) is None
        ):
            return None
        version = before_hash
    try:
        PackageVersion(ecosystem="npm", name=manager, version=version)
    except ValidationError:
        return None
    return manager


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate package.json key: {key}")
        result[key] = value
    return result


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _select_javascript(
    root: Path, candidates: tuple[DependencySource, ...], inputs: set[Path]
) -> SourceSelection:
    managers: dict[str, DependencySource] = {}
    manifest = None
    for candidate in candidates:
        if candidate.kind == "package_json":
            manifest = candidate
        else:
            manager = "bun" if candidate.kind == "bun_binary" else candidate.kind
            managers.setdefault(manager, candidate)
    if not managers:
        assert manifest is not None
        return _selected(manifest, candidates)
    if len(managers) == 1:
        return _selected(next(iter(managers.values())), candidates)

    manager_hint = None
    if manifest is not None:
        inputs.add(manifest.path)  # Register before open/decode, including failures.
        try:
            data = json.loads(
                manifest.path.read_text(encoding="utf-8-sig"),
                object_pairs_hook=_unique_object,
                parse_constant=_invalid_json_constant,
            )
            if not isinstance(data, dict):
                raise ValueError("package.json must contain a JSON object.")
            manager_hint = _hint_manager(data.get("packageManager"))
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            return SourceSelection(
                ecosystem="npm",
                status="failed",
                candidates=candidates,
                errors=(
                    _error("npm", manifest.path, f"Cannot read selection hint: {exc}"),
                ),
            )
    if manager_hint in managers:
        return _selected(managers[manager_hint], candidates)
    return SourceSelection(
        ecosystem="npm",
        status="ambiguous",
        candidates=candidates,
        errors=(
            _error(
                "npm",
                manifest.path if manifest else root,
                "Multiple package-manager locks and no valid matching packageManager "
                "hint; pass a lockfile explicitly.",
            ),
        ),
    )


def discover_sources(path: Path) -> DiscoveryResult:
    """Discover only the supplied root; explicit files bypass all precedence.

    Absolute display paths are deliberately not replaced by resolved symlink
    targets. Path errors fail the affected ecosystem rather than hiding evidence.
    Content is inspected only for a manifest needed to disambiguate JS managers.
    """
    path = path.absolute()
    inputs: set[Path] = set()
    try:
        mode = path.stat().st_mode
    except (OSError, ValueError) as exc:
        source = _explicit_source(path)
        return DiscoveryResult(
            selections=(
                SourceSelection(
                    ecosystem=source.ecosystem,
                    status="failed",
                    candidates=(source,),
                    errors=(_error(source.ecosystem, path, str(exc)),),
                ),
            ),
            input_paths=(path,),
        )
    if not stat.S_ISDIR(mode):
        source = _explicit_source(path)
        try:
            path.resolve()
            if not stat.S_ISREG(mode):
                raise ValueError("Not a regular dependency file.")
            selection = _selected(source, (source,))
        except (OSError, ValueError, RuntimeError) as exc:
            selection = SourceSelection(
                ecosystem=source.ecosystem,
                status="failed",
                candidates=(source,),
                errors=(_error(source.ecosystem, path, str(exc)),),
            )
        return DiscoveryResult(selections=(selection,), input_paths=(path,))

    selections: list[SourceSelection] = []
    for ecosystem, files in _FILE_GROUPS:
        candidates: list[DependencySource] = []
        errors: list[ScanError] = []
        for name, kind in files:
            candidate_path = path / name
            try:
                entry_mode = candidate_path.lstat().st_mode
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                entry_mode = None
                errors.append(_error(ecosystem, candidate_path, str(exc)))
            if entry_mode is not None and stat.S_ISDIR(entry_mode):
                continue
            inputs.add(candidate_path)
            candidates.append(
                DependencySource(ecosystem=ecosystem, path=candidate_path, kind=kind)
            )
            if entry_mode is not None:
                try:
                    # Explicit stat detects dangling/looped symlinks. resolve also
                    # surfaces resolution errors while preserving display spelling.
                    candidate_path.resolve()
                    if not stat.S_ISREG(candidate_path.stat().st_mode):
                        raise ValueError("Not a regular dependency file.")
                except (OSError, ValueError, RuntimeError) as exc:
                    errors.append(_error(ecosystem, candidate_path, str(exc)))
        evidence = tuple(candidates)
        if errors:
            selection = SourceSelection(
                ecosystem=ecosystem,
                status="failed",
                candidates=evidence,
                errors=tuple(errors),
            )
        elif not evidence:
            selection = SourceSelection(ecosystem=ecosystem, status="absent")
        elif ecosystem == "PyPI":
            selection = _selected(evidence[0], evidence)
        else:
            selection = _select_javascript(path, evidence, inputs)
        selections.append(selection)
    return DiscoveryResult(
        selections=tuple(selections), input_paths=tuple(sorted(inputs))
    )
