"""Offline Yarn Classic v1 and modern metadata 4/6/8/10 inventories."""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from depscan.javascript.identity import exact_npm_version, resolve_npm_declaration
from depscan.models import (
    DependencySource,
    ReadyRequirement,
    RequirementResult,
    ScanError,
    SourceLocation,
    SourceReadResult,
    UnscannedRequirement,
)


def _unscanned(
    source: SourceLocation, reason: str, name: str | None = None
) -> UnscannedRequirement:
    return UnscannedRequirement(
        ecosystem="npm", source=source, reason=reason, name=name
    )


def _tokens(line: str) -> list[Any]:
    """Classic's JSON strings, bare strings, integers, booleans and punctuation.

    This is deliberately not YAML: single quotes, flow collections, tags and
    anchors have no special meaning in Classic. Comments start at token edges.
    """
    tokens: list[Any] = []
    decoder = json.JSONDecoder()
    while line:
        if line.startswith(" "):
            line = line[1:]
        elif line.startswith("#"):
            break
        elif line[0] in ":,":
            tokens.append((line[0],))
            line = line[1:]
        elif line.startswith('"'):
            value, end = decoder.raw_decode(line)
            tokens.append(value)
            line = line[end:]
        else:
            match = re.match(r"[0-9]+|true|false|[a-zA-Z/.-][^: ,\r\n]*", line)
            if match is None:
                raise ValueError("Invalid Classic token.")
            value = match.group()
            if value.isdigit():
                tokens.append(int(value))
            elif value in ("true", "false"):
                tokens.append(value == "true")
            else:
                tokens.append(value)
            line = line[len(value) :]
    return tokens


def _classic(text: str) -> dict[str, Any]:
    """Parse the indentation-based Classic map grammar, rejecting duplicates.

    Unlike Yarn's installer we neither repair merge conflicts nor fall back to
    general YAML. A stack handles nested dependency maps without recursive reads.
    """
    root: dict[str, Any] = {}
    stack: list[dict[str, Any]] = [root]
    pending: dict[str, Any] | None = None
    for line in text.splitlines():
        width = len(line) - len(line.lstrip(" "))
        tokens = _tokens(line[width:])
        if not tokens:
            continue
        if width % 2:
            raise ValueError("Classic indentation must use pairs of spaces.")
        depth = width // 2
        if depth == len(stack) and pending is not None:
            stack.append(pending)
        elif depth >= len(stack):
            raise ValueError("Unexpected Classic indentation.")
        stack = stack[: depth + 1]
        pending = None
        keys: list[str] = []
        index = 0
        while True:
            if index >= len(tokens) or not isinstance(tokens[index], str):
                raise ValueError("Expected Classic property name.")
            keys.append(tokens[index])
            index += 1
            if index < len(tokens) and tokens[index] == (",",):
                index += 1
            else:
                break
        colon = index < len(tokens) and tokens[index] == (":",)
        if colon:
            index += 1
        if index == len(tokens) and colon:
            value: Any = {}
            pending = value
        elif index == len(tokens) - 1 and isinstance(tokens[index], (str, int, bool)):
            value = tokens[index]
        else:
            raise ValueError("Invalid Classic property value.")
        for key in keys:
            if key in stack[-1]:
                raise ValueError(f"Duplicate Classic key: {key!r}.")
            stack[-1][key] = value
    return root


def _split_locator(value: str) -> tuple[str, str]:
    # The first @ after a possible scope separates identity from reference;
    # rpartition would misinterpret aliases and embedded patch locators.
    index = value.find("@", 1)
    if index < 1:
        raise ValueError("Missing locator reference.")
    return value[:index], value[index + 1 :]


def _modern_record(
    record: dict[str, Any], source: SourceLocation
) -> list[RequirementResult]:
    locator = record.get("resolution")
    version = record.get("version")
    if not isinstance(locator, str) or not isinstance(version, str):
        return [_unscanned(source, "Missing or invalid resolution/version field.")]
    patched = False
    name: str | None = None
    try:
        # One final iteration inspects the npm locator after 16 wrappers.
        for _ in range(17):
            name, reference = _split_locator(locator)
            if reference.startswith("virtual:"):
                context, separator, inner = reference[8:].partition("#")
                if not context or not separator or not inner:
                    raise ValueError("Invalid virtual wrapper.")
                locator = f"{name}@{inner}"
            elif reference.startswith("patch:"):
                inner, separator, _ = reference[6:].partition("#")
                if not separator or not inner:
                    raise ValueError("Invalid patch wrapper.")
                # Yarn parseRange decodes the source component once; never decode
                # the whole locator, patch paths, or parent locator parameters.
                locator = unquote(inner, errors="strict")
                inner_name, _ = _split_locator(locator)
                if inner_name != name:
                    raise ValueError("Conflicting patch identity.")
                patched = True
            else:
                break
        else:
            raise ValueError("Wrapper nesting exceeds 16 levels.")
        if not reference.startswith("npm:"):
            reason = (
                "Workspace/link excluded; external workspace coverage is unavailable."
                if reference.startswith(("workspace:", "portal:", "link:"))
                else "Non-registry or unsupported Yarn resolution."
            )
            return [_unscanned(source, reason, name)]
        result = resolve_npm_declaration(name, reference[4:], source)
        if isinstance(result, ReadyRequirement):
            if exact_npm_version(version) != result.package.version:
                raise ValueError("Resolution and record version disagree.")
        results: list[RequirementResult] = [result]
        if patched and isinstance(result, ReadyRequirement):
            results.append(
                _unscanned(
                    source,
                    "Upstream-only advisory coverage; applied patch is not assessed.",
                    name,
                )
            )
        return results
    except (ValueError, UnicodeError) as exc:
        return [_unscanned(source, f"Untrustworthy Yarn locator: {exc}", name)]


def _classic_record(
    selector: str, record: dict[str, Any], source: SourceLocation
) -> RequirementResult:
    name: str | None = None
    try:
        name, request = _split_locator(selector)
        version = record.get("version")
        if not isinstance(version, str):
            raise ValueError("Missing exact package version.")
        if request.startswith("npm:"):
            target, request = _split_locator(request[4:])
        else:
            target = name
        if (
            not request
            or ":" in request
            or "/" in request
            or "\\" in request
            or request in (".", "..")
            or request.endswith((".tgz", ".tar.gz", ".tar"))
        ):
            raise ValueError(
                "Non-registry dependency; workspace/local coverage unavailable."
            )
        if "resolved" in record:
            resolved = record["resolved"]
            if not isinstance(resolved, str):
                raise ValueError("Invalid resolved field.")
            url = urlsplit(resolved)
            package, separator, artifact = (
                unquote(url.path).lstrip("/").partition("/-/")
            )
            if (
                url.scheme not in ("https", "http")
                or url.hostname not in ("registry.npmjs.org", "registry.yarnpkg.com")
                or not separator
                or not artifact
                or "/" in artifact
                or package != target
            ):
                raise ValueError("Non-registry or conflicting tarball identity.")
        return resolve_npm_declaration(name, f"npm:{target}@{version}", source)
    except ValueError as exc:
        return _unscanned(source, str(exc), name)


def read_yarn_lock(path: Path) -> SourceReadResult:
    """Read one supported Yarn lock, preserving entry provenance and coverage."""
    path = path.absolute()
    source = DependencySource(ecosystem="npm", path=path, kind="yarn")
    location = SourceLocation(path=path, line=1, text=path.name)
    try:
        text = path.read_text(encoding="utf-8-sig")
        headers = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("#"):
                break
            match = re.fullmatch(r"#\s*yarn lockfile v(\S+)", stripped)
            if match:
                headers.append(match[1])
        if headers:
            if any(header != "1" for header in headers):
                raise ValueError("Unsupported Classic lockfile version; expected v1.")
            document = _classic(text)
            if "__metadata" in document:
                raise ValueError("Classic lockfile must not contain __metadata.")
            classic = True
        else:
            yaml = YAML(typ="safe", pure=True)
            yaml.allow_duplicate_keys = False
            document = yaml.load(text)
            if not isinstance(document, dict):
                raise ValueError(
                    "Expected Yarn mapping with supported version metadata."
                )
            metadata = document.get("__metadata")
            if not isinstance(metadata, dict):
                raise ValueError("Missing Classic v1 header or modern __metadata.")
            version = metadata.get("version")
            if type(version) is not int or version not in (4, 6, 8, 10):
                raise ValueError(
                    "Unsupported __metadata.version; expected integer 4, 6, 8 or 10."
                )
            classic = False
        requirements: list[RequirementResult] = []
        errors: list[ScanError] = []
        for selector, record in document.items():
            if not classic and selector == "__metadata":
                continue
            entry = SourceLocation(path=path, line=1, text=f"yarn[{selector!r}]")
            if not isinstance(selector, str) or not isinstance(record, dict):
                errors.append(
                    ScanError(
                        ecosystem="npm",
                        source=entry,
                        reason="Expected string selector and package mapping.",
                    )
                )
                continue
            if classic:
                requirements.append(_classic_record(selector, record, entry))
            else:
                requirements.extend(_modern_record(record, entry))
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        YAMLError,
        RecursionError,
    ) as exc:
        return SourceReadResult(
            source=source,
            status="failed",
            input_paths=(path,),
            errors=(
                ScanError(
                    ecosystem="npm",
                    source=location,
                    reason=f"Cannot read yarn.lock: {exc}",
                ),
            ),
        )
    return SourceReadResult(
        source=source,
        status="success",
        requirements=tuple(requirements),
        errors=tuple(errors),
        input_paths=(path,),
    )
