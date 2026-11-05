"""Validated data shared by the scanner's components."""

import re
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from packaging.utils import canonicalize_name
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

type Ecosystem = Literal["PyPI", "npm"]
type SourceKind = Literal[
    "requirements",
    "pyproject",
    "uv",
    "poetry",
    "pipfile",
    "package_json",
    "npm",
    "yarn",
    "pnpm",
    "bun",
    "bun_binary",
]

_PYTHON_KINDS = {"requirements", "pyproject", "uv", "poetry", "pipfile"}
_NPM_SEGMENT = r"[A-Za-z0-9~-][A-Za-z0-9._~-]*"
_NPM_NAME = re.compile(rf"(?:{_NPM_SEGMENT}|@{_NPM_SEGMENT}/{_NPM_SEGMENT})", re.ASCII)
_NPM_VERSION = re.compile(
    r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
    re.ASCII,
)

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class PackageVersion(BaseModel):
    """A package and its selected version, ready for an OSV lookup.

    Requirement parsing and version selection remain the parser's responsibility.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    ecosystem: Ecosystem = "PyPI"
    name: str
    version: str

    @model_validator(mode="after")
    def canonical_identity(self) -> Self:
        if self.ecosystem == "PyPI":
            name, version = self.name.strip(), self.version.strip()
            if not name or not version:
                raise ValueError("Package name and version must not be empty.")
            name = canonicalize_name(name)
        else:
            name, version = self.name, self.version
            if len(name) > 214 or not _NPM_NAME.fullmatch(name):
                raise ValueError("Invalid raw npm package name.")
            match = _NPM_VERSION.fullmatch(version) if len(version) <= 256 else None
            if match is None or any(
                int(part) > 2**53 - 1 for part in match.groups()[:3]
            ):
                raise ValueError("Expected an exact npm SemVer version.")
            prerelease = match.group(4)
            if prerelease and any(
                part.isdigit() and len(part) > 1 and part.startswith("0")
                for part in prerelease.split(".")
            ):
                raise ValueError(
                    "Numeric npm prerelease identifiers cannot have leading zeros."
                )
            version = version.removeprefix("v")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        return self

    @property
    def identity(self) -> tuple[Ecosystem, str, str]:
        return self.ecosystem, self.name, self.version


class SourceLocation(BaseModel):
    """Location of a declaration, or the include that failed to load."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    path: Path
    line: Annotated[int, Field(ge=1)]
    text: str


class ReadyRequirement(BaseModel):
    """A resolved declaration, not yet checked for vulnerabilities."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["ready"] = "ready"
    source: SourceLocation
    package: PackageVersion

    @property
    def ecosystem(self) -> Ecosystem:
        return self.package.ecosystem


class UnscannedRequirement(BaseModel):
    """An invalid or unsupported declaration, or an unresolved version."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["unscanned"] = "unscanned"
    ecosystem: Ecosystem = "PyPI"
    source: SourceLocation
    reason: NonEmptyString
    name: str | None = None


class NonApplicableRequirement(BaseModel):
    """A declaration excluded by its environment marker."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["non_applicable"] = "non_applicable"
    ecosystem: Ecosystem = "PyPI"
    source: SourceLocation
    reason: NonEmptyString
    name: NonEmptyString


type RequirementResult = Annotated[
    ReadyRequirement | UnscannedRequirement | NonApplicableRequirement,
    Field(discriminator="status"),
]


class Advisory(BaseModel):
    """An advisory with a published severity label, if available."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    identifier: NonEmptyString
    severity: Literal["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    url: NonEmptyString


class SuccessfulLookup(BaseModel):
    """A completed lookup; an empty advisory tuple means no known vulnerabilities."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["success"] = "success"
    package: PackageVersion
    advisories: tuple[Advisory, ...]
    looked_up_at: AwareDatetime | None = None


class FailedLookup(BaseModel):
    """A lookup failure, never a claim that the package has no vulnerabilities."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["failed"] = "failed"
    package: PackageVersion
    reason: NonEmptyString


type LookupResult = Annotated[
    SuccessfulLookup | FailedLookup, Field(discriminator="status")
]


class ScannedRequirement(BaseModel):
    """A source declaration with a completed vulnerability lookup."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["vulnerable", "no_known_vulnerabilities"]
    source: SourceLocation
    package: PackageVersion
    advisories: tuple[Advisory, ...]
    looked_up_at: AwareDatetime | None = None

    @property
    def ecosystem(self) -> Ecosystem:
        return self.package.ecosystem


type ScanResult = Annotated[
    ScannedRequirement | UnscannedRequirement | NonApplicableRequirement,
    Field(discriminator="status"),
]


class ScanError(BaseModel):
    """A failure that makes a scan incomplete, with its source if available."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source: SourceLocation | None = None
    ecosystem: Ecosystem | None = None
    reason: NonEmptyString


class DependencySource(BaseModel):
    """A selected or candidate dependency document."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    ecosystem: Ecosystem
    path: Path
    kind: SourceKind

    @model_validator(mode="after")
    def matching_kind(self) -> Self:
        if (self.kind in _PYTHON_KINDS) != (self.ecosystem == "PyPI"):
            raise ValueError("Source kind does not match ecosystem.")
        return self


def _validate_context(
    ecosystem: Ecosystem,
    source: DependencySource | None,
    candidates: tuple[DependencySource, ...],
    errors: tuple[ScanError, ...] = (),
) -> None:
    if (
        any(item.ecosystem != ecosystem for item in candidates)
        or any(error.ecosystem != ecosystem for error in errors)
        or (source is not None and source.ecosystem != ecosystem)
    ):
        raise ValueError(
            "Source and error ecosystems must match their enclosing context."
        )


def _manager(source: DependencySource) -> str:
    if source.kind in {"npm", "package_json"}:
        return "npm"
    if source.kind == "bun_binary":
        return "bun"
    return source.kind


class SourceSelection(BaseModel):
    """Discovery evidence, including absence and selection failures."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    ecosystem: Ecosystem
    status: Literal["selected", "absent", "ambiguous", "failed"]
    source: DependencySource | None = None
    candidates: tuple[DependencySource, ...] = ()
    errors: tuple[ScanError, ...] = ()

    @model_validator(mode="after")
    def valid_selection(self) -> Self:
        _validate_context(self.ecosystem, self.source, self.candidates, self.errors)
        if self.status == "selected":
            valid = (
                self.source is not None
                and self.source in self.candidates
                and not self.errors
            )
        elif self.status == "absent":
            valid = self.source is None and not self.candidates and not self.errors
        elif self.status == "ambiguous":
            managers = {
                _manager(item)
                for item in self.candidates
                if item.kind != "package_json"
            }
            valid = (
                self.source is None
                and bool(self.errors)
                and len(managers) >= 2
                and self.ecosystem == "npm"
            )
        else:
            valid = self.source is None and bool(self.errors)
        if not valid:
            raise ValueError("Invalid source selection state.")
        return self


class DiscoveryResult(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    selections: tuple[SourceSelection, ...]
    input_paths: tuple[Path, ...] = ()

    @model_validator(mode="after")
    def unique_ecosystems(self) -> Self:
        if len({item.ecosystem for item in self.selections}) != len(self.selections):
            raise ValueError("Only one selection per ecosystem is allowed.")
        return self


class SourceReadResult(BaseModel):
    """Document status, separate from entry-level coverage and lookup status."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    source: DependencySource
    status: Literal["success", "failed"]
    requirements: tuple[RequirementResult, ...] = ()
    errors: tuple[ScanError, ...] = ()
    input_paths: tuple[Path, ...] = ()

    @model_validator(mode="after")
    def valid_read(self) -> Self:
        _validate_context(self.source.ecosystem, self.source, (), self.errors)
        if any(item.ecosystem != self.source.ecosystem for item in self.requirements):
            raise ValueError("Requirement ecosystem must match source.")
        if self.status == "failed" and (not self.errors or self.requirements):
            raise ValueError(
                "Failed reads require errors and cannot contain requirements."
            )
        return self


class SourceSummary(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    ecosystem: Ecosystem
    status: Literal["success", "failed", "absent", "ambiguous"]
    source: DependencySource | None = None
    candidates: tuple[DependencySource, ...] = ()

    @model_validator(mode="after")
    def valid_summary(self) -> Self:
        _validate_context(self.ecosystem, self.source, self.candidates)
        if self.source is not None and self.source not in self.candidates:
            raise ValueError("Summary source must be retained in candidates.")
        if self.status == "success" and self.source is None:
            raise ValueError("Successful summary requires a source.")
        if self.status in {"absent", "ambiguous"} and self.source is not None:
            raise ValueError("Absent/ambiguous summary cannot have a source.")
        if self.status == "absent" and self.candidates:
            raise ValueError("Absent summary cannot have candidates.")
        if self.status == "ambiguous" and (
            self.ecosystem != "npm"
            or len(
                {
                    _manager(item)
                    for item in self.candidates
                    if item.kind != "package_json"
                }
            )
            < 2
        ):
            raise ValueError("Ambiguous summary requires competing lock managers.")
        return self


class ScanReport(BaseModel):
    """Versioned report shared by terminal and JSON output."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: Literal[2] = 2
    scanned_at: datetime
    results: tuple[ScanResult, ...]
    errors: tuple[ScanError, ...]
    detected_ecosystems: tuple[Ecosystem, ...] = ()
    sources: tuple[SourceSummary, ...] = ()
    input_paths: tuple[Path, ...] = ()

    @property
    def exit_code(self) -> int:
        if (
            self.errors
            or not self.detected_ecosystems
            or any(item.status in {"failed", "ambiguous"} for item in self.sources)
            or any(item.status == "unscanned" for item in self.results)
        ):
            return 2
        return int(any(item.status == "vulnerable" for item in self.results))
