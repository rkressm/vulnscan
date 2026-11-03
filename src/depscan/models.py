"""Validated data shared by the scanner's components."""

from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class PackageVersion(BaseModel):
    """A package and its selected version, ready for an OSV lookup.

    Requirement parsing and version selection remain the parser's responsibility.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    name: NonEmptyString
    version: NonEmptyString


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


class UnscannedRequirement(BaseModel):
    """An invalid or unsupported declaration, or an unresolved version."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["unscanned"] = "unscanned"
    source: SourceLocation
    reason: NonEmptyString
    name: str | None = None


class NonApplicableRequirement(BaseModel):
    """A declaration excluded by its environment marker."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["non_applicable"] = "non_applicable"
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


type ScanResult = Annotated[
    ScannedRequirement | UnscannedRequirement | NonApplicableRequirement,
    Field(discriminator="status"),
]


class ScanError(BaseModel):
    """A failure that makes a scan incomplete, with its source if available."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source: SourceLocation | None = None
    reason: NonEmptyString


class ScanReport(BaseModel):
    """Versioned report shared by terminal and JSON output."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    scanned_at: datetime
    results: tuple[ScanResult, ...]
    errors: tuple[ScanError, ...]

    @property
    def exit_code(self) -> int:
        if self.errors or any(item.status == "unscanned" for item in self.results):
            return 2
        return int(any(item.status == "vulnerable" for item in self.results))
