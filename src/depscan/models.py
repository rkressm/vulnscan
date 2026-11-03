"""Validated data shared by the scanner's components."""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

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


class FailedLookup(BaseModel):
    """A lookup failure, never a claim that the package has no vulnerabilities."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["failed"] = "failed"
    package: PackageVersion
    reason: NonEmptyString


type LookupResult = Annotated[
    SuccessfulLookup | FailedLookup, Field(discriminator="status")
]
