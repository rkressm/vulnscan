"""Validated data shared by the scanner's future components."""

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
