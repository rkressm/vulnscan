"""Best-effort local OSV cache; stale or invalid data never replaces a lookup."""

import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from packaging.utils import canonicalize_name
from platformdirs import user_cache_path
from pydantic import BaseModel, ConfigDict, ValidationError

from depscan.models import PackageVersion, SuccessfulLookup

_TTL = timedelta(hours=24)


class _CacheFile(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    schema_version: Literal[1] = 1
    entries: dict[str, SuccessfulLookup]


def _key(package: PackageVersion) -> str:
    return json.dumps(["PyPI", canonicalize_name(package.name), package.version])


class LookupCache:
    """Load once, reuse fresh successes, and atomically save new successes.

    Cache I/O is optional: unreadable or corrupt files are treated as empty, and
    write failures leave scanning unaffected. Concurrent writers may lose cache
    entries, but atomic replacement prevents partial JSON files.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.path = (
            path if path is not None else user_cache_path("depscan") / "osv.json"
        )
        self._clock = clock
        self._dirty = False
        try:
            self._entries = _CacheFile.model_validate_json(
                self.path.read_text(encoding="utf-8")
            ).entries
        except OSError, ValueError, ValidationError:
            self._entries = {}

    def get(self, package: PackageVersion) -> SuccessfulLookup | None:
        result = self._entries.get(_key(package))
        if result is None or result.looked_up_at is None:
            return None
        if _key(result.package) != _key(package):
            return None
        age = self._clock() - result.looked_up_at
        if not timedelta(0) <= age < _TTL:
            return None
        return result.model_copy(update={"package": package})

    def put(self, result: SuccessfulLookup) -> None:
        if result.looked_up_at is not None:
            self._entries[_key(result.package)] = result
            self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        temporary: Path | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = _CacheFile(entries=self._entries).model_dump_json(indent=2)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent, delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(payload + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self._dirty = False
        except OSError, ValueError:
            pass
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
