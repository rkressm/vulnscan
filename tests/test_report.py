"""Report exports preserve prior data when filesystem operations fail."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from depscan.models import ScanReport
from depscan.report import write_json


def test_atomic_report_export(tmp_path: Path) -> None:
    report = ScanReport(scanned_at=datetime.now(UTC), results=(), errors=())
    destination = tmp_path / "report.json"
    destination.write_text("previous report", encoding="utf-8")

    write_json(report, destination)

    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == 1
    assert list(tmp_path.iterdir()) == [destination]


def test_failed_export_preserves_previous_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = ScanReport(scanned_at=datetime.now(UTC), results=(), errors=())
    destination = tmp_path / "report.json"
    destination.write_text("previous report", encoding="utf-8")

    def fail_replace(source: Path, target: Path) -> None:
        raise OSError("simulated replacement failure")

    monkeypatch.setattr("depscan.report.os.replace", fail_replace)
    with pytest.raises(OSError, match="replacement failure"):
        write_json(report, destination)

    assert destination.read_text(encoding="utf-8") == "previous report"
    assert list(tmp_path.iterdir()) == [destination]
