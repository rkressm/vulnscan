"""Offline CLI integration tests, including output and exit codes."""

import json
from datetime import datetime
from importlib import metadata
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depscan.cli import main


@pytest.fixture(autouse=True)
def offline_osv(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {}
    response.__enter__.return_value = response
    post = MagicMock(return_value=response)
    monkeypatch.setattr("depscan.osv.requests.post", post)
    return post


def test_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["depscan", "--help"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    assert "usage: depscan" in capsys.readouterr().out


def test_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["depscan", "--version"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "0.1.0"


def test_missing_argument_does_not_report_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["depscan"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    assert "required" in capsys.readouterr().err


def test_clean_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\nRequests==2.31.0\n", encoding="utf-8")

    assert main([str(requirements), "--no-cache"]) == 0

    output = capsys.readouterr().out
    assert "no known vulnerabilities" in output
    assert "Checked 1 unique package/version pairs" in output
    assert "Scan complete." in output
    assert offline_osv.call_count == 1


def test_vulnerabilities_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\ndemo==1\n", encoding="utf-8")
    offline_osv.return_value.json.return_value = {
        "vulns": [
            {"id": "TEST-1", "database_specific": {"severity": "HIGH"}},
            {"id": "TEST-2"},
        ]
    }
    destination = tmp_path / "report.json"

    assert main([str(requirements), "--json", str(destination)]) == 1

    output = capsys.readouterr().out
    assert "1 vulnerable" in output
    assert "2 advisories" in output
    assert "TEST-1" in output
    assert "HIGH" in output
    assert "UNKNOWN" in output
    assert "https://osv.dev/vulnerability/TEST-2" in output
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert datetime.fromisoformat(data["scanned_at"]).utcoffset() is not None
    assert data["errors"] == []
    assert len(data["results"]) == 2
    assert data["results"][0]["status"] == "vulnerable"
    assert data["results"][0]["source"]["line"] == 1
    assert data["results"][0]["advisories"][1]["severity"] == "UNKNOWN"


def test_mixed_results_are_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        'demo==1\n-e ./local\nexcluded==1; python_version < "0"\n', encoding="utf-8"
    )
    offline_osv.return_value.json.return_value = {"vulns": [{"id": "TEST-1"}]}
    destination = tmp_path / "report.json"

    assert main([str(requirements), "--json", str(destination)]) == 2

    output = capsys.readouterr().out
    assert "1 vulnerable" in output
    assert "1 unscanned, 1 non-applicable" in output
    assert "Scan incomplete." in output
    assert f"{requirements}:2" in output
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert [item["status"] for item in data["results"]] == [
        "vulnerable",
        "unscanned",
        "non_applicable",
    ]
    assert len(data["errors"]) == 1
    assert data["errors"][0]["source"]["line"] == 2
    assert offline_osv.call_count == 1


def test_non_applicable_is_not_a_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text('excluded==1; python_version < "0"\n', encoding="utf-8")

    assert main([str(requirements)]) == 0

    assert "0 unscanned, 1 non-applicable" in capsys.readouterr().out
    offline_osv.assert_not_called()


@pytest.mark.parametrize("contents", ["", "# only a comment\n"])
def test_empty_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], contents: str
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(contents, encoding="utf-8")

    assert main([str(requirements)]) == 0

    assert "Checked 0 unique package/version pairs" in capsys.readouterr().out


def test_unreadable_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "missing.txt")]) == 2

    output = capsys.readouterr().out
    assert "Cannot read requirements file" in output
    assert "Scan incomplete." in output
    assert "Traceback" not in output


def test_lookup_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")
    offline_osv.return_value.status_code = 503
    destination = tmp_path / "report.json"

    assert main([str(requirements), "--json", str(destination)]) == 2

    output = capsys.readouterr().out
    assert "OSV returned HTTP 503" in output
    assert "1 unscanned" in output
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["results"][0]["status"] == "unscanned"
    assert data["errors"][0]["reason"] == "OSV returned HTTP 503."


def test_json_write_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")

    assert main([str(requirements), "--json", str(tmp_path)]) == 2

    output = capsys.readouterr()
    assert "Cannot write JSON report" in output.err
    assert "Scan incomplete." in output.out
    assert "Traceback" not in output.err


def test_refuse_to_overwrite_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")

    assert main([str(requirements), "--json", str(requirements)]) == 2

    assert "must not overwrite" in capsys.readouterr().err
    assert requirements.read_text(encoding="utf-8") == "demo==1\n"
    offline_osv.assert_not_called()


def test_interruption(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")
    offline_osv.side_effect = KeyboardInterrupt

    assert main([str(requirements)]) == 2

    assert "scan interrupted" in capsys.readouterr().err


def test_include_and_installed_version_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    offline_osv: MagicMock,
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r base.txt\n", encoding="utf-8")
    (tmp_path / "base.txt").write_text("demo>=1,<3\nmissing\n", encoding="utf-8")

    def installed_version(name: str) -> str:
        if name == "demo":
            return "2.0"
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr("depscan.requirements.metadata.version", installed_version)
    # CLI --version metadata is independent of the installed dependency lookup.
    monkeypatch.setattr("depscan.cli.version", lambda name: "0.1.0")

    assert main([str(requirements)]) == 2

    output = capsys.readouterr().out
    assert "2.0" in output
    assert f"{tmp_path / 'base.txt'}:2" in output
    assert "Package is not installed" in output
    assert offline_osv.call_args.kwargs["json"]["version"] == "2.0"


def test_invalid_output_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")

    assert main([str(requirements), "--json", "invalid\x00.json"]) == 2

    assert "invalid JSON output path" in capsys.readouterr().err
