"""Smoke tests for the initial package entry point."""

import pytest

from depscan.cli import main


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


def test_unimplemented_scan_does_not_report_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["depscan"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    assert "not implemented" in capsys.readouterr().err
