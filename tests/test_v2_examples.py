"""Smoke-test the inert documented examples through the CLI with mocked OSV."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depscan.cli import main

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def example_osv(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    def forbid_process(*args: object, **kwargs: object) -> None:
        pytest.fail("Example scans must not invoke project code or package managers")

    monkeypatch.setattr(subprocess, "Popen", forbid_process)
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {}
    response.__enter__.return_value = response
    post = MagicMock(return_value=response)
    monkeypatch.setattr("depscan.osv.requests.post", post)
    return post


@pytest.mark.parametrize("explicit", [False, True])
def test_javascript_manifest_example(
    explicit: bool,
    tmp_path: Path,
    example_osv: MagicMock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _EXAMPLES / "javascript"
    if explicit:
        source /= "package.json"
    destination = tmp_path / "report.json"

    assert main([str(source), "--no-cache", "--json", str(destination)]) == 2

    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert data["detected_ecosystems"] == ["npm"]
    selected = next(item for item in data["sources"] if item["ecosystem"] == "npm")
    assert selected["status"] == "success"
    assert selected["source"]["kind"] == "package_json"
    assert Path(selected["source"]["path"]) == _EXAMPLES / "javascript/package.json"
    assert len(data["sources"]) == (1 if explicit else 2)
    queried = {
        (
            call.kwargs["json"]["package"]["ecosystem"],
            call.kwargs["json"]["package"]["name"],
            call.kwargs["json"]["version"],
        )
        for call in example_osv.call_args_list
    }
    assert queried == {
        ("npm", "lodash", "4.17.21"),
        ("npm", "@types/node", "22.0.0-beta.1"),
        ("npm", "typescript", "5.7.3"),
    }
    assert example_osv.call_count == 3
    unscanned = [item for item in data["results"] if item["status"] == "unscanned"]
    assert {item["name"] for item in unscanned} == {
        "unresolved-range",
        "unresolved-tag",
    }
    assert all(item["ecosystem"] == "npm" for item in unscanned)
    alias = next(
        item
        for item in data["results"]
        if item.get("package", {}).get("name") == "@types/node"
    )
    assert "types-alias" in alias["source"]["text"]
    captured = capsys.readouterr()
    assert "npm dependency source:" in captured.err
    assert "incomplete" in captured.out.lower()


@pytest.mark.parametrize("findings", [False, True])
def test_mixed_lock_example(
    findings: bool,
    tmp_path: Path,
    example_osv: MagicMock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if findings:
        example_osv.return_value.json.return_value = {
            "vulns": [{"id": "EXAMPLE-ONLY-001"}]
        }
    destination = tmp_path / "report.json"

    assert main(
        [str(_EXAMPLES / "mixed"), "--no-cache", "--json", str(destination)]
    ) == int(findings)

    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert data["detected_ecosystems"] == ["PyPI", "npm"]
    assert [(item["status"], item["source"]["kind"]) for item in data["sources"]] == [
        ("success", "requirements"),
        ("success", "npm"),
    ]
    assert data["errors"] == []
    assert {
        (
            item["package"]["ecosystem"],
            item["package"]["name"],
            item["package"]["version"],
        )
        for item in data["results"]
    } == {("PyPI", "requests", "2.31.0"), ("npm", "lodash", "4.17.21")}
    assert {item["status"] for item in data["results"]} == {
        "vulnerable" if findings else "no_known_vulnerabilities"
    }
    assert example_osv.call_count == 2
    assert {
        call.kwargs["json"]["package"]["ecosystem"]
        for call in example_osv.call_args_list
    } == {"PyPI", "npm"}
    assert {Path(path).name for path in data["input_paths"]} == {
        "requirements.txt",
        "package.json",
        "package-lock.json",
    }
    captured = capsys.readouterr()
    assert "PyPI dependency source:" in captured.err
    assert "npm dependency source:" in captured.err
