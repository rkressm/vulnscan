"""Offline CLI integration tests, including output and exit codes."""

import json
import zipfile
from datetime import datetime
from importlib import metadata
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depscan.cli import main


@pytest.fixture(autouse=True)
def offline_osv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> MagicMock:
    monkeypatch.setattr("depscan.cache.user_cache_path", lambda app: tmp_path / "cache")
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
    output = capsys.readouterr().out
    assert "usage: depscan" in output
    assert "Python and JavaScript" in output
    assert "read Python installed versions" in output


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


def test_project_lock_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline_osv: MagicMock
) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version=1\n[[package]]\nname="demo"\nversion="1"\n'
        'source={registry="https://pypi.org/simple"}\n',
        encoding="utf-8",
    )
    assert main([str(tmp_path), "--no-cache"]) == 0
    captured = capsys.readouterr()
    assert str(lock) in captured.err
    assert "Checked 1 unique" in captured.out
    assert offline_osv.call_count == 1


def test_project_export_cannot_overwrite_lockfile(
    tmp_path: Path, offline_osv: MagicMock
) -> None:
    lock = tmp_path / "uv.lock"
    content = "version=1\npackage=[]\n"
    lock.write_text(content, encoding="utf-8")
    assert main([str(tmp_path), "--json", str(lock)]) == 2
    assert lock.read_text(encoding="utf-8") == content
    offline_osv.assert_not_called()


@pytest.mark.parametrize("selected_venv", [False, True])
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink", "input-symlink"])
def test_json_cannot_overwrite_environment_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offline_osv: MagicMock,
    selected_venv: bool,
    alias: str,
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo>=1", encoding="utf-8")
    venv = tmp_path / "env"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("", encoding="utf-8")
    info = venv / "Lib/site-packages/demo-2.dist-info"
    info.mkdir(parents=True)
    metadata_file = info / "METADATA"
    content = "Name: demo\nVersion: 2\n"
    metadata_file.write_text(content, encoding="utf-8")
    destination = metadata_file
    if alias != "direct":
        destination = tmp_path / "report.json"
        if alias == "symlink":
            destination.symlink_to(metadata_file)
        elif alias == "hardlink":
            destination.hardlink_to(metadata_file)
        else:
            metadata_file.rename(destination)
            metadata_file.symlink_to(destination)
    arguments = [str(requirements), "--no-cache", "--json", str(destination)]
    if selected_venv:
        arguments.extend(["--venv", str(venv)])
    else:
        monkeypatch.setattr(
            metadata, "distribution", lambda name: metadata.PathDistribution(info)
        )
    assert main(arguments) == 2
    assert metadata_file.read_text(encoding="utf-8") == content
    assert destination.read_text(encoding="utf-8") == content
    offline_osv.assert_not_called()


@pytest.mark.parametrize("selected_venv", [False, True])
def test_json_cannot_overwrite_unmatched_metadata_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offline_osv: MagicMock,
    selected_venv: bool,
) -> None:
    venv = tmp_path / "env"
    if selected_venv:
        archive = venv / "lib/python3.14/site-packages"
        archive.parent.mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("", encoding="utf-8")
    else:
        archive = tmp_path / "environment.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("other-1.dist-info/METADATA", "Name: other\nVersion: 1\n")
        stream.writestr("unrelated.py", "raise RuntimeError('must not execute')")
    original = archive.read_bytes()
    if not selected_venv:
        monkeypatch.syspath_prepend(str(archive))
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("missing-archive-safety-package>=1", encoding="utf-8")
    arguments = [str(requirements), "--no-cache", "--json", str(archive)]
    if selected_venv:
        arguments.extend(["--venv", str(venv)])
    assert main(arguments) == 2
    assert archive.read_bytes() == original
    offline_osv.assert_not_called()


def test_project_without_manifest_is_incomplete(
    tmp_path: Path, offline_osv: MagicMock
) -> None:
    assert main([str(tmp_path), "--no-cache"]) == 2
    offline_osv.assert_not_called()


@pytest.mark.parametrize(
    "filename,content,status,exit_code",
    [
        ("requirements.txt", "", "success", 0),
        ("uv.lock", "version=1\npackage=[]\n", "success", 0),
        ("uv.lock", "invalid TOML[", "failed", 2),
        ("requirements.txt", None, "failed", 2),
        ("requirements.txt", "-e ./local\n", "success", 2),
        ("requirements.txt", "-r missing.txt\n", "success", 2),
    ],
)
def test_python_source_context_in_schema_v2(
    tmp_path: Path,
    filename: str,
    content: str | None,
    status: str,
    exit_code: int,
) -> None:
    source = tmp_path / filename
    if content is not None:
        source.write_text(content, encoding="utf-8")
    destination = tmp_path / "report.json"
    assert main([str(source), "--json", str(destination)]) == exit_code
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["detected_ecosystems"] == ["PyPI"]
    assert data["sources"][0]["status"] == status
    summary = data["sources"][0]
    assert summary["candidates"][0]["path"] == str(source)
    if content is None:
        assert summary["source"] is None  # Discovery failed before a reader ran.
        assert data["results"] == []
    else:
        assert summary["source"]["path"] == str(source)
        assert summary["candidates"] == [summary["source"]]
    assert str(source) in data["input_paths"]
    assert all(error["ecosystem"] == "PyPI" for error in data["errors"])
    assert all(result.get("ecosystem", "PyPI") == "PyPI" for result in data["results"])


def test_lookup_failure_retains_package_ecosystem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from depscan.models import (
        FailedLookup,
        PackageVersion,
    )

    source = tmp_path / "package.json"
    source.write_text('{"dependencies":{"demo":"1.2.3"}}', encoding="utf-8")
    package = PackageVersion(ecosystem="npm", name="demo", version="1.2.3")
    monkeypatch.setattr(
        "depscan.cli.lookup_packages",
        lambda *args, **kwargs: [FailedLookup(package=package, reason="Unavailable")],
    )
    destination = tmp_path / "report.json"
    assert main([str(source), "--json", str(destination)]) == 2
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["results"][0]["ecosystem"] == data["errors"][0]["ecosystem"] == "npm"
    assert data["sources"][0]["status"] == "success"


@pytest.mark.parametrize("content", ["", "# comment only\n", "\n  \n"])
@pytest.mark.parametrize("project_scan", [False, True])
def test_json_cannot_overwrite_empty_nested_include(
    tmp_path: Path, offline_osv: MagicMock, content: str, project_scan: bool
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r intermediate.txt\n", encoding="utf-8")
    intermediate = tmp_path / "intermediate.txt"
    intermediate.write_text("-r base.txt\n", encoding="utf-8")
    included = tmp_path / "base.txt"
    included.write_text(content, encoding="utf-8")

    target = tmp_path if project_scan else requirements
    assert main([str(target), "--json", str(included)]) == 2
    assert included.read_text(encoding="utf-8") == content
    offline_osv.assert_not_called()


def test_paginated_osv_response_reaches_cli(
    tmp_path: Path, offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n", encoding="utf-8")
    offline_osv.return_value.json.side_effect = [
        {"next_page_token": "more"},
        {"vulns": [{"id": "TEST-1"}]},
    ]
    report = tmp_path / "report.json"

    assert main([str(requirements), "--no-cache", "--json", str(report)]) == 1
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["results"][0]["advisories"][0]["identifier"] == "TEST-1"


def test_failed_later_page_makes_cli_incomplete(
    tmp_path: Path, offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n", encoding="utf-8")
    offline_osv.return_value.json.side_effect = [
        {"vulns": [{"id": "TEST-1"}], "next_page_token": "more"},
        {"vulns": [{}]},
    ]
    report = tmp_path / "report.json"

    assert main([str(requirements), "--json", str(report)]) == 2
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["results"][0]["status"] == "unscanned"
    assert data["errors"]
    assert not (tmp_path / "cache" / "osv.json").exists()


def test_pipfile_custom_category_reaches_osv(
    tmp_path: Path, offline_osv: MagicMock
) -> None:
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        json.dumps(
            {
                "_meta": {},
                "default": {},
                "develop": {},
                "production": {"requests": {"version": "==2.31.0"}},
            }
        ),
        encoding="utf-8",
    )

    assert main([str(tmp_path), "--no-cache"]) == 0
    offline_osv.assert_called_once()
    assert offline_osv.call_args.kwargs["json"]["package"]["name"] == "requests"


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
    assert data["schema_version"] == 2
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
    assert "No such file or directory" in output
    assert str(tmp_path / "missing.txt") in output
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


@pytest.mark.parametrize("included", [False, True])
def test_refuse_to_overwrite_hardlinked_input(
    tmp_path: Path, offline_osv: MagicMock, included: bool
) -> None:
    requirements = tmp_path / "requirements.txt"
    source = tmp_path / "base.txt" if included else requirements
    original = "# empty requirements\n"
    source.write_text(original, encoding="utf-8")
    if included:
        requirements.write_text("-r base.txt\n", encoding="utf-8")
    output = tmp_path / "report.json"
    output.hardlink_to(source)

    assert main([str(requirements), "--json", str(output)]) == 2
    assert source.read_text(encoding="utf-8") == original
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


def test_cache_reuse_and_no_cache_bypass(
    tmp_path: Path, offline_osv: MagicMock
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")
    destination = tmp_path / "report.json"
    args = [str(requirements), "--json", str(destination)]
    assert main(args) == 0
    first = json.loads(destination.read_text(encoding="utf-8"))
    timestamp = first["results"][0]["looked_up_at"]
    assert datetime.fromisoformat(timestamp).utcoffset() is not None
    cache_path = tmp_path / "cache" / "osv.json"
    cached_bytes = cache_path.read_bytes()

    assert main(args) == 0
    assert offline_osv.call_count == 1
    assert (
        json.loads(destination.read_text())["results"][0]["looked_up_at"] == timestamp
    )

    offline_osv.return_value.json.return_value = {"vulns": [{"id": "NEW-1"}]}
    assert main([*args, "--no-cache"]) == 1
    assert offline_osv.call_count == 2
    assert cache_path.read_bytes() == cached_bytes
    assert main(args) == 0
    assert offline_osv.call_count == 2


def test_no_cache_does_not_even_open_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offline_osv: MagicMock
) -> None:
    def forbidden_cache() -> None:
        pytest.fail("--no-cache must not open the cache")

    monkeypatch.setattr("depscan.cli.LookupCache", forbidden_cache)
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")
    assert main([str(requirements), "--no-cache"]) == 0
    offline_osv.assert_called_once()


def test_failed_lookup_is_not_persisted(tmp_path: Path, offline_osv: MagicMock) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1\n", encoding="utf-8")
    offline_osv.return_value.status_code = 503
    assert main([str(requirements)]) == 2
    assert main([str(requirements)]) == 2
    assert offline_osv.call_count == 2
    assert not (tmp_path / "cache" / "osv.json").exists()


@pytest.mark.parametrize(
    "failed", ["none", "python", "npm", "ambiguous", "discovery", "venv", "lookup"]
)
def test_mixed_ecosystems_continue_and_report_honestly(
    tmp_path: Path, offline_osv: MagicMock, failed: str
) -> None:
    (tmp_path / "requirements.txt").write_text("demo==1.2.3", encoding="utf-8")
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"demo":"1.2.3"}}', encoding="utf-8")
    args = [str(tmp_path), "--no-cache", "--json", str(tmp_path / "report.json")]
    if failed == "python":
        (tmp_path / "uv.lock").write_text("invalid TOML[", encoding="utf-8")
    elif failed == "npm":
        manifest.write_text("invalid JSON", encoding="utf-8")
    elif failed in {"ambiguous", "discovery"}:
        (tmp_path / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{}}', encoding="utf-8"
        )
        (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
        if failed == "discovery":
            manifest.write_text("invalid JSON", encoding="utf-8")
    elif failed == "venv":
        args.extend(["--venv", str(tmp_path / "missing-env")])
    if failed == "lookup":

        def reply(*args: object, **kwargs: object) -> MagicMock:
            response = MagicMock()
            payload = kwargs["json"]
            assert isinstance(payload, dict)
            response.status_code = (
                503 if payload["package"]["ecosystem"] == "npm" else 200
            )
            response.json.return_value = {"vulns": [{"id": "TEST-1"}]}
            response.__enter__.return_value = response
            return response

        offline_osv.side_effect = reply
    else:
        offline_osv.return_value.json.return_value = {"vulns": [{"id": "TEST-1"}]}
    assert main(args) == (1 if failed == "none" else 2)
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["detected_ecosystems"] == ["PyPI", "npm"]
    assert len(data["sources"]) == 2
    assert any(result["status"] == "vulnerable" for result in data["results"])
    assert len(data["errors"]) == (0 if failed == "none" else 1)
    if failed in {"ambiguous", "discovery"}:
        assert data["sources"][1]["source"] is None
        assert data["sources"][1]["status"] == (
            "ambiguous" if failed == "ambiguous" else "failed"
        )
    elif failed == "lookup":
        assert [source["status"] for source in data["sources"]] == [
            "success",
            "success",
        ]
    elif failed == "none":
        assert {
            call.kwargs["json"]["package"]["ecosystem"]
            for call in offline_osv.call_args_list
        } == {"PyPI", "npm"}


@pytest.mark.parametrize(
    "filename,content",
    [
        ("package.json", "{}"),
        ("package-lock.json", '{"lockfileVersion":3,"packages":{}}'),
        ("yarn.lock", "# yarn lockfile v1\n"),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\n"),
        ("bun.lock", '{"lockfileVersion":1,"workspaces":{"":{}}}'),
    ],
)
@pytest.mark.parametrize("explicit", [False, True])
def test_empty_js_sources_are_detected(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    offline_osv: MagicMock,
    filename: str,
    content: str,
    explicit: bool,
) -> None:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    destination = tmp_path / "report.json"
    assert (
        main(
            [
                str(path if explicit else tmp_path),
                "--json",
                str(destination),
                "--venv",
                str(tmp_path / "invalid-env"),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert str(path) in captured.err
    assert "npm" in captured.err
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["detected_ecosystems"] == ["npm"]
    assert data["results"] == data["errors"] == []
    assert data["sources"][-1]["status"] == "success"
    if not explicit:
        assert data["sources"][0]["status"] == "absent"
    offline_osv.assert_not_called()


@pytest.mark.parametrize(
    "selection",
    [
        "unselected",
        "hint",
        "failed-hint",
        "ambiguous",
        "failed-lock",
        "missing-include",
    ],
)
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink", "input-symlink"])
def test_all_discovery_and_attempted_inputs_are_protected(
    tmp_path: Path,
    offline_osv: MagicMock,
    selection: str,
    alias: str,
) -> None:
    manifest = tmp_path / "package.json"
    manifest.write_text('{"packageManager":"npm@10.0.0"}', encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"lockfileVersion":3,"packages":{}}', encoding="utf-8")
    protected = manifest
    if selection in {"hint", "failed-hint", "ambiguous"}:
        (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
        if selection != "hint":
            manifest.write_text(
                "invalid JSON" if selection == "failed-hint" else "{}", encoding="utf-8"
            )
    elif selection == "failed-lock":
        lock.write_text("invalid JSON", encoding="utf-8")
        protected = lock
    elif selection == "missing-include":
        (tmp_path / "requirements.txt").write_text("-r missing.txt", encoding="utf-8")
        protected = tmp_path / "missing.txt"
        if alias != "direct":
            protected.write_text("", encoding="utf-8")
    original = protected.read_bytes() if protected.exists() else None
    destination = protected
    if alias != "direct":
        destination = tmp_path / "report.json"
        if alias == "symlink":
            destination.symlink_to(protected)
        elif alias == "hardlink":
            destination.hardlink_to(protected)
        else:
            protected.rename(destination)
            protected.symlink_to(destination)
    assert main([str(tmp_path), "--json", str(destination)]) == 2
    if original is None:
        assert not destination.exists()
    else:
        assert protected.read_bytes() == original
    offline_osv.assert_not_called()


@pytest.mark.parametrize("operation", ["resolve", "stat", "samefile"])
def test_output_comparison_errors_block_before_lookups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offline_osv: MagicMock,
    operation: str,
) -> None:
    from depscan.project import read_sources

    source = tmp_path / "requirements.txt"
    source.write_text("demo==1", encoding="utf-8")
    destination = tmp_path / "report.json"
    destination.write_text("preserve", encoding="utf-8")
    evidence = read_sources(source)
    monkeypatch.setattr("depscan.cli.read_sources", lambda *args, **kwargs: evidence)
    original = getattr(Path, operation)

    def fail(self: Path, *args: object, **kwargs: object) -> object:
        if self == source or (operation == "samefile" and self == destination):
            raise OSError("comparison denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, operation, fail)
    assert main([str(source), "--json", str(destination)]) == 2
    assert destination.read_text(encoding="utf-8") == "preserve"
    offline_osv.assert_not_called()


def test_output_protection_resolves_every_input_after_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from depscan.cli import _overwrites_input

    first, second = tmp_path / "a.txt", tmp_path / "z.txt"
    first.write_text("", encoding="utf-8")
    second.write_text("", encoding="utf-8")
    original = Path.resolve
    resolved: list[Path] = []

    def track(path: Path) -> Path:
        resolved.append(path)
        return original(path)

    monkeypatch.setattr(Path, "resolve", track)
    assert _overwrites_input(first, {first, second})
    assert resolved == [first, second]
