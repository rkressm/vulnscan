"""Independent offline checks of discovery → parsing → OSV/cache → CLI reports."""

import json
import os
import shutil
import socket
import subprocess
import sys
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from depscan.cli import main
from depscan.models import Ecosystem, ScannedRequirement, ScanReport

FIXTURES = Path(__file__).parent / "fixtures"
PYTHON_FILES = (
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "requirements.txt",
)
JS_FILES = (
    "npm-shrinkwrap.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "package.json",
)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def response(payload: object, status: int = 200) -> Mock:
    result = Mock(spec=requests.Response)
    result.status_code = status
    result.json.return_value = payload
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    return result


def advisory(identifier: str) -> dict[str, object]:
    return {"vulns": [{"id": identifier, "database_specific": {"severity": "HIGH"}}]}


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Mock:
    """No host managers, subprocesses, real HTTP, sockets, or shared user cache."""
    empty_path = tmp_path / "empty-bin"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", str(empty_path))
    for executable in (
        "node",
        "nodejs",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "bun",
        "corepack",
    ):
        assert shutil.which(executable) is None

    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail(f"External execution/network forbidden: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    for name in ("system", "popen", "posix_spawn", "posix_spawnp", "execv", "execve"):
        monkeypatch.setattr(os, name, forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr("depscan.cache.user_cache_path", lambda app: tmp_path / "cache")
    # CLI's own --version metadata must remain available when tests isolate sys.path.
    # Dependency discovery below still uses real importlib filesystem evidence.
    monkeypatch.setattr("depscan.cli.version", lambda name: "0.1.0")
    post = Mock(return_value=response({}))
    monkeypatch.setattr(requests, "post", post)
    return post


def export(path: Path, destination: Path, *flags: str) -> tuple[int, ScanReport]:
    code = main([str(path), "--json", str(destination), *flags])
    report = ScanReport.model_validate_json(destination.read_text(encoding="utf-8"))
    assert report.schema_version == 2
    assert report.scanned_at.tzinfo is not None
    assert report.input_paths == tuple(sorted(set(report.input_paths)))
    assert all(item.is_absolute() for item in report.input_paths)
    return code, report


def queries(post: Mock) -> list[tuple[str, str, str]]:
    identities = []
    for call in post.call_args_list:
        assert call.args == ("https://api.osv.dev/v1/query",)
        assert call.kwargs["timeout"] == (5.0, 30.0)
        assert call.kwargs["allow_redirects"] is False
        data = call.kwargs["json"]
        identities.append(
            (data["package"]["ecosystem"], data["package"]["name"], data["version"])
        )
    return identities


def scanned(report: ScanReport) -> list[ScannedRequirement]:
    return [item for item in report.results if isinstance(item, ScannedRequirement)]


def mixed(root: Path) -> None:
    write(root / "requirements.txt", "demo==1.2.3\n")
    write(root / "package.json", '{"dependencies":{"demo":"1.2.3"}}')


def alias_output(target: Path, root: Path, alias: str) -> Path:
    if alias == "direct":
        return target
    destination = root / "output.json"
    if alias == "symlink":
        destination.symlink_to(target)
    elif alias == "hardlink":
        destination.hardlink_to(target)
    else:
        target.rename(destination)
        target.symlink_to(destination)
    return destination


# Every advertised lock format goes through real CLI dispatch and mocked HTTP.
FORMAT_CASES = [
    pytest.param("package.json", '{"dependencies":{"demo":"1.2.3"}}', id="manifest"),
    *[
        pytest.param(
            filename,
            json.dumps(
                {
                    "lockfileVersion": version,
                    **(
                        {"dependencies": {"demo": {"version": "1.2.3"}}}
                        if version == 1
                        else {"packages": {"node_modules/demo": {"version": "1.2.3"}}}
                    ),
                }
            ),
            id=f"{filename}-v{version}",
        )
        for filename in ("package-lock.json", "npm-shrinkwrap.json")
        for version in (1, 2, 3)
    ],
    pytest.param(
        "yarn.lock", '# yarn lockfile v1\n"demo@^1":\n  version "1.2.3"\n', id="classic"
    ),
    *[
        pytest.param(
            "yarn.lock",
            f'__metadata:\n  version: {version}\n"demo@npm:^1":\n'
            '  version: 1.2.3\n  resolution: "demo@npm:1.2.3"\n',
            id=f"yarn-{version}",
        )
        for version in (4, 6, 8, 10)
    ],
    *[
        pytest.param(
            "pnpm-lock.yaml",
            f"lockfileVersion: {version}\npackages:\n"
            f"  {'/' if '6' in version else ''}demo@1.2.3:\n"
            "    resolution: {integrity: synthetic}\n",
            id=f"pnpm-{version}",
        )
        for version in ("'6.0'", "'9.0'", "6", "9", "6.0", "9.0")
    ],
    pytest.param(
        "bun.lock",
        '// synthetic JSONC\n{"lockfileVersion":1,"workspaces":{"":{}},"packages":{"alias":["demo@1.2.3","",{},""]},"note":"https://example.invalid/a//b/*c*/",}',
        id="bun-1",
    ),
]


@pytest.mark.parametrize("filename,document", FORMAT_CASES)
@pytest.mark.parametrize("explicit", [False, True], ids=["mixed-directory", "explicit"])
def test_supported_formats_without_managers(
    tmp_path: Path,
    offline: Mock,
    filename: str,
    document: str,
    explicit: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = write(tmp_path / filename, document)
    write(tmp_path / "requirements.txt", "python-only==2.0\n")
    code, report = export(source if explicit else tmp_path, tmp_path / "report.json")
    assert code == 0
    expected = [("npm", "demo", "1.2.3")]
    if not explicit:
        expected.insert(0, ("PyPI", "python-only", "2.0"))
    assert queries(offline) == expected
    assert [item.package.identity for item in scanned(report)] == expected
    assert report.detected_ecosystems == (("npm",) if explicit else ("PyPI", "npm"))
    assert report.sources[-1].source is not None
    assert report.sources[-1].source.path == source
    assert all(item.source.line == 1 for item in report.results)
    assert all(item.looked_up_at is not None for item in scanned(report))
    captured = capsys.readouterr()
    assert str(source) in captured.err
    assert "npm dependency source: selected" in captured.err
    assert "no known vulnerabilities" in captured.out
    assert "safe" not in captured.out.lower()


@pytest.mark.parametrize("failed", ["PyPI", "npm"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_parser_failure_keeps_other_ecosystem(
    tmp_path: Path,
    offline: Mock,
    failed: Ecosystem,
    vulnerable: bool,
) -> None:
    mixed(tmp_path)
    broken = write(
        tmp_path / ("uv.lock" if failed == "PyPI" else "package-lock.json"), "["
    )
    if vulnerable:
        offline.return_value = response(advisory("PEER-1"))
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 2
    peer: Ecosystem = "npm" if failed == "PyPI" else "PyPI"
    assert queries(offline) == [(peer, "demo", "1.2.3")]
    assert len(report.results) == len(report.errors) == 1
    assert report.errors[0].ecosystem == failed
    assert report.errors[0].source is not None
    assert report.errors[0].source.path == broken
    summaries = {item.ecosystem: item for item in report.sources}
    failed_summary = summaries[failed]
    assert failed_summary.status == "failed"
    assert failed_summary.source is not None
    assert failed_summary.source.path == broken
    assert summaries[peer].status == "success"
    assert report.results[0].status == (
        "vulnerable" if vulnerable else "no_known_vulnerabilities"
    )


@pytest.mark.parametrize("failed", ["PyPI", "npm"])
@pytest.mark.parametrize("failure", ["timeout", "http", "malformed", "later-page"])
def test_lookup_failure_preserves_peer_and_only_caches_success(
    tmp_path: Path,
    offline: Mock,
    failed: str,
    failure: str,
) -> None:
    mixed(tmp_path)

    def reply(*args: object, **kwargs: Any) -> Mock:
        data = kwargs["json"]
        ecosystem = data["package"]["ecosystem"]
        if ecosystem != failed:
            return response(advisory("PEER-1"))
        if failure == "timeout" or data.get("page_token"):
            raise requests.Timeout("offline injected timeout")
        if failure == "later-page":
            return response(
                {**advisory("PARTIAL-NOT-A-SUCCESS"), "next_page_token": "next"}
            )
        return response(
            {"vulns": "bad"} if failure == "malformed" else {},
            503 if failure == "http" else 200,
        )

    offline.side_effect = reply
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 2
    assert [item.status for item in report.sources] == ["success", "success"]
    assert len(report.errors) == 1
    assert report.errors[0].ecosystem == failed
    unresolved = [item for item in report.results if item.status == "unscanned"]
    assert len(unresolved) == 1 and unresolved[0].ecosystem == failed
    assert [item.advisories[0].identifier for item in scanned(report)] == ["PEER-1"]
    first_queries = queries(offline)
    assert {item[0] for item in first_queries} == {"PyPI", "npm"}
    cache = json.loads((tmp_path / "cache/osv.json").read_text())
    assert len(cache["entries"]) == 1
    assert next(iter(cache["entries"].values()))["package"]["ecosystem"] != failed
    offline.reset_mock()
    offline.side_effect = None
    offline.return_value = response({})
    code, retried = export(tmp_path, tmp_path / "report.json")
    assert code == 1  # cached peer finding survives; failed identity is retried.
    assert queries(offline) == [(failed, "demo", "1.2.3")]
    assert len(scanned(retried)) == 2


def test_equal_identity_names_cache_and_no_cache_keep_provenance(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mixed(tmp_path)
    write(tmp_path / "requirements.txt", "Demo==1.2.3\ndemo==1.2.3\n")
    write(
        tmp_path / "package.json",
        json.dumps(
            {
                group: {f"alias{index}": "npm:demo@1.2.3"}
                for index, group in enumerate(
                    (
                        "dependencies",
                        "devDependencies",
                        "optionalDependencies",
                        "peerDependencies",
                    )
                )
            }
        ),
    )

    def reply(*args: object, **kwargs: Any) -> Mock:
        return response(
            advisory("NPM-ONLY")
            if kwargs["json"]["package"]["ecosystem"] == "npm"
            else {}
        )

    offline.side_effect = reply
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 1
    assert queries(offline) == [("PyPI", "demo", "1.2.3"), ("npm", "demo", "1.2.3")]
    assert len(report.results) == 6
    assert len({item.source.text for item in report.results}) == 6
    assert all(
        item.status
        == ("vulnerable" if item.ecosystem == "npm" else "no_known_vulnerabilities")
        for item in report.results
    )
    terminal = capsys.readouterr().out
    assert "Checked 2 unique package/version pairs: 1 vulnerable" in terminal
    assert "PyPI: Checked 1 unique" in terminal and "npm: Checked 1 unique" in terminal
    cache_path = tmp_path / "cache/osv.json"
    cache = json.loads(cache_path.read_text())
    assert cache["schema_version"] == 2
    assert {tuple(json.loads(key)) for key in cache["entries"]} == {
        ("PyPI", "demo", "1.2.3"),
        ("npm", "demo", "1.2.3"),
    }
    original = cache_path.read_bytes()
    offline.reset_mock()
    code, cached = export(tmp_path, tmp_path / "report.json")
    assert code == 1 and cached.results == report.results
    offline.assert_not_called()

    def forbidden_cache() -> Any:
        pytest.fail("--no-cache constructed/read a cache")

    monkeypatch.setattr("depscan.cli.LookupCache", forbidden_cache)
    code, uncached = export(tmp_path, tmp_path / "report.json", "--no-cache")
    assert code == 1 and len(uncached.results) == 6
    assert queries(offline) == [("PyPI", "demo", "1.2.3"), ("npm", "demo", "1.2.3")]
    assert cache_path.read_bytes() == original


@pytest.mark.parametrize(
    "fault", ["expired", "future", "corrupt", "legacy", "mismatch"]
)
def test_invalid_cache_does_not_cross_ecosystems(
    tmp_path: Path, offline: Mock, fault: str
) -> None:
    mixed(tmp_path)
    assert export(tmp_path, tmp_path / "report.json")[0] == 0
    path = tmp_path / "cache/osv.json"
    data = json.loads(path.read_text())
    if fault == "corrupt":
        path.write_text("{", encoding="utf-8")
    else:
        if fault == "legacy":
            data.pop("schema_version")
        for entry in data["entries"].values():
            if fault in {"expired", "future"}:
                entry["looked_up_at"] = (
                    datetime.now(UTC)
                    + timedelta(hours=-25 if fault == "expired" else 25)
                ).isoformat()
            elif fault == "mismatch":
                entry["package"]["ecosystem"] = (
                    "npm" if entry["package"]["ecosystem"] == "PyPI" else "PyPI"
                )
        path.write_text(json.dumps(data), encoding="utf-8")
    offline.reset_mock()
    assert export(tmp_path, tmp_path / "report.json")[0] == 0
    assert queries(offline) == [("PyPI", "demo", "1.2.3"), ("npm", "demo", "1.2.3")]


@pytest.mark.parametrize("target_name", (*PYTHON_FILES, *JS_FILES))
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink", "input-symlink"])
def test_every_detected_candidate_is_protected_before_network(
    tmp_path: Path,
    offline: Mock,
    target_name: str,
    alias: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # All siblings exist, but only uv.lock and shrinkwrap are selected.
    for name in (*PYTHON_FILES, *JS_FILES):
        write(tmp_path / name, "unselected, intentionally not parsed")
    write(
        tmp_path / "uv.lock",
        '[[package]]\nname="python-only"\nversion="1"\nsource={registry="https://pypi.org/simple"}\n',
    )
    write(
        tmp_path / "npm-shrinkwrap.json",
        '{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.2.3"}}}',
    )
    write(tmp_path / "package.json", '{"packageManager":"npm@10.0.0"}')
    target = tmp_path / target_name
    original = target.read_bytes()
    destination = alias_output(target, tmp_path, alias)

    def forbidden_cache() -> Any:
        pytest.fail("Input protection must precede cache access")

    monkeypatch.setattr("depscan.cli.LookupCache", forbidden_cache)
    assert main([str(tmp_path), "--json", str(destination)]) == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert target.read_bytes() == destination.read_bytes() == original
    offline.assert_not_called()


@pytest.mark.parametrize(
    "kind,alias",
    [
        (kind, alias)
        for kind in ("empty", "nested", "missing", "denied", "invalid-utf8")
        for alias in ("direct", "symlink", "hardlink", "input-symlink")
        if kind != "missing" or alias == "direct"
    ],
)
def test_included_attempts_and_empty_files_are_protected(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    alias: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mixed(tmp_path)
    write(tmp_path / "requirements.txt", "demo==1.2.3\n-r child/base.in\n")
    target = tmp_path / "child/target.in"
    write(tmp_path / "child/base.in", "-r target.in\n")
    if kind != "missing":
        write(target, "demo==1.2.3\n" if kind == "nested" else "")
    if kind == "invalid-utf8":
        target.write_bytes(b"\xff")
    original = target.read_bytes() if target.exists() else None
    destination = alias_output(target, tmp_path, alias)
    if kind == "denied":
        read_text = Path.read_text

        def denied(path: Path, *args: Any, **kwargs: Any) -> str:
            if path == target.resolve():
                raise PermissionError("injected include read denial")
            return read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", denied)
    assert main([str(tmp_path), "--json", str(destination)]) == 2
    assert "must not overwrite" in capsys.readouterr().err
    if original is None:
        assert not destination.exists()
    else:
        assert target.read_bytes() == destination.read_bytes() == original
    offline.assert_not_called()


@pytest.mark.parametrize("selected_venv", [False, True])
@pytest.mark.parametrize(
    "kind", ["METADATA", "PKG-INFO", "archive", "unmatched-archive"]
)
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink", "input-symlink"])
def test_metadata_inputs_and_archive_attempts_are_protected(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    selected_venv: bool,
    kind: str,
    alias: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mixed(tmp_path)
    requirements = write(tmp_path / "requirements.txt", "demo>=1\n")
    venv = tmp_path / "env"
    write(venv / "pyvenv.cfg", "")
    site = venv / "lib/python3.14/site-packages"
    archive = "archive" in kind
    info = site / "demo-2.dist-info"
    if archive:
        site.parent.mkdir(parents=True, exist_ok=True)
        target = site  # importlib attempts non-directory search roots as ZIPs.
        with zipfile.ZipFile(target, "w") as stream:
            name = "other" if kind == "unmatched-archive" else "demo"
            stream.writestr(
                f"{name}-2.dist-info/METADATA", f"Name: {name}\nVersion: 2\n"
            )
            stream.writestr("project.py", "raise RuntimeError('never execute')")
    else:
        target = write(info / kind, "Name: demo\nVersion: 2\n")
    original = target.read_bytes()
    destination = alias_output(target, tmp_path, alias)
    # Real importlib discovery, constrained to synthetic evidence, not host installs.
    monkeypatch.setattr(sys, "path", [str(site)])
    arguments = [
        str(tmp_path if selected_venv else requirements),
        "--json",
        str(destination),
    ]
    if selected_venv:
        arguments.extend(["--venv", str(venv)])
    assert main(arguments) == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert target.read_bytes() == destination.read_bytes() == original
    offline.assert_not_called()


@pytest.mark.parametrize("operation", ["resolve", "stat", "samefile"])
def test_unselected_path_comparison_errors_fail_closed(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mixed(tmp_path)
    target = write(tmp_path / "bun.lockb", "binary, unselected")
    write(tmp_path / "bun.lock", '{"lockfileVersion":1}')
    destination = write(tmp_path / "report.json", "preserve report")
    original: Callable[..., Any] = getattr(Path, operation)

    def denied(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == target or (operation == "samefile" and args == (target,)):
            raise PermissionError("injected protected-path comparison failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, operation, denied)
    assert main([str(tmp_path), "--json", str(destination)]) == 2
    assert "invalid JSON output path" in capsys.readouterr().err
    assert destination.read_text() == "preserve report"
    offline.assert_not_called()


@pytest.mark.parametrize(
    "state", ["absent", "empty", "failed", "ambiguous", "failed-hint"]
)
def test_zero_inventory_states_are_distinct(
    tmp_path: Path,
    offline: Mock,
    state: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write(tmp_path / "requirements.txt", "")
    if state != "absent":
        write(tmp_path / "package.json", "{" if state == "failed" else "{}")
    if state in {"ambiguous", "failed-hint"}:
        write(tmp_path / "package-lock.json", '{"lockfileVersion":3,"packages":{}}')
        write(tmp_path / "yarn.lock", "# yarn lockfile v1\n")
        if state == "failed-hint":
            write(tmp_path / "package.json", "{")
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == (0 if state in {"absent", "empty"} else 2)
    assert not report.results
    assert report.detected_ecosystems == (
        ("PyPI",) if state == "absent" else ("PyPI", "npm")
    )
    assert [item.status for item in report.sources] == [
        "success",
        {"empty": "success", "failed-hint": "failed"}.get(state, state),
    ]
    summary = report.sources[1]
    assert (summary.source is not None) == (state in {"empty", "failed"})
    assert len(report.errors) == (0 if code == 0 else 1)
    if report.errors:
        assert report.errors[0].ecosystem == "npm"
        assert report.errors[0].source is not None
    captured = capsys.readouterr()
    assert "PyPI dependency source: selected" in captured.err
    assert "npm dependency source:" in captured.err
    offline.assert_not_called()


def test_nested_sources_are_not_detected(tmp_path: Path, offline: Mock) -> None:
    mixed(tmp_path / "nested")
    write(
        tmp_path / "node_modules/hidden/package.json",
        '{"dependencies":{"wrong":"1.2.3"}}',
    )
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 2 and report.detected_ecosystems == ()
    assert [item.status for item in report.sources] == ["absent", "absent"]
    assert len(report.errors) == 1 and report.errors[0].ecosystem is None
    assert not report.input_paths
    offline.assert_not_called()


@pytest.mark.parametrize(
    "filename,document",
    [
        ("requirements.txt", ""),
        ("pyproject.toml", "[project]\ndependencies=[]\n"),
        ("uv.lock", "package=[]\n"),
        ("poetry.lock", "package=[]\n"),
        ("Pipfile.lock", '{"default":{},"develop":{}}'),
        ("package.json", "{}"),
        *[
            (
                name,
                json.dumps(
                    {"lockfileVersion": version, "dependencies": {}}
                    if version == 1
                    else {"lockfileVersion": version, "packages": {}}
                ),
            )
            for name in ("package-lock.json", "npm-shrinkwrap.json")
            for version in (1, 2, 3)
        ],
        ("yarn.lock", "# yarn lockfile v1\n"),
        *[
            ("yarn.lock", f"__metadata:\n  version: {version}\n")
            for version in (4, 6, 8, 10)
        ],
        *[
            ("pnpm-lock.yaml", f"lockfileVersion: '{version}'\npackages: {{}}\n")
            for version in ("6.0", "9.0")
        ],
        ("bun.lock", '{"lockfileVersion":1,"workspaces":{"":{}},"packages":{}}'),
    ],
)
def test_each_reader_exports_honest_empty_success(
    tmp_path: Path,
    offline: Mock,
    filename: str,
    document: str,
) -> None:
    source = write(tmp_path / filename, document)
    code, report = export(tmp_path, tmp_path / "report.json")
    ecosystem = "PyPI" if filename in PYTHON_FILES else "npm"
    assert code == 0 and not report.results and not report.errors
    assert report.detected_ecosystems == (ecosystem,)
    summary = next(item for item in report.sources if item.ecosystem == ecosystem)
    assert summary.status == "success"
    assert summary.source is not None and summary.source.path == source
    assert source in report.input_paths
    offline.assert_not_called()


@pytest.mark.parametrize(
    "filename,document",
    [
        (
            "uv.lock",
            '[[package]]\nname="demo"\nversion="1.2.3"\nsource={registry="https://pypi.org/simple"}\n',
        ),
        (
            "poetry.lock",
            '[[package]]\nname="demo"\nversion="1.2.3"\noptional=true\n'
            'markers="python_version < \'0\'"\n',
        ),
        (
            "Pipfile.lock",
            '{"default":{},"develop":{},"custom":{"demo":{"version":"==1.2.3",'
            '"markers":"python_version < \'0\'"}}}',
        ),
    ],
)
def test_python_lock_inventory_and_precedence_remain_independent_of_npm(
    tmp_path: Path,
    offline: Mock,
    filename: str,
    document: str,
) -> None:
    source = write(tmp_path / filename, document)
    write(tmp_path / "requirements.txt", "must-not-query==9\n")
    write(tmp_path / "package.json", '{"dependencies":{"demo":"1.2.3"}}')
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 0
    assert queries(offline) == [("PyPI", "demo", "1.2.3"), ("npm", "demo", "1.2.3")]
    assert report.sources[0].source is not None
    assert report.sources[0].source.path == source
    assert all(
        item.source.path != tmp_path / "requirements.txt" for item in report.results
    )


def test_entry_gaps_keep_usable_siblings_and_never_execute_project_code(
    tmp_path: Path,
    offline: Mock,
) -> None:
    write(tmp_path / "requirements.txt", "demo==1.2.3\n-e ./local\n")
    write(
        tmp_path / "package.json",
        json.dumps(
            {
                "scripts": {"preinstall": "touch should-never-exist"},
                "dependencies": {
                    "demo": "1.2.3",
                    "local": "file:./member",
                    "range": "^1",
                },
            }
        ),
    )
    write(
        tmp_path / "member/package.json", '{"dependencies":{"must-not-query":"1.0.0"}}'
    )
    offline.return_value = response(advisory("KEPT-1"))
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 2
    assert queries(offline) == [("PyPI", "demo", "1.2.3"), ("npm", "demo", "1.2.3")]
    assert [item.status for item in report.sources] == ["success", "success"]
    assert len(scanned(report)) == 2
    assert len([item for item in report.results if item.status == "unscanned"]) == 3
    assert {item.ecosystem for item in report.errors} == {"PyPI", "npm"}
    assert not (tmp_path / "should-never-exist").exists()


def test_punctuation_normalization_stays_ecosystem_specific(
    tmp_path: Path,
    offline: Mock,
) -> None:
    write(
        tmp_path / "requirements.txt",
        "Demo_Package.Name==1.2.3\ndemo-package-name==1.2.3\n",
    )
    write(
        tmp_path / "package.json",
        json.dumps(
            {
                "dependencies": {
                    "demo_package.name": "v1.2.3",
                    "demo-package-name": "1.2.3",
                    "@scope/alias": "npm:@scope/real@1.2.3-beta.1+build.2",
                }
            }
        ),
    )
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 0
    expected = [
        ("PyPI", "demo-package-name", "1.2.3"),
        ("npm", "demo_package.name", "1.2.3"),
        ("npm", "demo-package-name", "1.2.3"),
        ("npm", "@scope/real", "1.2.3-beta.1+build.2"),
    ]
    assert queries(offline) == expected
    assert len(report.results) == 5
    assert {item.package.identity for item in scanned(report)} == set(expected)


@pytest.mark.parametrize(
    "filename", ["requirements.txt", "dependencies.in", "pyproject.toml"]
)
@pytest.mark.parametrize("directory", [False, True])
def test_explicit_requirements_only_have_scanner_fallback(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    directory: bool,
) -> None:
    site = tmp_path / "synthetic-site"
    write(site / "demo-2.dist-info/METADATA", "Name: demo\nVersion: 2\n")
    monkeypatch.setattr(sys, "path", [str(site)])
    declaration = "demo>=1,<3"
    source = write(
        tmp_path / filename,
        f'[project]\ndependencies=["{declaration}"]'
        if filename == "pyproject.toml"
        else declaration,
    )
    if directory and filename == "dependencies.in":
        # Arbitrary filenames are explicit-only, not new discovery candidates.
        write(tmp_path / "requirements.txt", "-r dependencies.in\n")
    write(tmp_path / "package.json", '{"dependencies":{"npm-only":"1.2.3"}}')
    code, report = export(
        tmp_path if directory else source, tmp_path / "report.json", "--no-cache"
    )
    fallback = not directory and filename != "pyproject.toml"
    assert code == (0 if fallback else 2)
    expected = [("PyPI", "demo", "2")] if fallback else []
    if directory:
        expected.append(("npm", "npm-only", "1.2.3"))
    assert queries(offline) == expected
    assert (site / "demo-2.dist-info/METADATA" in report.input_paths) == fallback
    assert report.sources[0].status == "success"  # unresolved is entry-level.


@pytest.mark.parametrize(
    "site_layout", ["lib/python3.14/site-packages", "Lib/site-packages"]
)
def test_venv_includes_markers_and_js_ranges_do_not_leak_environment(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    site_layout: str,
) -> None:
    venv = tmp_path / "env"
    write(venv / "pyvenv.cfg", "")
    write(venv / site_layout / "demo-2.dist-info/METADATA", "Name: demo\nVersion: 2\n")
    write(tmp_path / "requirements.txt", "-r nested/base.in\n")
    include = write(
        tmp_path / "nested/base.in",
        'demo>=1,<3\ndemo<2\nmissing; python_version < "0"\n',
    )
    write(tmp_path / "package.json", '{"dependencies":{"demo":"^2","exact":"1.2.3"}}')
    write(
        tmp_path / "node_modules/demo/package.json", '{"name":"demo","version":"2.0.0"}'
    )

    def forbidden_host(*args: object, **kwargs: object) -> Any:
        pytest.fail("Selected venv/JS must not use scanner metadata")

    monkeypatch.setattr(metadata, "version", forbidden_host)
    code, report = export(tmp_path, tmp_path / "report.json", "--venv", str(venv))
    assert code == 2
    assert queries(offline) == [("PyPI", "demo", "2"), ("npm", "exact", "1.2.3")]
    python = [item for item in report.results if item.ecosystem == "PyPI"]
    assert [item.status for item in python] == [
        "no_known_vulnerabilities",
        "unscanned",
        "non_applicable",
    ]
    assert [item.source.line for item in python] == [1, 2, 3]
    assert all(item.source.path == include for item in python)
    assert len(report.errors) == 2
    assert not any("node_modules" in str(path) for path in report.input_paths)


@pytest.mark.parametrize("mode", ["mixed", "directory-js", "explicit-js"])
def test_invalid_venv_only_affects_python(
    tmp_path: Path, offline: Mock, mode: str
) -> None:
    source = write(tmp_path / "package.json", '{"dependencies":{"demo":"1.2.3"}}')
    if mode == "mixed":
        write(tmp_path / "requirements.txt", "python-only==1\n")
    offline.return_value = response(advisory("JS-1"))
    code, report = export(
        source if mode == "explicit-js" else tmp_path,
        tmp_path / "report.json",
        "--venv",
        str(tmp_path / "missing-env"),
    )
    assert code == (2 if mode == "mixed" else 1)
    assert queries(offline) == [("npm", "demo", "1.2.3")]
    assert [item.status for item in report.sources] == (
        ["failed", "success"]
        if mode == "mixed"
        else ["absent", "success"]
        if mode == "directory-js"
        else ["success"]
    )


@pytest.mark.parametrize(
    "fixture,filename,identities",
    [
        (
            "yarn/wrappers.lock",
            "yarn.lock",
            {
                ("@scope/real", "1.2.3"),
                ("virtual-example", "2.0.0"),
                ("@strictsoftware/typedoc-plugin-monorepo", "0.2.2"),
                ("nested", "1.0.0"),
            },
        ),
        (
            "pnpm/contexts.yaml",
            "pnpm-lock.yaml",
            {
                ("real", "1.2.3"),
                ("real", "1.2.4"),
                ("@scope/real", "2.0.0"),
                ("peer", "3.0.0"),
                ("foo", "1.2.3-beta.1+build.2"),
            },
        ),
    ],
)
def test_inventory_wrappers_keep_identity_and_visible_gaps(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    filename: str,
    identities: set[tuple[str, str]],
) -> None:
    write(tmp_path / "requirements.txt", "python-only==1\n")
    (tmp_path / filename).write_bytes((FIXTURES / fixture).read_bytes())
    forbidden = write(tmp_path / "packages/member/package.json", "must not read")
    read_text = Path.read_text

    def guarded(path: Path, *args: Any, **kwargs: Any) -> str:
        if path == forbidden or ".patch" in path.suffix:
            pytest.fail(f"Nested manifests/patches must not be opened: {path}")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 2
    assert set(queries(offline)) == {
        ("PyPI", "python-only", "1"),
        *(("npm", name, version) for name, version in identities),
    }
    assert len(queries(offline)) == len(identities) + 1
    assert [item.status for item in report.sources] == ["success", "success"]
    assert any(
        item.status == "unscanned" and "patch" in item.reason.lower()
        for item in report.results
    )
    assert any(
        item.status == "unscanned" and "workspace" in item.reason.lower()
        for item in report.results
    )
    assert forbidden not in report.input_paths
    if filename == "pnpm-lock.yaml":
        assert sum(item.package.name == "@scope/real" for item in scanned(report)) >= 2


@pytest.mark.parametrize(
    "document",
    [
        "lockfileVersion: '9.0'\n? [a, {b: c}]\n: value\n",
        "lockfileVersion: '9.0'\npackages:\n  ? [a, {b: c}]\n  : value\n",
    ],
)
def test_pnpm_loader_type_error_is_a_source_failure_not_traceback(
    tmp_path: Path,
    offline: Mock,
    document: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write(tmp_path / "requirements.txt", "demo==1.2.3\n")
    source = write(tmp_path / "pnpm-lock.yaml", document)
    offline.return_value = response(advisory("PYTHON-1"))
    code, report = export(tmp_path, tmp_path / "report.json")
    assert code == 2 and queries(offline) == [("PyPI", "demo", "1.2.3")]
    assert len(report.results) == len(report.errors) == 1
    assert report.errors[0].ecosystem == "npm"
    assert report.sources[1].status == "failed"
    assert (
        report.sources[1].source is not None and report.sources[1].source.path == source
    )
    assert "Traceback" not in capsys.readouterr().out


def test_failed_atomic_export_preserves_previous_report(
    tmp_path: Path,
    offline: Mock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mixed(tmp_path)
    destination = write(tmp_path / "report.json", "previous complete export")
    before = set(tmp_path.iterdir())
    replace = os.replace

    def fail_report(source: Path, target: Path) -> None:
        if target == destination:
            raise OSError("injected atomic report replacement failure")
        replace(source, target)

    monkeypatch.setattr("depscan.report.os.replace", fail_report)
    assert main([str(tmp_path), "--no-cache", "--json", str(destination)]) == 2
    assert destination.read_text() == "previous complete export"
    assert set(tmp_path.iterdir()) == before
    assert len(queries(offline)) == 2
    captured = capsys.readouterr()
    assert "Cannot write JSON report" in captured.err
    assert "Error [global]" in captured.out and "Scan incomplete." in captured.out
