import tomllib
from pathlib import Path


def test_build_excludes_only_generated_local_report() -> None:
    project_root = Path(__file__).resolve().parents[1]
    with (project_root / "pyproject.toml").open("rb") as file:
        config = tomllib.load(file)

    assert config["tool"]["uv"]["build-backend"] == {
        "source-exclude": ["/src/depscan/report.json"]
    }
