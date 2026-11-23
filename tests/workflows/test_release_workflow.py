"""The release build refuses a checkout or a wheel that is not the gated release."""

from __future__ import annotations

import re
import subprocess
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from webauth import __version__

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_RELEASE = _WORKFLOWS / "release.yml"
_WITHIN_STEP = r"(?:(?!      - ).*\n)*?"
_COMMIT_STEP = "Refuse unless the checkout is the commit the gate judged"
_WHEEL_STEP = "Refuse unless the build holds exactly the wheel at the version"
_QUALITY_WORKFLOW = r"overnightworks/quality/\.github/workflows/{}\.yml@(\S+ # v\S+)"


@dataclass(frozen=True)
class _Release:
    """What one release dispatches and the commit the gate judged."""

    version: str = __version__
    gated_commit: str = ""


@pytest.fixture
def release() -> _Release:
    return _Release()


def _distribution() -> str:
    name = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    return name.replace("-", "_")


def _run_script(step_name: str) -> str:
    step = re.search(
        rf"- name: {re.escape(step_name)}\n{_WITHIN_STEP}        run: \|\n((?:          .*\n|\n)+)",
        _RELEASE.read_text(encoding="utf-8"),
    )
    assert step, f"release.yml has no run script for {step_name}"
    return "\n".join(line[10:] for line in step.group(1).splitlines())


def _run_step(
    step_name: str, directory: Path, release: _Release
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", "-e", "-c", _run_script(step_name)],
        cwd=directory,
        env={
            "PATH": "/usr/bin:/bin",
            "VERSION": release.version,
            "COMMIT": release.gated_commit,
        },
        capture_output=True,
        text=True,
        check=False,
    )


def _refused_once(result: subprocess.CompletedProcess[str]) -> bool:
    return (
        result.returncode != 0
        and len(result.stderr.splitlines()) == 1
        and result.stderr.startswith("Refused: ")
    )


def _checkout_head(directory: Path) -> str:
    git_env = {
        "PATH": "/usr/bin:/bin",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    for command in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "head"]):
        subprocess.run(["git", *command], cwd=directory, env=git_env, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=directory,
        env=git_env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.mark.parametrize("gated_is_head", [True, False], ids=["the gated commit", "another commit"])
def test_the_build_must_check_out_the_commit_the_gate_judged(tmp_path, release, gated_is_head):
    head = _checkout_head(tmp_path)
    gated = replace(release, gated_commit=head if gated_is_head else "0" * 40)

    result = _run_step(_COMMIT_STEP, tmp_path, gated)

    assert gated_is_head is (result.returncode == 0)
    assert gated_is_head or _refused_once(result)


@pytest.mark.parametrize(
    ("built_wheels", "dispatched_version", "passes"),
    [
        (("{distribution}-{version}-py3-none-any.whl",), __version__, True),
        (("{distribution}-{version}-py3-none-any.whl",), "9999.0.0", False),
        (
            (
                "{distribution}-{version}-py3-none-any.whl",
                "another-{version}-py3-none-any.whl",
            ),
            __version__,
            False,
        ),
        ((), __version__, False),
        (None, __version__, False),
    ],
    ids=[
        "the expected wheel",
        "another version",
        "a second wheel",
        "no wheel",
        "no dist directory",
    ],
)
def test_the_build_must_hold_exactly_the_wheel_at_the_dispatched_version(
    tmp_path, release, built_wheels, dispatched_version, passes
):
    if built_wheels is not None:
        (tmp_path / "dist").mkdir()
    for name in built_wheels or ():
        wheel = name.format(distribution=_distribution(), version=release.version)
        (tmp_path / "dist" / wheel).touch()

    result = _run_step(_WHEEL_STEP, tmp_path, replace(release, version=dispatched_version))

    assert passes is (result.returncode == 0)
    assert passes or _refused_once(result)


def _jobs() -> dict[str, str]:
    text = _RELEASE.read_text(encoding="utf-8")
    jobs_block = text.split("\njobs:\n", 1)[1]
    return {
        match.group(1): match.group(0)
        for match in re.finditer(r"^  (\w+):\n(?:(?:    .*)?\n)*", jobs_block, re.MULTILINE)
    }


def test_a_release_run_value_never_interpolates_an_expression():
    run_values = re.findall(
        r"^ +run: (.*(?:\n(?: {10}.*|)$)*)", _RELEASE.read_text(encoding="utf-8"), re.MULTILINE
    )

    assert run_values
    assert not [value for value in run_values if "${{" in value]


def test_only_the_tag_job_may_write():
    jobs = _jobs()

    assert [name for name, job in jobs.items() if ": write" in job] == ["tag"]
    assert re.search(r"^permissions: \{\}$", _RELEASE.read_text(encoding="utf-8"), re.MULTILINE)


def _needs(job: str) -> set[str]:
    needs = re.search(r"^    needs: (.*)$", job, re.MULTILINE)
    assert needs
    return set(re.findall(r"\w+", needs.group(1)))


def _value(job: str, key: str) -> str:
    value = re.search(rf"^      {key}: (.*)$", job, re.MULTILINE)
    assert value
    return value.group(1)


def test_the_build_and_the_tag_wait_for_the_jobs_before_them():
    jobs = _jobs()

    assert _needs(jobs["build"]) == {"gate"}
    assert _needs(jobs["tag"]) == {"gate", "build"}


def test_the_tag_lands_on_the_commit_and_version_the_build_verified():
    jobs = _jobs()

    assert _value(jobs["tag"], "commit") == _value(jobs["build"], "COMMIT")
    assert _value(jobs["tag"], "version") == _value(jobs["build"], "VERSION")


def test_a_failed_or_skipped_gate_or_build_skips_the_jobs_after_it():
    jobs = _jobs()

    conditioned = [
        name for name in ("build", "tag") if re.search(r"^    if:", jobs[name], re.MULTILINE)
    ]

    assert conditioned == []


@pytest.mark.parametrize("workflow", ["release-gate", "release-tag"])
def test_each_quality_workflow_is_pinned_where_ci_pins_the_quality_gate(workflow):
    ci_pin = re.search(
        _QUALITY_WORKFLOW.format("gate"), (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    )
    assert ci_pin

    release_pin = re.search(
        _QUALITY_WORKFLOW.format(workflow), _RELEASE.read_text(encoding="utf-8")
    )

    assert release_pin
    assert release_pin.group(1) == ci_pin.group(1)
