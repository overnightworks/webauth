from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "publish_release.sh"
TOOLS = (
    "git",
    "sh",
    "bash",
    "sed",
    "grep",
    "cat",
    "rm",
    "mktemp",
    "dirname",
    "wc",
    "tr",
    "head",
    "env",
)

GH_STUB = r"""#!/usr/bin/env bash
# Answer files: SEQUENCE__WORKFLOW__COMMIT__BRANCH, one line per query, the last repeats.
# Like gh, a filter given narrows the runs and the newest remaining run answers.
if [[ "$1 $2" == "auth status" ]]; then
  [[ -e "$STUB_DIR/not-logged-in" ]] && { echo "not logged in" >&2; exit 1; }
  exit 0
fi
[[ "$1 $2" == "run list" ]] || { echo "unexpected: $*" >&2; exit 2; }
while (($#)); do
  case "$1" in
    --workflow) workflow="$2" ;;
    --commit) commit="$2" ;;
    --branch) branch="$2" ;;
  esac
  shift
done
answers=""
for candidate in "$STUB_DIR"/answers/*__"${workflow%.yml}"__*; do
  [[ -e "$candidate" && "$candidate" != *.queries ]] || continue
  read -r _ _ file_commit file_branch <<<"$(echo "${candidate##*/}" | sed 's/__/ /g')"
  [[ -z "${commit:-}" || "$file_commit" == "$commit" ]] || continue
  [[ -z "${branch:-}" || "$file_branch" == "$branch" ]] || continue
  answers="$candidate"
done
[[ -n "$answers" ]] || exit 0
queries=$(($(cat "$answers.queries" 2>/dev/null || echo 0) + 1))
echo "$queries" >"$answers.queries"
total=$(wc -l <"$answers")
line=$(sed -n "$((queries < total ? queries : total))p" "$answers")
line=$(echo -e "$line")
if [[ "$line" == ERROR* ]]; then
  echo "${line#ERROR }" >&2
  exit 1
fi
echo "$line"
"""

SLEEP_STUB = r"""#!/usr/bin/env bash
echo "$1" >>"$STUB_DIR/sleeps"
if [[ -e "$STUB_DIR/on-sleep" ]]; then
  hook=$(cat "$STUB_DIR/on-sleep")
  rm "$STUB_DIR/on-sleep"
  eval "$hook"
fi
# A wait that never ends is cut here, with the script as its parent.
(($(wc -l <"$STUB_DIR/sleeps") > 6)) && kill -TERM "$PPID"
exit 0
"""

VERIFY_STUB = """#!/usr/bin/env bash
echo "$1" >>"$STUB_DIR/verified"
"""

CONFIG_LINES = (
    "user.name=Tester",
    "user.email=tester@example.test",
    "commit.gpgsign=false",
    "tag.gpgsign=false",
)


@dataclass
class Release:
    root: Path
    work: Path
    origin: Path
    environment: dict[str, str]
    version: str = "1.2.3"
    run_url: str = "https://example.test/runs/11"

    @property
    def tag(self) -> str:
        return f"v{self.version}"

    def run_line(self, status: str, run_id: int = 11) -> str:
        return f"{run_id} {status} {self.run_url}"

    @property
    def success(self) -> str:
        return self.run_line("completed success")

    @property
    def failure(self) -> str:
        return self.run_line("completed failure")

    def git(self, *arguments: str, cwd: Path | None = None) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=cwd or self.work,
            env=self.environment,
            capture_output=True,
            text=True,
            check=True,
        )
        return completed.stdout.strip()

    def commit(self, name: str, cwd: Path | None = None) -> str:
        (cwd or self.work).joinpath(name).write_text(name)
        self.git("add", name, cwd=cwd)
        self.git("commit", "-m", name, cwd=cwd)
        return self.git("rev-parse", "HEAD", cwd=cwd)

    def answer(
        self, workflow: str, commit: str, *lines: str, branch: str | None = None
    ) -> None:
        answers = self.root / "stub" / "answers"
        answers.mkdir(exist_ok=True)
        branch = branch or ("main" if workflow == "ci" else self.tag)
        sequence = len(list(answers.iterdir()))
        (answers / f"{sequence:03d}__{workflow}__{commit}__{branch}").write_text(
            "\n".join(lines) + "\n"
        )

    def on_sleep(self, script: str) -> None:
        (self.root / "stub" / "on-sleep").write_text(script)

    def publish(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.work / "scripts" / "publish_release.sh"), *arguments],
            cwd=self.work,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def origin_tags(self) -> list[str]:
        return self.git("tag", "--list", cwd=self.origin).split()

    def local_tags(self) -> list[str]:
        return self.git("tag", "--list").split()

    def sleeps(self) -> list[int]:
        recorded = self.root / "stub" / "sleeps"
        return [int(line) for line in recorded.read_text().split()] if recorded.exists() else []

    def verified(self) -> list[str]:
        recorded = self.root / "stub" / "verified"
        return recorded.read_text().split() if recorded.exists() else []

    @property
    def main_commit(self) -> str:
        return self.git("rev-parse", "main")


@pytest.fixture
def release(tmp_path: Path) -> Release:
    stub = tmp_path / "stub"
    tools = tmp_path / "tools"
    for directory in (stub, tools, tmp_path / "home"):
        directory.mkdir()
    for tool in TOOLS:
        (tools / tool).symlink_to(shutil.which(tool) or tool)
    for name, body in (("gh", GH_STUB), ("sleep", SLEEP_STUB)):
        (tools / name).write_text(body)
        (tools / name).chmod(0o755)
    environment = {
        "PATH": str(tools),
        "HOME": str(tmp_path / "home"),
        "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": str(len(CONFIG_LINES)),
        "STUB_DIR": str(stub),
    }
    for index, line in enumerate(CONFIG_LINES):
        key, value = line.split("=")
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    origin, work = tmp_path / "origin.git", tmp_path / "work"
    arrangement = Release(tmp_path, work, origin, environment)
    arrangement.git("init", "--bare", "--initial-branch=main", str(origin), cwd=tmp_path)
    arrangement.git("init", "--initial-branch=main", str(work), cwd=tmp_path)
    arrangement.git("remote", "add", "origin", str(origin))
    package = work / "src" / "webauth"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(f'__version__ = "{arrangement.version}"\n')
    (work / "scripts").mkdir()
    shutil.copy(SCRIPT, work / "scripts" / "publish_release.sh")
    verify = work / "scripts" / "verify_release.sh"
    verify.write_text(VERIFY_STUB)
    verify.chmod(0o755)
    arrangement.git("add", ".")
    arrangement.git("commit", "-m", "initial")
    arrangement.git("push", "-u", "origin", "main")
    return arrangement


def release_on_green_ci(release: Release) -> str:
    commit = release.main_commit
    release.answer("ci", commit, release.success)
    return commit


def push_from_another_clone(release: Release) -> None:
    other = release.root / "other"
    release.git("clone", str(release.origin), str(other), cwd=release.root)
    release.commit("elsewhere", cwd=other)
    release.git("push", "origin", "main", cwd=other)


def set_up_dirty_tree(release: Release) -> None:
    (release.work / "scripts" / "verify_release.sh").write_text("changed\n")


def set_up_local_main_ahead(release: Release) -> None:
    release.commit("ahead")


def set_up_origin_main_ahead(release: Release) -> None:
    push_from_another_clone(release)


def set_up_other_branch(release: Release) -> None:
    release.git("switch", "-c", "feature")


def set_up_tag_on_origin(release: Release) -> None:
    release.git("tag", "-a", release.tag, "-m", "old")
    release.git("push", "origin", f"refs/tags/{release.tag}")


def set_up_tag_only_local(release: Release) -> None:
    release.git("tag", "-a", release.tag, "-m", "old")


def set_up_not_logged_in(release: Release) -> None:
    (release.root / "stub" / "not-logged-in").write_text("")


def set_up_gh_missing(release: Release) -> None:
    (release.root / "tools" / "gh").unlink()


@pytest.mark.parametrize(
    ("arguments", "set_up", "cause"),
    [
        ("", None, "vMAJOR.MINOR.PATCH"),
        ("{tag} extra", None, "vMAJOR.MINOR.PATCH"),
        ("{version}", None, "vMAJOR.MINOR.PATCH"),
        ("v1.2", None, "vMAJOR.MINOR.PATCH"),
        ("{tag}-rc1", None, "vMAJOR.MINOR.PATCH"),
        ("v1.2.4", None, "{version}"),
        ("{tag}", set_up_other_branch, "main"),
        ("{tag}", set_up_dirty_tree, "clean"),
        ("{tag}", set_up_local_main_ahead, "origin/main"),
        ("{tag}", set_up_origin_main_ahead, "origin/main"),
        ("{tag}", set_up_tag_on_origin, "origin"),
        ("{tag}", set_up_tag_only_local, "git tag -d {tag}"),
        ("{tag}", set_up_gh_missing, "gh"),
        ("{tag}", set_up_not_logged_in, "gh"),
    ],
)
def test_publish_refuses_before_any_tag(
    release: Release, arguments: str, set_up, cause: str
) -> None:
    release_on_green_ci(release)
    if set_up:
        set_up(release)
    local_tags_before = release.local_tags()
    origin_tags_before = release.origin_tags()
    values = {"tag": release.tag, "version": release.version}

    result = release.publish(*arguments.format(**values).split())

    assert result.returncode == 1
    assert result.stderr.startswith("publish_release: ")
    assert result.stderr.count("\n") == 1
    assert cause.format(**values) in result.stderr
    assert release.local_tags() == local_tags_before
    assert release.origin_tags() == origin_tags_before


@pytest.mark.parametrize(
    ("answers", "cause"),
    [
        (["{url_failure}"], "{url}"),
        (["11 completed cancelled {url}"], "gh run rerun 11"),
        (["ERROR api exploded"], "api exploded"),
        (["not a run"], "not a run"),
        (["11 completed success {url}\\nsurplus"], "surplus"),
        (["11 sleeping - {url}"], "11 sleeping"),
    ],
)
def test_publish_refuses_when_ci_did_not_succeed(
    release: Release, answers: list[str], cause: str
) -> None:
    values = {"url": release.run_url, "url_failure": release.failure}
    release.answer("ci", release.main_commit, *(a.format(**values) for a in answers))

    result = release.publish(release.tag)

    assert result.returncode == 1
    assert cause.format(**values) in result.stderr
    assert release.local_tags() == []
    assert release.origin_tags() == []


def test_publish_never_reads_success_for_another_commit(release: Release) -> None:
    release.answer("ci", "0" * 40, release.success)

    result = release.publish(release.tag)

    assert result.returncode != 0
    assert len(release.sleeps()) > 1
    assert release.local_tags() == []
    assert release.origin_tags() == []


def test_publish_waits_for_a_missing_run_then_tags_the_recorded_commit(release: Release) -> None:
    commit = release.main_commit
    release.answer("ci", commit, "", "", release.run_line("in_progress -", 12), release.success)
    release.answer("release", commit, "", release.success)
    release.answer("release", commit, release.failure, branch="v9.9.9")
    release.on_sleep(
        "echo moved > moved && git add moved && git commit -q -m moved\n"
    )

    result = release.publish(release.tag)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == "verified"
    assert release.verified() == [release.tag]
    assert release.origin_tags() == [release.tag]
    assert release.main_commit != commit
    assert release.git("rev-parse", f"{release.tag}^{{commit}}", cwd=release.origin) == commit
    assert len(release.sleeps()) == 4
    assert min(release.sleeps()) >= 60


def test_publish_pushes_only_its_tag_and_keeps_it_when_release_run_fails(release: Release) -> None:
    commit = release_on_green_ci(release)
    release.answer("release", commit, release.failure)
    release.git("tag", "-a", "stray", "-m", "stray")
    release.git("config", "push.followTags", "true")

    result = release.publish(release.tag)

    assert result.returncode == 1
    assert release.run_url in result.stderr
    assert release.origin_tags() == [release.tag]
    assert release.git("rev-parse", f"{release.tag}^{{commit}}", cwd=release.origin) == commit
    assert release.tag in release.local_tags()
    assert release.verified() == []


def test_publish_deletes_its_local_tag_when_the_push_fails(release: Release) -> None:
    release_on_green_ci(release)
    hook = release.origin / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho rejected by origin >&2\nexit 1\n")
    hook.chmod(0o755)

    result = release.publish(release.tag)

    assert result.returncode == 1
    assert "rejected by origin" in result.stderr
    assert release.local_tags() == []
    assert release.origin_tags() == []
