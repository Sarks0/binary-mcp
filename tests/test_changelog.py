"""Tests for scripts/changelog.py, run against a real throwaway git repository.

The generator's whole job is turning git history into Markdown, so the tests
build real history rather than mocking git: a fake would only prove the code
agrees with the fake.
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "changelog.py"
REPO_URL = "https://github.com/Sarks0/binary-mcp"


def load_changelog_module():
    spec = importlib.util.spec_from_file_location("changelog_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


changelog = load_changelog_module()


class Repo:
    """A scratch repository with a fixed clock, so tag dates are predictable."""

    def __init__(self, path: Path):
        self.path = path
        self.day = 0
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Maintainer")
        self.git("config", "user.email", "maintainer@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")

    def git(self, *args: str) -> str:
        date = f"2026-01-{max(self.day, 1):02d}T12:00:00Z"
        env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        return subprocess.run(
            ["git", *args], cwd=self.path, env=env, check=True, capture_output=True, text=True
        ).stdout

    def commit(
        self,
        message: str,
        author: str = "Maintainer <maintainer@example.invalid>",
        files: tuple[str, ...] = (),
    ):
        self.day += 1
        for name in files:
            (self.path / name).write_text(f"changed on day {self.day}\n", encoding="utf-8")
            self.git("add", name)
        message_file = self.path.parent / f"message-{self.day}.txt"
        message_file.write_text(message, encoding="utf-8")
        self.git("commit", "-q", "--allow-empty", "--author", author, "-F", str(message_file))

    def tag(self, name: str):
        self.git("tag", name)


DEPENDABOT = "dependabot[bot] <support@github.com>"


@pytest.fixture
def repo(tmp_path):
    work = tmp_path / "repo"
    work.mkdir()
    return Repo(work)


def run(repo: Repo, *args: str, capsys) -> tuple[int, str, str]:
    code = changelog.main(["--repo", str(repo.path), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_release_candidates_sort_below_their_release():
    names = ["v1.3.0", "v1.3.0-rc2", "v1.2.9", "v1.3.0-rc10", "v1.10.0", "not-a-release"]
    keyed = [name for name in names if changelog.version_key(name) is not None]
    ordered = sorted(keyed, key=changelog.version_key)
    assert ordered == ["v1.2.9", "v1.3.0-rc2", "v1.3.0-rc10", "v1.3.0", "v1.10.0"]


def test_full_release_lists_everything_since_the_last_full_release(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Add the first feature (#1)")
    repo.tag("v1.1.0-rc1")
    repo.commit("Fix what the candidate found (#2)")
    repo.tag("v1.1.0")

    code, out, _ = run(repo, "notes", "v1.1.0", capsys=capsys)

    assert code == 0
    # The candidate's change belongs to the release that shipped it, so the
    # range runs from v1.0.0 and not from v1.1.0-rc1.
    assert f"- Add the first feature ([#1]({REPO_URL}/pull/1))" in out
    assert f"- Fix what the candidate found ([#2]({REPO_URL}/pull/2))" in out
    assert "Initial commit" not in out
    assert f"Full diff: [v1.0.0...v1.1.0]({REPO_URL}/compare/v1.0.0...v1.1.0)" in out


def test_prerelease_notes_cover_only_what_changed_since_the_previous_tag(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Add the first feature (#1)")
    repo.tag("v1.1.0-rc1")
    repo.commit("Fix what the candidate found (#2)")
    repo.tag("v1.1.0-rc2")

    _, out, _ = run(repo, "notes", "v1.1.0-rc2", capsys=capsys)

    assert "Fix what the candidate found" in out
    assert "Add the first feature" not in out


def test_patch_on_an_older_line_compares_against_that_line(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Ship the next minor (#1)")
    repo.tag("v1.1.0")
    repo.git("switch", "-q", "-c", "maint-1.0", "v1.0.0")
    repo.commit("Backport a fix (#2)")
    repo.tag("v1.0.1")

    _, out, _ = run(repo, "notes", "v1.0.1", capsys=capsys)

    assert "Backport a fix" in out
    assert "Ship the next minor" not in out
    assert "v1.0.0...v1.0.1" in out


def test_breaking_footers_are_collected_and_prose_mentions_are_not(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit(
        "Rename the tools (#1)\n\n"
        "The old names were inconsistent. BREAKING: this sentence only describes it.\n\n"
        "BREAKING CHANGE: every tool name changed, and a client that\n"
        "  hardcodes one must update it.\n"
        "Co-Authored-By: Someone <someone@example.invalid>\n"
    )
    repo.commit("Drop the legacy flag (#2)\n\nBREAKING: --legacy is gone.\n")
    repo.commit("Drop it again (#3)\n\nBREAKING-CHANGE: --legacy is gone.\n")
    repo.commit("Restate it (#4)\n\nBREAKING: --legacy is gone.\n")
    repo.tag("v2.0.0")

    _, out, _ = run(repo, "notes", "v2.0.0", capsys=capsys)

    breaking = out.split("## Breaking changes\n\n", 1)[1].split("\n\n", 1)[0]
    assert breaking.splitlines() == [
        "- --legacy is gone.",
        "- every tool name changed, and a client that hardcodes one must update it.",
    ]
    assert "this sentence only describes it" not in breaking
    assert "Read these before upgrading." in out


def test_no_breaking_section_without_a_breaking_footer(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")

    _, out, _ = run(repo, "notes", "v1.0.0", capsys=capsys)

    assert "Breaking changes" not in out
    # Nothing came before the first release, so there is nothing to diff against.
    assert "Full diff" not in out


def test_dependabot_bumps_collapse_to_one_line_in_pr_order(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("chore(deps): bump ruff (#7)", author=DEPENDABOT)
    repo.commit("Add a feature (#6)")
    repo.commit("ci(deps): bump actions/checkout from 4 to 7 (#5)", author=DEPENDABOT)
    repo.tag("v1.1.0")

    _, out, _ = run(repo, "notes", "v1.1.0", capsys=capsys)

    assert "bump" not in out
    assert (
        f"- Dependency updates from Dependabot: [#5]({REPO_URL}/pull/5), [#7]({REPO_URL}/pull/7)"
    ) in out
    assert "- Add a feature" in out


def test_a_commit_without_a_pr_links_to_the_commit(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Pushed straight to main")
    repo.tag("v1.0.1")
    sha = repo.git("rev-parse", "HEAD").strip()

    _, out, _ = run(repo, "notes", "v1.0.1", capsys=capsys)

    assert f"- Pushed straight to main ([{sha[:7]}]({REPO_URL}/commit/{sha}))" in out


def test_changelog_has_a_section_per_full_release_and_none_per_candidate(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Add the first feature (#1)")
    repo.tag("v1.1.0-rc1")
    repo.commit("Fix what the candidate found (#2)")
    repo.tag("v1.1.0")
    repo.commit("Unreleased work (#3)")

    code, out, _ = run(repo, "changelog", capsys=capsys)

    assert code == 0
    assert out.startswith("# Changelog\n")
    assert "Do not edit by hand" in out
    headings = [line for line in out.splitlines() if line.startswith("## ")]
    assert headings == ["## v1.1.0 - 2026-01-03", "## v1.0.0 - 2026-01-01"]
    assert "### Changes" in out
    assert "Add the first feature" in out
    assert "Unreleased work" not in out
    assert out.endswith(")\n") and not out.endswith("\n\n")


def test_changelog_output_file_is_written_with_unix_newlines(repo, tmp_path, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    target = tmp_path / "CHANGELOG.md"

    code, out, _ = run(repo, "changelog", "--output", str(target), capsys=capsys)

    assert code == 0
    assert out == ""
    assert b"\r\n" not in target.read_bytes()
    assert "## v1.0.0" in target.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("tag", "message"),
    [
        ("v9.9.9", "tag v9.9.9 does not exist"),
        ("latest", "latest is not a release tag"),
    ],
)
def test_an_unknown_tag_fails_loudly(repo, capsys, tag, message):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")

    code, out, err = run(repo, "notes", tag, capsys=capsys)

    assert code == 1
    assert out == ""
    assert message in err


def test_a_footer_line_starting_with_a_url_is_not_a_trailer(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit(
        "Move the config (#1)\n\n"
        "BREAKING CHANGE: the config file moved, see\n"
        "https://example.invalid/install for the new location.\n"
        "Signed-off-by: Maintainer <maintainer@example.invalid>\n"
    )
    repo.tag("v2.0.0")

    _, out, _ = run(repo, "notes", "v2.0.0", capsys=capsys)

    assert (
        "- the config file moved, see https://example.invalid/install for the new location."
    ) in out
    assert "Signed-off-by" not in out


def test_the_commit_that_writes_the_changelog_is_not_listed(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Add a feature (#1)", files=("feature.py",))
    repo.commit("Prepare 1.1.0 (#2)", files=("CHANGELOG.md", "version.txt"))
    repo.tag("v1.1.0")

    _, out, _ = run(repo, "notes", "v1.1.0", capsys=capsys)

    assert "- Add a feature" in out
    assert "Prepare 1.1.0" not in out


def test_next_describes_the_branch_head_as_the_coming_release(repo, capsys):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")
    repo.commit("Add a feature (#1)")
    repo.git("switch", "-q", "-c", "release-prep")
    repo.commit("Unmerged release-prep work")

    code, out, err = run(repo, "changelog", "--next", "v1.1.0", "--head", "main", capsys=capsys)

    assert code == 0, err
    headings = [line for line in out.splitlines() if line.startswith("## ")]
    assert headings[0].startswith("## v1.1.0 - ")
    assert headings[1] == "## v1.0.0 - 2026-01-01"
    # --head is main as merged, so the release branch's own commits are not in it.
    assert "- Add a feature" in out
    assert "Unmerged release-prep work" not in out
    assert "v1.0.0...v1.1.0" in out


@pytest.mark.parametrize(
    ("version", "head", "message"),
    [
        ("v1.0.0", "main", "v1.0.0 is already tagged"),
        ("v0.9.0", "main", "is below the newest release, v1.0.0"),
        ("v1.1.0-rc1", "main", "is not a full release version"),
        ("v1.1.0", "no-such-branch", "--head no-such-branch is not a commit"),
    ],
)
def test_next_refuses_a_version_or_head_that_cannot_be_the_coming_release(
    repo, capsys, version, head, message
):
    repo.commit("Initial commit")
    repo.tag("v1.0.0")

    code, out, err = run(repo, "changelog", "--next", version, "--head", head, capsys=capsys)

    assert code == 1
    assert out == ""
    assert message in err
