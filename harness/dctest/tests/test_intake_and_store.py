"""Run intake → store layout sanity."""

from __future__ import annotations

import subprocess

from dctest.services import intake, run_store


def _is_git_repo(path) -> bool:
    try:
        subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


def test_create_run_writes_canonical_layout(tmp_path, isolated_runs_root):
    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "test@dctest"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "dctest"], check=True)
    (work / "hello.txt").write_text("hi", encoding="utf-8")
    subprocess.run(["git", "-C", str(work), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-q", "-m", "seed"],
        check=True,
        env={"GIT_AUTHOR_NAME": "dctest", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "dctest", "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(tmp_path)},
    )
    assert _is_git_repo(work)
    run = intake.create_run(slug="dctest-itest", worktree=work, backend="manual")
    assert run.target_head_sha != "unknown"
    assert (isolated_runs_root / run.slug / "run.json").exists()
    assert (isolated_runs_root / run.slug / "host_info.json").exists()
    reloaded = run_store.load_run(isolated_runs_root, run.slug)
    assert reloaded.slug == run.slug
