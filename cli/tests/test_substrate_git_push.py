"""B2 2.4: the Python mirror of substrate.git.push_branch and git_push."""

from defenseclaw.config import (
    _merge_openshell_admin,
    _merge_substrate_git,
    _sandbox_runtime_keys_error,
)


def test_push_branch_and_git_push_are_mirrored():
    assert _merge_substrate_git({"push_branch": "deny"}).push_branch == "deny"
    assert _merge_substrate_git({}).push_branch == ""
    assert _merge_openshell_admin({"git_push": "ask"}).git_push == "ask"


def test_git_push_values_are_checked():
    assert _sandbox_runtime_keys_error({"git_push": "deny"}, "sandbox") is None
    error = _sandbox_runtime_keys_error({"git_push": "maybe"}, "sandbox")
    assert error and "git_push" in error
