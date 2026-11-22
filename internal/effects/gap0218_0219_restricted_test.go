// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// rel-1-0-10 GAP-0218 and GAP-0219: rows where the restricted tier claimed a
// fully known mutation of a protected file that the command never makes (the
// shell never runs the write, or the program rejects the flag and exits).
// Each such row must leave no restricted-eligible effect at the target and
// must not be fully known. The control rows are the same shapes that do write
// the file: they must keep the restricted-eligible claim, so no fix turns a
// real block into an unknown or a clean (no fail-open).

var raMacBSD = func() Options { o := raMac; o.BSDUserland = true; return o }()

const rMacAK = "/Users/u/.ssh/authorized_keys"

// restrictedClaim mirrors the restricted gate of the effect lane
// (gateway.classifyEffects): every token accounted, and a mutation at the
// target whose target and role are known with no reason.
func restrictedClaim(r Result, path string) bool {
	if len(r.Unknowns) != 0 {
		return false
	}
	for _, e := range r.Effects {
		if !isMutation(e.Kind) || e.Target.Type != TargetPath || e.Target.Path != path {
			continue
		}
		if e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown && len(e.Reasons) == 0 {
			return true
		}
	}
	return false
}

type restrictedRow struct {
	id     string
	o      Options
	cmd    string
	target string
	claim  bool // true: the command writes target, the claim must stay
}

var gap0218Rows = []restrictedRow{
	// Execution-suppressing shell state: the write after it never runs.
	{"rv10-R03 set -n", raLin, `set -n; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R04 set -o noexec", raLin, `set -o noexec; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R05 exit before", raLin, `exit 0; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R06 exec CMD before", raLin, `exec true; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R07 false &&", raLin, `false && echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R17 trap exit DEBUG", raLin, `trap exit DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 set -eo noexec", raLin, `set -eo noexec; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 command exec", raLin, `command exec true; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 exec in bash -c", raLin, `bash -c 'exec true; echo k >> /home/u/.ssh/authorized_keys'`, rlAK, false},
	{"g0218 set -n in eval", raLin, `eval 'set -n'; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 true ||", raLin, `true || echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 ! true &&", raLin, `! true && echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 : || tee", raLin, `: || tee -a /home/u/.ssh/authorized_keys < /t/k`, rlAK, false},
	{"g0218 false && true &&", raLin, `false && true && echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 false && block", raLin, `false && { echo a; echo k >> /home/u/.ssh/authorized_keys; }`, rlAK, false},
	// Controls: the write runs.
	{"g0218 ctl plain", raLin, `echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set -e", raLin, `set -e; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set -euo pipefail", raLin, `set -euo pipefail; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set +x -o errexit", raLin, `set +x -o errexit; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set --", raLin, `set -- -n a; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exec redirect only", raLin, `exec 3>>/home/u/.ssh/authorized_keys; echo k >&3`, rlAK, true},
	{"g0218 ctl true &&", raLin, `true && echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl false ||", raLin, `false || echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl false && x || write", raLin, `false && true || echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl conditional exit", raLin, `cd /t/x || exit 1; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl conditional exec", raLin, `test -f /t/x && exec true; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exit in child shell", raLin, `bash -c 'exit 0'; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exit in subshell", raLin, `(exit 0); echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exec in pipeline", raLin, `exec true | cat; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exit in function body", raLin, `die() { exit 1; }; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl EXIT trap", raLin, `trap 'rm -f /t/x' EXIT; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl ignored DEBUG trap", raLin, `trap '' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl DEBUG trap reset", raLin, `trap - DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl shadowed false", raLin, `false() { :; }; false && echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl shadowed exec", raLin, `exec() { :; }; exec true; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl shadowed set", raLin, `set() { :; }; set -n; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 guard with argument", raLin, `false x && echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 shopt -so noexec", raLin, `shopt -so noexec; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 DEBUG trap runs a function", raLin, `f() { exit 0; }; trap f DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 DEBUG trap with extdebug", raLin, `shopt -s extdebug; trap false DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 dynamic DEBUG trap", raLin, `trap "$T" DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	// Review round 1: shapes that do not stop the write must keep the claim.
	{"g0218 ctl set -E", raLin, `set -E; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set -Eeuo pipefail rm", raLin, `set -Eeuo pipefail; rm -f /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set -f +H -o posix", raLin, `set -f; set +H; set -o posix; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set -C append", raLin, `set -C; tee -a /home/u/.ssh/authorized_keys < /t/k`, rlAK, true},
	{"g0218 ctl set +n", raLin, `set +n; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl trap : DEBUG", raLin, `trap : DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl trap echo DEBUG", raLin, `trap 'echo dbg >&2' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exit in background block", raLin, `{ exit; } & echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl exit in background list", raLin, `exit || : & echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl enable -n exit", raLin, `enable -n exit; exit; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl enable -n false", raLin, `enable -n false; hash -p /bin/true false; false && echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl execfail", raLin, `shopt -s execfail; exec /t/none 2>/dev/null; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	// Review round 2: bash -c ignores onecmd; a RETURN trap fires only on a
	// return; eval in a background list is a child; a subshell has no DEBUG
	// trap; a flow word in argument position changes nothing.
	{"g0218 ctl set -t under -c", raLin, `set -t; true; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl set -o onecmd under -c", raLin, `set -o onecmd; true; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl trap RETURN", raLin, `trap 'exit 0' RETURN; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl eval exit in background block", raLin, `{ eval exit; } & echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl eval set -n in background list", raLin, `eval 'set -n' || : & echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl DEBUG trap and subshell", raLin, `trap exit DEBUG; (echo k >> /home/u/.ssh/authorized_keys)`, rlAK, true},
	{"g0218 ctl trap echo exit", raLin, `trap 'echo exit' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl trap command -v", raLin, `trap 'command -v x' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 trap command exit", raLin, `trap 'command exit' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	// Review round 3: the shell opens a compound command's redirects before
	// its body runs, so an exec / exit in the body does not undo them.
	{"g0218 ctl block exec redirect", raLin, `{ exec cat /t/k; } > /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl block exit redirect", raLin, `{ exit; } >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl while exit redirect", raLin, `while exit; do :; done >> /home/u/.ssh/authorized_keys`, rlAK, true},
	// Batch review P2-1: an elif condition runs only when the conditions
	// before it failed, so a suppressor there is conditional.
	{"g0218 ctl elif exit", raLin, `if true; then :; elif exit; then :; fi; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl elif set -n", raLin, `if test -f /t/x; then :; elif set -n; then :; fi; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl elif exec", raLin, `if true; then :; elif exec true; then :; fi; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl elif trap exit DEBUG", raLin, `if true; then :; elif trap exit DEBUG; then :; fi; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	// Batch review P2-2: a DEBUG trap whose parsed action cannot end or stop
	// execution keeps the claim; one that can still demotes.
	{"g0218 ctl trap echo $BASH_COMMAND", raLin, `trap 'echo $BASH_COMMAND >&2' DEBUG; rm -f /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl trap set +x", raLin, `trap 'set +x' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 ctl trap logger $(date)", raLin, `trap 'logger "$(date) $BASH_COMMAND"' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0218 trap echo; exit", raLin, `trap 'echo $BASH_COMMAND; exit 0' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 trap set -n", raLin, `trap 'set -n' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 trap $(exit) dynamic word", raLin, `trap '$CMD' DEBUG; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0218 after a block that exits", raLin, `{ exit; } > /t/x; echo k >> /home/u/.ssh/authorized_keys`, rlAK, false},
}

var gap0219Rows = []restrictedRow{
	// A flag the program rejects: it exits without touching the file.
	{"rv10-R11 rm -u (shred-only)", raLin, `rm -u /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R12 unlink -f (no options)", raLin, `unlink -f /home/u/.ssh/authorized_keys`, rlAK, false},
	{"rv10-R15 macOS BSD /bin/cp -t", raMacBSD, `/bin/cp -t /Users/u/.ssh /t/authorized_keys`, rMacAK, false},
	{"g0219 rm -z (shred-only)", raLin, `rm -z /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0219 shred -r (rm-only)", raLin, `shred -r /home/u/.ssh/authorized_keys`, rlAK, false},
	{"g0219 cp -D (install-only)", raLin, `cp -D -t /home/u/.ssh /t/authorized_keys`, rlAK, false},
	{"g0219 cp -m (install-only)", raLin, `cp -m 600 -t /home/u/.ssh /t/authorized_keys`, rlAK, false},
	{"g0219 install -n (cp-only)", raLin, `install -n -t /home/u/.ssh /t/authorized_keys`, rlAK, false},
	{"g0219 install -a (cp-only)", raLin, `install -a -t /home/u/.ssh /t/authorized_keys`, rlAK, false},
	{"g0219 macOS /bin/mv -t", raMacBSD, `/bin/mv -t /Users/u/.ssh /t/authorized_keys`, rMacAK, false},
	{"g0219 macOS /bin/rm --force", raMacBSD, `/bin/rm --force /Users/u/.ssh/authorized_keys`, rMacAK, false},
	{"g0219 macOS /bin/rm -u", raMacBSD, `/bin/rm -u /Users/u/.ssh/authorized_keys`, rMacAK, false},
	{"g0219 macOS /usr/bin/tee -p", raMacBSD, `/usr/bin/tee -p /Users/u/.ssh/authorized_keys < /t/k`, rMacAK, false},
	{"g0219 macOS /bin/unlink -f", raMacBSD, `/bin/unlink -f /Users/u/.ssh/authorized_keys`, rMacAK, false},
	// Controls: valid flags, the file is changed.
	{"g0219 ctl rm -f", raLin, `rm -f /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0219 ctl rm -rf --", raLin, `rm -rf -- /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0219 ctl unlink", raLin, `unlink /home/u/.ssh/authorized_keys`, rlAK, true},
	{"g0219 ctl cp -t", raLin, `cp -t /home/u/.ssh /t/authorized_keys`, rlAK, true},
	{"g0219 ctl cp -p -t", raLin, `cp -p -t /home/u/.ssh /t/authorized_keys`, rlAK, true},
	{"g0219 ctl install -m -t", raLin, `install -m 600 -t /home/u/.ssh /t/authorized_keys`, rlAK, true},
	{"g0219 ctl mv -t", raLin, `mv -t /home/u/.ssh /t/authorized_keys`, rlAK, true},
	{"g0219 ctl tee -a", raLin, `tee -a /home/u/.ssh/authorized_keys < /t/k`, rlAK, true},
	{"g0219 ctl macOS rm -f", raMacBSD, `rm -f /Users/u/.ssh/authorized_keys`, rMacAK, true},
	{"g0219 ctl macOS /bin/rm -P", raMacBSD, `/bin/rm -P /Users/u/.ssh/authorized_keys`, rMacAK, true},
	{"g0219 ctl macOS unlink", raMacBSD, `unlink /Users/u/.ssh/authorized_keys`, rMacAK, true},
	{"g0219 ctl macOS tee -a", raMacBSD, `tee -a /Users/u/.ssh/authorized_keys < /t/k`, rMacAK, true},
	{"g0219 ctl macOS redirect", raMacBSD, `echo k >> /Users/u/.ssh/authorized_keys`, rMacAK, true},
	{"g0219 ctl GNU host cp -t under raMac", raMac, `cp -t /Users/u/.ssh /t/authorized_keys`, rMacAK, true},
	{"g0219 macOS /bin/cp -t", raMacBSD, `/bin/cp -t /Users/u/.ssh /t/authorized_keys`, rMacAK, false},
	// Review round 1: BSD getopt stops at the first operand; a GNU path is GNU.
	{"g0219 ctl macOS /bin/rm -f AK --verbose", raMacBSD, `/bin/rm -f /Users/u/.ssh/authorized_keys --verbose`, rMacAK, true},
	{"g0219 ctl macOS /usr/bin/tee AK --append", raMacBSD, `/usr/bin/tee /Users/u/.ssh/authorized_keys --append < /t/k`, rMacAK, true},
	{"g0219 ctl macOS gnubin cp -t", raMacBSD, `/opt/homebrew/opt/coreutils/libexec/gnubin/cp -t /Users/u/.ssh /t/authorized_keys`, rMacAK, true},
	// Review round 2: a trailing option moves cp/install's destination under
	// GNU (permutes) but not under BSD: unaccounted, and the write is kept.
	{"g0219 macOS /bin/cp trailing -f", raMacBSD, `/bin/cp /t/k /Users/u/.ssh/authorized_keys -f`, rMacAK, false},
	{"g0219 macOS /usr/bin/install trailing -m", raMacBSD, `/usr/bin/install /t/k /Users/u/.ssh/authorized_keys -m 600`, rMacAK, false},
	{"g0219 macOS /bin/mv trailing -f", raMacBSD, `/bin/mv /t/authorized_keys /Users/u/.ssh/authorized_keys -f`, rMacAK, false},
	// Review round 3: a flag both tools take with a different arity moves the
	// operands between the readings.
	{"g0219 macOS /usr/bin/install -T (arity differs)", raMacBSD, `/usr/bin/install -T /t/k /Users/u/.ssh/authorized_keys`, rMacAK, false},
	{"g0219 macOS /bin/cp -S (arity differs)", raMacBSD, `/bin/cp -S x /t/k /Users/u/.ssh/authorized_keys`, rMacAK, false},
	// Batch review P2-3: a bare name may be GNU coreutils first on PATH
	// (Homebrew gnubin, a Linux sandbox): the GNU reading keeps its claim.
	{"g0219 ctl macOS bare cp -t", raMacBSD, `cp -t /Users/u/.ssh /t/authorized_keys`, rMacAK, true},
	{"g0219 ctl macOS bare rm --force", raMacBSD, `rm --force /Users/u/.ssh/authorized_keys`, rMacAK, true},
	{"g0219 ctl macOS bare mv -t", raMacBSD, `mv -t /Users/u/.ssh /t/authorized_keys`, rMacAK, true},
	{"g0219 ctl macOS gnubin rm --force", raMacBSD, `/usr/local/opt/coreutils/libexec/gnubin/rm --force /Users/u/.ssh/authorized_keys`, rMacAK, true},
}

func runRestrictedRows(t *testing.T, rows []restrictedRow) {
	t.Helper()
	for _, c := range rows {
		t.Run(c.id, func(t *testing.T) {
			r := Extract(Call{Surface: SurfaceShell, Command: c.cmd}, c.o)
			got := restrictedClaim(r, c.target)
			if got != c.claim {
				t.Fatalf("restricted claim at %s = %v, want %v\n%s", c.target, got, c.claim, fmtRes(r))
			}
			if !c.claim && r.FullyKnown() && hasMutationAt(r, c.target) {
				t.Fatalf("fully known mutation at %s the command never makes\n%s", c.target, fmtRes(r))
			}
			if !c.claim && !hasAnyMutationAt(r, c.target) {
				// Fail closed: the write stays visible (unknown tier), never dropped.
				t.Fatalf("the mutation at %s was dropped, want it kept as unaccounted\n%s", c.target, fmtRes(r))
			}
		})
	}
}

// hasAnyMutationAt reports a mutation effect at the path in any state.
func hasAnyMutationAt(r Result, path string) bool {
	for _, e := range r.Effects {
		if isMutation(e.Kind) && e.Target.Path == path {
			return true
		}
	}
	return false
}

func TestGap0218ExecutionStateRestricted(t *testing.T) { runRestrictedRows(t, gap0218Rows) }

func TestGap0219FlagTablesRestricted(t *testing.T) { runRestrictedRows(t, gap0219Rows) }
