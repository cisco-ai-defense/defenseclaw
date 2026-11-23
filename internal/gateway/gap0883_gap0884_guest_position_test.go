// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestGAP0883GuestReadsEachStatementWhereItRuns: the copy-mode guest
// placement reads each statement only in the folders known at its own place.
// A folder only a later cd reaches (cd ~/.defenseclaw && ls after the write)
// made echo m > config.yaml a strict block (tamper.detector_state_write) and a
// default alert where the laptop and rel/1.0.10 allow (substrate-1 GAP-0883,
// RV-SEC10 rows C01-C03, C08, B43, B44, B48), and so did a statement ending
// in ; after pushd and popd, cd -, cd "$D", a function, a group or a loop
// (substrate-1 GAP-0947, RV-SEC10B rows N01-N23). The hook-config write after a
// folder change the laptop's statement reader cannot follow (cd -, popd, cd
// "$D", a called function, a group or a loop that cds) keeps the laptop's
// tamper.agent_hook_config_write alert for a later cd ~/.claude: the laptop
// guard reads such a call whole (substrate-1 GAP-0988, RV-SEC10C rows Z01-Z12,
// Y18). Every row must give the laptop's answer in every pack.
func TestGAP0883GuestReadsEachStatementWhereItRuns(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "C01 sub tmp later dc", command: "(cd /tmp)\n$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "C02 no sub later dc", command: "$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "C03 no unread later dc", command: "echo m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "C08 proj source later dc", command: "cd ~/p || exit\nsource .env\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "B43 sub-or claude later cd", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json\ncd .claude\nls", benign: true},
		{name: "B44 sub-or dc later cd", command: "(cd ~/.defenseclaw || cd /tmp)\n$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "B48 dc sub later cd abs", command: "(cd ~/.defenseclaw || true)\n$CMD\necho m > config.yaml\ncd ~/.defenseclaw\ncat config.yaml", benign: true},
		// RV-SEC10B N01-N23: a folder only a later cd reaches, after pushd and
		// popd, cd -, cd "$D", a function, a group or a loop (substrate-1 GAP-0947).
		{name: "N01 src or-exit cfg", command: "cd src || exit; make; cd ..; echo x > config.yaml", benign: true},
		{name: "N02 CMD build or-exit", command: "$CMD; cd build || exit 1; make install", benign: true},
		{name: "N03 tmp or-return", command: "cd /tmp || return; $CMD; echo m > config.yaml", benign: true},
		{name: "N04 venv src or-exit later claude", command: "source .venv/bin/activate; cd src || exit; pytest -q; cd ~/.claude && ls", benign: true},
		{name: "N05 CMD and src or-exit", command: "$CMD && cd src || exit; echo x > settings.json", benign: true},
		{name: "N06 p or-exit CMD later dc ls", command: "cd p || exit; $CMD; echo m > notes.txt; cd ~/.defenseclaw && ls", benign: true},
		{name: "N07 later claude read", command: "$CMD; echo '{}' > settings.json; cd ~/.claude || exit; cat settings.json", benign: true},
		{name: "N08 src or-exit CMD write cfg", command: "cd src || exit; $CMD; echo m > config.yaml", benign: true},
		{name: "N09 group src make", command: "{ cd src || exit; make; }; $CMD; echo x > out.txt", benign: true},
		{name: "N10 pushd src popd later dc", command: "pushd src; $CMD; popd; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N11 pushd popd no later cd", command: "pushd src; $CMD; popd; echo m > config.yaml", benign: true},
		{name: "N12 pushd popd no CMD later dc", command: "pushd src; popd; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N13 popd only later dc", command: "popd; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N14 cd dash later dc", command: "cd -; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N15 cd var later dc", command: "cd \"$D\"; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N16 fn decl later dc", command: "f() { :; }; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N17 pushd popd later claude", command: "pushd src; $CMD; popd; echo '{}' > settings.json; cd ~/.claude && ls", benign: true},
		{name: "N18 pushd popd later tmp", command: "pushd src; $CMD; popd; echo m > config.yaml; cd /tmp && ls", benign: true},
		{name: "N19 pushd popd later dc newline", command: "pushd src >/dev/null\nmake\npopd >/dev/null\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "N20 called fn later dc", command: "f() { cd src; }; f; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N21 cd var CMD later dc", command: "cd \"$D\"; $CMD; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N22 group cd later dc", command: "{ cd src; }; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "N23 loop cd later dc", command: "for d in src; do cd $d; done; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		// RV-SEC10C: the laptop alerts the hook-config write after a folder
		// change it cannot follow (substrate-1 GAP-0988) and allows it where
		// it places each statement (Z05, Z10, Z13, Y12).
		{name: "Z01 cd dash later claude", command: "cd -; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z02 pushd popd later claude", command: "pushd src; popd; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z03 popd later claude", command: "popd; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z04 cd var later claude", command: "cd \"$D\"; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z06 called fn later claude", command: "f() { cd src; }; f; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z07 group cd later claude", command: "{ cd src; }; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z08 loop cd later claude", command: "for d in src; do cd $d; done; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z09 build cd dash later claude", command: "cd build && make; cd -; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z12 fail cd dash later claude", command: "cd /nonexistent && true; cd -; echo '{}' > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Y18 build cd dash later claude", command: "cd build && cmake .. && make -j8; cd -; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z05 fn decl later claude", command: "f() { :; }; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z10 build cd up later claude", command: "cd build && make; cd ..; echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Z13 plain later claude", command: "echo x > settings.json; cd ~/.claude && ls", benign: true},
		{name: "Y12 later claude git", command: "ls ~/.claude; echo '{}' > settings.json; cd ~/.claude; git status", benign: true},
	})
}

// TestGAP0989GuestKnowsTheFolderWhereTheMoveRuns: the folder a cd reaches is
// known only from where that cd may first run. builtin cd and command cd move
// the shell as cd does; a cd in a function body moves it from the first call
// of the function; after export CDPATH=. a relative cd reaches only a folder
// that ends in its operand. Read as known from the start, each made the
// earlier echo m > config.yaml a strict tamper.detector_state_write block
// where the laptop and both rels allow (substrate-1 GAP-0989, RV-SEC10C rows
// Y04, Z14, Y08, Y10, Z16). The attack rows keep the laptop's block: the
// write after a builtin cd, a CDPATH spelled CD""PATH, a function called
// after the cd. A command the split cannot read before a function's
// declaration cannot call it: $CMD; g() { echo m > config.yaml; }; g; cd
// ~/.defenseclaw && ls ran the body at the end of the script (Y23).
func TestGAP0989GuestKnowsTheFolderWhereTheMoveRuns(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "Y04 git -C builtin later dc", command: "git -C src status; echo m > config.yaml; builtin cd ~/.defenseclaw && ls", benign: true},
		{name: "Z14 command cd later dc", command: "git -C src status; echo m > config.yaml; command cd ~/.defenseclaw && ls", benign: true},
		{name: "Y08 fn cd called after write", command: "f() { cd ~/.defenseclaw && ls; }; echo m > config.yaml; f", benign: true},
		{name: "Y10 CDPATH later dc", command: "export CDPATH=.; cd src; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "Z16 CDPATH home later dc", command: "export CDPATH=$HOME; cd src; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "X01 builtin cd ssh", command: "$CMD; builtin cd .ssh; echo k >> authorized_keys; cd ~/.ssh"},
		{name: "X02 command cd ssh", command: "$CMD; command cd .ssh; echo k >> authorized_keys; cd ~/.ssh"},
		{name: "X18 CD quote PATH", command: "cd /tmp; export CD\"\"PATH=$HOME; $CMD; cd .ssh; echo k >> authorized_keys; cd ~/.ssh"},
		{name: "X19 CD quote PATH no later", command: "cd /tmp; export CD\"\"PATH=$HOME; $CMD; cd .ssh; echo k >> authorized_keys"},
		{name: "X28 builtin cd dc", command: "$CMD; builtin cd .defenseclaw; echo m > config.yaml; cd ~/.defenseclaw"},
		{name: "Z17 fn cd ssh called", command: "f() { cd ~/.ssh; }; f; echo k >> authorized_keys"},
		{name: "Z18 fn cd ssh write twice", command: "f() { cd ~/.ssh; }; echo k >> authorized_keys; f; echo k >> authorized_keys"},
		{name: "W01 CDPATH home ssh", command: "cd /tmp; export CDPATH=$HOME; cd .ssh; echo k >> authorized_keys"},
		{name: "W02 fn builtin cd dc", command: "f() { builtin cd ~/.defenseclaw; }; f; echo m > config.yaml"},
		// An unread command before a function's declaration cannot call it
		// (RV-SEC10C Y23); one after it, or one that moved the shell before the
		// call, still counts.
		{name: "Y23 CMD fn write later dc", command: "$CMD; g() { echo m > config.yaml; }; g; cd ~/.defenseclaw && ls", benign: true},
		{name: "W03 CMD fn builtin cd ssh", command: "$CMD; f() { echo k >> authorized_keys; }; builtin cd .ssh; f"},
		{name: "W04 fn CD var after decl", command: "$CMD; CD=cd; f() { echo k >> authorized_keys; }; $CD .ssh; f; cd ~/.ssh"},
		{name: "W05 CD var before decl", command: "CD=cd; $CD .ssh; f() { echo k >> authorized_keys; }; f; cd ~/.ssh"},
		{name: "W06 CMD fn cd ssh called", command: "$CMD; f() { cd ~/.ssh; }; f; echo k >> authorized_keys"},
		// An unread command before the declaration in a loop that goes on past
		// it may call the function only where the loop runs: before a cd after
		// the loop, not after it (substrate-1 GAP-0991). A cd in the loop, or a
		// call after the cd, still counts.
		{name: "W18 loop CMD before decl", command: "for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; g; cd ~/.defenseclaw && ls", benign: true},
		{name: "K01 loop CMD before decl no call", command: "for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; cd ~/.defenseclaw && ls", benign: true},
		{name: "K02 while CMD before decl", command: "while read l; do $CMD; g() { echo m > config.yaml; }; done < /dev/null; g; cd ~/.defenseclaw && ls", benign: true},
		{name: "K03 nested loop CMD before decl", command: "for j in 1; do for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; done; g; cd ~/.defenseclaw && ls", benign: true},
		{name: "K04 loop CMD decl cd in loop", command: "for i in 1 2; do $CMD; g() { echo m > config.yaml; }; cd ~/.defenseclaw; done"},
		{name: "K05 loop CMD decl call after cd", command: "for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; cd ~/.defenseclaw && g"},
		{name: "K06 loop CMD decl cd ssh in loop", command: "for i in 1 2; do $CMD; f() { echo k >> authorized_keys; }; cd ~/.ssh; done"},
		{name: "K07 loop CMD after decl", command: "for i in 1 2; do g() { echo m > config.yaml; }; $CMD; done; cd ~/.defenseclaw && ls"},
		{name: "K08 decl then loop CMD", command: "g() { echo m > config.yaml; }; for i in 1 2; do $CMD; done; cd ~/.defenseclaw && ls"},
	})
}

// TestGAP0884GuestCdOrExitStandsInTheFolder: after the failing-cd fan, cd
// ../.ssh || exit leaves the shell in ../.ssh for what follows, as on the
// laptop, so the authorized_keys write there blocks
// (persistence.ssh_authorized_keys_command) where the actor alerted
// (substrate-1 GAP-0884, RV-SEC10 rows C05, C06).
func TestGAP0884GuestCdOrExitStandsInTheFolder(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "C05 fan7 or-exit", command: "cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ncd s5\ncd s6\ncd ../.ssh || exit\necho k >> authorized_keys"},
		{name: "C06 fan7 or-exit-1", command: "cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ncd s5\ncd s6\ncd ../.ssh || exit 1\necho k >> authorized_keys"},
	})
}

// TestGAP0888GuestHookConfigCandidateWhereTheShellStands: after a command the
// split cannot read ($CMD), the sandbox hook-config guard counted every
// candidate folder of the call, wherever it came: a cd in a subshell that
// ended before $CMD, or one a later statement runs, made the settings.json
// write an alert where the laptop and the rel actor allow (substrate-1
// GAP-0888, RV-SEC10 B43). The tilde and uncalled-function shapes still
// alert as on the laptop. Every row must give the laptop's answer.
func TestGAP0888GuestHookConfigCandidateWhereTheShellStands(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "V1 sub-or rel claude", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json", benign: true},
		{name: "V6 sub-or later cd", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json\ncd .claude", benign: true},
		{name: "V7 sub-or ls first", command: "(cd .claude || cd /tmp)\n$CMD\nls\necho '{}' > settings.json\ncd .claude", benign: true},
		{name: "V8 sub-or echo after", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json\necho hi", benign: true},
		{name: "B02 sub-or tilde claude", command: "(cd ~/.claude || cd /tmp)\n$CMD\necho '{}' > settings.json", benign: true},
		{name: "V4 sub-or tilde later cd", command: "(cd ~/.claude || cd /tmp)\n$CMD\necho '{}' > settings.json\ncd ~/.claude\nls", benign: true},
		{name: "B03 uncalled fn claude", command: "f() { cd .claude; }\n$CMD\necho '{}' > settings.json", benign: true},
		{name: "pushd dyn claude", command: "pushd .claude\n$CMD\necho '{}' > settings.json"},
		{name: "cd dyn claude", command: "cd .claude\n$CMD\necho '{}' > settings.json"},
	})
}

// TestGAP0991GuestLoopUnreadRunsTheFunctionWhereTheLoopRuns: the body of a
// function an unread command in a loop may call on a later pass runs where
// the loop may run, not at the end of the script; an unread command after
// the declaration still runs it at the end (substrate-1 GAP-0991).
func TestGAP0991GuestLoopUnreadRunsTheFunctionWhereTheLoopRuns(t *testing.T) {
	for _, row := range []struct {
		command string
		after   bool // the write may run after the cd
	}{
		{"for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; g; cd ~/.defenseclaw && ls", false},
		{"for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; cd ~/.defenseclaw && ls", false},
		{"for i in 1 2; do $CMD; g() { echo m > config.yaml; }; cd ~/.defenseclaw; done", true},
		{"for i in 1 2; do $CMD; g() { echo m > config.yaml; }; done; cd ~/.defenseclaw && g", true},
		{"for i in 1 2; do g() { echo m > config.yaml; }; $CMD; done; cd ~/.defenseclaw && ls", true},
		{"g() { echo m > config.yaml; }; for i in 1 2; do $CMD; done; cd ~/.defenseclaw && ls", true},
		{"f() { $CMD; }; for i in 1 2; do f; g() { echo m > config.yaml; }; done; cd ~/.defenseclaw && ls", true},
	} {
		calls, _ := guestScriptCalls(row.command, "/home/alice")
		write, cd := -1, -1
		for _, call := range calls {
			switch {
			case strings.HasPrefix(call.text, "echo m"):
				write = call.at
			case strings.HasPrefix(call.text, "cd ~/.defenseclaw"):
				cd = call.start
			}
		}
		if write < 0 || cd < 0 {
			t.Fatalf("%q: no write or cd in %+v", row.command, calls)
		}
		if got := write > cd; got != row.after {
			t.Errorf("%q: write at %d, cd at %d: after = %v, want %v", row.command, write, cd, got, row.after)
		}
	}
}
