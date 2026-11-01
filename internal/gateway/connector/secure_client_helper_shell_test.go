// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// secureClientHelperScript sources _hardening.sh the way a rendered hook does
// (markers assigned before the source, the managed one exported) and prints
// what the review of 0f2e3b002c compared: the xpg_echo option, the folder
// mktemp gave, the stat answer and FUNCNEST.
const secureClientHelperScript = `DEFENSECLAW_MANAGED_HOOK=1
export DEFENSECLAW_MANAGED_HOOK
[ "$2" = baked ] && _DC_SECURE_CLIENT_HOOK=1
[ "$2" = standalone ] && _DC_SECURE_CLIENT_HOOK=0
. "$1"
defenseclaw_harden_env
if shopt -q xpg_echo; then echo xpg=on; else echo xpg=off; fi
case "$DEFENSECLAW_HOOK_HOME" in "$3"*) echo mktemp=function ;; *) echo mktemp=program ;; esac
defenseclaw_stat_into %a %Lp "$1" && echo "stat=$_DC_STAT_OUT"
echo "funcnest=${FUNCNEST-unset}"
`

// TestSecureClientHelperKeepsItsPrePerfShellBehaviour: a Secure Client hook
// keeps the shell behaviour it had before the 1.0.7 perf rewrite (owner rule;
// review of 0f2e3b002c, items 1a and 1b): an inherited xpg_echo stays on, and
// mktemp and stat run as the agent's exported functions when there are any,
// as the pre-perf substitutions did. A standalone managed hook keeps the 1.0.7
// behaviour. And a marker the agent exported (a per-user hook an older build
// rendered) is not a Secure Client render for the review-2 checks
// (item 3): FUNCNEST is dropped.
func TestSecureClientHelperKeepsItsPrePerfShellBehaviour(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o600); err != nil {
		t.Fatal(err)
	}
	fnHome := filepath.Join(dir, "from-function")
	run := func(mode string, extra ...string) string {
		t.Helper()
		cmd := exec.Command("/bin/bash", "-c", secureClientHelperScript, "bash", helperPath, mode, fnHome)
		cmd.Env = append(sanitizedTestEnv(), "HOME="+dir, "BASHOPTS=xpg_echo", "FUNCNEST=50",
			"BASH_FUNC_mktemp%%=() {  mkdir -p '"+fnHome+"' && echo '"+fnHome+"'; }",
			"BASH_FUNC_stat%%=() {  echo 777; }")
		cmd.Env = append(cmd.Env, extra...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		return string(out)
	}
	for _, tc := range []struct {
		mode  string
		extra []string
		want  []string
	}{
		{"baked", nil, []string{"xpg=on", "mktemp=function", "stat=777", "funcnest=50"}},
		{"standalone", nil, []string{"xpg=off", "mktemp=program", "stat=600", "funcnest=unset"}},
		{"inherited", []string{"_DC_SECURE_CLIENT_HOOK=1"}, []string{"funcnest=unset"}},
	} {
		got := run(tc.mode, tc.extra...)
		for _, want := range tc.want {
			if !strings.Contains(got, want+"\n") {
				t.Errorf("%s: want %s, got:\n%s", tc.mode, want, got)
			}
		}
	}
}
