// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRunTimeShellTwinGAP1219MatchesBash checks the text that a real holding
// bash hands to a receiving bash. An unread twin is required where the two
// shells can produce different text; the other rows must still match.
func TestRunTimeShellTwinGAP1219MatchesBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	run := func(command string) string {
		cmd := exec.Command("bash", "-c", command)
		cmd.Env = append(os.Environ(), "HOME=/hh")
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "ERR:" + err.Error() + ":" + string(out)
		}
		return string(out)
	}
	rows := []struct {
		name, body string
		known      bool
	}{
		{"nested-single-quote-alternate", "printf '<%s>' ${HOME:+'$HOME'}", false},
		{"nested-single-quote-default", "printf '<%s>' ${NOPE:-'$HOME'}", false},
		{"printf-fused", "printf -vD zz; printf '<%s>' $D", false},
		{"eval", "eval D=zz; printf '<%s>' $D", false},
		{"directory-change", "cd /; printf '<%s>' $PWD", false},
		{"underscore", "true zz; printf '<%s>' $_", false},
		{"read-reply", "read <<< zz; printf '<%s>' $REPLY", false},
		{"shell-level", "printf '<%s>' $SHLVL", false},
		{"B07-named-coproc-pid", "coproc WORK { :; }; printf '<%s>' $WORK_PID", false},
		{"B08-unnamed-coproc-pid", "coproc { :; }; printf '<%s>' $COPROC_PID", false},
		{"B15-shell-opt-prefix", "printf '<%s>' $OPT_EXTRA", false},
		{"joined-parameter", "printf '<%s>' $HOME\\\nx", true},
		{"plain", "printf '<%s>' $HOME/x", true},
		{"nested-plain", "printf '<%s>' ${HOME:+$HOME}", true},
		{"removal", "printf '<%s>' ${HOME##*/}", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			command := "cat <<EOF | bash\n" + row.body + "\nEOF"
			if strings.HasPrefix(row.name, "B15-") {
				command = "OPT_EXTRA=outer; " + command
			}
			real := run(command)
			if strings.HasPrefix(row.name, "B") && real == run(row.body) {
				t.Fatalf("bash did not show a holding/receiving shell difference: %q", real)
			}
			twin, ok, _, unread := RunTimeShellTwin(command)
			if row.known {
				if !ok || unread || run(twin) != real {
					t.Errorf("known text: ok=%v unread=%v real=%q twin=%q", ok, unread, real, twin)
				}
			} else if ok || !unread {
				t.Errorf("unknown text: ok=%v unread=%v twin=%q", ok, unread, twin)
			}
		})
	}
}

func TestRunTimeShellTwinGAP1219ParameterSpan(t *testing.T) {
	text := "echo $HOME\\\nx"
	if heredocParamsExpandAsWritten(text, map[int]int{5: 10}, map[string]bool{"HOME": true}) {
		t.Fatal("a parameter joined to the following text changed its span")
	}
}
