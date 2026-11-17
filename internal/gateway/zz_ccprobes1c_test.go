// Scratch code-close probe, round 2 (S7 lane s7-probe1, test-only branch
// s7/ccprobes-1). Old-API behaviour probe through the managed and per-user
// gateway hook route (awkPackFixture/awkVerdicts, present at the pre-fix
// sha): red at the pre-fix sha, green at rel. Its own file, so it is
// overlaid only on trees that have the awk hook harness.

package gateway

import (
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-0654 (P2 security): an awk program with a regular
// expression literal (holding a double quote) after + - * % ^ < > or ) and
// then a system() call reaches the rule in every cell, as the direct command
// does. Pre-fix the tokenizer read the slash as division, so the quote opened
// a fake string that hid the system() call and the managed cells allowed it.
func TestCCP1GAP0654AwkRegexAfterOperatorReachesTheRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX managed hook fixture")
	}
	rows := map[string]string{
		"A42": `awk 'BEGIN{ y = 1 + /"/; system("touch keylink"); y = 1 + /"/ }'`,
		"A43": `awk 'BEGIN{ if (1) /"/; system("touch keylink"); if (1) /"/ }'`,
		"A44": `awk 'BEGIN{ y = 1 < /"/; system("touch keylink"); y = 1 < /"/ }'`,
		"A45": `awk 'BEGIN{ y = 2 * /"/; system("touch keylink"); y = 2 * /"/ }'`,
		"B39": `awk 'BEGIN{ y = 1 - /"/; system("touch keylink"); y = 1 - /"/ }'`,
		"B41": `awk 'BEGIN{ print > "/dev/null"; y = 3 % /"/; system("touch keylink"); y = 3 % /"/ }'`,
		"B42": `awk 'BEGIN{ y = 3 ^ /"/; system("touch keylink"); y = 3 ^ /"/ }'`,
		"B43": `awk 'BEGIN{ y = 3 > /"/; system("touch keylink"); y = 3 > /"/ }'`,
	}
	const direct = "touch keylink"
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			f := awkPackFixture(t, pack)
			commands := []string{direct}
			for _, id := range []string{"A42", "A43", "A44", "A45", "B39", "B41", "B42", "B43"} {
				commands = append(commands, rows[id])
			}
			got := awkVerdicts(t, f, commands)
			for _, call := range got[direct] {
				if call.verdict != "block" {
					t.Skipf("control: the direct command %s is %s on this tree, want block", call.name, call.verdict)
				}
			}
			for _, id := range []string{"A42", "A43", "A44", "A45", "B39", "B41", "B42", "B43"} {
				for _, call := range got[rows[id]] {
					if call.verdict != "block" {
						t.Errorf("%s %s cell=%s managed=%v: %s, want block as the direct command",
							pack, id, call.connector, call.managed, call.verdict)
					}
				}
			}
		})
	}
}
