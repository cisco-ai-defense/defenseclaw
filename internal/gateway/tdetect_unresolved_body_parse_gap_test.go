package gateway

import (
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-0535, GAP-1083 (s7-cdfold review of the owner A/B case
// at/codex/99368258d0a5a388/w72). A shell -c body made at run time is the
// unknown tier (an alert in every pack). A LATER statement of the same call
// that the walk gives up on (a parse gap, here a shell option the walk does
// not read before -c) must not drop that record: on rel the walk stopped at the
// first statement and kept it; the walk that reads the rest of the call
// returned the parse gap alone, and the call became an allow.
func TestUnresolvedBodyIsKeptWhenALaterStatementIsAParseGap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			for i, command := range []string{
				`bash -c "$X"; bash -O extglob -c 'echo hi'`,
				`bash -c "$(cat f)"; bash -O extglob -c 'echo hi'`,
				`sudo bash -c "$X"; sudo bash -O extglob -c 'echo hi'`,
				`echo a; bash -c "$X"; echo b; bash -O extglob -c 'echo hi'; echo c`,
				`bash -c "$X"; stat -c "%a" f; sudo python3 -c "print(1)"`,
			} {
				out := gap0437Hook(t, hook, cwd, p.name+"-ub-"+string(rune('a'+i)), command)
				if !gap0526Names(out, parseFailureRuleID) || out["action"] != "alert" {
					t.Errorf("%s %q: action %v rules %v, want an alert recording %s", p.name, command, out["action"], out["rule_ids"], parseFailureRuleID)
				}
			}
		})
	}
}
