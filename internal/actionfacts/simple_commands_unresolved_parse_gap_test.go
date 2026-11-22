package actionfacts

import "testing"

// A shell -c body made at run time is recorded (EvaluationFailureUnresolvedBody,
// rel-1-0-10:GAP-0535); a later statement the walk gives up on returns a parse
// gap, and the record stays with it (s7-cdfold, owner A/B case w72).
func TestSimpleCommandsKeepTheUnresolvedBodyBesideALaterParseGap(t *testing.T) {
	for _, command := range []string{
		`bash -c "$X"; bash -O extglob -c 'echo hi'`,
		`bash -c "$X"; echo a; bash -O extglob -c 'echo hi'`,
		`bash -c "$(cat f)"; bash -O extglob -c 'echo hi'`,
	} {
		input := Input{Tool: "Bash", Command: command, CWD: "/home/alice/proj"}
		got := map[string]bool{}
		for _, simple := range SimpleCommands(input, Analyze(input)) {
			got[simple.EvaluationFailure] = true
		}
		if !got[EvaluationFailureUnresolvedBody] {
			t.Errorf("%q: the unresolved body is dropped, failures %v", command, got)
		}
	}
}
