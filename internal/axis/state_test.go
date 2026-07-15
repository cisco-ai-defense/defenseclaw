package axis

import "testing"

func TestStateMachine(t *testing.T) {
	if e := ValidTransition(Received, Authorized); e != nil {
		t.Fatal(e)
	}
	if e := ValidTransition(Received, Running); e == nil {
		t.Fatal("skipped start gate")
	}
}
