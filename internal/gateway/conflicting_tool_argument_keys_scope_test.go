// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestConflictingToolArgumentKeysScope pins which calls the conflict check
// covers: ambiguous or partial calls whose candidates are complete analyses,
// and the conservative block only for shell and file-write calls.
func TestConflictingToolArgumentKeysScope(t *testing.T) {
	for _, c := range []struct {
		name         string
		input        actionfacts.Input
		applies      bool
		shellOrWrite bool
		candidates   int
	}{
		{"bash case variant", actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls","Command":"true"}`)}, true, true, 4},
		{"write target keys", actionfacts.Input{Tool: "Write", Args: json.RawMessage(`{"file_path":"/w/a","content":"x","path":"/w/b"}`)}, true, true, 4},
		{"read target keys", actionfacts.Input{Tool: "Read", Args: json.RawMessage(`{"file_path":"/w/a","path":"/w/b"}`)}, true, false, 4},
		// The closed shell contract reads the second key as unknown even
		// when it repeats the value; each spelling is judged, but one value
		// is one action and takes no conservative finding (GAP-0696).
		{"same value twice", actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls","Command":"ls"}`)}, true, false, 2},
		{"alias, same value", actionfacts.Input{Tool: "exec", Args: json.RawMessage(`{"command":"ls","cmd":"ls"}`)}, false, false, 0},
		{"same value twice, generic tool", actionfacts.Input{Tool: "shell", Args: json.RawMessage(`{"command":"ls","Command":"ls"}`)}, false, false, 0},
		// Keys ActionFacts reads as one field.
		{"command alias, generic tool", actionfacts.Input{Tool: "exec", Args: json.RawMessage(`{"command":"ls","cmd":"true"}`)}, true, true, 4},
		{"command alias value, generic tool", actionfacts.Input{Tool: "shell", Args: json.RawMessage(`{"command":"true","script":"ls"}`)}, true, true, 4},
		{"command alias, bash", actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls","cmd":"true"}`)}, true, true, 4},
		{"command alias only", actionfacts.Input{Tool: "exec", Args: json.RawMessage(`{"cmd":"ls"}`)}, false, false, 0},
		// One key repeated: every value of a reviewed key is a candidate.
		{"command twice", actionfacts.Input{Tool: "exec", Args: json.RawMessage(`{"command":"true","command":"ls"}`)}, true, true, 2},
		{"write path twice", actionfacts.Input{Tool: "write_file", Args: json.RawMessage(`{"path":"/w/a","content":"x","path":"/w/b"}`)}, true, true, 2},
		// A key repeated with the value it has is the one call it names: it
		// is judged as that call, with no conservative finding (GAP-0691).
		{"command twice, same value", actionfacts.Input{Tool: "exec", Args: json.RawMessage(`{"command":"ls","command":"ls"}`)}, true, false, 1},
		{"unreviewed key twice", actionfacts.Input{Tool: "write_file", Args: json.RawMessage(`{"path":"/w/a","content":"x","note":"a","note":"b"}`)}, false, false, 0},
		{"single key", actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls"}`)}, false, false, 0},
		// An unknown extra key leaves every candidate partial: GAP-0686.
		{"other unknown key", actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls","shell":"x"}`)}, false, false, 0},
		{"case variant and unknown key (GAP-0686)", actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls","Command":"true","shell":"x"}`)}, false, false, 0},
		{"unreviewed tool", actionfacts.Input{Tool: "github.create_issue", Args: json.RawMessage(`{"title":"a","Title":"b"}`)}, false, false, 0},
		{"explicit command", actionfacts.Input{Tool: "Bash", Command: "ls", Args: json.RawMessage(`{"command":"ls","Command":"true"}`)}, false, false, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			facts := actionfacts.Analyze(c.input)
			conflict, ok := conflictingToolArgumentKeys(trustedActionRequest{Input: c.input}, facts)
			if ok != c.applies || conflict.shellOrWrite != c.shellOrWrite || (ok && len(conflict.candidates) != c.candidates) {
				t.Fatalf("applies=%t shellOrWrite=%t candidates=%d, want %t %t %d (status %s %v)",
					ok, conflict.shellOrWrite, len(conflict.candidates), c.applies, c.shellOrWrite, c.candidates,
					facts.Parse.Status, facts.Parse.Issues)
			}
			for _, candidate := range conflict.candidates {
				if _, again := conflictingToolArgumentKeys(trustedActionRequest{Input: candidate.input}, actionfacts.Analyze(candidate.input)); again {
					t.Fatalf("candidate %s still conflicts", candidate.input.Args)
				}
			}
		})
	}
}

// TestConflictingToolArgumentKeysReadsArgumentsBeforeProjection pins that the
// check reads the arguments as the call carried them: a case twin of an
// argument a connector projection takes out is a conflict, and every
// candidate is projected before it is judged.
func TestConflictingToolArgumentKeysReadsArgumentsBeforeProjection(t *testing.T) {
	raw := json.RawMessage(`{"command":"ls","timeout":5,"Timeout":6}`)
	project := func(args json.RawMessage) actionfacts.Input {
		var object map[string]json.RawMessage
		_ = json.Unmarshal(args, &object)
		delete(object, "timeout")
		out, _ := json.Marshal(object)
		return actionfacts.Input{Tool: "Bash", Args: out}
	}
	request := trustedActionRequest{
		Input:          project(raw),
		conflictSource: &conflictingToolArgumentSource{raw: raw, project: project},
	}
	facts := actionfacts.Analyze(request.Input)
	if _, ok := conflictingToolArgumentKeys(trustedActionRequest{Input: request.Input}, facts); ok {
		t.Fatalf("projected arguments %s alone have no second key", request.Input.Args)
	}
	conflict, ok := conflictingToolArgumentKeys(request, facts)
	if !ok || !conflict.shellOrWrite || len(conflict.candidates) != 4 {
		t.Fatalf("applies=%t shellOrWrite=%t candidates=%d, want true true 4 (status %s)",
			ok, conflict.shellOrWrite, len(conflict.candidates), facts.Parse.Status)
	}
	for _, candidate := range conflict.candidates {
		if strings.Contains(string(candidate.input.Args), `"timeout"`) || !strings.Contains(string(candidate.raw), "imeout") {
			t.Fatalf("candidate raw %s projected %s: want the projection applied to the raw candidate", candidate.raw, candidate.input.Args)
		}
	}
}

func TestConflictingToolArgumentKeysBoundsCandidates(t *testing.T) {
	var fields []string
	for i := range 6 {
		fields = append(fields, fmt.Sprintf(`"k%d":"a","K%d":"b"`, i, i))
	}
	input := actionfacts.Input{Tool: "Bash", Args: json.RawMessage(`{"command":"ls","Command":"true",` + strings.Join(fields, ",") + `}`)}
	facts := actionfacts.Analyze(input)
	facts.Parse.Status, facts.Parse.Issues = actionfacts.StatusAmbiguous, []actionfacts.IssueCode{actionfacts.IssueConflictingSources}
	conflict, _ := conflictingToolArgumentKeys(trustedActionRequest{Input: input}, facts)
	if n := len(conflict.candidates); n == 0 || n > maxConflictingToolArgumentCandidates {
		t.Fatalf("candidates = %d, want 1..%d", n, maxConflictingToolArgumentCandidates)
	}
}
