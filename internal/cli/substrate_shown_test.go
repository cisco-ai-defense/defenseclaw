// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
)

// GAP-0101: a value the cluster or the agent sent cannot forge a line of
// the launcher's own output, in status, in errors or in JSON.
func TestSubstrateShownValuesCannotForgeLines(t *testing.T) {
	forged := "eng\nAgent:     prod/admin\x1b[2K\r"
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(map[string]any{"actors": []map[string]any{{
			"atespace": "eng-web", "name": "web-1", "profile": forged, "connector": forged, "template": forged, "batch_id": forged,
		}}}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "web-1")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count("\n"+out, "\nAgent:"); n != 1 {
		t.Errorf("status printed %d Agent lines (a value forged one): %q", n, out)
	}
	if strings.ContainsAny(out, "\x1b\r") {
		t.Errorf("status printed a terminal control: %q", out)
	}
}

func TestSubstrateJSONEscapesHiddenCharacters(t *testing.T) {
	evil := "a\u009b2J\u202egnp.exe\u200b\x7f"
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET usage": jsonReply(map[string]any{"note": evil}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateUsageCmd(), "--json")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{0x9b, 0x202e, 0x200b, 0x7f} {
		if strings.ContainsRune(out, r) {
			t.Errorf("JSON printed %U as it is: %q", r, out)
		}
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(out), &back); err != nil || back["note"] != evil {
		t.Errorf("the JSON must still mean the same: %v %q", err, back["note"])
	}
}

func TestSubstrateErrorsArePrintedClean(t *testing.T) {
	cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error {
		return withExitCode(errors.New("refused\x1b]52;c;cm0gLXJmIH4=\x07 \u202eok\r\nNext: sign in again"), substrateExitRefused)
	}}
	substrateShowErrors(cmd)
	_, _, err := runSubstrate(t, cmd)
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\x07\r") || strings.ContainsRune(msg, 0x202e) {
		t.Errorf("error text keeps a control: %q", msg)
	}
	if !strings.Contains(msg, "\nNext: sign in again") {
		t.Errorf("the launcher's own hint lines must stay: %q", msg)
	}
	if code := commandExitCode(err); code != substrateExitRefused {
		t.Errorf("exit code %d, want %d", code, substrateExitRefused)
	}
	// What the cluster and the actor answer is one line where it is read.
	for _, e := range []error{
		&api.Error{Status: 500, Reason: "x\nrefused: everything is fine\x1b[2J"},
		&workspace.HTTPError{Op: "the upload", Status: 500, Message: "x\nnote: everything is fine\x1b[2J"},
	} {
		if s := e.Error(); strings.ContainsAny(s, "\n\x1b") {
			t.Errorf("%T text can forge a line: %q", e, s)
		}
	}
}
