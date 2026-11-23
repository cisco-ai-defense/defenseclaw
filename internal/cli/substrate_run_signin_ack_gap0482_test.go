// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// GAP-0482: in open source, run amp printed the cluster's sign-in warning
// after the actor was made and the folder was being uploaded, and asked
// nothing. The cluster now answers an unacknowledged create 428
// signin_ack_required with the warning and makes nothing; the launcher
// shows it and asks first. No sends nothing more, --yes and a yes send the
// create again with acknowledge_signin, and a batch or a run with no
// terminal needs --yes. At the base the 428 was a plain failure: no
// question, no second create.
func TestRunAsksBeforeASigninAgentStartsGAP0482(t *testing.T) {
	const warning = "Amp signs in with a vendor account. Its sign-in token is stored in this actor and kept in every snapshot of it."
	var mu sync.Mutex
	var acks []bool
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST actors": func(w http.ResponseWriter, r *http.Request) {
			var req api.CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			acks = append(acks, req.AcknowledgeSignin)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if !req.AcknowledgeSignin {
				w.WriteHeader(http.StatusPreconditionRequired)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Precondition Required", "reason": "signin_ack_required", "message": warning})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.Actor{Atespace: "eng-web", Name: req.Name, Profile: req.Profile, Warnings: []string{warning}})
		},
	}}
	useFakeAdmin(t, f)
	s, err := substrateOpen(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolveSubstrateRunTarget(s, &substrateRunFlags{}, "amp")
	if err != nil {
		t.Fatal(err)
	}
	oldInteractive := substrateInteractive
	t.Cleanup(func() { substrateInteractive = oldInteractive })

	run := func(interactive bool, in string, flags *substrateRunFlags, req api.CreateRequest) (string, error) {
		t.Helper()
		mu.Lock()
		acks = nil
		mu.Unlock()
		substrateInteractive = func() bool { return interactive }
		cmd := &cobra.Command{}
		var errOut strings.Builder
		cmd.SetIn(strings.NewReader(in))
		cmd.SetOut(new(strings.Builder))
		cmd.SetErr(&errOut)
		_, err := substrateCreate(t.Context(), cmd, s, target, flags, req, "")
		return errOut.String(), err
	}
	exitCode := func(err error) int {
		var ec *cliusage.ExitCodeError
		if errors.As(err, &ec) {
			return ec.ExitCode()
		}
		return -1
	}
	sent := func() []bool {
		mu.Lock()
		defer mu.Unlock()
		return append([]bool(nil), acks...)
	}

	// No: the warning, the question, and nothing created.
	out, err := run(true, "n\n", &substrateRunFlags{}, api.CreateRequest{Name: "amp"})
	if err == nil || exitCode(err) != 1 || !strings.Contains(err.Error(), "nothing was created") {
		t.Fatalf("answer n: err %v (exit %d)", err, exitCode(err))
	}
	if !strings.Contains(out, "Warning: "+warning) || !strings.Contains(out, "Start Amp anyway? [y/N]") || strings.Contains(out, "Started ") {
		t.Fatalf("answer n: output %q", out)
	}
	if got := sent(); len(got) != 1 || got[0] {
		t.Fatalf("answer n: creates sent %v, want one without acknowledge_signin", got)
	}

	// Yes: the create goes again with the acknowledgement; the warning is
	// shown once, before the actor exists.
	out, err = run(true, "y\n", &substrateRunFlags{}, api.CreateRequest{Name: "amp"})
	if err != nil {
		t.Fatalf("answer y: %v", err)
	}
	if got := sent(); len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("answer y: creates sent %v, want [false true]", got)
	}
	if strings.Count(out, warning) != 1 || strings.Index(out, warning) > strings.Index(out, "Started ") {
		t.Fatalf("answer y: the warning must come once, before Started: %q", out)
	}

	// --yes answers it without a terminal.
	out, err = run(false, "", &substrateRunFlags{yes: true}, api.CreateRequest{Name: "amp"})
	if err != nil || !strings.Contains(out, "Acknowledged with --yes.") {
		t.Fatalf("--yes: err %v, output %q", err, out)
	}
	if got := sent(); len(got) != 2 || !got[1] {
		t.Fatalf("--yes: creates sent %v", got)
	}

	// No terminal and no --yes: refused with the warning and the fix.
	_, err = run(false, "", &substrateRunFlags{}, api.CreateRequest{Name: "amp", Task: "fix it", Unattended: true})
	if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), warning) || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no terminal: err %v (exit %d)", err, exitCode(err))
	}
	if got := sent(); len(got) != 1 || got[0] {
		t.Fatalf("no terminal: creates sent %v", got)
	}

	// A batch never asks on the terminal: it needs --yes.
	_, err = run(true, "y\n", &substrateRunFlags{}, api.CreateRequest{Name: "amp-1", Task: "fix it", BatchID: "b-1", Unattended: true})
	if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("batch: err %v (exit %d)", err, exitCode(err))
	}
	if got := sent(); len(got) != 1 || got[0] {
		t.Fatalf("batch: creates sent %v", got)
	}
}
