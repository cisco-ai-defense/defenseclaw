// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

const ourCalloutInfo = `{"sign_in":"oidc","attach":true,"egress_callout":{"state":"defenseclaw","fail_mode":"closed"}}`

// gap0505Fake answers create with a new actor, list with it, and create
// failures for the batch case.
func gap0505Fake(createFails bool) *fakeAdmin {
	actor := api.Actor{Atespace: "dc-eng", Name: "j32cb-1", UID: "u1", Profile: "eng", Connector: "claudecode", State: "running"}
	return &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST actors": func(w http.ResponseWriter, r *http.Request) {
			if createFails {
				jsonStatus(http.StatusInternalServerError, "boom")(w, r)
				return
			}
			var req api.CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			a := actor
			a.Name = req.Name
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(a)
		},
		"GET actors": jsonReply(map[string]any{"actors": []api.Actor{actor}}),
	}}
}

func gap0505Target(t *testing.T, s *substrateSession, f *substrateRunFlags) substrateRunTarget {
	t.Helper()
	t.Setenv("DEFENSECLAW_SUBSTRATE_PROFILE", "")
	t.Setenv("DEFENSECLAW_SUBSTRATE_TEMPLATE", "")
	target, err := resolveSubstrateRunTarget(s, f, "claude")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// GAP-0505 (J32 ours-then-other, closed mode): with another callout in
// Substrate's egress slot, run and run --task printed only "Started ..."
// and the agent's curl said "Could not resolve host"; the summary was built
// only for status and doctor. Now the create every run, run --task and
// --detach make prints status's Egress line after "Started", and nothing
// while the DefenseClaw callout holds the slot.
func TestGAP0505RunPrintsTheEgressLineAfterStarted(t *testing.T) {
	for _, tc := range []struct {
		name, info string
		batch      string
		want       bool
	}{
		{"other closed", otherCalloutInfo, "", true},
		{"none", strings.Replace(otherCalloutInfo, `"state":"other"`, `"state":"none"`, 1), "", true},
		{"ours", ourCalloutInfo, "", false},
		{"older gateway", `{"sign_in":"oidc","attach":true}`, "", false},
		// A batch prints it once for all its tasks (runSubstrateBatch).
		{"batch task", otherCalloutInfo, "b-1234", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useFakeAdminWithInfo(t, gap0505Fake(false), tc.info)
			s, err := substrateOpen(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			fl := &substrateRunFlags{}
			target := gap0505Target(t, s, fl)
			cmd := &cobra.Command{}
			var errOut strings.Builder
			cmd.SetOut(new(strings.Builder))
			cmd.SetErr(&errOut)
			if _, err := substrateCreate(t.Context(), cmd, s, target, fl, api.CreateRequest{Name: "j32cb", BatchID: tc.batch}, ""); err != nil {
				t.Fatal(err)
			}
			out := errOut.String()
			started, egress := strings.Index(out, "Started "), strings.Index(out, "Egress: ")
			if !tc.want {
				if egress >= 0 {
					t.Fatalf("printed the Egress line:\n%s", out)
				}
				return
			}
			if started < 0 || egress < started {
				t.Fatalf("no Egress line after Started:\n%s", out)
			}
			for _, w := range []string{"protections are off", "ask hosts", "reach only DefenseClaw", "every other host is refused"} {
				if !strings.Contains(out[egress:], w) {
					t.Errorf("Egress line lacks %q:\n%s", w, out)
				}
			}
		})
	}
}

// GAP-0505: the Egress line is status's (one text, substrateEgressSummary),
// and a task's end prints it from the same /info read as the token refusal.
func TestGAP0505TaskEndLineIsStatusLine(t *testing.T) {
	var e api.EgressCallout
	if err := json.Unmarshal([]byte(`{"state":"other","fail_mode":"closed","checks_off":["ask hosts"]}`), &e); err != nil {
		t.Fatal(err)
	}
	if got, want := substrateEgressLine(&e), "Egress: "+substrateEgressSummary(&e); got != want {
		t.Fatalf("launcher line %q, want status's %q", got, want)
	}
	for _, quiet := range []*api.EgressCallout{nil, {State: "defenseclaw", FailMode: "closed"}, {State: "unknown", FailMode: "closed"}} {
		if got := substrateEgressLine(quiet); got != "" {
			t.Errorf("%+v printed %q", quiet, got)
		}
	}
	s := f12InfoClient(t, map[string]any{"sign_in": "oidc", "attach": true,
		"egress_callout": map[string]any{"state": "other", "fail_mode": "closed", "checks_off": []string{"ask hosts"}}})
	info := substrateTaskEndInfo(context.Background(), s)
	if info == nil || !strings.Contains(substrateEgressLine(info.EgressCallout), "reach only DefenseClaw") {
		t.Fatalf("task end info %+v", info)
	}
}

// GAP-0505: a batch shows none of its tasks' output, so it prints the Egress
// line itself, at its start and at its end.
func TestGAP0505BatchPrintsTheEgressLine(t *testing.T) {
	for _, tc := range []struct {
		name, info string
		want       int
	}{{"other", otherCalloutInfo, 2}, {"ours", ourCalloutInfo, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			useFakeAdminWithInfo(t, gap0505Fake(true), tc.info)
			s, err := substrateOpen(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "tasks.yaml")
			if err := os.WriteFile(file, []byte("- task: fix the tests\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fl := &substrateRunFlags{batch: file, noUpload: true}
			target := gap0505Target(t, s, fl)
			cmd := &cobra.Command{}
			var errOut bytes.Buffer
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(&errOut)
			_ = runSubstrateBatch(t.Context(), cmd, s, target, fl, "", nil, false)
			if got := strings.Count(errOut.String(), "Egress: another egress callout is in place of DefenseClaw's"); got != tc.want {
				t.Fatalf("%d Egress lines, want %d:\n%s", got, tc.want, errOut.String())
			}
		})
	}
}

// GAP-0505: connect prints the Egress line before it attaches.
func TestGAP0505ConnectPrintsTheEgressLine(t *testing.T) {
	for _, tc := range []struct {
		name, info string
		want       bool
	}{{"other", otherCalloutInfo, true}, {"ours", ourCalloutInfo, false}} {
		t.Run(tc.name, func(t *testing.T) {
			useFakeAdminWithInfo(t, gap0505Fake(false), tc.info)
			substrateNoConsole(t)
			cmd := newSubstrateConnectCmd()
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs([]string{"j32cb-1", "--transport", "longpoll"})
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			// The fake has no relay: attach fails or runs until the deadline.
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_ = cmd.ExecuteContext(ctx)
			if got := strings.Contains(errOut.String(), "Egress: another egress callout is in place of DefenseClaw's"); got != tc.want {
				t.Fatalf("Egress line printed %v, want %v:\n%s", got, tc.want, errOut.String())
			}
		})
	}
}
