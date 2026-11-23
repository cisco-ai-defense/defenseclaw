// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// fakeAdmin records the calls it gets and answers from a table.
type fakeAdmin struct {
	mu    sync.Mutex
	calls []string
	h     map[string]func(w http.ResponseWriter, r *http.Request)
}

func (f *fakeAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api/v1/substrate/")
	f.mu.Lock()
	f.calls = append(f.calls, key+"?"+r.URL.RawQuery)
	h := f.h[key]
	f.mu.Unlock()
	if r.Header.Get("Authorization") == "" {
		http.Error(w, `{"error":"Unauthorized","reason":"missing"}`, http.StatusUnauthorized)
		return
	}
	if h == nil {
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"Not Implemented","reason":"not_implemented"}`))
		return
	}
	h(w, r)
}

func jsonReply(v any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
}

func jsonStatus(code int, reason string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":%q,"reason":%q}`, http.StatusText(code), reason)
	}
}

// useFakeAdmin points substrateOpen at an httptest server and a workload
// token file, so no keychain or sign-in server is involved.
func useFakeAdmin(t *testing.T, f *fakeAdmin) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	claims, _ := json.Marshal(map[string]any{"sub": "user-1", "email": "dev@example.test", "exp": time.Now().Add(time.Hour).Unix(), "iss": "https://sso.example.test", "aud": []string{"defenseclaw"}})
	jwt := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".c2ln"
	file := filepath.Join(t.TempDir(), "workload-token")
	if err := os.WriteFile(file, []byte(jwt), 0o600); err != nil {
		t.Fatal(err)
	}
	old := substrateOpen
	substrateOpen = func(*cobra.Command, *substrateCommon) (*substrateSession, error) {
		c := auth.Context{AdminURL: srv.URL, Profile: "eng"}
		src := auth.NewSource("test", c, nil, auth.SourceOptions{Workload: &auth.WorkloadOptions{TokenFile: file}})
		cl, err := api.New(api.Options{Base: srv.URL, Token: src.Token})
		if err != nil {
			return nil, err
		}
		return &substrateSession{Name: "test", Ctx: c, Source: src, Client: cl}, nil
	}
	t.Cleanup(func() { substrateOpen = old })
}

func runSubstrate(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	substrateNoConsole(t)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// substrateNoConsole points os.Stdin at the null device for the rest of the
// test. The commands ask their yes/no questions only when stdin is a
// terminal, so a test process whose stdin is a console (a Windows scheduled
// task, a run from a terminal) would otherwise wait for an answer forever
// (GAP-1018). The null device is not a terminal on any platform and reads
// as end of file. A command input set with cmd.SetIn is kept.
func substrateNoConsole(t *testing.T) {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = old
		_ = f.Close()
	})
}

func sampleActors() map[string]any {
	return map[string]any{"actors": []map[string]any{
		{"atespace": "eng-web", "name": "fix-tests-1", "uid": "u1", "profile": "eng", "connector": "claudecode", "created_at": time.Now().Add(-5 * time.Minute)},
		{"atespace": "eng-web", "name": "old", "uid": "u2", "profile": "eng", "connector": "codex", "deleted": true},
		{"atespace": "eng-web", "name": "batch-1", "uid": "u3", "profile": "eng", "connector": "codex", "batch_id": "b-1", "created_at": time.Now().Add(-3 * time.Hour)},
	}}
}

func TestSubstrateListShowsOnlyLiveAgents(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(sampleActors())}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateListCmd())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"eng-web/fix-tests-1", "claudecode", "5m", "eng-web/batch-1", "b-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "old") {
		t.Errorf("a deleted agent is listed:\n%s", out)
	}
	jsonOut, _, err := runSubstrate(t, newSubstrateListCmd(), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Actors []api.Actor `json:"actors"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil || len(got.Actors) != 2 {
		t.Fatalf("json list = %v, %s", err, jsonOut)
	}
}

func TestSubstrateListIsEmptyWithAHint(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(map[string]any{"actors": []any{}})}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateListCmd())
	if err != nil || !strings.Contains(out, "defenseclaw substrate run claude") {
		t.Fatalf("empty list = %q, %v", out, err)
	}
}

func TestSubstrateRefusalsAreInPlainWords(t *testing.T) {
	for _, c := range []struct {
		name     string
		h        func(http.ResponseWriter, *http.Request)
		want     string
		wantCode int
	}{
		{"signed out", jsonStatus(401, "expired"), "defenseclaw substrate login", substrateExitSignedOut},
		{"profile", jsonStatus(403, "profile_not_allowed"), "may not use that profile", substrateExitRefused},
		{"not there yet", nil, "does not offer that yet", substrateExitRefused},
		{"busy", jsonStatus(503, "registrations_unavailable"), "try again in a minute", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){}}
			if c.h != nil {
				f.h["GET actors"] = c.h
			}
			useFakeAdmin(t, f)
			_, _, err := runSubstrate(t, newSubstrateListCmd())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want text %q", err, c.want)
			}
			if got := cliusage.ExitCode(err); got != c.wantCode {
				t.Errorf("exit code = %d, want %d", got, c.wantCode)
			}
			if strings.Contains(err.Error(), "Bearer") {
				t.Errorf("the error shows a credential: %v", err)
			}
		})
	}
}

func TestSubstrateActorReferenceIsResolvedAndAmbiguityRefused(t *testing.T) {
	list := map[string]any{"actors": []map[string]any{
		{"atespace": "eng-web", "name": "dup"}, {"atespace": "eng-ops", "name": "dup"}, {"atespace": "eng-web", "name": "solo"},
	}}
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(list)}}
	useFakeAdmin(t, f)
	s, _ := substrateOpen(nil, nil)
	ctx := t.Context()
	if a, err := resolveSubstrateActor(ctx, s.Client, "solo"); err != nil || a.Atespace != "eng-web" {
		t.Fatalf("solo = %+v, %v", a, err)
	}
	if a, err := resolveSubstrateActor(ctx, s.Client, "eng-ops/dup"); err != nil || a.Atespace != "eng-ops" {
		t.Fatalf("eng-ops/dup = %+v, %v", a, err)
	}
	if _, err := resolveSubstrateActor(ctx, s.Client, "dup"); err == nil || !strings.Contains(err.Error(), "ATESPACE/NAME") {
		t.Fatalf("dup: %v", err)
	}
	if _, err := resolveSubstrateActor(ctx, s.Client, "ghost"); err == nil || !strings.Contains(err.Error(), "defenseclaw substrate list") {
		t.Fatalf("ghost: %v", err)
	}
}

func TestSubstrateDeleteNeedsAYesAndDeletes(t *testing.T) {
	var deleted []string
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(sampleActors()),
		"DELETE actors/eng-web/fix-tests-1": func(w http.ResponseWriter, r *http.Request) {
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		},
	}}
	useFakeAdmin(t, f)
	if _, _, err := runSubstrate(t, newSubstrateDeleteCmd(), "fix-tests-1"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("without a terminal and --yes it must refuse, got %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted without a yes: %v", deleted)
	}
	out, _, err := runSubstrate(t, newSubstrateDeleteCmd(), "fix-tests-1", "--yes")
	if err != nil || !strings.Contains(out, "Deleted eng-web/fix-tests-1") || len(deleted) != 1 {
		t.Fatalf("delete = %q, %v, %v", out, err, deleted)
	}
	if _, _, err := runSubstrate(t, newSubstrateDeleteCmd()); err == nil {
		t.Fatal("delete with no name and no --batch must be a usage error")
	}
}

func TestSubstrateApprovalsAndDecisions(t *testing.T) {
	var body map[string]any
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET asks": jsonReply(map[string]any{"asks": []map[string]any{{"id": "a1", "actor": "eng-web/fix-tests-1", "summary": "run npm publish", "severity": "HIGH", "created": time.Now().Add(-30 * time.Second)}}}),
		"POST asks/a1": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusNoContent)
		},
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateApprovalsCmd())
	if err != nil || !strings.Contains(out, "run npm publish") || !strings.Contains(out, "substrate approve ID") {
		t.Fatalf("approvals = %q, %v", out, err)
	}
	if !strings.Contains(out, "RUN") || !strings.Contains(out, "attached") || strings.Contains(out, "unattended") {
		t.Fatalf("an attached ask: %q", out)
	}
	if out, _, err := runSubstrate(t, newSubstrateApproveCmd(), "a1", "--always", "--reason", "known"); err != nil || !strings.Contains(out, "Approved a1") {
		t.Fatalf("approve = %q, %v", out, err)
	}
	if body["decision"] != "approve" || body["always"] != true || body["reason"] != "known" {
		t.Errorf("approve body = %v", body)
	}
	if _, _, err := runSubstrate(t, newSubstrateRejectCmd(), "a1"); err != nil || body["decision"] != "deny" {
		t.Errorf("reject body = %v, %v", body, err)
	}
}

// D12 (F3 c8172fd81e): an ask an unattended run queued is marked
// "unattended" with the time left before it is denied, and --json carries
// the field.
func TestSubstrateApprovalsShowUnattended(t *testing.T) {
	now := time.Now()
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET asks": jsonReply(map[string]any{"asks": []map[string]any{{"id": "a2", "actor": "eng-web/nightly-3", "summary": "reach registry.npmjs.org",
			"severity": "MEDIUM", "created": now.Add(-time.Minute), "expires": now.Add(29*time.Minute + 30*time.Second), "unattended": true}}}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateApprovalsCmd())
	if err != nil || !strings.Contains(out, "unattended, 29m left") {
		t.Fatalf("approvals = %q, %v", out, err)
	}
	out, _, err = runSubstrate(t, newSubstrateApprovalsCmd(), "--json")
	if err != nil || !strings.Contains(out, `"unattended": true`) {
		t.Fatalf("approvals --json = %q, %v", out, err)
	}
}

func TestSubstrateSecretsNeverTakeAValueOnTheCommandLine(t *testing.T) {
	var stored map[string]string
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"PUT secrets/NPM_TOKEN": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&stored)
			w.WriteHeader(http.StatusNoContent)
		},
		"GET secrets": jsonReply(map[string]any{"secrets": []map[string]any{{"name": "NPM_TOKEN", "scope": "per_person", "hosts": []string{"registry.example.test"}}}}),
	}}
	useFakeAdmin(t, f)
	t.Setenv("SUBSTRATE_TEST_SECRET", "s3cret-value")
	out, errOut, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "NPM_TOKEN", "--from-env", "SUBSTRATE_TEST_SECRET")
	if err != nil || stored["value"] != "s3cret-value" {
		t.Fatalf("set = %v, %v", stored, err)
	}
	if strings.Contains(out+errOut, "s3cret-value") {
		t.Errorf("the value was printed: %q %q", out, errOut)
	}
	if _, _, err := runSubstrate(t, newSubstrateSecretsSetCmd(), "NPM_TOKEN", "--from-env", "SUBSTRATE_TEST_UNSET"); err == nil {
		t.Error("an empty environment variable must be refused")
	}
	if out, _, err := runSubstrate(t, newSubstrateSecretsListCmd(), "--mine"); err != nil || !strings.Contains(out, "registry.example.test") {
		t.Fatalf("list = %q, %v", out, err)
	}
	if !strings.Contains(strings.Join(f.calls, " "), "mine=1") {
		t.Errorf("--mine was not sent: %v", f.calls)
	}
}

func TestSubstrateUsageAndPolicyPrintTheDocument(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET usage":          jsonReply(map[string]any{"by": "actor", "rows": []map[string]any{{"key": "eng-web/fix-login", "calls": 12, "usage_calls": 12, "input_tokens": 100, "output_tokens": 50, "cost_usd": 1.5, "cost_calls": 12}}}),
		"GET actors":         jsonReply(sampleActors()),
		"GET policy/explain": jsonReply(map[string]any{"model": "claude", "verdict": "allow"}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateUsageCmd())
	if err != nil || !strings.Contains(out, "eng-web/fix-login") || !strings.Contains(out, "$1.50") {
		t.Fatalf("usage = %q, %v", out, err)
	}
	out, _, err = runSubstrate(t, newSubstratePolicyTestCmd(), "fix-tests-1", "--host", "registry.example.test")
	if err != nil || !strings.Contains(out, "verdict: allow") {
		t.Fatalf("policy test = %q, %v", out, err)
	}
	last := f.calls[len(f.calls)-1]
	if !strings.Contains(last, "actor=eng-web%2Ffix-tests-1") || !strings.Contains(last, "host=registry.example.test") {
		t.Errorf("policy query = %s", last)
	}
	if _, _, err := runSubstrate(t, newSubstratePolicyTestCmd(), "fix-tests-1"); err == nil {
		t.Error("policy test with nothing to test must be refused")
	}
}

func TestParseSubstrateBatch(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     []substrateTask
		err      string
	}{
		{"bare strings", "- fix the tests\n- update the docs\n", []substrateTask{{Task: "fix the tests"}, {Task: "update the docs"}}, ""},
		{"tasks map", "tasks:\n  - name: a\n    task: do a\n  - task: do b\n    agent: codex\n", []substrateTask{{Name: "a", Task: "do a"}, {Task: "do b", Agent: "codex"}}, ""},
		{"empty", "", nil, "empty"},
		{"no list", "name: x\n", nil, "tasks:"},
		{"blank task", "- ' '\n", nil, "has no text"},
		{"not a list", "tasks: 3\n", nil, "list of tasks"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseSubstrateBatch([]byte(c.in))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || len(got) != len(c.want) {
				t.Fatalf("got %+v, %v", got, err)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("task %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestSubstrateCheckProjectRefusesHomeAndRoot(t *testing.T) {
	home, _ := os.UserHomeDir()
	if home != "" {
		if err := substrateCheckProject(home); err == nil {
			t.Error("the home folder must be refused")
		}
	}
	if err := substrateCheckProject(t.TempDir()); err != nil {
		t.Errorf("a temp folder is fine: %v", err)
	}
}

func TestSubstrateAgeWords(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{-time.Second: "now", 30 * time.Second: "30s", 5 * time.Minute: "5m", 3 * time.Hour: "3h", 72 * time.Hour: "3d"} {
		if got := substrateAge(now.Add(-d), now); got != want {
			t.Errorf("age(%v) = %q, want %q", d, got, want)
		}
	}
	if substrateAge(time.Time{}, now) != "-" {
		t.Error("an unknown time is a dash")
	}
}

func TestSubstrateUsageTable(t *testing.T) {
	cost := 14.02
	pct, spent := 32.0, 16.13
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET usage": jsonReply(map[string]any{"by": "actor", "rows": []map[string]any{
			{"key": "eng-web/fix-login", "calls": 212, "usage_calls": 212, "input_tokens": 1900000, "output_tokens": 88100, "cost_usd": cost, "cost_calls": 212},
			{"key": "eng-web/batch-7f3a-03", "calls": 40, "usage_calls": 40, "input_tokens": 310200, "output_tokens": 12000, "cost_usd": 2.11, "cost_calls": 39},
		}, "budgets": []map[string]any{{"id": "day-per-person", "scope": "user", "period": "day", "limit_usd": 50, "spent_usd": spent, "percent_used": pct, "resets_at": "2026-11-23T00:00:00Z"}}}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateUsageCmd())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out)
	for _, want := range []string{"Your usage by agent, last 7d (UTC):", "AGENT", "1.9M", "88.1K", "total", "$16.13",
		"1 call had no known cost", "Budget day-per-person: $16.13 of $50.00 today (32 %), resets 2026-11-23T00:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(strings.Join(f.calls, " "), "by=actor") || !strings.Contains(strings.Join(f.calls, " "), "since=7d") {
		t.Errorf("by and since were not sent: %v", f.calls)
	}
}

func TestSubstrateUsageFlagsAndErrors(t *testing.T) {
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){}})
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--by", "person"}, "--by person needs --all"},
		{[]string{"--by", "nope"}, "--by is one of"},
		{[]string{"--since", "99d"}, "at most 31 days"},
		{[]string{"--since", "soon"}, "--since takes a window"},
	} {
		_, _, err := runSubstrate(t, newSubstrateUsageCmd(), c.args...)
		if err == nil || !strings.Contains(err.Error(), c.want) || cliusage.ExitCode(err) != 2 {
			t.Errorf("%v: err = %v (exit %d), want %q exit 2", c.args, err, cliusage.ExitCode(err), c.want)
		}
	}
	for reason, want := range map[string]string{
		"usage_disabled": "turned off on this cluster", "usage_unavailable": "leader did not answer",
		"usage_hidden": "users_see: none", "usage_forbidden": "only administrators",
	} {
		if got := substrateUsageMessage(reason); !strings.Contains(got, want) {
			t.Errorf("%s: %q lacks %q", reason, got, want)
		}
	}
}
