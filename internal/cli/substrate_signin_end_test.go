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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

func exitOf(err error) int {
	var e *cliusage.ExitCodeError
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return 1
}

// B5.1: logout ends the sign-in on the cluster before it forgets it, and
// says what the cluster did; --all ends nothing locally when the cluster
// ended nothing.
func TestLogoutEndsSigninOnCluster(t *testing.T) {
	now := time.Date(2026, 11, 23, 14, 2, 0, 0, time.UTC)
	saved := &auth.Token{AccessToken: "acc-marker", Expiry: now.Add(15 * time.Minute)}
	var gotScope string
	var gotAlso []string
	answer := func(code int, body string) *api.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Scope string   `json:"scope"`
				Also  []string `json:"also"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			gotScope, gotAlso = in.Scope, in.Also
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/substrate/signin/revoke" {
				code, body = 404, `{"reason":"wrong_route"}`
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		cl, err := api.New(api.Options{Base: srv.URL, Token: func(context.Context) (string, error) { return "acc-marker", nil }})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	for _, tc := range []struct {
		name      string
		code      int
		body      string
		all       bool
		want      []string
		wantErr   string
		wantExit  int
		wantScope string
	}{
		{name: "this", code: 200, body: `{"person":"https://idp#alice","scope":"this"}`, want: []string{"Signed out of e1. This sign-in no longer works on the cluster."}, wantScope: "this"},
		{name: "all", code: 200, all: true, body: `{"person":"https://idp#alice","principal":"alice@example.com","scope":"all","not_before":"2026-11-23T14:02:01Z"}`,
			want: []string{"Signed out of e1: every token of alice@example.com issued before 14:02:01 UTC is refused, on every device.", "also end your sessions at the sign-in server"}, wantScope: "all"},
		{name: "old gateway", code: 404, body: `{"reason":"not_found"}`, want: []string{"Signed out of e1.", "can't end sign-ins", "works until 14:17 UTC"}},
		{name: "old gateway all", code: 404, all: true, body: `{"reason":"not_found"}`, wantErr: "nothing was changed", wantExit: substrateExitRefused},
		{name: "already ended", code: 401, body: `{"reason":"signin_ended"}`, want: []string{"had already been ended"}},
		{name: "already ended all", code: 401, all: true, body: `{"reason":"signin_ended"}`, wantErr: "sign in again", wantExit: substrateExitSignedOut},
		{name: "expired", code: 401, body: `{"reason":"expired"}`, want: []string{"Signed out of e1."}},
		{name: "stale replica", code: 503, body: `{"reason":"revocation_unavailable"}`, want: []string{"could not end this sign-in", "can't check ended sign-ins", "works until 14:17 UTC"}},
		{name: "kube token with no iat all", code: 400, all: true, body: `{"reason":"signin_no_issue_time"}`, wantErr: "no issue time the cluster can use (a static Kubernetes token, a legacy Secret-based ServiceAccount token, or a token whose issue time is ahead of the cluster's clock)"},
		{name: "stale replica all", code: 503, all: true, body: `{"reason":"revocation_unavailable"}`, wantErr: "can't check ended sign-ins"},
	} {
		gotScope = ""
		msg, err := substrateEndSignin(context.Background(), answer(tc.code, tc.body), "e1", saved, tc.all, now)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want %q", tc.name, err, tc.wantErr)
			} else if tc.wantExit != 0 && exitOf(err) != tc.wantExit {
				t.Errorf("%s: exit %d, want %d", tc.name, exitOf(err), tc.wantExit)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: %q has no %q", tc.name, msg, w)
			}
		}
		if strings.Contains(msg, "marker") || strings.Contains(msg, "does not revoke") {
			t.Errorf("%s: %q", tc.name, msg)
		}
		if tc.wantScope != "" && gotScope != tc.wantScope {
			t.Errorf("%s: scope %q", tc.name, gotScope)
		}
		// RV1-03: a one-sign-in logout names the stored tokens; --all
		// needs none.
		if wantAlso := !tc.all; tc.wantScope != "" && (len(gotAlso) == 1 && gotAlso[0] == "acc-marker") != wantAlso {
			t.Errorf("%s: also %d tokens", tc.name, len(gotAlso))
		}
	}
	if msg, err := substrateEndSignin(context.Background(), nil, "e1", nil, false, now); err != nil || msg != "Signed out of e1." {
		t.Fatalf("nothing stored: %q %v", msg, err)
	}
}

func TestAdminRevokeCommand(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST admin/revocations": func(w http.ResponseWriter, r *http.Request) {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["user"] == "carol@example.com" {
				jsonStatus(404, "person_unknown")(w, r)
				return
			}
			jsonReply(map[string]any{"person": "https://idp#bob", "scope": "all", "not_before": "2026-11-23T14:05:00Z", "closed": 2, "reason": in["reason"]})(w, r)
		},
		"GET admin/revocations": jsonReply(map[string]any{"revocations": []map[string]any{{"person": "https://idp#bob", "scope": "all",
			"not_before": "2026-11-23T14:05:00Z", "until": "2026-11-24T14:05:00Z", "by": "https://idp#root", "reason": "laptop lost"}}}),
		"DELETE admin/revocations": jsonReply(map[string]any{"person": "https://idp#bob", "lifted": true}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateAdminCmd(), "revoke", "--user", "bob@example.com", "--reason", "laptop lost")
	if err != nil || !strings.Contains(out, "Ended every token of bob@example.com issued before 14:05:00 UTC, on every device. 2 open terminals were closed.") ||
		!strings.Contains(out, "also end their sessions at the sign-in server") {
		t.Fatalf("revoke: %q %v", out, err)
	}
	out, _, err = runSubstrate(t, newSubstrateAdminCmd(), "revoke", "--list")
	if err != nil || !strings.Contains(out, "https://idp#bob") || !strings.Contains(out, "laptop lost") {
		t.Fatalf("list: %q %v", out, err)
	}
	out, _, err = runSubstrate(t, newSubstrateAdminCmd(), "revoke", "--list", "--json")
	if err != nil || !strings.Contains(out, `"revocations":[{"person":"https://idp#bob"`) {
		t.Fatalf("list json: %q %v", out, err)
	}
	out, _, err = runSubstrate(t, newSubstrateAdminCmd(), "revoke", "--lift", "--user", "bob@example.com")
	if err != nil || !strings.Contains(out, "Lifted the end of the sign-ins of bob@example.com") || !strings.Contains(out, "Tokens ended one at a time stay ended.") {
		t.Fatalf("lift: %q %v", out, err)
	}
	_, _, err = runSubstrate(t, newSubstrateAdminCmd(), "revoke", "--user", "carol@example.com")
	if err == nil || !strings.Contains(err.Error(), "No sign-in of carol@example.com has been seen") && !strings.Contains(err.Error(), "no sign-in of carol@example.com has been seen") {
		t.Fatalf("unknown person: %v", err)
	}
	for _, args := range [][]string{{"revoke"}, {"revoke", "--list", "--user", "x"}, {"revoke", "--lift", "--user", "x", "--reason", "y"}} {
		if _, _, err := runSubstrate(t, newSubstrateAdminCmd(), args...); err == nil || exitOf(err) != 2 {
			t.Errorf("%v: %v", args, err)
		}
	}
	want := []string{"POST admin/revocations?", "GET admin/revocations?", "GET admin/revocations?", "DELETE admin/revocations?user=bob%40example.com", "POST admin/revocations?"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v", f.calls)
	}
}
