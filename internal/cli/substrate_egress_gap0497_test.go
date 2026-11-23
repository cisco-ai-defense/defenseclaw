// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

const otherCalloutInfo = `{"sign_in":"oidc","attach":true,"egress_callout":{"state":"other","fail_mode":"closed",` +
	`"checks_off":["ask hosts","URL rules","egress feeds","secret and DLP scans","body and MCP inspection","tool chains at egress"]}}`

// GAP-0497 (J32 doctor-explains): with another callout in Substrate's egress
// slot the user doctor printed "ready for agents". At base it has no
// egress_callout row and ignores /info's member. Now the row fails, says
// another callout is in place and which protections are off.
func TestGAP0497DoctorSaysAnotherCalloutIsInPlace(t *testing.T) {
	for _, tc := range []struct {
		name, info string
		exit       int
		want       []string
		notWant    []string
	}{
		{"other", otherCalloutInfo, 1,
			[]string{"fail  egress_callout", "another egress callout is in place of DefenseClaw's", "ask hosts", "URL rules", "secret and DLP scans",
				"body and MCP inspection", "reach only DefenseClaw", "egress_callout: ask your administrator to register the DefenseClaw callout again"},
			[]string{"ready for agents"}},
		{"none", strings.Replace(otherCalloutInfo, `"state":"other"`, `"state":"none"`, 1), 1,
			[]string{"fail  egress_callout", "no egress callout is registered"}, nil},
		{"open", strings.Replace(otherCalloutInfo, `"fail_mode":"closed"`, `"fail_mode":"open"`, 1), 1,
			[]string{"fail  egress_callout", "keep their egress allow list without these checks", "unattended runs reach only DefenseClaw"}, nil},
		{"ours", `{"sign_in":"oidc","egress_callout":{"state":"defenseclaw","fail_mode":"closed"}}`, 0,
			[]string{"ok    egress_callout", "the cluster components were not checked"}, []string{"protections are off"}},
		{"unknown", `{"sign_in":"oidc","egress_callout":{"state":"unknown","fail_mode":"closed"}}`, 0,
			[]string{"warn  egress_callout", "cannot verify the egress callout", "cannot tell which egress callout", "the cluster components were not checked"}, nil},
		{"older gateway", "", 0, []string{"skip  egress_callout", "the cluster components were not checked"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubAdminFake(t)
			f.infoBody = tc.info
			c := f.context()
			subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, c), nil }, nil)
			out, _, err := runSubAdmin(newSubstrateDoctorCmd())
			if got := cliusage.ExitCode(err); (err == nil) != (tc.exit == 0) || (err != nil && got != tc.exit) {
				t.Fatalf("exit %d (err %v), want %d\n%s", got, err, tc.exit, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
		})
	}
}

// useFakeAdminWithInfo is useFakeAdmin with an /info answer (the route takes
// no token, which fakeAdmin refuses).
func useFakeAdminWithInfo(t *testing.T, f *fakeAdmin, info string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/substrate/info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(info))
			return
		}
		f.ServeHTTP(w, r)
	}))
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

// GAP-0497 (J32 actors-with-other): status said nothing while another
// callout held the slot. Now status, of the account and of one agent, says
// which protections are off; with the DefenseClaw callout it says nothing.
func TestGAP0497StatusSaysWhichProtectionsAreOff(t *testing.T) {
	actors := map[string]any{"actors": []map[string]any{{"atespace": "dc-eng", "name": "l7awo-1", "uid": "u1", "profile": "eng",
		"connector": "claudecode", "created_at": time.Now().Add(-time.Minute), "state": "running"}}}
	for _, args := range [][]string{{}, {"l7awo-1"}} {
		useFakeAdminWithInfo(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(actors)}}, otherCalloutInfo)
		out, _, err := runSubstrate(t, newSubstrateStatusCmd(), args...)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []string{"Egress:", "another egress callout is in place of DefenseClaw's", "ask hosts", "URL rules", "secret and DLP scans", "body and MCP inspection"} {
			if !strings.Contains(out, w) {
				t.Errorf("status %v lacks %q:\n%s", args, w, out)
			}
		}
		useFakeAdminWithInfo(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(actors)}},
			`{"sign_in":"oidc","egress_callout":{"state":"defenseclaw","fail_mode":"closed"}}`)
		if out, _, err = runSubstrate(t, newSubstrateStatusCmd(), args...); err != nil || strings.Contains(out, "Egress:") {
			t.Errorf("status %v with the DefenseClaw callout: %v\n%s", args, err, out)
		}
	}
	// --json carries the member.
	useFakeAdminWithInfo(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(actors)}}, otherCalloutInfo)
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Egress *api.EgressCallout `json:"egress_callout"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || !doc.Egress.Replaced() || len(doc.Egress.ChecksOff) == 0 {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
}
