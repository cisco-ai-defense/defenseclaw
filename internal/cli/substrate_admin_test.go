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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// subAdminFake is an admin listener, sign-in server and agent entrance in one
// TLS server.
type subAdminFake struct {
	srv          *httptest.Server
	caFile       string
	actorsStatus int
	verifyStatus int
	verifyDoc    fleet.VerifyDocument
	issuerAnswer string
	sessionCert  api.SessionCert
	bundleStatus int
	statusStatus int
	attachStatus int
	statusBody   string

	bundleBody  []byte
	bundleQuery url.Values
	bundleType  string
	bundleAuth  string
	bundleCalls int
}

func newSubAdminFake(t *testing.T) *subAdminFake {
	t.Helper()
	f := &subAdminFake{attachStatus: 200, actorsStatus: 200, verifyStatus: 200, bundleStatus: 200, statusStatus: 200,
		verifyDoc: fleet.VerifyDocument{SchemaVersion: 1, Command: "verify", OK: true, Checks: []fleet.Check{
			{ID: fleet.CheckIssuer, Status: fleet.Pass, Message: "the issuer is unique"},
			{ID: fleet.CheckCallout, Status: fleet.Pass, Message: "the callout is registered"},
		}},
		sessionCert: api.SessionCert{Token: "t", ClientCertificatePEM: "pem", ClientKeyPEM: "key"},
		statusBody:  `{"bundles":[{"name":"policy.bundle","atespaces":["team-a"]}]}`,
	}
	writeJSONStatus := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/substrate/actors", func(w http.ResponseWriter, r *http.Request) {
		if f.actorsStatus != 200 {
			writeJSONStatus(w, f.actorsStatus, `{"error":"x","reason":"token_invalid"}`)
			return
		}
		writeJSONStatus(w, 200, `{"actors":[{"atespace":"a1","name":"n1"}]}`)
	})
	mux.HandleFunc("/api/v1/substrate/fleet/verify", func(w http.ResponseWriter, r *http.Request) {
		if f.verifyStatus != 200 {
			writeJSONStatus(w, f.verifyStatus, `{"error":"x","reason":"admin_only"}`)
			return
		}
		b, _ := json.Marshal(f.verifyDoc)
		writeJSONStatus(w, 200, string(b))
	})
	mux.HandleFunc("/api/v1/substrate/actors/a1/n1/attach/status", func(w http.ResponseWriter, r *http.Request) {
		if f.attachStatus != 200 {
			writeJSONStatus(w, f.attachStatus, `{"error":"x","reason":"attach"}`)
			return
		}
		writeJSONStatus(w, 200, `{"version":"dcrelay/1","tasks":{}}`)
	})
	mux.HandleFunc("/api/v1/substrate/session-cert", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(f.sessionCert)
		writeJSONStatus(w, 200, string(b))
	})
	mux.HandleFunc("/api/v1/substrate/bundle", func(w http.ResponseWriter, r *http.Request) {
		f.bundleCalls++
		f.bundleBody, _ = io.ReadAll(r.Body)
		f.bundleQuery, f.bundleType, f.bundleAuth = r.URL.Query(), r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		if f.bundleStatus != 200 {
			writeJSONStatus(w, f.bundleStatus, `{"error":"x","reason":"nope"}`)
			return
		}
		writeJSONStatus(w, 200, `{"accepted":true,"generation":7}`)
	})
	mux.HandleFunc("/api/v1/substrate/bundle/status", func(w http.ResponseWriter, r *http.Request) {
		if f.statusStatus != 200 {
			writeJSONStatus(w, f.statusStatus, `{"error":"x","reason":"admin_only"}`)
			return
		}
		writeJSONStatus(w, 200, f.statusBody)
	})
	mux.HandleFunc("/realms/x/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, 200, `{"issuer":"`+f.issuerAnswer+`"}`)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	f.issuerAnswer = f.srv.URL + "/realms/x"
	f.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *subAdminFake) context() auth.Context {
	return auth.Context{
		AdminURL: f.srv.URL, AdminCAFile: f.caFile,
		Issuer: f.srv.URL + "/realms/x", IssuerCAFile: f.caFile, ClientID: "launcher",
	}
}

func (f *subAdminFake) session(t *testing.T, c auth.Context) *substrateSession {
	t.Helper()
	cl, err := api.New(api.Options{Base: f.srv.URL, HTTP: f.srv.Client(), Token: func(context.Context) (string, error) { return "test-bearer", nil }})
	if err != nil {
		t.Fatal(err)
	}
	return &substrateSession{Name: "test", Ctx: c, Client: cl, Bearer: func(context.Context) (string, error) { return "test-bearer", nil }}
}

// subAdminSeams replaces what the admin commands take from the machine.
func subAdminSeams(t *testing.T, open func() (*substrateSession, error), storeErr error) {
	t.Helper()
	oldOpen, oldStore, oldAlert, oldDial := substrateOpen, substrateDoctorStore, substrateDoctorAlertWait, substrateDoctorDialWait
	t.Cleanup(func() {
		substrateOpen, substrateDoctorStore, substrateDoctorAlertWait, substrateDoctorDialWait = oldOpen, oldStore, oldAlert, oldDial
	})
	substrateOpen = func(*cobra.Command, *substrateCommon) (*substrateSession, error) { return open() }
	substrateDoctorStore = func() (string, error) {
		if storeErr != nil {
			return "", storeErr
		}
		return "the test store", nil
	}
	substrateDoctorAlertWait = 50 * time.Millisecond
	substrateDoctorDialWait = 3 * time.Second
}

func runSubAdmin(cmd *cobra.Command, args ...string) (string, string, error) {
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

// closedAddress is an address nothing listens on.
func closedAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestSubstrate_Admin_Doctor(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(f *subAdminFake, c *auth.Context)
		args     []string
		storeErr error
		openErr  error
		wantExit int
		want     []string
		notWant  []string
	}{
		{
			name:    "green",
			want:    []string{"ok    context", "ok    token_store", "the test store", "ok    admin_address", "ok    sign_in", "ok    sign_in_server", "ok    attach", "attach through the gateway works"},
			notWant: []string{"not ready"},
		},
		{
			name:    "green with cluster checks",
			args:    []string{"--cluster"},
			want:    []string{"ok    cluster.issuer_unique", "ok    cluster.callout_registered", "ready for agents"},
			notWant: []string{"not ready"},
		},
		{
			name: "cluster checks run by themselves",
			want: []string{"cluster.issuer_unique", "ready for agents"},
		},
		{
			name:   "warnings do not block",
			mutate: func(f *subAdminFake, c *auth.Context) { f.attachStatus = 501 },
			want:   []string{"warn  attach", "does not offer attach", "to fix:", "ready for agents"},
		},
		{
			name:     "not signed in to the cluster",
			mutate:   func(f *subAdminFake, c *auth.Context) { f.actorsStatus = 401 },
			wantExit: 1,
			want:     []string{"fail  sign_in", "did not accept your sign-in", "not ready: 1 problem(s)", "sign_in: defenseclaw substrate login"},
			notWant:  []string{"ready for agents\n", "cluster."},
		},
		{
			name:     "sign-in server names another issuer",
			mutate:   func(f *subAdminFake, c *auth.Context) { f.issuerAnswer = "https://other.example.test/realms/x" },
			wantExit: 1,
			want:     []string{"fail  sign_in_server", "https://other.example.test/realms/x", "not ready: 1 problem(s)", "sign_in_server: defenseclaw substrate login --issuer https://other.example.test/realms/x"},
		},
		{
			name:     "admin address does not resolve",
			mutate:   func(f *subAdminFake, c *auth.Context) { c.AdminURL = "https://admin.invalid:9443" },
			wantExit: 1,
			want:     []string{"fail  admin_address", "does not resolve", "skip  sign_in", "admin_address: check the address"},
		},
		{
			name:     "admin address refuses the connection",
			mutate:   func(f *subAdminFake, c *auth.Context) { c.AdminURL = "https://" + closedAddress(t) },
			wantExit: 1,
			want:     []string{"fail  admin_address", "cannot connect to", "skip  sign_in"},
		},
		{
			name:     "admin certificate is not trusted",
			mutate:   func(f *subAdminFake, c *auth.Context) { c.AdminCAFile = "" },
			wantExit: 1,
			want:     []string{"fail  admin_address", "is not trusted", "--admin-ca-file FILE"},
		},
		{
			name:     "attach is refused for the sign-in",
			mutate:   func(f *subAdminFake, c *auth.Context) { f.attachStatus = 401 },
			wantExit: 1,
			want:     []string{"fail  attach", "did not accept your sign-in for attach", "attach: defenseclaw substrate login"},
		},
		{
			name:     "attach fails inside the cluster",
			mutate:   func(f *subAdminFake, c *auth.Context) { f.attachStatus = 500 },
			wantExit: 1,
			want:     []string{"fail  attach", "attach through the gateway failed"},
		},
		{
			name:   "attach is not allowed for that agent",
			mutate: func(f *subAdminFake, c *auth.Context) { f.attachStatus = 403 },
			want:   []string{"warn  attach", "would not let you reach a1/n1", "ready for agents"},
		},
		{
			name:     "token store unusable",
			storeErr: errors.New("no keychain here"),
			wantExit: 1,
			want:     []string{"fail  token_store", "no keychain here", "DEFENSECLAW_SUBSTRATE_TOKEN_STORE=file"},
		},
		{
			name:     "no context",
			openErr:  errors.New("no cluster is configured"),
			wantExit: 1,
			want:     []string{"fail  context", "no cluster is configured", "skip  admin_address", "context: defenseclaw substrate login --admin-url"},
		},
		{
			name: "cluster check fails",
			mutate: func(f *subAdminFake, c *auth.Context) {
				f.verifyDoc.OK = false
				f.verifyDoc.Checks = append(f.verifyDoc.Checks, fleet.Check{ID: fleet.CheckBucket, Status: fleet.Fail, Message: "the bucket is public"},
					fleet.Check{ID: fleet.CheckIngressClients, Status: fleet.Warn, Message: "2 other router clients"})
			},
			wantExit: 1,
			want: []string{"fail  cluster.snapshot_bucket", "the bucket is public", "warn  cluster.ingress_clients", "not ready: 1 problem(s)",
				"cluster.snapshot_bucket: turn on encryption and block public access"},
		},
		{
			name:    "cluster checks are for administrators",
			mutate:  func(f *subAdminFake, c *auth.Context) { f.verifyStatus = 403 },
			args:    []string{"--cluster"},
			want:    []string{"skip  cluster", "cluster checks are for administrators", "ready for agents"},
			notWant: []string{"cluster.issuer"},
		},
		{
			name:    "cluster without the checks yet",
			mutate:  func(f *subAdminFake, c *auth.Context) { f.verifyStatus = 501 },
			args:    []string{"--cluster"},
			want:    []string{"skip  cluster", "this cluster does not offer them yet", "ready for agents"},
			notWant: []string{"cluster.issuer"},
		},
		{
			name:    "refused cluster checks are silent without --cluster",
			mutate:  func(f *subAdminFake, c *auth.Context) { f.verifyStatus = 403 },
			want:    []string{"ok    sign_in", "ready for agents"},
			notWant: []string{"administrators", "skip  cluster"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubAdminFake(t)
			c := f.context()
			if tc.mutate != nil {
				tc.mutate(f, &c)
			}
			subAdminSeams(t, func() (*substrateSession, error) {
				if tc.openErr != nil {
					return nil, tc.openErr
				}
				return f.session(t, c), nil
			}, tc.storeErr)
			out, _, err := runSubAdmin(newSubstrateDoctorCmd(), tc.args...)
			if got := commandExitCode(err); (err == nil && tc.wantExit != 0) || (err != nil && got != tc.wantExit) {
				t.Fatalf("exit %d (err %v), want %d\n%s", got, err, tc.wantExit, out)
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
			trimmed := strings.TrimSpace(out)
			if tc.wantExit == 0 && !strings.HasSuffix(trimmed, "ready for agents") {
				t.Errorf("the last line is not 'ready for agents':\n%s", out)
			}
			if tc.wantExit != 0 && strings.Contains(out, "ready for agents") {
				t.Errorf("a failed doctor says it is ready:\n%s", out)
			}
			if strings.Contains(out, "test-bearer") {
				t.Errorf("the token is in the output:\n%s", out)
			}
		})
	}
}

func TestSubstrate_Admin_DoctorJSON(t *testing.T) {
	f := newSubAdminFake(t)
	f.actorsStatus = 401
	c := f.context()
	subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, c), nil }, nil)
	out, errText, err := runSubAdmin(newSubstrateDoctorCmd(), "--json")
	if commandExitCode(err) != 1 {
		t.Fatalf("exit %d, want 1 with --json too (err %v)", commandExitCode(err), err)
	}
	if errText != "" {
		t.Errorf("the failure is printed on stderr as well: %q", errText)
	}
	var rep substrateDoctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if rep.OK || rep.Problems != 1 || rep.Context != "test" {
		t.Errorf("report: %+v", rep)
	}
	byID := map[string]substrateCheck{}
	for _, ch := range rep.Checks {
		byID[ch.ID] = ch
	}
	if got := byID["sign_in"]; got.Status != "fail" || got.Fix == "" || got.Summary == "" {
		t.Errorf("sign_in: %+v", got)
	}
	if got := byID["context"]; got.Status != "ok" {
		t.Errorf("context: %+v", got)
	}
}

func TestSubstrate_Admin_DoctorBadOutputFlag(t *testing.T) {
	f := newSubAdminFake(t)
	subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
	if _, _, err := runSubAdmin(newSubstrateDoctorCmd(), "--output", "yaml"); err == nil {
		t.Fatal("--output yaml is accepted")
	}
}

func TestSubstrate_Admin_ClassifyProbe(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "x.invalid"}}, "dns"},
		{"connect", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, "connect"},
		{"certificate", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "certificate"},
		{"handshake", errors.New("tls: first record does not look like a TLS handshake"), "handshake"},
	}
	for _, tc := range cases {
		if got := classifyProbe(tc.err); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSubstrate_Admin_BundleApply(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "policy.bundle")
	payload := []byte("signed-bundle-bytes\x00\x01")
	if err := os.WriteFile(bundle, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.bundle")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.bundle")
	bf, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := bf.Truncate(api.MaxBundleBytes + 1); err != nil {
		t.Fatal(err)
	}
	bf.Close()

	t.Run("sends the bytes as they are", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", bundle, "--atespaces", "team-a,team-b")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.bundleBody, payload) {
			t.Errorf("body %q", f.bundleBody)
		}
		if f.bundleType != "application/octet-stream" || f.bundleAuth != "Bearer test-bearer" {
			t.Errorf("content type %q auth %q", f.bundleType, f.bundleAuth)
		}
		if f.bundleQuery.Get("atespaces") != "team-a,team-b" || f.bundleQuery.Get("name") != "policy.bundle" {
			t.Errorf("query %v", f.bundleQuery)
		}
		for _, w := range []string{"Sent policy.bundle", "for team-a, team-b", "generation: 7", "bundle status"} {
			if !strings.Contains(out, w) {
				t.Errorf("output lacks %q:\n%s", w, out)
			}
		}
		if strings.Contains(out, "test-bearer") {
			t.Error("the token is in the output")
		}
	})
	t.Run("no atespaces sends none", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		if _, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", bundle, "--json"); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.bundleQuery["atespaces"]; ok {
			t.Errorf("query %v", f.bundleQuery)
		}
	})
	t.Run("json", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", bundle, "--json")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Bundle string         `json:"bundle"`
			Bytes  int            `json:"bytes"`
			Answer map[string]any `json:"answer"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Bundle != "policy.bundle" || doc.Bytes != len(payload) || doc.Answer["accepted"] != true {
			t.Errorf("%v %+v\n%s", err, doc, out)
		}
	})
	t.Run("dry run sends nothing", func(t *testing.T) {
		f := newSubAdminFake(t)
		opened := false
		subAdminSeams(t, func() (*substrateSession, error) { opened = true; return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", bundle, "--dry-run", "--atespaces", "team-a")
		if err != nil {
			t.Fatal(err)
		}
		if f.bundleCalls != 0 || opened {
			t.Errorf("a dry run contacted the cluster (calls %d, opened %v)", f.bundleCalls, opened)
		}
		if !strings.Contains(out, "Nothing was sent") {
			t.Errorf("output:\n%s", out)
		}
	})
	for _, tc := range []struct {
		name, file, want string
	}{
		{"empty file", empty, "empty"},
		{"missing file", filepath.Join(dir, "none.bundle"), "cannot be read"},
		{"folder", dir, "folder"},
		{"too large", big, "32 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubAdminFake(t)
			subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
			_, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.want) || commandExitCode(err) != 2 {
				t.Fatalf("err %v (exit %d), want %q and exit 2", err, commandExitCode(err), tc.want)
			}
			if f.bundleCalls != 0 {
				t.Error("the cluster was called")
			}
		})
	}
	for _, tc := range []struct {
		status   int
		want     string
		wantExit int
	}{
		{501, "does not accept bundles yet", substrateExitRefused},
		{404, "does not accept bundles yet", substrateExitRefused},
		{403, "refused", substrateExitRefused},
		{401, "sign in again", substrateExitSignedOut},
	} {
		t.Run("cluster answers "+http.StatusText(tc.status), func(t *testing.T) {
			f := newSubAdminFake(t)
			f.bundleStatus = tc.status
			subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
			_, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply", bundle)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) || commandExitCode(err) != tc.wantExit {
				t.Fatalf("err %v (exit %d), want %q and exit %d", err, commandExitCode(err), tc.want, tc.wantExit)
			}
		})
	}
	t.Run("needs a file", func(t *testing.T) {
		if _, _, err := runSubAdmin(newSubstrateBundleCmd(), "apply"); err == nil {
			t.Fatal("apply without a file works")
		}
	})
}

func TestSubstrate_Admin_BundleStatus(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "status")
		if err != nil || !strings.Contains(out, "policy.bundle") || !strings.Contains(out, "team-a") {
			t.Fatalf("%v\n%s", err, out)
		}
	})
	t.Run("json", func(t *testing.T) {
		f := newSubAdminFake(t)
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "status", "--output", "json")
		var doc map[string]any
		if err != nil || json.Unmarshal([]byte(out), &doc) != nil || doc["bundles"] == nil {
			t.Fatalf("%v\n%s", err, out)
		}
	})
	t.Run("none in force", func(t *testing.T) {
		f := newSubAdminFake(t)
		f.statusBody = `{}`
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		out, _, err := runSubAdmin(newSubstrateBundleCmd(), "status")
		if err != nil || !strings.Contains(out, "No policy bundle is in force") {
			t.Fatalf("%v\n%s", err, out)
		}
	})
	for _, status := range []int{501, 404} {
		t.Run("cluster answers "+http.StatusText(status), func(t *testing.T) {
			f := newSubAdminFake(t)
			f.statusStatus = status
			subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
			_, _, err := runSubAdmin(newSubstrateBundleCmd(), "status")
			if err == nil || !strings.Contains(err.Error(), "does not accept bundles yet") || commandExitCode(err) != substrateExitRefused {
				t.Fatalf("err %v (exit %d)", err, commandExitCode(err))
			}
		})
	}
	t.Run("a person who is not an administrator", func(t *testing.T) {
		f := newSubAdminFake(t)
		f.statusStatus = 403
		subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, f.context()), nil }, nil)
		_, _, err := runSubAdmin(newSubstrateBundleCmd(), "status")
		if err == nil || commandExitCode(err) != substrateExitRefused {
			t.Fatalf("err %v (exit %d)", err, commandExitCode(err))
		}
	})
}
