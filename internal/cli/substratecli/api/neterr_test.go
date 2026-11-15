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

package api

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

func TestTransportErrorsSayWhatToDo(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "nothing answers"},
		{"dns", &net.DNSError{Err: "no such host", Name: "x.example.test"}, "cannot find the cluster address"},
		{"unknown ca", x509.UnknownAuthorityError{}, "--admin-ca-file"},
		{"timeout", context.DeadlineExceeded, "did not answer in time"},
		{"other", errors.New("boom"), "cannot reach the cluster"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := friendlyTransport("admin.example.test:9443", c.err)
			if !strings.Contains(got.Error(), c.want) || !strings.Contains(got.Error(), "defenseclaw substrate doctor") {
				t.Fatalf("got %q, want %q and the doctor hint", got, c.want)
			}
			if !errors.Is(got, c.err) && !errors.As(got, new(*net.OpError)) && c.name != "unknown ca" {
				t.Errorf("the cause is lost: %v", got)
			}
		})
	}
	if got := friendlyTransport("h", context.Canceled); !errors.Is(got, context.Canceled) || strings.Contains(got.Error(), "doctor") {
		t.Errorf("a cancelled call must stay a cancel: %v", got)
	}
}

func TestClientNeverLeaksTheTokenAndDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.test/", http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(Options{Base: srv.URL, Token: func(context.Context) (string, error) { return "tok-secret", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.List(t.Context(), ListOptions{})
	e, ok := AsError(err)
	if !ok || e.Status != http.StatusFound {
		t.Fatalf("a redirect must surface as a refusal, got %v", err)
	}
	if strings.Contains(err.Error(), "tok-secret") {
		t.Errorf("the token is in the error: %v", err)
	}
}

func TestNewRefusesUnsafeAddresses(t *testing.T) {
	tok := func(context.Context) (string, error) { return "t", nil }
	for _, base := range []string{"", "ftp://x.example.test", "http://admin.example.test:9443", "https://user:pw@admin.example.test"} {
		if _, err := New(Options{Base: base, Token: tok}); err == nil {
			t.Errorf("%q must be refused", base)
		}
	}
	if _, err := New(Options{Base: "http://127.0.0.1:9443", Token: tok}); err != nil {
		t.Errorf("loopback http is allowed: %v", err)
	}
}
