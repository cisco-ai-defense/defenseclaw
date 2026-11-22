// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// countingTransport answers every request with a token and records the hosts.
type countingTransport struct {
	mu    sync.Mutex
	hosts []string
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.hosts = append(c.hosts, r.URL.Host)
	c.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"token":"tok"}`)), Header: http.Header{}, Request: r}, nil
}

// GAP-0361: a registry reached by name cannot point the token request at a
// private, loopback or link-local address literal over https (the cloud
// metadata service); a registry that is itself at a private address keeps
// its own realm.
func TestHTTPSRealmCannotNameAPrivateAddress(t *testing.T) {
	ct := &countingTransport{}
	reg := NewRegistry(RegistryOptions{HTTPClient: &http.Client{Transport: ct}})
	for _, realm := range []string{
		"https://169.254.169.254/t", "https://[::ffff:169.254.169.254]/t", "https://10.0.0.7/t",
		"https://127.0.0.1:8443/t", "https://[::1]/t", "https://[fe80::1]/t", "https://0.0.0.0/t", "https://192.168.1.1/token",
	} {
		if _, err := reg.fetchToken(context.Background(), "registry.example.com", `Bearer realm="`+realm+`",service="s"`, "repository:a/b:pull"); err == nil {
			t.Errorf("realm %s accepted", realm)
		}
	}
	if len(ct.hosts) != 0 {
		t.Fatalf("the token service was asked at %v", ct.hosts)
	}
	for _, c := range []struct{ host, realm string }{
		{"registry.example.com", "https://auth.example.com/token"},
		{"10.0.0.5:5000", "https://10.0.0.5:5000/token"},
		{"10.0.0.5:5000", "https://10.0.0.6/token"},
	} {
		if tok, err := reg.fetchToken(context.Background(), c.host, `Bearer realm="`+c.realm+`"`, "repository:a/b:pull"); err != nil || tok != "tok" {
			t.Errorf("registry %s realm %s: %q %v", c.host, c.realm, tok, err)
		}
	}
}
