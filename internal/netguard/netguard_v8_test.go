// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestV8NetworkSafetyPolicyAddressMatrix(t *testing.T) {
	t.Parallel()
	policies := map[string]V8NetworkSafetyPolicy{
		"default": {},
		"private": {AllowPrivateNetworks: true},
		"cgnat":   {AllowCGNAT: true},
		"both":    {AllowPrivateNetworks: true, AllowCGNAT: true},
	}
	tests := []struct {
		name    string
		address string
		allowed map[string]bool
	}{
		{name: "public IPv4", address: "8.8.8.8", allowed: allV8Policies()},
		{name: "public IPv6", address: "2606:4700:4700::1111", allowed: allV8Policies()},
		{name: "RFC1918 class A", address: "10.0.0.1", allowed: privateV8Policies()},
		{name: "RFC1918 class B", address: "172.31.255.254", allowed: privateV8Policies()},
		{name: "RFC1918 class C", address: "192.168.1.2", allowed: privateV8Policies()},
		{name: "IPv4 loopback", address: "127.0.0.1", allowed: privateV8Policies()},
		{name: "IPv6 loopback", address: "::1", allowed: privateV8Policies()},
		{name: "IPv6 ULA", address: "fd12:3456::1", allowed: privateV8Policies()},
		{name: "CGNAT lower", address: "100.64.0.1", allowed: cgnatV8Policies()},
		{name: "CGNAT upper", address: "100.127.255.254", allowed: cgnatV8Policies()},
		{name: "IPv4 unspecified", address: "0.0.0.0", allowed: noV8Policies()},
		{name: "IPv6 unspecified", address: "::", allowed: noV8Policies()},
		{name: "deprecated IPv4 compatible IPv6", address: "::8.8.8.8", allowed: noV8Policies()},
		{name: "NAT64 well known prefix", address: "64:ff9b::808:808", allowed: noV8Policies()},
		{name: "IPv4 link-local", address: "169.254.1.1", allowed: noV8Policies()},
		{name: "IPv6 link-local", address: "fe80::1", allowed: noV8Policies()},
		{name: "IPv4 multicast", address: "224.0.0.1", allowed: noV8Policies()},
		{name: "IPv6 multicast", address: "ff02::1", allowed: noV8Policies()},
		{name: "IPv4 protocol assignments", address: "192.0.0.8", allowed: noV8Policies()},
		{name: "IPv4 documentation one", address: "192.0.2.1", allowed: noV8Policies()},
		{name: "IPv4 documentation two", address: "198.51.100.2", allowed: noV8Policies()},
		{name: "IPv4 documentation three", address: "203.0.113.3", allowed: noV8Policies()},
		{name: "IPv4 benchmarking", address: "198.18.0.1", allowed: noV8Policies()},
		{name: "IPv4 reserved", address: "240.0.0.1", allowed: noV8Policies()},
		{name: "IPv4 broadcast", address: "255.255.255.255", allowed: noV8Policies()},
		{name: "IPv6 discard-only", address: "100::1", allowed: noV8Policies()},
		{name: "IPv6 documentation", address: "2001:db8::1", allowed: noV8Policies()},
		{name: "IPv6 benchmarking", address: "2001:2::1", allowed: noV8Policies()},
		{name: "IPv6 6to4", address: "2002::1", allowed: noV8Policies()},
		{name: "IPv6 documentation two", address: "3fff::1", allowed: noV8Policies()},
		{name: "IPv6 segment routing local", address: "5f00::1", allowed: noV8Policies()},
		{name: "cloud metadata IPv4", address: "169.254.169.254", allowed: noV8Policies()},
		{name: "task credentials IPv4", address: "169.254.170.2", allowed: noV8Policies()},
		{name: "task credentials range", address: "169.254.170.23", allowed: noV8Policies()},
		{name: "CGNAT metadata", address: "100.100.100.200", allowed: noV8Policies()},
		{name: "private metadata IPv6", address: "fd00:ec2::254", allowed: noV8Policies()},
		{name: "link-local metadata IPv6", address: "fe80::a9fe:a9fe", allowed: noV8Policies()},
		{name: "mapped public IPv4", address: "::ffff:8.8.8.8", allowed: allV8Policies()},
		{name: "mapped private IPv4", address: "::ffff:10.0.0.1", allowed: privateV8Policies()},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(test.address)
			if ip == nil {
				t.Fatalf("invalid test address %q", test.address)
			}
			for name, policy := range policies {
				err := policy.ValidateIP(ip)
				if want := test.allowed[name]; (err == nil) != want {
					t.Errorf("policy %s ValidateIP(%s) error=%v; allowed=%v", name, test.address, err, want)
				}
				if err != nil && !errors.Is(err, ErrV8AddressProhibited) {
					t.Errorf("policy %s error=%v; want ErrV8AddressProhibited", name, err)
				}
			}
		})
	}

	if err := (V8NetworkSafetyPolicy{}).ValidateIP(nil); !errors.Is(err, ErrV8AddressProhibited) {
		t.Fatalf("nil IP error=%v; want ErrV8AddressProhibited", err)
	}
}

func allV8Policies() map[string]bool {
	return map[string]bool{"default": true, "private": true, "cgnat": true, "both": true}
}

func privateV8Policies() map[string]bool {
	return map[string]bool{"private": true, "both": true}
}

func cgnatV8Policies() map[string]bool {
	return map[string]bool{"cgnat": true, "both": true}
}

func noV8Policies() map[string]bool { return map[string]bool{} }

func TestParseV8PushURLIsOfflineAndPolicyScoped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		raw    string
		policy V8NetworkSafetyPolicy
		want   error
	}{
		{name: "public hostname", raw: "https://collector.example.test/v1/traces?token=secret"},
		{name: "public literal", raw: "https://8.8.8.8/v1/logs"},
		{name: "private blocked", raw: "http://10.1.2.3:4318/v1/traces", want: ErrV8AddressProhibited},
		{name: "private allowed", raw: "http://10.1.2.3:4318/v1/traces", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}},
		{name: "loopback allowed", raw: "http://127.0.0.1:4318", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}},
		{name: "cgnat not allowed by private", raw: "http://100.64.1.2:4318", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}, want: ErrV8AddressProhibited},
		{name: "cgnat allowed", raw: "http://100.64.1.2:4318", policy: V8NetworkSafetyPolicy{AllowCGNAT: true}},
		{name: "metadata always blocked", raw: "http://169.254.169.254/credentials", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true, AllowCGNAT: true}, want: ErrV8AddressProhibited},
		{name: "inline credentials", raw: "https://alice:secret@collector.example.test/v1/logs", want: ErrInlineCredentials},
		{name: "unsupported scheme", raw: "file:///tmp/telemetry", want: ErrUnsupportedScheme},
		{name: "missing scheme", raw: "collector.example.test:4318", want: ErrUnsupportedScheme},
		{name: "missing host", raw: "https:///v1/logs", want: ErrV8EndpointInvalid},
		{name: "empty explicit port", raw: "https://collector.example.test:", want: ErrV8EndpointInvalid},
		{name: "zero port", raw: "https://collector.example.test:0", want: ErrV8EndpointInvalid},
		{name: "port above range", raw: "https://collector.example.test:65536", want: ErrV8EndpointInvalid},
		{name: "invalid URL", raw: "https://collector.example.test/%zz?token=do-not-echo", want: ErrV8EndpointInvalid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			u, err := ParseV8PushURL(test.raw, test.policy)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ParseV8PushURL() error=%v", err)
				}
				if u == nil {
					t.Fatal("ParseV8PushURL() returned nil URL")
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("ParseV8PushURL() error=%v; want %v", err, test.want)
			}
			if u != nil {
				t.Fatalf("ParseV8PushURL() URL=%v on error", u)
			}
			assertV8ErrorBounded(t, err, test.raw)
		})
	}
}

func TestResolveV8PushURLRejectsMixedAnswers(t *testing.T) {
	t.Parallel()
	u := mustV8URL(t, "https://collector.example.test/v1/traces")
	resolver := staticV8Resolver{answers: []net.IPAddr{
		{IP: net.ParseIP("8.8.8.8")},
		{IP: net.ParseIP("10.1.2.3")},
	}}
	err := ResolveV8PushURL(context.Background(), u, V8NetworkSafetyPolicy{}, resolver)
	if !errors.Is(err, ErrV8AddressProhibited) {
		t.Fatalf("ResolveV8PushURL() error=%v; want ErrV8AddressProhibited", err)
	}
}

func TestResolveV8PushURLPolicyAndFailureClasses(t *testing.T) {
	t.Parallel()
	u := mustV8URL(t, "https://collector.example.test/v1/traces")
	tests := []struct {
		name     string
		policy   V8NetworkSafetyPolicy
		resolver V8Resolver
		want     error
	}{
		{name: "public", resolver: staticV8Resolver{answers: v8IPs("8.8.8.8", "2606:4700:4700::1111")}},
		{name: "private blocked", resolver: staticV8Resolver{answers: v8IPs("10.0.0.2")}, want: ErrV8AddressProhibited},
		{name: "private allowed", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}, resolver: staticV8Resolver{answers: v8IPs("10.0.0.2")}},
		{name: "CGNAT blocked by private", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}, resolver: staticV8Resolver{answers: v8IPs("100.64.0.2")}, want: ErrV8AddressProhibited},
		{name: "CGNAT allowed separately", policy: V8NetworkSafetyPolicy{AllowCGNAT: true}, resolver: staticV8Resolver{answers: v8IPs("100.64.0.2")}},
		{name: "metadata remains blocked", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true, AllowCGNAT: true}, resolver: staticV8Resolver{answers: v8IPs("100.100.100.200")}, want: ErrV8AddressProhibited},
		{name: "no answers", resolver: staticV8Resolver{}, want: ErrV8ResolutionFailed},
		{name: "temporary resolver failure", resolver: staticV8Resolver{err: errors.New("resolver leaked collector.example.test")}, want: ErrV8ResolutionFailed},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ResolveV8PushURL(context.Background(), u, test.policy, test.resolver)
			if !errors.Is(err, test.want) {
				t.Fatalf("ResolveV8PushURL() error=%v; want %v", err, test.want)
			}
			if err != nil {
				assertV8ErrorBounded(t, err, "collector.example.test")
			}
		})
	}
}

func TestV8SafeDialContextReResolvesAndBlocksRebinding(t *testing.T) {
	t.Parallel()
	resolver := &sequenceV8Resolver{answers: [][]net.IPAddr{
		v8IPs("8.8.8.8"),
		v8IPs("10.0.0.8"),
	}}
	u := mustV8URL(t, "https://collector.example.test/v1/traces")
	if err := ResolveV8PushURL(context.Background(), u, V8NetworkSafetyPolicy{}, resolver); err != nil {
		t.Fatalf("activation validation error=%v", err)
	}
	dialer := &recordingV8Dialer{}
	_, err := V8SafeDialContext(V8NetworkSafetyPolicy{}, dialer, resolver)(context.Background(), "tcp", "collector.example.test:443")
	if !errors.Is(err, ErrV8AddressProhibited) {
		t.Fatalf("guarded dial error=%v; want ErrV8AddressProhibited", err)
	}
	if dialer.Calls() != 0 {
		t.Fatalf("underlying dial calls=%d; want 0", dialer.Calls())
	}
	if resolver.Calls() != 2 {
		t.Fatalf("resolver calls=%d; want activation + dial", resolver.Calls())
	}
}

func TestV8SafeDialContextSelectsCompatiblePublicAddress(t *testing.T) {
	t.Parallel()
	resolver := staticV8Resolver{answers: v8IPs("2606:4700:4700::1111", "8.8.8.8")}
	dialer := &recordingV8Dialer{}
	conn, err := V8SafeDialContext(V8NetworkSafetyPolicy{}, dialer, resolver)(context.Background(), "tcp4", "collector.example.test:4318")
	if err != nil {
		t.Fatalf("guarded dial error=%v", err)
	}
	if conn == nil {
		t.Fatal("guarded dial returned nil connection")
	}
	_ = conn.Close()
	if got := dialer.LastAddress(); got != "8.8.8.8:4318" {
		t.Fatalf("underlying dial address=%q; want public IPv4 literal", got)
	}
}

func TestV8SafeDialContextRejectsMixedAnswersBeforeDial(t *testing.T) {
	t.Parallel()
	resolver := staticV8Resolver{answers: v8IPs("8.8.8.8", "fd00::2")}
	dialer := &recordingV8Dialer{}
	_, err := V8SafeDialContext(V8NetworkSafetyPolicy{}, dialer, resolver)(context.Background(), "tcp", "collector.example.test:4318")
	if !errors.Is(err, ErrV8AddressProhibited) {
		t.Fatalf("guarded dial error=%v; want ErrV8AddressProhibited", err)
	}
	if dialer.Calls() != 0 {
		t.Fatalf("underlying dial calls=%d; want 0", dialer.Calls())
	}
}

func TestV8SafeDialContextLiteralAndInputValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		network string
		address string
		policy  V8NetworkSafetyPolicy
		want    error
	}{
		{name: "private literal blocked", network: "tcp", address: "10.0.0.1:4318", want: ErrV8AddressProhibited},
		{name: "private literal allowed", network: "tcp", address: "10.0.0.1:4318", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}},
		{name: "link-local always blocked", network: "tcp6", address: "[fe80::1%lo0]:4318", policy: V8NetworkSafetyPolicy{AllowPrivateNetworks: true}, want: ErrV8AddressProhibited},
		{name: "family mismatch", network: "tcp4", address: "[2606:4700:4700::1111]:4318", want: ErrV8AddressProhibited},
		{name: "unsupported network", network: "udp", address: "8.8.8.8:4318", want: ErrV8EndpointInvalid},
		{name: "missing port", network: "tcp", address: "8.8.8.8", want: ErrV8EndpointInvalid},
		{name: "empty port", network: "tcp", address: "8.8.8.8:", want: ErrV8EndpointInvalid},
		{name: "service port", network: "tcp", address: "8.8.8.8:https", want: ErrV8EndpointInvalid},
		{name: "zero port", network: "tcp", address: "8.8.8.8:0", want: ErrV8EndpointInvalid},
		{name: "large port", network: "tcp", address: "8.8.8.8:65536", want: ErrV8EndpointInvalid},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dialer := &recordingV8Dialer{}
			conn, err := V8SafeDialContext(test.policy, dialer, staticV8Resolver{})(context.Background(), test.network, test.address)
			if !errors.Is(err, test.want) {
				t.Fatalf("guarded dial error=%v; want %v", err, test.want)
			}
			if test.want == nil {
				if conn == nil {
					t.Fatal("guarded dial returned nil connection")
				}
				_ = conn.Close()
				return
			}
			if conn != nil {
				t.Fatal("guarded dial returned connection on error")
			}
			assertV8ErrorBounded(t, err, test.address)
		})
	}
}

func TestV8SafeDialContextSanitizesResolverAndDialErrors(t *testing.T) {
	t.Parallel()
	secret := "collector-secret.example.test"
	resolver := staticV8Resolver{err: fmt.Errorf("lookup %s: bearer-token", secret)}
	_, err := V8SafeDialContext(V8NetworkSafetyPolicy{}, &recordingV8Dialer{}, resolver)(context.Background(), "tcp", secret+":443")
	if !errors.Is(err, ErrV8ResolutionFailed) {
		t.Fatalf("resolver error=%v; want ErrV8ResolutionFailed", err)
	}
	assertV8ErrorBounded(t, err, secret, "bearer-token")

	dialer := &recordingV8Dialer{err: fmt.Errorf("dial %s with response body", secret)}
	_, err = V8SafeDialContext(V8NetworkSafetyPolicy{}, dialer, staticV8Resolver{answers: v8IPs("8.8.8.8")})(context.Background(), "tcp", secret+":443")
	if !errors.Is(err, ErrV8ConnectionFailed) {
		t.Fatalf("dial error=%v; want ErrV8ConnectionFailed", err)
	}
	assertV8ErrorBounded(t, err, secret, "response body")
}

func TestV8CancellationIsPreservedAndBounded(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u := mustV8URL(t, "https://collector.example.test/v1/traces")
	err := ResolveV8PushURL(ctx, u, V8NetworkSafetyPolicy{}, waitingV8Resolver{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveV8PushURL() error=%v; want context.Canceled", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err = V8SafeDialContext(V8NetworkSafetyPolicy{}, waitingV8Dialer{}, staticV8Resolver{answers: v8IPs("8.8.8.8")})(ctx, "tcp", "collector.example.test:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("guarded dial error=%v; want context.DeadlineExceeded", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	resolver := cancelingV8Resolver{cancel: cancel, answers: v8IPs("8.8.8.8")}
	err = ResolveV8PushURL(ctx, u, V8NetworkSafetyPolicy{}, resolver)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveV8PushURL() after non-cooperative resolver error=%v; want context.Canceled", err)
	}
}

func TestBlockV8RedirectsRejectsWithoutEcho(t *testing.T) {
	t.Parallel()
	req := &http.Request{URL: mustV8URL(t, "https://redirect-secret.example.test/path?token=secret")}
	via := []*http.Request{{URL: mustV8URL(t, "https://origin-secret.example.test/start")}}
	err := BlockV8Redirects(req, via)
	if !errors.Is(err, ErrV8RedirectBlocked) {
		t.Fatalf("BlockV8Redirects() error=%v; want ErrV8RedirectBlocked", err)
	}
	assertV8ErrorBounded(t, err, "redirect-secret", "origin-secret", "token=secret")
}

func TestV8PolicyIgnoresLegacyAndHypotheticalGlobalBypasses(t *testing.T) {
	for _, envName := range []string{
		"DEFENSECLAW_ALLOW_CGNAT",
		"DEFENSECLAW_ALLOW_PRIVATE_NETWORKS",
		"OTEL_EXPORTER_ALLOW_PRIVATE_NETWORKS",
	} {
		t.Run(envName, func(t *testing.T) {
			t.Setenv(envName, "1")
			policy := V8NetworkSafetyPolicy{}
			if err := policy.ValidateIP(net.ParseIP("100.64.0.1")); !errors.Is(err, ErrV8AddressProhibited) {
				t.Fatalf("CGNAT error=%v with %s set; v8 must ignore environment bypass", err, envName)
			}
			if err := policy.ValidateIP(net.ParseIP("10.0.0.1")); !errors.Is(err, ErrV8AddressProhibited) {
				t.Fatalf("private error=%v with %s set; v8 must ignore environment bypass", err, envName)
			}
		})
	}
}

func TestV8PolicyAndDialAreRaceSafe(t *testing.T) {
	policy := V8NetworkSafetyPolicy{AllowPrivateNetworks: true}
	resolver := staticV8Resolver{answers: v8IPs("8.8.8.8", "2606:4700:4700::1111")}
	dialer := &recordingV8Dialer{}
	dial := V8SafeDialContext(policy, dialer, resolver)

	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if err := policy.ValidateIP(net.ParseIP("10.0.0.1")); err != nil {
					t.Errorf("ValidateIP() error=%v", err)
					return
				}
				conn, err := dial(context.Background(), "tcp", "collector.example.test:4318")
				if err != nil {
					t.Errorf("guarded dial error=%v", err)
					return
				}
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()
	if got, want := dialer.Calls(), int64(workers*25); got != want {
		t.Fatalf("underlying dial calls=%d; want %d", got, want)
	}
}

func mustV8URL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func v8IPs(raw ...string) []net.IPAddr {
	result := make([]net.IPAddr, 0, len(raw))
	for _, value := range raw {
		result = append(result, net.IPAddr{IP: net.ParseIP(value)})
	}
	return result
}

func assertV8ErrorBounded(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		return
	}
	message := err.Error()
	if len(message) > 96 {
		t.Fatalf("error length=%d; want <=96: %q", len(message), message)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("error %q contains forbidden content %q", message, value)
		}
	}
}

type staticV8Resolver struct {
	answers []net.IPAddr
	err     error
}

func (r staticV8Resolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]net.IPAddr(nil), r.answers...), r.err
}

type waitingV8Resolver struct{}

func (waitingV8Resolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type cancelingV8Resolver struct {
	cancel  context.CancelFunc
	answers []net.IPAddr
}

func (r cancelingV8Resolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.cancel()
	return r.answers, nil
}

type sequenceV8Resolver struct {
	mu      sync.Mutex
	answers [][]net.IPAddr
	calls   int
}

func (r *sequenceV8Resolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls >= len(r.answers) {
		return nil, errors.New("unexpected resolver call")
	}
	answers := append([]net.IPAddr(nil), r.answers[r.calls]...)
	r.calls++
	return answers, nil
}

func (r *sequenceV8Resolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type recordingV8Dialer struct {
	calls       atomic.Int64
	mu          sync.Mutex
	lastAddress string
	err         error
}

func (d *recordingV8Dialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.calls.Add(1)
	d.mu.Lock()
	d.lastAddress = address
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func (d *recordingV8Dialer) Calls() int64 { return d.calls.Load() }

func (d *recordingV8Dialer) LastAddress() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastAddress
}

type waitingV8Dialer struct{}

func (waitingV8Dialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
