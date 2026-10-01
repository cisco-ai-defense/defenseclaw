// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/netguard/netguardtest"
)

func standaloneEgressConfig(proxy, noProxy string) *config.Config {
	return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{
		Profile: managed.ProfileStandalone,
		Network: config.EnterpriseNetworkConfig{HTTPSProxy: proxy, NoProxy: noProxy},
	}}
}

// useEnterpriseEgress installs a standalone route for one test.
func useEnterpriseEgress(t *testing.T, proxy, noProxy string) {
	t.Helper()
	if err := SetEnterpriseEgress(standaloneEgressConfig(proxy, noProxy)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { enterpriseEgress.Store(nil) })
}

// egressNames maps destination names to one address each.
type egressNames map[string]string

func (n egressNames) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	address, ok := n[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
}

// useSecureDialNames makes secureDialContext resolve names for one test.
func useSecureDialNames(t *testing.T, names egressNames) {
	t.Helper()
	secureDialResolverOverride.Store(&secureDialResolverBox{resolver: names})
	t.Cleanup(func() { secureDialResolverOverride.Store(nil) })
}

// egressBackend is a local server; port is its listening port.
func egressBackend(t *testing.T, handler http.HandlerFunc) (server *httptest.Server, port string) {
	t.Helper()
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return server, port
}

func echoHost(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, "reached "+r.Host)
}

func readReached(t *testing.T, response *http.Response, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestSetEnterpriseEgressAppliesOnlyToTheStandaloneProfile(t *testing.T) {
	t.Cleanup(func() { enterpriseEgress.Store(nil) })
	network := config.EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}
	for _, tc := range []struct {
		name  string
		cfg   *config.Config
		proxy string
	}{
		{name: "standalone with a proxy", cfg: standaloneEgressConfig(network.HTTPSProxy, network.NoProxy), proxy: "http://proxy.corp:3128"},
		{name: "standalone without a proxy", cfg: standaloneEgressConfig("", "")},
		{name: "secure client", cfg: &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}},
		{name: "unmanaged", cfg: &config.Config{Enterprise: config.EnterpriseConfig{Network: network}}},
		{name: "no config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enterpriseEgress.Store(nil)
			if tc.proxy == "" {
				// A previous route must be cleared, not kept.
				if err := SetEnterpriseEgress(standaloneEgressConfig("http://stale.corp:3128", "")); err != nil {
					t.Fatal(err)
				}
			}
			if err := SetEnterpriseEgress(tc.cfg); err != nil {
				t.Fatal(err)
			}
			route := currentEnterpriseEgress()
			if tc.proxy == "" {
				if route != nil {
					t.Fatalf("route = %s, want none", route.URL())
				}
				return
			}
			if route == nil || route.URL().String() != tc.proxy {
				t.Fatalf("route = %v, want %s", route, tc.proxy)
			}
		})
	}
	if err := SetEnterpriseEgress(standaloneEgressConfig("socks5://proxy.corp:1080", "")); err == nil {
		t.Fatal("an invalid enterprise proxy must fail gateway startup")
	}
}

func TestStandaloneWebhookClientReachesItsEndpointThroughTheEnterpriseProxy(t *testing.T) {
	backend, port := egressBackend(t, echoHost)
	proxy := netguardtest.NewRecordingProxy(t, map[string]string{"hooks.example.test:" + port: backend.Listener.Addr().String()})
	useEnterpriseEgress(t, proxy.URL, "direct.example.test")
	useSecureDialNames(t, egressNames{
		"hooks.example.test":    "127.0.0.1",
		"direct.example.test":   "127.0.0.1",
		"metadata.example.test": "169.254.169.254",
	})
	client := newWebhookHTTPClient(true, nil)

	response, err := client.Post("http://hooks.example.test:"+port+"/notify", "application/json", strings.NewReader(`{}`))
	if got := readReached(t, response, err); got != "reached hooks.example.test:"+port {
		t.Fatalf("webhook through the proxy = %q", got)
	}
	response, err = client.Post("http://direct.example.test:"+port+"/notify", "application/json", strings.NewReader(`{}`))
	if got := readReached(t, response, err); got != "reached direct.example.test:"+port {
		t.Fatalf("no_proxy webhook = %q", got)
	}
	// The destination check still runs first: the proxy is never asked to
	// reach an address the webhook client refuses.
	if _, err := client.Post("http://metadata.example.test:"+port+"/", "application/json", strings.NewReader(`{}`)); err == nil ||
		!strings.Contains(err.Error(), "unsafe IP") {
		t.Fatalf("webhook to a refused address = %v", err)
	}
	if got, want := proxy.Targets(), []string{"hooks.example.test:" + port}; !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy CONNECT targets = %v, want %v", got, want)
	}
}

// Every other standalone egress client reaches its destination through
// enterprise.network.https_proxy: the LLM passthrough, the remote model
// router, the telemetry dialer (which connects directly without a route) and
// a Bifrost judge provider.
func TestStandaloneEgressClientsGoThroughTheEnterpriseProxy(t *testing.T) {
	judge := func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-egress","object":"chat.completion","created":1,"model":"gpt-4o-mini",`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":"verdict: allow"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
	}
	routerHealth := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
		}
	}
	for _, tc := range []struct {
		name, host string
		handler    http.HandlerFunc
		call       func(t *testing.T, host, port string)
	}{
		{"passthrough", "llm.example.test", echoHost, func(t *testing.T, host, port string) {
			useSecureDialNames(t, egressNames{host: "127.0.0.1"})
			providerHTTPClient.CloseIdleConnections()
			t.Cleanup(providerHTTPClient.CloseIdleConnections)
			response, err := providerHTTPClient.Get("http://" + host + ":" + port + "/v1/models")
			if got := readReached(t, response, err); got != "reached "+host+":"+port {
				t.Fatalf("passthrough through the proxy = %q", got)
			}
		}},
		{"remote model router", "router.example.test", routerHealth, func(t *testing.T, host, port string) {
			if !newRemoteRouterClient("http://"+host+":"+port, 1000, nil, "").Healthy(context.Background()) {
				t.Fatal("the remote router must be reachable through the enterprise proxy")
			}
		}},
		{"telemetry dialer", "collector.example.test", echoHost, func(t *testing.T, host, port string) {
			// The dialer the observability factory receives, below the
			// exporters' own destination check.
			dial := netguard.V8SafeDialContext(netguard.V8NetworkSafetyPolicy{AllowPrivateNetworks: true},
				enterpriseEgressDialer{direct: &net.Dialer{}}, egressNames{host: "127.0.0.1"})
			client := &http.Client{Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true}, Timeout: 10 * time.Second}
			response, err := client.Get("http://" + host + ":" + port + "/v1/logs")
			if got := readReached(t, response, err); got != "reached "+host+":"+port {
				t.Fatalf("telemetry through the proxy = %q", got)
			}
			enterpriseEgress.Store(nil)
			response, err = client.Get("http://127.0.0.1:" + port)
			if got := readReached(t, response, err); !strings.HasPrefix(got, "reached 127.0.0.1:") {
				t.Fatalf("telemetry without a route = %q, want a direct connection", got)
			}
		}},
		{"bifrost judge", "judge.example.test", judge, func(t *testing.T, host, port string) {
			provider, err := NewProviderWithBase("openai/gpt-4o-mini", "sk-egress-test", "http://"+host+":"+port)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			response, err := provider.ChatCompletion(ctx, &ChatRequest{
				Model:    "gpt-4o-mini",
				Messages: []ChatMessage{{Role: "user", Content: "classify this"}},
			})
			if err != nil || len(response.Choices) != 1 || response.ID != "chatcmpl-egress" {
				t.Fatalf("judge call through the proxy: %+v %v", response, err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, port := egressBackend(t, tc.handler)
			proxy := netguardtest.NewRecordingProxy(t, map[string]string{tc.host + ":" + port: backend.Listener.Addr().String()})
			useEnterpriseEgress(t, proxy.URL, "")
			tc.call(t, tc.host, port)
			if got := proxy.Targets(); len(got) == 0 || got[0] != tc.host+":"+port {
				t.Fatalf("proxy CONNECT targets = %v", got)
			}
		})
	}
}

func TestBifrostEgressProxySelection(t *testing.T) {
	route, err := (netguard.EgressProxy{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}).Route()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		endpoint string
		proxied  bool
	}{
		{endpoint: "", proxied: true}, // the provider's public default
		{endpoint: "https://judge.example.com/v1", proxied: true},
		{endpoint: "judge.example.com", proxied: true},
		{endpoint: "https://llm.internal.corp/v1"},
		{endpoint: "http://127.0.0.1:11434"},
		{endpoint: "http://localhost:8000/v1"},
	} {
		got, err := bifrostEgressProxy(route, tc.endpoint)
		if err != nil {
			t.Fatalf("%q: %v", tc.endpoint, err)
		}
		if !tc.proxied {
			if got != nil {
				t.Errorf("%q: proxy %+v, want a direct connection", tc.endpoint, got)
			}
			continue
		}
		if got == nil || got.Type != schemas.HTTPProxy || got.URL == nil || got.URL.GetValue() != "http://proxy.corp:3128" {
			t.Errorf("%q: proxy %+v, want the enterprise proxy", tc.endpoint, got)
		}
	}
	if got, err := bifrostEgressProxy(nil, "https://judge.example.com"); got != nil || err != nil {
		t.Fatalf("without a route: %v, %v", got, err)
	}
	tlsProxy, err := (netguard.EgressProxy{HTTPSProxy: "https://proxy.corp"}).Route()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bifrostEgressProxy(tlsProxy, "https://judge.example.com"); err == nil || !strings.Contains(err.Error(), "http:// proxy URL") {
		t.Fatalf("an https:// proxy must be refused for LLM providers instead of connecting directly, got %v", err)
	}
	if got, err := bifrostEgressProxy(tlsProxy, "http://127.0.0.1:11434"); got != nil || err != nil {
		t.Fatalf("an excluded endpoint needs no proxy support: %v, %v", got, err)
	}
}
