// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard/netguardtest"
)

// namedResolver answers only the names it maps, each with one address.
type namedResolver map[string]string

func (r namedResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	address, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
}

func routeTestBackend(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "reached "+r.Host)
	}))
	t.Cleanup(backend.Close)
	_, port, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return backend, port
}

// guardedRouteClient is an outbound client shaped like the telemetry
// exporters: the V8 destination check over an enterprise route.
func guardedRouteClient(route *EgressRoute, resolver V8Resolver) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: V8SafeDialContext(V8NetworkSafetyPolicy{AllowPrivateNetworks: true}, route.Dialer(&net.Dialer{Timeout: 5 * time.Second}), resolver),
	}, Timeout: 10 * time.Second}
}

func getBody(t *testing.T, client *http.Client, target string) (string, error) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

func TestEgressRouteTunnelsCheckedDestinationsThroughTheProxy(t *testing.T) {
	backend, port := routeTestBackend(t)
	proxy := netguardtest.NewRecordingProxy(t, map[string]string{
		"collector.example.test:" + port: backend.Listener.Addr().String(),
	})
	route, err := (EgressProxy{HTTPSProxy: proxy.URL + "/", NoProxy: "direct.example.test"}).Route()
	if err != nil || route == nil {
		t.Fatalf("Route() = %v, %v", route, err)
	}
	if got := route.URL().String(); got != proxy.URL {
		t.Fatalf("route URL = %q, want %q", got, proxy.URL)
	}
	client := guardedRouteClient(route, namedResolver{
		"collector.example.test": "127.0.0.1",
		"direct.example.test":    "127.0.0.1",
		"metadata.example.test":  "169.254.169.254",
	})

	// A covered destination is checked, then reached by name through the
	// proxy (the name does not resolve anywhere but in the check).
	body, err := getBody(t, client, "http://collector.example.test:"+port+"/v1/logs")
	if err != nil || body != "reached collector.example.test:"+port {
		t.Fatalf("proxied request = %q, %v", body, err)
	}
	// no_proxy connects directly to the checked address.
	body, err = getBody(t, client, "http://direct.example.test:"+port+"/")
	if err != nil || body != "reached direct.example.test:"+port {
		t.Fatalf("no_proxy request = %q, %v", body, err)
	}
	// Loopback always connects directly.
	if _, err := getBody(t, client, backend.URL); err != nil {
		t.Fatalf("loopback request: %v", err)
	}
	// The destination check still runs before the proxy is asked.
	if _, err := getBody(t, client, "http://metadata.example.test:"+port+"/"); !errors.Is(err, ErrV8AddressProhibited) {
		t.Fatalf("a prohibited destination must fail its check before the proxy, got %v", err)
	}
	if got, want := proxy.Targets(), []string{"collector.example.test:" + port}; !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy CONNECT targets = %v, want %v", got, want)
	}
}

func TestEgressRouteCarriesTLSToTheDestinationAndSupportsAnHTTPSProxy(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls "+r.Host)
	}))
	t.Cleanup(backend.Close)
	_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())
	// The proxy reuses the test certificate (valid for 127.0.0.1).
	proxy := netguardtest.NewTLSRecordingProxy(t, map[string]string{
		"judge.example.test:" + port: backend.Listener.Addr().String(),
	}, &tls.Config{Certificates: backend.TLS.Certificates})
	if !strings.HasPrefix(proxy.URL, "https://") {
		t.Fatalf("TLS proxy URL = %q", proxy.URL)
	}
	route, err := (EgressProxy{HTTPSProxy: proxy.URL}).Route()
	if err != nil {
		t.Fatal(err)
	}
	route.proxyTLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client := guardedRouteClient(route, namedResolver{"judge.example.test": "127.0.0.1"})
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "example.com"}
	body, err := getBody(t, client, "https://judge.example.test:"+port+"/v1")
	if err != nil || body != "tls judge.example.test:"+port {
		t.Fatalf("TLS through an https:// proxy = %q, %v", body, err)
	}
	if got := proxy.Targets(); len(got) != 1 || got[0] != "judge.example.test:"+port {
		t.Fatalf("proxy CONNECT targets = %v", got)
	}
}

func TestEgressRouteReportsARefusedConnect(t *testing.T) {
	proxy := netguardtest.NewRecordingProxy(t, nil)
	route, err := (EgressProxy{HTTPSProxy: proxy.URL}).Route()
	if err != nil {
		t.Fatal(err)
	}
	_, err = route.Dial(WithDialTarget(context.Background(), "blocked.example.test"), &net.Dialer{}, "tcp", "203.0.113.9:443")
	if err == nil || !strings.Contains(err.Error(), "refused CONNECT blocked.example.test:443") {
		t.Fatalf("refused CONNECT error = %v", err)
	}
}

func TestEgressRouteHonorsTheCallerDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn // never answers the CONNECT
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})
	route, err := (EgressProxy{HTTPSProxy: "http://" + listener.Addr().String()}).Route()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = route.Dial(ctx, &net.Dialer{}, "tcp", "api.example.test:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent proxy error = %v, want the context deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("CONNECT waited %s past the caller deadline", elapsed)
	}
}

func TestEgressRouteWithoutAProxyDialsDirectly(t *testing.T) {
	route, err := (EgressProxy{NoProxy: "internal.corp"}).Route()
	if err != nil || route != nil {
		t.Fatalf("Route() without a proxy = %v, %v; want no route", route, err)
	}
	direct := &net.Dialer{}
	if got := route.Dialer(direct); got != V8Dialer(direct) {
		t.Fatalf("a nil route must hand back the direct dialer, got %T", got)
	}
	if route.URL() != nil || route.ID() != "" {
		t.Fatal("a nil route has no proxy URL or identity")
	}
	if proxied, err := route.Proxies(&url.URL{Scheme: "https", Host: "api.example.com"}); proxied || err != nil {
		t.Fatalf("a nil route proxies nothing: %v, %v", proxied, err)
	}
	if _, err := (EgressProxy{HTTPSProxy: "socks5://proxy.corp:1080"}).Route(); err == nil {
		t.Fatal("an invalid proxy must fail route compilation")
	}
}

func TestEgressRouteSelection(t *testing.T) {
	route, err := (EgressProxy{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp,10.0.0.0/8,svc.example.com:8443"}).Route()
	if err != nil {
		t.Fatal(err)
	}
	if route.ID() != "http://proxy.corp:3128|internal.corp,10.0.0.0/8,svc.example.com:8443" {
		t.Fatalf("route ID = %q", route.ID())
	}
	if route.proxyAddr != "proxy.corp:3128" {
		t.Fatalf("proxy address = %q", route.proxyAddr)
	}
	for target, want := range map[string]bool{
		"https://api.example.com/v1":       true,
		"http://api.example.com:8080/v1":   true,
		"https://svc.internal.corp/x":      false,
		"https://10.1.2.3/x":               false,
		"https://127.0.0.1:18970/x":        false,
		"https://localhost:4318/v1/logs":   false,
		"https://svc.example.com:8443/api": false,
		"https://svc.example.com/api":      true,
	} {
		parsed, _ := url.Parse(target)
		got, err := route.Proxies(parsed)
		if err != nil || got != want {
			t.Errorf("Proxies(%s) = %v, %v; want %v", target, got, err, want)
		}
	}
	defaultPort, err := (EgressProxy{HTTPSProxy: "https://proxy.corp"}).Route()
	if err != nil || defaultPort.proxyAddr != "proxy.corp:443" {
		t.Fatalf("https proxy default port: %v, %v", defaultPort, err)
	}
}
