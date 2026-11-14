// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/localobservability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// clusterResolver answers like a cluster DNS: every name resolves to one
// address (a Service ClusterIP), or fails when address is empty.
type clusterResolver struct{ address string }

func (resolver clusterResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	if resolver.address == "" {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	return []net.IPAddr{{IP: net.ParseIP(resolver.address)}}, nil
}

// refusingDialer fails the test if anything is dialed: a refused address
// must never be reached.
type refusingDialer struct{ t *testing.T }

func (dialer refusingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	dialer.t.Error("a destination dialed an address its network_safety refuses")
	return nil, net.ErrClosed
}

func newClusterFactory(t *testing.T, stderr io.Writer, address string, secureClient bool) *Factory {
	t.Helper()
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewFactory(Options{
		SecureClient:  secureClient,
		ConsoleStream: ConsoleStderr, Stdout: io.Discard, Stderr: stderr,
		Secrets:  &secretResolver{values: map[string]string{"HEC_TOKEN": "hec-token-value"}, calls: map[string]int{}},
		CALoader: &caLoader{bundles: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}},
		Resolver: clusterResolver{address: address}, Dialer: refusingDialer{t: t}, Warnings: &warningCollector{},
		RedactionEngine:       engine,
		DeliveryObserver:      delivery.ObserverFunc(func(delivery.HealthTransition) {}),
		OTLPCanonicalObserver: otlp.CanonicalObserverFunc(func(otlp.CanonicalFailure) {}),
		GalileoObserver:       galileo.CanonicalObserverFunc(func(galileo.CanonicalFailure) {}),
		LocalObserver:         localobservability.ObserverFunc(func(localobservability.Failure) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

// smkDestination is the GAP-0272 destination: an in-cluster collector
// Service, valid for config validate (a hostname is not checked offline).
func smkDestination(t *testing.T, safety config.ObservabilityV8NetworkSafetySource) config.ObservabilityV8EffectiveDestination {
	t.Helper()
	return compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "smk-otlp", Kind: config.ObservabilityV8DestinationOTLP,
		Endpoint: "http://opentelemetry-collector.otel-system.svc:4318",
		TLS:      config.ObservabilityV8TLSSource{Insecure: true}, NetworkSafety: safety,
	})
}

// GAP-0272: in a cluster the Service name resolves to a private ClusterIP.
// The start refused that answer with only adapter_prepare_failed, which the
// gateway reported as "observability v8 bootstrap failed: runtime_unavailable"
// for a config that config validate accepted. It now starts deferred and one
// line names the destination, the host and the option that allows it.
func TestGAP0272InClusterOTLPServiceStartsDeferredAndNamesTheFix(t *testing.T) {
	var stderr bytes.Buffer
	factory := newClusterFactory(t, &stderr, "10.96.12.34", false)
	adapter, cleanup, err := factory.PrepareDestination(t.Context(), smkDestination(t, config.ObservabilityV8NetworkSafetySource{}), testResourceContext(t))
	if err != nil || adapter == nil || cleanup == nil {
		t.Fatalf("an in-cluster OTLP Service must start (deferred): adapter=%T error=%v", adapter, err)
	}
	t.Cleanup(func() { _ = cleanup(context.Background()) })
	line := stderr.String()
	for _, want := range []string{
		`defenseclaw: observability destination "smk-otlp": endpoint host opentelemetry-collector.otel-system.svc`,
		"network_safety.allow_private_networks: true",
		"the gateway runs without this destination",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("deferred line %q does not say %q", line, want)
		}
	}
	if strings.Contains(line, "10.96.12.34") || strings.Count(line, "\n") != 1 {
		t.Fatalf("deferred line names the address or repeats: %q", line)
	}
	// The same destination again (a reload, or its trace pipeline) adds no line.
	_, cleanupAgain, err := factory.PrepareDestination(t.Context(), smkDestination(t, config.ObservabilityV8NetworkSafetySource{}), testResourceContext(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = cleanupAgain(context.Background())
	if strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("the deferred line repeated: %q", stderr.String())
	}
	// A delivery re-resolves and refuses the address without dialing it.
	counters := deliverOne(t, "smk-otlp", adapter, `{"event":"one"}`)
	if counters.Delivered != 0 {
		t.Fatalf("a refused address received a record: %+v", counters)
	}
	if factory.LastPreparationFailure() != "" {
		t.Fatalf("a deferred start is not a preparation failure: %q", factory.LastPreparationFailure())
	}
}

// With the option the destination is ready and says nothing.
func TestGAP0272AllowPrivateNetworksStartsTheServiceSilently(t *testing.T) {
	var stderr bytes.Buffer
	factory := newClusterFactory(t, &stderr, "10.96.12.34", false)
	adapter, cleanup, err := factory.PrepareDestination(t.Context(),
		smkDestination(t, config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true}), testResourceContext(t))
	if err != nil || adapter == nil {
		t.Fatalf("adapter=%T error=%v", adapter, err)
	}
	_ = cleanup(context.Background())
	if stderr.Len() != 0 {
		t.Fatalf("a ready destination wrote %q", stderr.String())
	}
}

// Secure Client keeps the origin/main start refusal, with no line (GAP-1018).
func TestGAP0272SecureClientKeepsTheRefusal(t *testing.T) {
	var stderr bytes.Buffer
	factory := newClusterFactory(t, &stderr, "10.96.12.34", true)
	adapter, _, err := factory.PrepareDestination(t.Context(), smkDestination(t, config.ObservabilityV8NetworkSafetySource{}), testResourceContext(t))
	if adapter != nil || !IsError(err, ErrorAdapterPrepare) || stderr.Len() != 0 || factory.LastPreparationFailure() != "" {
		t.Fatalf("secure client adapter=%T error=%v stderr=%q last=%q", adapter, err, stderr.String(), factory.LastPreparationFailure())
	}
}

// Validate/start parity for every push kind: a hostname config validate
// accepts starts, deferred, whatever its DNS answer, and the line names the
// destination and the fix for that answer.
func TestGAP0272PushKindsStartForEveryDNSAnswerAndNameTheFix(t *testing.T) {
	sources := map[string]config.ObservabilityV8DestinationSource{
		"otlp-grpc": {
			Name: "otlp-grpc", Kind: config.ObservabilityV8DestinationOTLP,
			Endpoint: "collector.observability.svc:4317", Protocol: "grpc",
			TLS: config.ObservabilityV8TLSSource{Insecure: true},
		},
		"otlp-http": {
			Name: "otlp-http", Kind: config.ObservabilityV8DestinationOTLP,
			Endpoint: "https://collector.observability.svc:4318", Protocol: "http/protobuf",
		},
		"hec": {
			Name: "hec", Kind: config.ObservabilityV8DestinationSplunkHEC,
			Endpoint: "https://splunk.observability.svc:8088/services/collector/event", TokenEnv: "HEC_TOKEN",
		},
		"archive": {
			Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
			Endpoint: "https://archive.observability.svc/ingest",
		},
	}
	answers := []struct {
		name, address, want string
	}{
		{"private", "10.96.0.20", "network_safety.allow_private_networks: true"},
		{"cgnat", "100.64.3.4", "network_safety.allow_cgnat: true"},
		{"metadata", "169.254.169.254", "no destination may reach"},
		{"no answer", "", "does not resolve"},
	}
	for name, source := range sources {
		for _, answer := range answers {
			t.Run(name+"/"+answer.name, func(t *testing.T) {
				var stderr bytes.Buffer
				factory := newClusterFactory(t, &stderr, answer.address, false)
				destination := compileDestination(t, source)
				adapter, cleanup, err := factory.PrepareDestination(t.Context(), destination, testResourceContext(t))
				if err != nil || adapter == nil {
					t.Fatalf("a destination config validate accepts must start: adapter=%T error=%v", adapter, err)
				}
				_ = cleanup(context.Background())
				line := stderr.String()
				if !strings.HasPrefix(line, `defenseclaw: observability destination "`+source.Name+`": endpoint host `) ||
					!strings.Contains(line, answer.want) {
					t.Fatalf("line %q does not name %s and %q", line, source.Name, answer.want)
				}
				if answer.address != "" && strings.Contains(line, answer.address) {
					t.Fatalf("line names the address: %q", line)
				}
			})
		}
	}
}

// Every refused start names the destination and the cause, on stderr and in
// LastPreparationFailure (the gateway's bootstrap error), with no endpoint,
// path or secret in the latter.
func TestGAP0272RefusalsNameTheDestinationAndTheCause(t *testing.T) {
	cases := []struct {
		name   string
		source config.ObservabilityV8DestinationSource
		want   string
	}{
		{
			name: "hec secret unset",
			source: config.ObservabilityV8DestinationSource{
				Name: "hec", Kind: config.ObservabilityV8DestinationSplunkHEC,
				Endpoint: "https://splunk.example.test:8088/services/collector/event", TokenEnv: "HEC_TOKEN_UNSET",
			},
			want: "a secret it names",
		},
		{
			name: "otlp header secret unset",
			source: config.ObservabilityV8DestinationSource{
				Name: "otlp-auth", Kind: config.ObservabilityV8DestinationOTLP,
				Endpoint: "https://otlp.example.test:4318", Protocol: "http/protobuf",
				Headers: map[string]config.ObservabilityV8HeaderValue{
					"Authorization": {Secret: &config.ObservabilityV8SecretRef{Env: "OTLP_AUTH_UNSET"}},
				},
			},
			want: "a secret it names",
		},
		{
			name: "otlp ca file missing",
			source: config.ObservabilityV8DestinationSource{
				Name: "otlp-ca", Kind: config.ObservabilityV8DestinationOTLP,
				Endpoint: "https://otlp.example.test:4318", Protocol: "http/protobuf",
				TLS: config.ObservabilityV8TLSSource{CACert: absoluteDestinationTestPath(t, "missing-ca.pem")},
			},
			want: "tls.ca_cert",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			factory := newClusterFactory(t, &stderr, "192.0.2.10", false)
			adapter, cleanup, err := factory.PrepareDestination(t.Context(), compileDestination(t, tc.source), testResourceContext(t))
			if adapter != nil || err == nil {
				t.Fatalf("adapter=%T error=%v", adapter, err)
			}
			if cleanup != nil {
				_ = cleanup(context.Background())
			}
			line := stderr.String()
			if !strings.HasPrefix(line, `defenseclaw: observability destination "`+tc.source.Name+`": `) ||
				!strings.Contains(line, tc.want) || !strings.HasSuffix(line, "or remove the destination\n") {
				t.Fatalf("refusal line %q", line)
			}
			last := factory.LastPreparationFailure()
			if !strings.HasPrefix(last, `destination "`+tc.source.Name+`": `) || !strings.Contains(last, tc.want) ||
				strings.Contains(last, "example.test") || strings.Contains(last, "UNSET") || strings.Contains(last, "missing-ca") {
				t.Fatalf("bootstrap cause %q", last)
			}
			if strings.Contains(err.Error(), tc.source.Name) {
				t.Fatalf("the returned error stays content-free: %v", err)
			}
		})
	}
}

// The jsonl refusal keeps its GAP-0890 line, and its bootstrap cause names no
// path.
func TestGAP0272JSONLRefusalKeepsItsLineAndAPathFreeCause(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	factory := newClusterFactory(t, &stderr, "", false)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "file", Kind: config.ObservabilityV8DestinationJSONL, Path: path,
	})
	adapter, _, err := factory.PrepareDestination(t.Context(), destination, telemetry.V8ResourceContext{})
	if adapter != nil || !IsError(err, ErrorAdapterPrepare) {
		t.Fatalf("a jsonl path that is a directory must refuse the start: adapter=%T error=%v", adapter, err)
	}
	line := stderr.String()
	if !strings.HasPrefix(line, `defenseclaw: observability destination "file": `+path+" is a directory") ||
		!strings.HasSuffix(line, "; fix the path or remove the destination\n") {
		t.Fatalf("jsonl refusal line %q", line)
	}
	if last := factory.LastPreparationFailure(); !strings.HasPrefix(last, `destination "file": `) || strings.Contains(last, path) {
		t.Fatalf("jsonl bootstrap cause %q", last)
	}
}

func TestV8ProhibitedOptionNamesTheOptionOnly(t *testing.T) {
	for address, want := range map[string]string{
		"10.0.0.1": "allow_private_networks", "127.0.0.1": "allow_private_networks", "fd00::1": "allow_private_networks",
		"100.64.0.1": "allow_cgnat", "169.254.169.254": "", "224.0.0.1": "",
	} {
		_, err := netguard.V8SafeDialContext(netguard.V8NetworkSafetyPolicy{}, refusingDialer{t: t}, clusterResolver{address: address})(
			t.Context(), "tcp", "collector.example.test:4317")
		if !strings.Contains(err.Error(), "prohibited") || netguard.V8ProhibitedOption(err) != want {
			t.Fatalf("%s: error=%v option=%q, want %q", address, err, netguard.V8ProhibitedOption(err), want)
		}
	}
}
