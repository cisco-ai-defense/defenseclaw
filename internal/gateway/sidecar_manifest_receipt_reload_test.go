// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/managedaid"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func TestConfigReloadRebindsManifestGenerationAndFlagOnlyChanges(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	raw := func(include bool, retention int) []byte {
		return []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\nai_discovery:\n  enabled: false\n  include_skill_manifests: %t\nobservability:\n  local:\n    retention_days: %d\n", fixture.dataDir, include, retention))
	}
	initialRaw := raw(false, 7)
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, initialRaw); err != nil || !bound {
		t.Fatalf("bootstrap=%t %v", bound, err)
	}
	// Inject only publisher memory into this ordinary component fixture. The
	// host remains unmanaged; no Secure Client profile or credentials are used.
	state := managedPublishTestState(t)
	fixture.sidecar.inventoryPublish = state
	mgr := newConfigManagerWithSnapshot(fixture.configPath, initial, nil, nil, fixture.sidecar.observabilityV8ActivePlanDigest(), fixture.sidecar.applyConfigReloadSnapshot)
	reload := func(next []byte) {
		t.Helper()
		if err := os.WriteFile(fixture.configPath, next, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := mgr.Reload(t.Context(), "test"); err != nil {
			t.Fatal(err)
		}
	}
	reload(raw(false, 30))
	owner := fixture.sidecar.observabilityV8Emitter().(*sidecarOwnedObservabilityV8Runtime)
	state.mu.Lock()
	generation, epoch := state.receiptBinding.generation, state.receiptEpoch
	state.mu.Unlock()
	if generation != owner.runtime.Active().Generation() || generation < 2 {
		t.Fatal("normal graph reload retained the old receipt generation")
	}
	reload(raw(true, 30))
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.receiptEpoch <= epoch || state.receiptBinding.generation != owner.runtime.Active().Generation() {
		t.Fatal("manifest flag-only reload did not rebind receipts")
	}
	if state.receiptReader != nil {
		t.Fatal("unmanaged fixture acquired a managed receipt reader")
	}
}

func TestManifestReceiptBindingFollowsSwitchWithoutResolvingCredentials(t *testing.T) {
	runtime, _, _ := newManagedAIDFailOpenRuntime(t)
	plan, err := config.WithObservabilityV8ManagedAIDDestination(runtime.Active().Plan(), config.ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
		SourceContentHash: config.ObservabilityV8SourceContentHash([]byte("receipt-binding-component-fixture")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false)); err != nil {
		t.Fatal(err)
	}
	providerCalls := 0
	network := &receiptBindingNoNetwork{t: t}
	factory, err := destinations.NewFactory(destinations.Options{
		ManagedService: true,
		ConsoleStream:  destinations.ConsoleStderr,
		Stdout:         io.Discard, Stderr: io.Discard,
		Secrets: sidecarObservabilityV8SecretResolver{credentialsDir: t.TempDir()},
		CALoader: destinations.CAFileLoaderFunc(func(context.Context, string) ([]byte, error) {
			t.Fatal("binding tried to load a certificate")
			return nil, net.ErrClosed
		}),
		Resolver: network, Dialer: network,
		Warnings: push.WarningObserverFunc(func(push.Warning) {}),
		ManagedAIDProvider: managedaid.ProviderResolverFunc(func(context.Context) (cloudreg.Provider, error) {
			providerCalls++
			return nil, managedaid.ErrReceiptUnavailable
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	owner := &sidecarOwnedObservabilityV8Runtime{runtime: runtime, destinationFactory: factory}
	state := managedPublishTestState(t)
	sidecar := &Sidecar{inventoryPublish: state}
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	plan = runtime.Active().Plan()
	sidecar.bindManifestReceipts(t.Context(), owner, cfg, plan)
	if state.receiptReader != nil || network.lookups != 0 {
		t.Fatal("disabled manifest switch constructed a receipt reader")
	}
	cfg.AIDiscovery.IncludeSkillManifests = true
	sidecar.bindManifestReceipts(t.Context(), owner, cfg, plan)
	if state.receiptReader == nil || state.receiptBinding.generation != runtime.Active().Generation() || state.receiptBinding.current() != runtime.Active().Generation() {
		t.Fatal("enabled switch did not bind a current receipt reader")
	}
	cfg.AIDiscovery.IncludeSkillManifests = false
	lookups := network.lookups
	sidecar.bindManifestReceipts(t.Context(), owner, cfg, plan)
	if state.receiptReader != nil || providerCalls != 0 || network.lookups != lookups {
		t.Fatal("binding resolved credentials or retained a disabled reader")
	}
}

type receiptBindingNoNetwork struct {
	t       *testing.T
	lookups int
}

func (network *receiptBindingNoNetwork) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	// Transport construction performs DNS safety validation. Return a
	// synthetic public result without querying DNS or permitting a dial.
	network.lookups++
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

func (network *receiptBindingNoNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	network.t.Fatal("binding tried to dial a destination")
	return nil, net.ErrClosed
}
