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
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

// registerFakeCloudProvider installs a credential factory for one test.
// The OSS build registers none, so every managed test that expects to
// get past the guardrail's boot gate has to opt in.
func registerFakeCloudProvider(t *testing.T, provider cloudreg.Provider, buildErr error) {
	t.Helper()
	cloudreg.Register(func(cloudreg.Config) (cloudreg.Provider, error) {
		if buildErr != nil {
			return nil, buildErr
		}
		return provider, nil
	})
	t.Cleanup(func() { cloudreg.Register(nil) })
}

func managedInspectionSidecar(t *testing.T) *Sidecar {
	t.Helper()
	return &Sidecar{
		cfg: &config.Config{
			DataDir:        t.TempDir(),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Guardrail:      config.GuardrailConfig{Enabled: true},
		},
		health: NewSidecarHealth(),
	}
}

func TestManagedGuardrailRefusesABuildWithNoCredentialProvider(t *testing.T) {
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	s := managedInspectionSidecar(t)

	err := s.runManagedEnterpriseMultiHookGuardrail(
		context.Background(), reg, []connector.Connector{conn}, "gateway-token", "a", "b", "master",
	)
	if !errors.Is(err, cloudreg.ErrNoProviderRegistered) {
		t.Fatalf("error = %v, want %v", err, cloudreg.ErrNoProviderRegistered)
	}
	if state := s.health.Snapshot().Guardrail.State; state != StateError {
		t.Fatalf("guardrail state = %s, want %s", state, StateError)
	}
	if conn.credsSet {
		t.Fatal("connector credentials were installed by a build that cannot inspect")
	}
}

func TestEnsureCMIDProviderRecordsInspectionAvailability(t *testing.T) {
	s := managedInspectionSidecar(t)
	if available, _ := s.inspectionAvailability(); available {
		t.Fatal("inspection reported available before a provider was built")
	}

	registerFakeCloudProvider(t, nil, errors.New("cmidapi.dll: cannot find the file specified"))
	if _, err := s.ensureCMIDProvider(context.Background()); err == nil {
		t.Fatal("ensureCMIDProvider succeeded without a loadable library")
	}
	available, detail := s.inspectionAvailability()
	if available {
		t.Fatal("inspection reported available after the provider failed to build")
	}
	if !strings.Contains(detail, "cannot find the file specified") {
		t.Fatalf("inspection detail = %q, want the provider's failure", detail)
	}

	registerFakeCloudProvider(t, newFakeCloudProvider("token"), nil)
	if _, err := s.ensureCMIDProvider(context.Background()); err != nil {
		t.Fatalf("ensureCMIDProvider: %v", err)
	}
	if available, detail := s.inspectionAvailability(); !available || detail != "" {
		t.Fatalf("inspection availability = %t (%q), want true with no detail", available, detail)
	}
}
