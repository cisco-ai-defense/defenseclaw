// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestCreateRuntimeSelectionBeforeAnyLaunchPreparation(t *testing.T) {
	for _, test := range []struct {
		name, requested, configured, code string
		common, openshellEnabled          bool
	}{
		{"explicit axis", "axis", "", sandboxapi.CodeUnavailable, false, true},
		{"configured axis", "auto", "axis", sandboxapi.CodeUnavailable, true, true},
		{"unknown runtime", "other", "", sandboxapi.CodeInvalid, false, true},
		{"common adapter disabled", "openshell", "openshell", sandboxapi.CodeDisabled, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true}}
			if test.common {
				cfg.Sandbox = &config.SandboxConfig{Enabled: true, Runtime: test.configured,
					Runtimes: config.SandboxRuntimesConfig{OpenShell: config.SandboxRuntimeConfig{Enabled: test.openshellEnabled}}}
			}
			manager := &Manager{opts: Options{Config: func() *config.Config { return cfg },
				Listeners: func() error { t.Fatal("listener preparation before runtime refusal"); return nil },
				Connect:   func(context.Context) (*Gateway, error) { t.Fatal("gateway lookup before refusal"); return nil, nil }}}
			value, err := manager.Create(context.Background(), sandboxapi.CreateRequest{
				Runtime: test.requested, Project: "must-not-be-read", Harness: "must-not-be-resolved"})
			var refused *sandboxapi.Error
			if value != nil || !errors.As(err, &refused) || refused.Code != test.code {
				t.Fatalf("Create = %v, %v; want %s", value, err, test.code)
			}
		})
	}
}

func TestCreateLegacyOrExplicitOpenShellKeepsItsRoute(t *testing.T) {
	for _, requested := range []string{"", "auto", "openshell"} {
		cfg := &config.Config{OpenShell: config.OpenShellConfig{Enabled: true}}
		manager := &Manager{opts: Options{Config: func() *config.Config { return cfg },
			Listeners: func() error { return errors.New("test-owned listener sentinel") }}}
		_, err := manager.Create(context.Background(), sandboxapi.CreateRequest{Runtime: requested})
		var sentinel *sandboxapi.Error
		if !errors.As(err, &sentinel) || sentinel.Detail != "test-owned listener sentinel" {
			t.Fatalf("legacy route %q: %v", requested, err)
		}
	}
}
