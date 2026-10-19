// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

func TestSandboxCommonPersistCurrentSource(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	for _, tc := range []struct {
		name, source, target string
		duplicate            bool
	}{
		{"legacy", "openshell: {egress: {unblocked: [old.example]}}", "openshell.egress.unblocked", false},
		{"common", "sandbox: {enabled: false, egress: {unblocked: [old.example]}}", "sandbox.egress.unblocked", false},
		{"inherited", "sandbox: {enabled: false}\nopenshell: {egress: {unblocked: [old.example]}}", "sandbox.egress.unblocked", true},
		{"duplicate", "sandbox: {enabled: false, egress: {unblocked: [old.example]}}\nopenshell: {egress: {unblocked: [old.example]}}", "sandbox.egress.unblocked", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			if err := os.WriteFile(path, sandboxReloadSource(dir, tc.source), 0o600); err != nil {
				t.Fatal(err)
			}
			live := loadSandboxReloadConfig(t, path, dir, tc.source)
			api := &APIServer{configSnapshot: func() *config.Config { return live }}
			api.configReloader = func(context.Context, string) error {
				raw, err := os.ReadFile(path)
				if err == nil {
					live, err = loadRuntimeConfigCandidate(path, raw)
				}
				return err
			}
			// A different writer commits after the gateway snapshot was loaded.
			changes := []configwrite.Change{{Path: tc.target, Value: []string{"old.example", "concurrent.example"}}}
			if tc.duplicate {
				changes = append(changes, configwrite.Change{Path: "openshell.egress.unblocked", Value: []string{"old.example", "concurrent.example"}})
			}
			if _, err := configwrite.Apply(context.Background(), path, changes, configwrite.Options{Actor: "cli:test"}); err != nil {
				t.Fatal(err)
			}
			p := sandboxConfigPersister{api: api}
			if err := p.AllowAlways(context.Background(), "new.example"); err != nil {
				t.Fatal(err)
			}
			want := []string{"old.example", "concurrent.example", "new.example"}
			if !slices.Equal(live.OpenShell.Egress.Unblocked, want) || len(live.OpenShell.Egress.Allow) != 0 {
				t.Fatalf("effective policy = %+v", live.OpenShell.Egress)
			}
			if live.Sandbox != nil && !slices.Equal(live.Sandbox.Egress.Unblocked, want) {
				t.Fatalf("common policy = %+v", live.Sandbox.Egress)
			}
			before, _ := os.ReadFile(path)
			generation, _ := configwrite.ReadGenerationState(path)
			if err := p.AllowAlways(context.Background(), "new.example"); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			repeated, _ := configwrite.ReadGenerationState(path)
			if string(before) != string(after) || generation != repeated {
				t.Fatal("repeated decision changed source or generation")
			}
			if err := p.BlockAlways(context.Background(), "blocked.example"); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(live.OpenShell.Egress.Block, []string{"blocked.example"}) {
				t.Fatal("block decision did not reach effective policy")
			}
		})
	}
}

func TestSandboxCommonPersistReloadRollback(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	source := "sandbox: {enabled: false, egress: {block: [old.example]}}"
	original := sandboxReloadSource(dir, source)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	live := loadSandboxReloadConfig(t, path, dir, source)
	want := errors.New("reload refused")
	calls := 0
	api := &APIServer{configSnapshot: func() *config.Config { return live }}
	api.configReloader = func(context.Context, string) error {
		calls++
		if calls == 1 {
			return want
		}
		return nil
	}
	err := (sandboxConfigPersister{api: api}).BlockAlways(context.Background(), "new.example")
	after, _ := os.ReadFile(path)
	if !errors.Is(err, want) || calls != 2 || string(after) != string(original) {
		t.Fatalf("reload rollback = %v, calls=%d, original restored=%v", err, calls, string(after) == string(original))
	}
}

func TestSandboxCommonDecisionPatchRefusesManagedSource(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	for _, source := range []string{
		"deployment_mode: managed_enterprise\nenterprise: {profile: standalone}",
		"deployment_mode: managed_enterprise\nenterprise: {profile: secure_client}",
	} {
		// Secure Client remains on its supported v8 graph.
		raw := []byte("config_version: 8\n" + source + "\n")
		_, err := sandboxDecisionPatch("", raw, "openshell.egress.block", "new.example")
		if !errors.Is(err, configwrite.ErrManaged) {
			t.Fatalf("managed decision patch = %v", err)
		}
	}
}
