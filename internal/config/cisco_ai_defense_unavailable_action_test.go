// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestCiscoAIDefenseUnavailableActionNormalizes(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		want  string
		block bool
	}{
		{raw: "", want: AIDUnavailableActionAllow},
		{raw: "allow", want: AIDUnavailableActionAllow},
		{raw: "block", want: AIDUnavailableActionBlock, block: true},
		{raw: " Block ", want: AIDUnavailableActionBlock, block: true},
		{raw: "deny", want: AIDUnavailableActionAllow},
	} {
		cfg := &CiscoAIDefenseConfig{UnavailableAction: tc.raw}
		if got := cfg.EffectiveUnavailableAction(); got != tc.want {
			t.Errorf("EffectiveUnavailableAction(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if got := cfg.BlocksWhenUnavailable(); got != tc.block {
			t.Errorf("BlocksWhenUnavailable(%q) = %t, want %t", tc.raw, got, tc.block)
		}
	}
	var missing *CiscoAIDefenseConfig
	if missing.BlocksWhenUnavailable() {
		t.Fatal("nil config must keep the allow default")
	}
}

func TestRuntimeV8LoadsCiscoAIDefenseUnavailableAction(t *testing.T) {
	source := func(value string) []byte {
		return []byte("config_version: 8\n" +
			"data_dir: /tmp/defenseclaw-v8\n" +
			"cisco_ai_defense:\n" +
			"  unavailable_action: " + value + "\n" +
			"observability: {}\n")
	}
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", source("block"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CiscoAIDefense.BlocksWhenUnavailable() {
		t.Fatalf("unavailable_action = %q, want block", cfg.CiscoAIDefense.UnavailableAction)
	}
	// The file loader validates the canonical schema before decoding, so a
	// misspelled value is refused rather than silently read as allow.
	options := ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()}
	if _, err := ParseCompileObservabilityV8("config.yaml", source("block"), options); err != nil {
		t.Fatalf("schema rejected unavailable_action=block: %v", err)
	}
	if _, err := ParseCompileObservabilityV8("config.yaml", source("deny"), options); err == nil {
		t.Fatal("schema accepted unavailable_action=deny")
	}

	cfg, err = LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 8\ndata_dir: /tmp/defenseclaw-v8\nobservability: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.CiscoAIDefense.EffectiveUnavailableAction(); got != AIDUnavailableActionAllow {
		t.Fatalf("default unavailable_action = %q, want allow", got)
	}
}
