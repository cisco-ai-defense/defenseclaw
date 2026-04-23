// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestCodexWizardRegisteredBetweenObservabilityAndWebhooks(t *testing.T) {
	if wizardCodex != wizardObservability+1 {
		t.Fatalf("wizardCodex=%d want immediately after Observability=%d", wizardCodex, wizardObservability)
	}
	if wizardClaudeCode != wizardCodex+1 {
		t.Fatalf("wizardClaudeCode=%d want immediately after Codex=%d", wizardClaudeCode, wizardCodex)
	}
	if wizardWebhook != wizardClaudeCode+1 {
		t.Fatalf("wizardWebhook=%d want immediately after Claude Code=%d", wizardWebhook, wizardClaudeCode)
	}
	if wizardNames[wizardCodex] != "Codex" {
		t.Fatalf("wizard name=%q want Codex", wizardNames[wizardCodex])
	}
	want := []string{"setup", "codex"}
	got := wizardCommands[wizardCodex]
	if len(got) != len(want) {
		t.Fatalf("wizardCommands[wizardCodex]=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wizardCommands[wizardCodex][%d]=%q want %q", i, got[i], want[i])
		}
	}
	if !strings.Contains(wizardHowTo[wizardCodex], "defenseclaw setup codex") {
		t.Fatalf("Codex wizard how-to missing command: %q", wizardHowTo[wizardCodex])
	}
}

func TestClaudeCodeWizardRegisteredBetweenCodexAndWebhooks(t *testing.T) {
	if wizardNames[wizardClaudeCode] != "Claude Code" {
		t.Fatalf("wizard name=%q want Claude Code", wizardNames[wizardClaudeCode])
	}
	want := []string{"setup", "claude-code"}
	got := wizardCommands[wizardClaudeCode]
	if len(got) != len(want) {
		t.Fatalf("wizardCommands[wizardClaudeCode]=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wizardCommands[wizardClaudeCode][%d]=%q want %q", i, got[i], want[i])
		}
	}
	if !strings.Contains(wizardHowTo[wizardClaudeCode], "defenseclaw setup claude-code") {
		t.Fatalf("Claude Code wizard how-to missing command: %q", wizardHowTo[wizardClaudeCode])
	}
}

func TestBuildWizardArgs_CodexDefaultsEnableFeature(t *testing.T) {
	p := &SetupPanel{wizRunIdx: wizardCodex}
	p.wizFormFields = p.wizardFormDefs(wizardCodex)

	args := p.buildWizardArgs(wizardCodex)
	joined := strings.Join(args, " ")

	wantPrefix := []string{"setup", "codex", "--non-interactive"}
	for i, w := range wantPrefix {
		if i >= len(args) || args[i] != w {
			t.Fatalf("args prefix=%v want %v", args[:min(len(args), len(wantPrefix))], wantPrefix)
		}
	}
	if !strings.Contains(joined, "--enable-feature") {
		t.Fatalf("Codex wizard should enable feature flag by default; args=%v", args)
	}
	if strings.Contains(joined, "--scope user") {
		t.Fatalf("default scope should be skipped for non-observability wizard; args=%v", args)
	}
}

func TestBuildWizardArgs_CodexChangedFields(t *testing.T) {
	p := &SetupPanel{wizRunIdx: wizardCodex}
	p.wizFormFields = p.wizardFormDefs(wizardCodex)
	for i := range p.wizFormFields {
		switch p.wizFormFields[i].Flag {
		case "--scope":
			p.wizFormFields[i].Value = "repo"
		case "--scan-on-stop":
			p.wizFormFields[i].Value = "no"
		case "--fail-closed":
			p.wizFormFields[i].Value = "yes"
		}
	}

	args := p.buildWizardArgs(wizardCodex)
	joined := strings.Join(args, " ")
	for _, want := range []string{"--scope repo", "--no-scan-on-stop", "--fail-closed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args missing %q: %v", want, args)
		}
	}
}

func TestBuildWizardArgs_ClaudeCodeChangedFields(t *testing.T) {
	p := &SetupPanel{wizRunIdx: wizardClaudeCode}
	p.wizFormFields = p.wizardFormDefs(wizardClaudeCode)
	for i := range p.wizFormFields {
		switch p.wizFormFields[i].Flag {
		case "--scope":
			p.wizFormFields[i].Value = "repo"
		case "--scan-on-stop":
			p.wizFormFields[i].Value = "no"
		case "--fail-closed":
			p.wizFormFields[i].Value = "yes"
		}
	}

	args := p.buildWizardArgs(wizardClaudeCode)
	joined := strings.Join(args, " ")
	wantPrefix := []string{"setup", "claude-code", "--non-interactive"}
	for i, w := range wantPrefix {
		if i >= len(args) || args[i] != w {
			t.Fatalf("args prefix=%v want %v", args[:min(len(args), len(wantPrefix))], wantPrefix)
		}
	}
	for _, want := range []string{"--scope repo", "--no-scan-on-stop", "--fail-closed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args missing %q: %v", want, args)
		}
	}
}

func TestSetupSections_CodexExposesConfigFields(t *testing.T) {
	cfg := config.DefaultConfig()
	p := NewSetupPanel(nil, cfg, nil)
	p.loadSections()

	var codex *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Codex" {
			codex = &p.sections[i]
			break
		}
	}
	if codex == nil {
		t.Fatal("Codex config section missing")
	}

	want := map[string]bool{
		"codex.enabled":                         false,
		"codex.mode":                            false,
		"codex.install_scope":                   false,
		"codex.fail_closed":                     false,
		"codex.scan_on_session_start":           false,
		"codex.scan_on_stop":                    false,
		"codex.component_scan_interval_minutes": false,
		"codex.scan_paths":                      false,
	}
	for _, f := range codex.Fields {
		if _, ok := want[f.Key]; ok {
			want[f.Key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("Codex section missing %s", key)
		}
	}
}

func TestSetupSections_ClaudeCodeExposesConfigFields(t *testing.T) {
	cfg := config.DefaultConfig()
	p := NewSetupPanel(nil, cfg, nil)
	p.loadSections()

	var section *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Claude Code" {
			section = &p.sections[i]
			break
		}
	}
	if section == nil {
		t.Fatal("Claude Code config section missing")
	}

	want := map[string]bool{
		"claude_code.enabled":                         false,
		"claude_code.mode":                            false,
		"claude_code.install_scope":                   false,
		"claude_code.fail_closed":                     false,
		"claude_code.scan_on_session_start":           false,
		"claude_code.scan_on_stop":                    false,
		"claude_code.component_scan_interval_minutes": false,
		"claude_code.scan_paths":                      false,
	}
	for _, f := range section.Fields {
		if _, ok := want[f.Key]; ok {
			want[f.Key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("Claude Code section missing %s", key)
		}
	}
}

func TestApplyConfigField_CodexRoundTrip(t *testing.T) {
	c := &config.Config{}

	applyConfigField(c, "codex.enabled", "true")
	applyConfigField(c, "codex.mode", "action")
	applyConfigField(c, "codex.install_scope", "repo")
	applyConfigField(c, "codex.fail_closed", "true")
	applyConfigField(c, "codex.scan_on_session_start", "false")
	applyConfigField(c, "codex.scan_on_stop", "false")
	applyConfigField(c, "codex.component_scan_interval_minutes", "15")
	applyConfigField(c, "codex.scan_paths", "a.py,b.go")

	if !c.Codex.Enabled || c.Codex.Mode != "action" || c.Codex.InstallScope != "repo" {
		t.Fatalf("basic Codex config fields did not stick: %+v", c.Codex)
	}
	if !c.Codex.FailClosed || c.Codex.ScanOnSessionStart || c.Codex.ScanOnStop {
		t.Fatalf("boolean Codex config fields did not stick: %+v", c.Codex)
	}
	if c.Codex.ComponentScanIntervalMinutes != 15 {
		t.Fatalf("component interval=%d want 15", c.Codex.ComponentScanIntervalMinutes)
	}
	if len(c.Codex.ScanPaths) != 2 || c.Codex.ScanPaths[0] != "a.py" || c.Codex.ScanPaths[1] != "b.go" {
		t.Fatalf("scan_paths=%v want [a.py b.go]", c.Codex.ScanPaths)
	}
}

func TestApplyConfigField_ClaudeCodeRoundTrip(t *testing.T) {
	c := &config.Config{}

	applyConfigField(c, "claude_code.enabled", "true")
	applyConfigField(c, "claude_code.mode", "action")
	applyConfigField(c, "claude_code.install_scope", "repo")
	applyConfigField(c, "claude_code.fail_closed", "true")
	applyConfigField(c, "claude_code.scan_on_session_start", "false")
	applyConfigField(c, "claude_code.scan_on_stop", "false")
	applyConfigField(c, "claude_code.component_scan_interval_minutes", "15")
	applyConfigField(c, "claude_code.scan_paths", "a.py,b.go")

	if !c.ClaudeCode.Enabled || c.ClaudeCode.Mode != "action" || c.ClaudeCode.InstallScope != "repo" {
		t.Fatalf("basic Claude Code config fields did not stick: %+v", c.ClaudeCode)
	}
	if !c.ClaudeCode.FailClosed || c.ClaudeCode.ScanOnSessionStart || c.ClaudeCode.ScanOnStop {
		t.Fatalf("boolean Claude Code config fields did not stick: %+v", c.ClaudeCode)
	}
	if c.ClaudeCode.ComponentScanIntervalMinutes != 15 {
		t.Fatalf("component interval=%d want 15", c.ClaudeCode.ComponentScanIntervalMinutes)
	}
	if len(c.ClaudeCode.ScanPaths) != 2 || c.ClaudeCode.ScanPaths[0] != "a.py" || c.ClaudeCode.ScanPaths[1] != "b.go" {
		t.Fatalf("scan_paths=%v want [a.py b.go]", c.ClaudeCode.ScanPaths)
	}
}

func TestCommandRegistryIncludesCodexSetupEntries(t *testing.T) {
	reg := BuildRegistry()
	want := map[string]bool{
		"setup codex":                   false,
		"setup codex --status":          false,
		"setup codex --scan-components": false,
	}
	for _, entry := range reg {
		if _, ok := want[entry.TUIName]; ok {
			want[entry.TUIName] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("command registry missing %q", name)
		}
	}
}

func TestCommandRegistryIncludesClaudeCodeSetupEntries(t *testing.T) {
	reg := BuildRegistry()
	want := map[string]bool{
		"setup claude-code":                   false,
		"setup claude-code --status":          false,
		"setup claude-code --scan-components": false,
	}
	for _, entry := range reg {
		if _, ok := want[entry.TUIName]; ok {
			want[entry.TUIName] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("command registry missing %q", name)
		}
	}
}
