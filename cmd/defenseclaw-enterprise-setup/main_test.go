// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseEnterpriseSetupInstallContract(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{
		"/install",
		`CONFIG=C:\staging\config.yaml`,
		`MANIFEST=C:\staging\targets.yaml`,
		"NOSTART=1",
		"JSON=true",
		"TIMEOUTSECONDS=600",
	})
	if err != nil {
		t.Fatal(err)
	}
	if help {
		t.Fatal("install arguments unexpectedly requested help")
	}
	if opts.Action != "install" || opts.Config != `C:\staging\config.yaml` ||
		opts.Manifest != `C:\staging\targets.yaml` || !opts.NoStart || !opts.JSON ||
		opts.LifecycleTimeout != 10*time.Minute {
		t.Fatalf("parsed options = %+v", opts)
	}
}

func TestParseEnterpriseSetupRejectsUnsafeScopeCombinations(t *testing.T) {
	tests := [][]string{
		{"/install", "--config", "config.yaml"},
		{"/status", "--no-start"},
		{"/repair", "--purge"},
		{"/install", "--config", "config.yaml", "--manifest", "targets.yaml", "--allow-unsigned"},
		{"/repair", "--attest-codex-trusted-hook-launcher"},
		{"/verify", "--timeout-seconds", "59"},
	}
	for _, arguments := range tests {
		if _, _, err := parseEnterpriseSetupOptions(arguments); err == nil {
			t.Errorf("parseEnterpriseSetupOptions(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestParseEnterpriseSetupAcceptsDeploymentSystemNoOps(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{"/quiet", "/norestart", "/status"})
	if err != nil || help {
		t.Fatalf("parse status: help=%v err=%v", help, err)
	}
	if opts.Action != "status" {
		t.Fatalf("action = %q, want status", opts.Action)
	}
}

// TestParseEnterpriseSetupShorthandAcceptsModeAndConnector pins the
// macOS-parity QA shorthand: MODE + CONNECTOR alone satisfy the install
// contract (config / manifest are rendered by install-enterprise.ps1
// inside its bootstrap staging directory).
func TestParseEnterpriseSetupShorthandAcceptsModeAndConnector(t *testing.T) {
	opts, help, err := parseEnterpriseSetupOptions([]string{
		"/install",
		"MODE=action",
		"CONNECTOR=codex,cursor,claudecode",
		"JSON=1",
	})
	if err != nil || help {
		t.Fatalf("shorthand install: help=%v err=%v", help, err)
	}
	if opts.Action != "install" || opts.Mode != "action" ||
		opts.Connector != "codex,cursor,claudecode" || !opts.JSON {
		t.Fatalf("parsed = %+v", opts)
	}
	if opts.Config != "" || opts.Manifest != "" {
		t.Fatalf("shorthand must leave config/manifest empty, got %+v", opts)
	}
}

// TestParseEnterpriseSetupShorthandRejectsBadGrammar covers the
// mutual-exclusion and pairing invariants the shorthand enforces.
func TestParseEnterpriseSetupShorthandRejectsBadGrammar(t *testing.T) {
	tests := map[string][]string{
		"mode without connector": {"/install", "MODE=action"},
		"connector without mode": {"/install", "CONNECTOR=codex"},
		"mode + config":          {"/install", "MODE=action", "CONNECTOR=codex", "CONFIG=x.yaml"},
		"mode + manifest":        {"/install", "MODE=action", "CONNECTOR=codex", "MANIFEST=x.yaml"},
		"invalid mode":           {"/install", "MODE=paranoid", "CONNECTOR=codex"},
		"shorthand on status":    {"/status", "MODE=action", "CONNECTOR=codex"},
	}
	for name, arguments := range tests {
		if _, _, err := parseEnterpriseSetupOptions(arguments); err == nil {
			t.Errorf("%s: parseEnterpriseSetupOptions(%q) unexpectedly succeeded", name, arguments)
		}
	}
}

func TestPlaceholderBuildFailsClosedWithoutEnterprisePayload(t *testing.T) {
	_, err := loadEmbeddedEnterprisePayload()
	if err == nil || !strings.Contains(err.Error(), "build-windows-enterprise-installer.ps1") {
		t.Fatalf("loadEmbeddedEnterprisePayload() error = %v", err)
	}
}

func TestRunEnterpriseSetupHelpDoesNotInvokePlatform(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runEnterpriseSetup([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(stdout.String(), enterpriseSetupArtifactName) || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
