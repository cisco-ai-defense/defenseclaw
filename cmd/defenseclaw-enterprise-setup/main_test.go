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
