// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestNewEnterpriseWindowsEnumerateCommandRegistersFlags pins the
// public CLI surface — a maintainer who renames a flag in the
// registrar breaks this test immediately, forcing them to think
// about backwards compat (SCM ImagePath strings baked into installed
// services).
func TestNewEnterpriseWindowsEnumerateCommandRegistersFlags(t *testing.T) {
	cmd := newEnterpriseWindowsEnumerateCommand()
	if cmd.Use != "enumerate" {
		t.Fatalf("cobra Use = %q, want %q", cmd.Use, "enumerate")
	}
	for _, name := range []string{"manifest", "interval", "once", "initial-cycle-delay"} {
		if flag := cmd.Flags().Lookup(name); flag == nil {
			t.Fatalf("flag %q not registered", name)
		}
	}
	// Normalize whitespace before matching. The raw `cmd.Long` block
	// wraps at column ~80 with two-space indent, so any assertion
	// phrase that spans a wrap point (e.g. "omitted from the
	// manifest" reflows as "omitted from the\n    manifest") would
	// spuriously fail a byte-level `strings.Contains`. Collapsing
	// every run of whitespace to a single space lets the assertions
	// focus on semantic content rather than the reflow shape, and
	// stays robust when the surrounding paragraph is edited.
	long := strings.Join(strings.Fields(cmd.Long), " ")
	if !strings.Contains(long, "publishes an updated targets.yaml") ||
		!strings.Contains(long, "auto-authorizing") ||
		!strings.Contains(long, "omitted from the manifest without failing the cycle") ||
		!strings.Contains(long, "macOS parity") {
		t.Fatalf("command documentation does not describe the macOS-parity auto-authorize posture:\n%s", cmd.Long)
	}
}

// TestRunEnterpriseWindowsEnumerateRejectsMissingManifest asserts
// the CLI refuses to run without an explicit `--manifest` path. The
// helper is invoked via cobra so the shape mirrors production.
func TestRunEnterpriseWindowsEnumerateRejectsMissingManifest(t *testing.T) {
	cmd := newEnterpriseWindowsEnumerateCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	err := runEnterpriseWindowsEnumerate(context.Background(), cmd, &enterpriseWindowsEnumerateOptions{})
	if err == nil {
		t.Fatal("empty --manifest: want error, got nil")
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("error should cite --manifest: %v", err)
	}
}

// TestRunEnterpriseWindowsEnumerateRejectsRelativeManifest asserts a
// relative --manifest path is refused — same discipline the
// installer already uses for other file arguments (a service
// ImagePath resolved against SCM's cwd could point at an
// unexpected location).
func TestRunEnterpriseWindowsEnumerateRejectsRelativeManifest(t *testing.T) {
	cmd := newEnterpriseWindowsEnumerateCommand()
	cmd.SetErr(new(bytes.Buffer))
	err := runEnterpriseWindowsEnumerate(context.Background(), cmd, &enterpriseWindowsEnumerateOptions{
		manifestPath: `relative\path\targets.yaml`,
		once:         true,
	})
	if err == nil {
		t.Fatal("relative --manifest: want error, got nil")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error should cite 'absolute': %v", err)
	}
}

// TestRunEnterpriseWindowsEnumerateOnceHonoursMissingConfig asserts
// the --once path returns the specific "config missing" error
// upward so the installer's shell-out can distinguish "no config
// yet" from "cycle wrote a manifest" — a distinguishable exit
// signature.
func TestRunEnterpriseWindowsEnumerateOnceHonoursMissingConfig(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")

	prev := enterpriseWindowsEnumerateConfigLoader
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return nil, errors.New("open C:\\ProgramData\\Cisco\\...\\config.yaml: The system cannot find the file specified.")
	}
	defer func() { enterpriseWindowsEnumerateConfigLoader = prev }()

	cmd := newEnterpriseWindowsEnumerateCommand()
	stderr := new(bytes.Buffer)
	cmd.SetErr(stderr)
	err := runEnterpriseWindowsEnumerate(context.Background(), cmd, &enterpriseWindowsEnumerateOptions{
		manifestPath: manifest,
		once:         true,
	})
	if err == nil {
		t.Fatal("--once with missing config: want error, got nil")
	}
	if !isEnterpriseWindowsEnumerateConfigMissing(err) {
		t.Fatalf("error not recognised as config-missing: %v", err)
	}
	if !strings.Contains(stderr.String(), "waiting_for_config") {
		t.Fatalf("stderr should mention waiting_for_config; got: %s", stderr.String())
	}
}

// TestRunEnterpriseWindowsEnumerateOnceRefusesNonManagedEnterprise
// pins the deploy-mode gate: the enumerator MUST NOT run on
// non-managed-enterprise builds. If an operator points the CLI at a
// dev/BYOD config the command errors out rather than silently
// walking the local users.
func TestRunEnterpriseWindowsEnumerateOnceRefusesNonManagedEnterprise(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")

	prev := enterpriseWindowsEnumerateConfigLoader
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: "unmanaged_byod"}, nil
	}
	defer func() { enterpriseWindowsEnumerateConfigLoader = prev }()

	cmd := newEnterpriseWindowsEnumerateCommand()
	cmd.SetErr(new(bytes.Buffer))
	err := runEnterpriseWindowsEnumerate(context.Background(), cmd, &enterpriseWindowsEnumerateOptions{
		manifestPath: manifest,
		once:         true,
	})
	if err == nil {
		t.Fatal("non-managed-enterprise deploy mode: want error, got nil")
	}
	if !strings.Contains(err.Error(), "managed_enterprise") {
		t.Fatalf("error should cite managed_enterprise: %v", err)
	}
}

func TestRunEnterpriseWindowsEnumerateServiceAuditNeverPublishesNewProfile(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "targets.yaml")
	committed := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{
			SID:          "S-1-5-21-1000-2000-3000-1001",
			UserHome:     `C:\Users\Alice`,
			Connector:    "codex",
			DataDir:      `C:\Users\Alice\.defenseclaw`,
			AgentVersion: "1.2.3",
		},
	}}
	disabled := false
	discovered := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		committed.Targets[0],
		{
			SID:       "S-1-5-21-1000-2000-3000-1002",
			UserHome:  `C:\Users\Bob`,
			Connector: "codex",
			DataDir:   `C:\Users\Bob\.defenseclaw`,
			Enabled:   &disabled,
		},
	}}

	previousConfigLoader := enterpriseWindowsEnumerateConfigLoader
	previousManifestLoader := enterpriseWindowsEnumerateManifestLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	defer func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfigLoader
		enterpriseWindowsEnumerateManifestLoader = previousManifestLoader
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
	}()
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, nil
	}
	loadCount := 0
	enterpriseWindowsEnumerateManifestLoader = func(path string) (enterprisehooks.Manifest, string, error) {
		loadCount++
		if path != manifestPath {
			t.Fatalf("manifest loader path = %q, want %q", path, manifestPath)
		}
		return committed, strings.Repeat("a", 64), nil
	}
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		if opts.ExistingManifestPath != manifestPath {
			t.Fatalf("enumerator existing manifest = %q, want %q", opts.ExistingManifestPath, manifestPath)
		}
		// The package enumerator still has a legacy message describing a new
		// row as emitted. Audit mode must suppress it because it writes nothing.
		opts.Logger(discovered.Targets[1].SID, "newly-discovered (SID, codex) row emitted as disabled; admin must enable")
		return discovered, nil
	}
	writerCalled := false
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) {
		writerCalled = true
		return false, errors.New("service audit must not call manifest writer")
	}

	stderr := new(bytes.Buffer)
	err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), stderr, manifestPath, false)
	if err != nil {
		t.Fatalf("service audit: %v", err)
	}
	if writerCalled {
		t.Fatal("service audit called the manifest publication primitive")
	}
	if loadCount != 2 {
		t.Fatalf("authenticated manifest loads = %d, want 2", loadCount)
	}
	output := stderr.String()
	for _, want := range []string{
		"discovered uncommitted target sid=S-1-5-21-1000-2000-3000-1002 connector=codex",
		"targets.yaml unchanged",
		"administrator Repair or Upgrade",
		"publication=disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("service audit output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "emitted as disabled") {
		t.Fatalf("service audit retained inaccurate publication log:\n%s", output)
	}
}

func TestRunEnterpriseWindowsEnumerateServiceAuditRejectsManifestGenerationChange(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "targets.yaml")
	committed := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}

	previousConfigLoader := enterpriseWindowsEnumerateConfigLoader
	previousManifestLoader := enterpriseWindowsEnumerateManifestLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	defer func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfigLoader
		enterpriseWindowsEnumerateManifestLoader = previousManifestLoader
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
	}()
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, nil
	}
	loadCount := 0
	enterpriseWindowsEnumerateManifestLoader = func(string) (enterprisehooks.Manifest, string, error) {
		loadCount++
		return committed, strings.Repeat(string(rune('a'+loadCount-1)), 64), nil
	}
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		return committed, nil
	}
	writerCalled := false
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) {
		writerCalled = true
		return false, nil
	}

	err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifestPath, false)
	if err == nil || !strings.Contains(err.Error(), "changed during profile audit") {
		t.Fatalf("manifest generation change error = %v", err)
	}
	if writerCalled {
		t.Fatal("mixed-generation audit called the manifest writer")
	}
}

func TestRunEnterpriseWindowsEnumerateOnceRetainsPreCommitPublication(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "targets.yaml")
	want := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}

	previousConfigLoader := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	defer func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfigLoader
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
	}()
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, nil
	}
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		return want, nil
	}
	writerCalled := false
	enterpriseWindowsEnumerateManifestWriter = func(path string, got enterprisehooks.Manifest) (bool, error) {
		writerCalled = true
		if path != manifestPath || !reflect.DeepEqual(got, want) {
			t.Fatalf("publication got path=%q manifest=%+v", path, got)
		}
		return true, nil
	}

	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifestPath, true); err != nil {
		t.Fatalf("pre-commit --once publication: %v", err)
	}
	if !writerCalled {
		t.Fatal("pre-commit --once did not call the manifest writer")
	}
}

// TestIsEnterpriseWindowsEnumerateConfigMissingRecognisesBothOSes
// asserts the "config missing" detector recognises Windows'
// "The system cannot find the file specified" AND Unix's
// "no such file or directory" wording — both surface via
// os.Open-wrapped errors depending on which OS we're compiled for.
func TestIsEnterpriseWindowsEnumerateConfigMissingRecognisesBothOSes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"windows", errors.New("open C:\\...\\config.yaml: The system cannot find the file specified."), true},
		{"windows lowercase", errors.New("open C:\\...\\config.yaml: cannot find the file specified"), true},
		{"unix", errors.New("open /etc/defenseclaw/config.yaml: no such file or directory"), true},
		{"unrelated error", errors.New("open C:\\...\\config.yaml: access denied"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEnterpriseWindowsEnumerateConfigMissing(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCountDistinctSIDsHandlesEmptyAndDuplicates asserts the summary-
// log helper counts unique SIDs case-insensitively.
func TestCountDistinctSIDsHandlesEmptyAndDuplicates(t *testing.T) {
	cases := []struct {
		name    string
		targets []enterprisehooks.ManifestTarget
		want    int
	}{
		{"empty", nil, 0},
		{
			"single user, two connectors",
			[]enterprisehooks.ManifestTarget{
				{SID: "S-1-5-21-1000-2000-3000-1001", Connector: "codex"},
				{SID: "S-1-5-21-1000-2000-3000-1001", Connector: "claudecode"},
			},
			1,
		},
		{
			"two users, one connector each",
			[]enterprisehooks.ManifestTarget{
				{SID: "S-1-5-21-1000-2000-3000-1001", Connector: "codex"},
				{SID: "S-1-5-21-1000-2000-3000-1002", Connector: "codex"},
			},
			2,
		},
		{
			"case difference is normalised",
			[]enterprisehooks.ManifestTarget{
				{SID: "S-1-5-21-1000-2000-3000-1001", Connector: "codex"},
				{SID: "s-1-5-21-1000-2000-3000-1001", Connector: "claudecode"},
			},
			1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := countDistinctSIDs(tc.targets); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestEnumerationLoggerForStderrFormatsSubjectAndReason asserts the
// per-drop log line format so a log-scraping oncall alert keyed on
// "skipped SID X: Y" doesn't silently break if we tweak the string.
func TestEnumerationLoggerForStderrFormatsSubjectAndReason(t *testing.T) {
	buf := new(bytes.Buffer)
	logf := enumerationLoggerForStderr(buf)
	logf("S-1-5-21-1000-2000-3000-1001", "reparse point in ancestor chain")
	got := buf.String()
	if !strings.Contains(got, "[hook-enumerator] skipped S-1-5-21-1000-2000-3000-1001: reparse point in ancestor chain") {
		t.Fatalf("logger output missing expected line: %q", got)
	}
}

// TestEnterpriseWindowsEnumerateIntervalHonoursCtxCancel bounds the
// interval-loop's shutdown behaviour: a ctx-cancel MUST return
// within the initial delay + a small grace period. Uses a
// deliberately-short initial-delay so the test wall-clock stays
// under a second.
func TestEnterpriseWindowsEnumerateIntervalHonoursCtxCancel(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")

	prev := enterpriseWindowsEnumerateConfigLoader
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, nil
	}
	defer func() { enterpriseWindowsEnumerateConfigLoader = prev }()

	stderr := new(bytes.Buffer)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately: the initial-delay timer sees ctx.Done()
	// before it fires, and the loop returns nil.
	cancel()

	err := runEnterpriseWindowsEnumerateInterval(ctx, stderr, &enterpriseWindowsEnumerateOptions{
		manifestPath: manifest,
		// Both durations are explicit time.Millisecond values;
		// they never actually fire because ctx is cancelled
		// before the initial-delay timer, but the numeric shape
		// documents intent (100ms, not 100ns) for a future maintainer
		// who removes the pre-cancel. See CR
		// spec-005:PRRT_kwDORuAK-s6atye4.
		interval:     100 * time.Millisecond,
		initialDelay: 100 * time.Millisecond,
	}, manifest)
	if err != nil {
		t.Fatalf("ctx-cancelled interval-loop should return nil; got %v", err)
	}
}
