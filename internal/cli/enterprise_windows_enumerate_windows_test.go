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
