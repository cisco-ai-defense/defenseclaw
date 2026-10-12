//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

const (
	recordedObserve  = "defenseclaw-observe-aaaaaaaa"
	recordedControls = "defenseclaw-controls-bbbbbbbb"
	lookalikeName    = "defenseclaw-controls-cccccccc"
)

type cleanupFake struct {
	loaded   map[string]bool
	deleted  []string
	failWith map[string]error
	calls    []string
}

func (f *cleanupFake) Agent(context.Context) (kernelpolicy.Agent, error) {
	f.calls = append(f.calls, "agent")
	return kernelpolicy.Agent{}, nil
}

func (f *cleanupFake) ListTracingPolicies(context.Context) ([]kernelpolicy.LoadedPolicy, error) {
	f.calls = append(f.calls, "list")
	var out []kernelpolicy.LoadedPolicy
	for name := range f.loaded {
		out = append(out, kernelpolicy.LoadedPolicy{Name: name, Mode: kernelpolicy.LoadedEnforce, State: kernelpolicy.StateEnabled})
	}
	return out, nil
}

func (f *cleanupFake) AddTracingPolicy(context.Context, []byte) error {
	f.calls = append(f.calls, "add")
	return errors.New("cleanup must not add")
}

func (f *cleanupFake) DeleteTracingPolicy(_ context.Context, name string) error {
	f.calls = append(f.calls, "delete:"+name)
	if err := f.failWith[name]; err != nil {
		return err
	}
	delete(f.loaded, name)
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *cleanupFake) ConfigureTracingPolicy(context.Context, string, kernelpolicy.PolicyMode) error {
	f.calls = append(f.calls, "configure")
	return errors.New("cleanup must not configure")
}

func cleanupDirs(t *testing.T, recorded ...string) kernelpolicy.Dirs {
	t.Helper()
	dirs := kernelpolicy.Dirs{State: t.TempDir(), Run: t.TempDir()}
	if len(recorded) > 0 {
		if err := os.WriteFile(filepath.Join(dirs.State, "tetragon-loaded"), []byte(strings.Join(recorded, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dirs
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The kernel enrollment is targets.yaml plus, for the machine-policy
// connectors of the drop-in, the eligible accounts targets.yaml is silent
// about; both files pass the same trust check.
func TestKernelEnrollmentAddsTheEligibleAccountsForMachinePolicy(t *testing.T) {
	trusted := func(string) error { return nil }
	restoreManifest, restoreEligible := validateManifestTrust, validateEligibleAccountsTrust
	validateManifestTrust, validateEligibleAccountsTrust = trusted, trusted
	t.Cleanup(func() { validateManifestTrust, validateEligibleAccountsTrust = restoreManifest, restoreEligible })

	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("targets:\n- user: bob\n  uid: 1002\n  user_home: /home/bob\n  connector: opencode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kernelpolicy.EligibleAccountsPath(manifest), []byte(`{"version":1,"accounts":[
{"user":"alice","uid":1001,"gid":1001,"home":"/home/alice"},{"user":"bob","uid":1002,"gid":1002,"home":"/home/bob"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := func(e kernelpolicy.Enrollment) string {
		var out []string
		for _, row := range e.Rows {
			out = append(out, row.User+":"+row.Connector)
		}
		return strings.Join(out, ",")
	}
	got, err := loadKernelEnrollment(manifest, []string{"claudecode"})
	if err != nil || rows(got) != "alice:claudecode,bob:claudecode,bob:opencode" {
		t.Fatalf("enrollment %q %v", rows(got), err)
	}
	if got, err := loadKernelEnrollment(manifest, nil); err != nil || rows(got) != "bob:opencode" {
		t.Fatalf("without machine-policy connectors only targets.yaml counts: %q %v", rows(got), err)
	}
	if got, err := loadKernelEnrollment("", []string{"claudecode"}); err != nil || len(got.Rows) != 0 {
		t.Fatalf("no manifest path reads nothing: %+v %v", got, err)
	}
	validateEligibleAccountsTrust = func(string) error { return errors.New("untrusted") }
	if _, err := loadKernelEnrollment(manifest, []string{"claudecode"}); err == nil {
		t.Fatal("an untrusted eligible-accounts record must be an error, so the reconciler keeps its last enrollment")
	}
}

func TestKernelPolicyCleanupWithNothingRecordedNeverDials(t *testing.T) {
	var out bytes.Buffer
	dial := func(context.Context) (kernelpolicy.Client, func(), error) {
		t.Fatal("nothing is recorded; an uninstall must not need Tetragon")
		return nil, nil, nil
	}
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, cleanupDirs(t), dial); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestKernelPolicyCleanupRemovesOnlyRecordedNames(t *testing.T) {
	fake := &cleanupFake{loaded: map[string]bool{recordedObserve: true, recordedControls: true, lookalikeName: true, "customer-policy": true}}
	dirs := cleanupDirs(t, recordedObserve, recordedControls)
	var out bytes.Buffer
	dial := func(context.Context) (kernelpolicy.Client, func(), error) { return fake, func() {}, nil }
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, dirs, dial); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if len(fake.deleted) != 2 || fake.loaded[recordedObserve] || fake.loaded[recordedControls] || !fake.loaded[lookalikeName] || !fake.loaded["customer-policy"] {
		t.Fatalf("deleted %v, left %v", fake.deleted, fake.loaded)
	}
	for _, call := range fake.calls {
		if call != "list" && !strings.HasPrefix(call, "delete:") {
			t.Fatalf("cleanup called %s", call)
		}
	}
	for _, want := range []string{"removed " + recordedObserve, "removed " + recordedControls, "left alone (not recorded by this helper) " + lookalikeName} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if recorded, _ := kernelpolicy.Recorded(dirs); len(recorded) != 0 {
		t.Fatalf("record after cleanup = %v", recorded)
	}
}

func TestKernelPolicyCleanupExitCodes(t *testing.T) {
	var out bytes.Buffer
	down := func(context.Context) (kernelpolicy.Client, func(), error) {
		return nil, nil, errors.New("connection refused")
	}
	dirs := cleanupDirs(t, recordedObserve)
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, dirs, down); code != cleanupUnreachable {
		t.Fatalf("exit %d; an unreachable Tetragon is its own code so the lifecycle can warn and go on", code)
	}
	if !strings.Contains(out.String(), "systemctl restart tetragon") {
		t.Fatalf("the last-resort advice is missing:\n%s", out.String())
	}
	if recorded, _ := kernelpolicy.Recorded(dirs); len(recorded) != 1 {
		t.Fatal("the record must survive an unreachable Tetragon")
	}

	fake := &cleanupFake{loaded: map[string]bool{recordedObserve: true}, failWith: map[string]error{recordedObserve: errors.New("boom")}}
	out.Reset()
	bad := func(context.Context) (kernelpolicy.Client, func(), error) { return fake, func() {}, nil }
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, dirs, bad); code != cleanupFailed {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "kept "+recordedObserve) {
		t.Fatalf("output:\n%s", out.String())
	}
}

// A one-shot cleanup while a helper in observe or enforce reconciles leaves
// its policies alone: removing them under it reads as an operator's deletion.
func TestKernelPolicyCleanupRefusesWhileAHelperReconciles(t *testing.T) {
	dirs := cleanupDirs(t, recordedObserve)
	unlock, err := kernelpolicy.LockForCleanup(dirs) // the running helper's hold
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	dial := func(context.Context) (kernelpolicy.Client, func(), error) {
		t.Fatal("a refused cleanup must not reach Tetragon")
		return nil, nil, nil
	}
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, dirs, dial); code != cleanupFailed {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "stop it first") {
		t.Fatalf("output:\n%s", out.String())
	}
	if recorded, _ := kernelpolicy.Recorded(dirs); len(recorded) != 1 {
		t.Fatalf("record = %v", recorded)
	}
	unlock()
	fake := &cleanupFake{loaded: map[string]bool{recordedObserve: true}}
	ok := func(context.Context) (kernelpolicy.Client, func(), error) { return fake, func() {}, nil }
	if code := kernelPolicyCleanup(context.Background(), quiet(), &out, dirs, ok); code != cleanupOK {
		t.Fatalf("exit %d once the helper stopped", code)
	}
}

func TestKernelPolicyIntentIsSafeOnBadInput(t *testing.T) {
	t.Setenv(kernelpolicy.EnvMode, "enforce-everything")
	t.Setenv(kernelpolicy.EnvBurnIn, "soon")
	intent := kernelPolicyIntent(os.LookupEnv, quiet())
	if intent.Mode != kernelpolicy.ModeConsume || intent.BurnIn != kernelpolicy.DefaultBurnIn || len(intent.Problems) != 2 {
		t.Fatalf("intent = %+v", intent)
	}
	t.Setenv(kernelpolicy.EnvMode, "observe")
	t.Setenv(kernelpolicy.EnvBurnIn, "")
	if got := kernelPolicyIntent(os.LookupEnv, quiet()); got.Mode != kernelpolicy.ModeObserve || got.BurnIn != kernelpolicy.DefaultBurnIn {
		t.Fatalf("intent = %+v", got)
	}
}
