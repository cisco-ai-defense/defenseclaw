// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

var setupVMSettings = map[string]any{"install": "setup", "version": "0.1.3", "driver": "vm"}

// The account's sandboxes, providers and profiles are deleted through its
// daemon and its OpenShell gateway, so `sandbox teardown` runs first, while
// both answer; the units stop afterwards, and a purge removes the files last.
func TestSandboxUninstallTearsDownBeforeTheUnitsStop(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(fmt.Sprintf("purge=%v", purge), func(t *testing.T) {
			h := newOSHost(t, "linux")
			requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVMSettings)))
			h.installTarballFiles(t, h.alice, "0.1.3")
			r := h.run(Options{Action: ActionUninstall, Purge: purge})
			requireOK(t, r)
			if got := strings.Join(h.ops.events, ", "); got != "teardown alice, stop alice" {
				t.Fatalf("order = %q, want the teardown before the stop", got)
			}
			if !containsLine(r.Changes, "ran `defenseclaw sandbox teardown` as user alice") {
				t.Errorf("changes = %v", r.Changes)
			}
			if purge && h.exists(filepath.Join(h.alice.Home, ".local/bin/openshell")) {
				t.Error("the purge left the OpenShell DefenseClaw installed")
			}
		})
	}
	t.Run("a teardown that fails is reported and the units still stop", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVMSettings)))
		h.installTarballFiles(t, h.alice, "0.1.3")
		h.ops.teardownErr = errors.New("the gateway did not answer")
		r := h.run(Options{Action: ActionUninstall})
		requireOK(t, r)
		if got := strings.Join(h.ops.events, ", "); got != "teardown alice, stop alice" {
			t.Errorf("order = %q", got)
		}
		if !hasWarning(r, codeSandboxUserState) || !strings.Contains(fmt.Sprint(r.Warnings), "were not torn down") {
			t.Errorf("warnings = %+v", r.Warnings)
		}
		if containsLine(r.Changes, "ran `defenseclaw sandbox teardown`") {
			t.Errorf("a failed teardown is reported as done: %v", r.Changes)
		}
	})
}

// GAP-0667: image build logs kept the managed account's data directory alive
// after its sandbox state was purged. Other logs and a personal install stay.
func TestSandboxPurgeRemovesImageBuildLogs(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name       string
			otherLog   bool
			ownConfig  bool
			linkedLogs bool
		}{
			{name: "only image logs"},
			{name: "other logs", otherLog: true},
			{name: "personal install", ownConfig: true},
			{name: "linked logs", linkedLogs: true},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				h := newOSHost(t, goos)
				data := filepath.Join(h.alice.Home, ".defenseclaw")
				log := filepath.Join(data, "logs/sandbox-image-claudecode.log")
				if tc.linkedLogs {
					outside := t.TempDir()
					writeFile := filepath.Join(outside, "sandbox-image-claudecode.log")
					if err := os.WriteFile(writeFile, []byte("image build output\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(h.env.P(data), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, h.env.P(filepath.Join(data, "logs"))); err != nil {
						t.Fatal(err)
					}
				} else {
					writeHostFile(t, h.testHost, log, "image build output\n")
				}
				if tc.otherLog {
					writeHostFile(t, h.testHost, filepath.Join(data, "logs/other.log"), "kept\n")
				}
				if tc.ownConfig {
					writeHostFile(t, h.testHost, filepath.Join(data, "config.yaml"), "openshell: {}\n")
				}
				l := &lifecycle{env: h.env, result: &enterprisestatus.Result{}}
				l.purgeAccountSandbox(h.alice)
				if want := tc.ownConfig || tc.linkedLogs; h.exists(log) != want {
					t.Errorf("image log exists = %v, want %v", h.exists(log), want)
				}
				if want := tc.otherLog || tc.ownConfig || tc.linkedLogs; h.exists(data) != want {
					t.Errorf("data directory exists = %v, want %v", h.exists(data), want)
				}
				if tc.linkedLogs && !hasWarning(l.result, codeSandboxUserState) {
					t.Fatal("purge did not report the linked logs directory it kept")
				}
				if tc.otherLog && h.read(filepath.Join(data, "logs/other.log")) != "kept\n" {
					t.Error("an unrelated log changed")
				}
			})
		}
	}
}

// GAP-0668: a failed teardown leaves gateway resources, while purge still
// removes local files. Its warning must describe that combined outcome.
func TestSandboxPurgeReportsCleanupAfterTeardownFailure(t *testing.T) {
	h := newOSHost(t, "darwin")
	requireOK(t, h.ensure(sandboxConfig(t, "darwin", true, setupVMSettings)))
	h.installTarballFiles(t, h.alice, "0.1.3")
	h.ops.teardownErr = errors.New("`defenseclaw sandbox teardown` exited 1: start Docker and rerun, or rerun with --keep-images; nothing was changed")
	r := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, r)
	warning := messagesOf(r.Warnings, codeSandboxUserState)
	if !strings.Contains(warning, "Docker images") || !strings.Contains(warning, "manual cleanup") ||
		strings.Contains(warning, "nothing was changed") || strings.Contains(warning, "run `defenseclaw sandbox teardown`") {
		t.Fatalf("purge warning does not describe the remaining resources: %s", warning)
	}
	if !containsLine(r.Changes, "removed local sandbox files of user alice") ||
		containsLine(r.Changes, "ran `defenseclaw sandbox teardown`") {
		t.Fatalf("purge changes do not describe the local cleanup: %v", r.Changes)
	}
	if h.exists(filepath.Join(h.alice.Home, ".local/bin/openshell")) {
		t.Fatal("purge left the installed OpenShell binary")
	}
}

// recordBackedOps lists accounts only while the enumerator's eligible-accounts
// record exists, as the command-based implementation does (it reads the
// record), so the order of the uninstall decides whether the account is found.
type recordBackedOps struct {
	*fakeSandboxOps
	record string
}

func (o recordBackedOps) Accounts(ctx context.Context) []SandboxAccount {
	if _, err := os.Stat(o.record); err != nil {
		return nil
	}
	return o.fakeSandboxOps.Accounts(ctx)
}

// Removing the per-user registrations deletes the eligible-accounts record.
// An account that only the record names (no registration or decision file)
// still gets its sandboxes torn down and its state purged.
func TestSandboxTeardownFindsAccountsTheUninstallRecordsLose(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVMSettings)))
	h.installTarballFiles(t, h.alice, "0.1.3")
	record := h.env.P(enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath))
	writeHostFile(t, h.testHost, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		fmt.Sprintf(`{"accounts":[{"user":"alice","uid":%d,"home":%q}]}`, h.alice.UID, h.alice.Home))
	h.env.SandboxUsers = recordBackedOps{fakeSandboxOps: h.ops, record: record}
	h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
		// What `enterprise hooks remove-all` does to the record.
		_ = os.Remove(record)
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":1}`)}, nil
	}}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if exists(record) {
		t.Fatal("the stand-in for remove-all did not delete the record")
	}
	if got := strings.Join(h.ops.events, ", "); got != "teardown alice, stop alice" {
		t.Fatalf("events = %q: the account the record named was not taken out", got)
	}
	if h.exists(filepath.Join(h.alice.Home, ".local/bin/openshell")) {
		t.Error("the purge did not reach the account the record named")
	}
}

// The hook manifest names accounts too: an enrolled account that no store or
// record lists is still found.
func TestSandboxAccountsIncludeTheManifestAndThePendingChanges(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVMSettings)))
	l := &lifecycle{env: h.env, result: nil}
	bobUID := h.alice.UID + 7
	writeHostFile(t, h.testHost, h.env.Layout.ManifestPath,
		fmt.Sprintf("version: 1\ntargets:\n  - user: bob\n    uid: %d\n    user_home: /home/bob\n    connector: codex\n"+
			"  - user: root\n    uid: 0\n    user_home: /root\n    connector: codex\n"+
			"  - user: svc\n    uid: 5\n    user_home: /\n    connector: codex\n", bobUID))
	var names []string
	for _, a := range l.sandboxAccounts(context.Background()) {
		names = append(names, a.Name)
	}
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("accounts = %v, want %v (root and a root home are never acted in)", names, want)
	}
	// A host that never ran sandboxes has none.
	fresh := newOSHost(t, "linux")
	if got := (&lifecycle{env: fresh.env}).sandboxAccounts(context.Background()); got != nil {
		t.Errorf("a host without sandboxes lists %v", got)
	}
}

// The record the gateway reads keeps its shape: the keys the writer emits are
// exactly the ones openshell.PrerequisitesRecord reads.
func TestSandboxPrerequisitesRecordIsTheGatewaysContract(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"})))
	raw := h.read(h.env.prerequisitesPath())
	if filepath.Base(h.env.prerequisitesPath()) != openshell.PrerequisitesFile || filepath.Base(filepath.Dir(h.env.prerequisitesPath())) != "openshell" {
		t.Errorf("the record is at %s", h.env.prerequisitesPath())
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]any) string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	// driver vm with the default driver_fallback (docker) carries the
	// fallback's readiness.
	if got := keys(generic); got != "checked_at,driver,fallback,install,missing,ready,version" {
		t.Errorf("record keys = %s", got)
	}
	if fb, _ := generic["fallback"].(map[string]any); fb == nil || keys(fb) != "driver,missing,ready" {
		t.Errorf("fallback keys = %v", generic["fallback"])
	}
	missing, _ := generic["missing"].([]any)
	if len(missing) == 0 {
		t.Fatal("an empty host misses nothing")
	}
	if got := keys(missing[0].(map[string]any)); got != "detail,fix,item" {
		t.Errorf("missing keys = %s", got)
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record openshell.PrerequisitesRecord
	if err := decoder.Decode(&record); err != nil {
		t.Fatalf("the reader does not know a key the writer emits: %v", err)
	}
	if record.Version != openshell.PrerequisitesVersion || record.Ready || record.Install != "prerequisite" || record.Driver != "vm" || len(record.Missing) != len(missing) {
		t.Errorf("record = %+v", record)
	}
}
