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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

var setupVMSettings = map[string]any{"install": "setup", "version": "0.1.5", "driver": "vm"}

// A purge deletes the account's sandboxes, providers and profiles through
// its daemon and its OpenShell gateway, so `sandbox teardown` runs first,
// while both answer; the units stop afterwards, and the files go last.
func TestSandboxPurgeTearsDownBeforeTheUnitsStop(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			requireOK(t, h.ensure(sandboxConfig(t, goos, true, setupVMSettings)))
			h.installTarballFiles(t, h.alice, "0.1.5")
			r := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, r)
			if got := strings.Join(h.ops.events, ", "); got != "teardown alice, stop alice" {
				t.Fatalf("order = %q, want the teardown before the stop", got)
			}
			if !containsLine(r.Changes, "ran `defenseclaw sandbox teardown` as user alice") {
				t.Errorf("changes = %v", r.Changes)
			}
			if h.exists(filepath.Join(h.alice.Home, ".local/bin/openshell")) {
				t.Error("the purge left the OpenShell DefenseClaw installed")
			}
		})
	}
}

// GAP-0598: an uninstall without --purge ran `sandbox teardown --keep-images`
// as each account, which deleted its sandboxes and the copy-mode work never
// pulled back, while the result said each account kept its sandbox state.
// It keeps every sandbox, running or stopped, with its records, disks and
// work, stops the running ones through the daemon before the units, says so,
// and a reactivation finds all of it again.
func TestSandboxUninstallKeepsSandboxesAndUnpulledWork(t *testing.T) {
	// Where each sandbox keeps its record, its MicroVM disk, its unpulled
	// copy and the CLI's state of it.
	sandboxFiles := func(h *osHost, name string) []string {
		return []string{
			filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", name, "record.json"),
			filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", name, "copy", "added.txt"),
			filepath.Join(h.alice.Home, openshellVMStateRel, name, "rootfs.ext4"),
			filepath.Join(h.alice.Home, userSandboxDataRel, name, "handover.json"),
		}
	}
	prepare := func(t *testing.T, goos string) *osHost {
		t.Helper()
		h := newOSHost(t, goos)
		requireOK(t, h.ensure(sandboxConfig(t, goos, true, setupVMSettings)))
		h.installTarballFiles(t, h.alice, "0.1.5")
		for _, name := range []string{"sb-running", "sb-stopped"} {
			for _, path := range sandboxFiles(h, name) {
				writeHostFile(t, h.testHost, path, "work of "+name+"\n")
			}
		}
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
		h.ops.running = map[int][]string{h.alice.UID: {"sb-running"}}
		// What the real teardown does in the home: the sandboxes and the
		// CLI's state of them go.
		h.ops.onTeardown = func(a SandboxAccount) {
			for _, rel := range []string{h.env.daemonStateRel(), openshellVMStateRel, userSandboxDataRel} {
				_ = os.RemoveAll(h.env.P(filepath.Join(a.Home, rel)))
			}
		}
		return h
	}
	requireKept := func(t *testing.T, h *osHost) {
		t.Helper()
		for _, name := range []string{"sb-running", "sb-stopped"} {
			for _, path := range sandboxFiles(h, name) {
				if !h.exists(path) {
					t.Errorf("%s is gone", path)
				} else if got := h.read(path); got != "work of "+name+"\n" {
					t.Errorf("%s = %q", path, got)
				}
			}
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := prepare(t, goos)
			r := h.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			if len(h.ops.teardowns) != 0 {
				t.Fatalf("a non-purge uninstall tore down %v", h.ops.teardowns)
			}
			if got := strings.Join(h.ops.events, ", "); got != "stop-sandboxes alice, stop alice, stop alice" {
				t.Errorf("order = %q, want the sandboxes stopped through the daemon before its units", got)
			}
			if got := strings.Join(h.ops.stopped(), ", "); got != "alice:daemon+socket, alice:gateway" {
				t.Errorf("stops = %q, want the daemon before the OpenShell gateway", got)
			}
			requireKept(t, h)
			changes := strings.Join(r.Changes, "\n")
			if !containsLine(r.Changes, "stopped the running sandboxes of user alice (sb-running); they are kept, with their work") ||
				!containsLine(r.Changes, "stopped the sandbox subsystem; kept the sandboxes of alice in their homes with their records, disks and any work not pulled yet") ||
				strings.Contains(changes, "come back") ||
				strings.Contains(changes, "teardown") || strings.Contains(changes, "removed local sandbox files") {
				t.Errorf("changes = %v", r.Changes)
			}
			if hasWarning(r, codeSandboxUserState) {
				t.Errorf("warnings = %+v", r.Warnings)
			}
			// The documented reactivation finds every sandbox again.
			requireOK(t, h.ensure(sandboxConfig(t, goos, true, setupVMSettings)))
			requireKept(t, h)
		})
	}
	t.Run("an idle account stops no sandbox", func(t *testing.T) {
		h := prepare(t, "linux")
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
		r := h.run(Options{Action: ActionUninstall})
		requireOK(t, r)
		if got := strings.Join(h.ops.events, ", "); got != "stop alice, stop alice" {
			t.Errorf("events = %q", got)
		}
		if containsLine(r.Changes, "stopped the running sandboxes") {
			t.Errorf("changes = %v", r.Changes)
		}
		requireKept(t, h)
	})
	t.Run("a daemon that cannot say is stopped as if a sandbox ran", func(t *testing.T) {
		h := prepare(t, "linux")
		h.ops.statusErr[h.alice.UID] = errors.New("the daemon did not answer")
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		if got := strings.Join(h.ops.events, ", "); got != "stop-sandboxes alice, stop alice, stop alice" {
			t.Errorf("events = %q", got)
		}
		requireKept(t, h)
	})
	t.Run("a stop that fails is reported and the sandboxes stay", func(t *testing.T) {
		h := prepare(t, "darwin")
		h.ops.running = nil
		h.ops.stopSandboxesErr = errors.New("stop sb-running: the gateway did not answer")
		r := h.run(Options{Action: ActionUninstall})
		requireOK(t, r)
		if warning := messagesOf(r.Warnings, codeSandboxUserState); !strings.Contains(warning, "could not stop every running sandbox of alice") ||
			!strings.Contains(warning, "the gateway did not answer") {
			t.Errorf("warnings = %+v", r.Warnings)
		}
		if containsLine(r.Changes, "stopped the running sandboxes") || len(h.ops.teardowns) != 0 {
			t.Errorf("changes = %v, teardowns = %v", r.Changes, h.ops.teardowns)
		}
		if got := strings.Join(h.ops.stopped(), ", "); got != "alice:daemon+socket, alice:gateway" {
			t.Errorf("stops = %q", got)
		}
		requireKept(t, h)
	})
}

// GAP-0598 (F1): a sandbox kept by a non-purge uninstall is started, reviewed
// and pulled through its daemon, which names it to the gateway by the
// registration id the gateway gave it. The uninstall deleted the whole data
// folder, with the registration store and the correlation key the
// registrations' subject keys are HMACs of: the gateway of the next
// activation answered sandbox_registration_unknown, the daemon revoked every
// kept sandbox, and a stopped copy-mode MicroVM, whose review and pull have
// to start it, could not be reached any more. The store and the key stay
// (root's while the service account is gone), the rest of the machine state
// goes, the next ensure gives them to the account it creates, the gateway
// knows the registration again and its subject still matches the account,
// and a purge removes them.
func TestSandboxUninstallKeepsTheRegistrationStoreForTheNextActivation(t *testing.T) {
	subjectKey := func(key []byte, uid int, account string) string {
		mac := hmac.New(sha256.New, key)
		_, _ = fmt.Fprintf(mac, "%s|%d|%s|%s", sandboxreg.SubjectKeyVersion, uid, strings.ToLower(account), "")
		return sandboxreg.DigestPrefix + hex.EncodeToString(mac.Sum(nil))
	}
	gatewayKey := func(t *testing.T, data string) redaction.CorrelationKey {
		t.Helper()
		key, err := redaction.LoadOrCreateCorrelationKey(data)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			l := h.env.Layout
			uid := h.alice.UID
			cfg := sandboxConfig(t, goos, true, setupVMSettings)
			requireOK(t, h.ensure(cfg))
			data := h.env.P(l.DataDir)
			// What the gateway wrote for alice's stopped copy-mode sandbox,
			// and the daemon's record of it in her home.
			key := gatewayKey(t, data)
			material, _ := key.Material()
			id, err := sandboxreg.NewID()
			if err != nil {
				t.Fatal(err)
			}
			store := sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(data))
			if err := store.Create(uid, sandboxreg.Registration{ID: id, SubjectKey: subjectKey(material[:], uid, "alice"), Connector: "claudecode", UserName: "alice"}); err != nil {
				t.Fatal(err)
			}
			decisions := filepath.Join(l.DataDir, "sandbox", "decisions", fmt.Sprint(uid)+".json")
			writeHostFile(t, h.testHost, decisions, `{"v":1,"decisions":[]}`+"\n")
			daemonRecord := filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", "sb-stopped", "record.json")
			writeHostFile(t, h.testHost, daemonRecord, `{"registration":"`+id+`"}`+"\n")
			writeHostFile(t, h.testHost, filepath.Join(l.DataDir, "audit.db"), "audit\n")
			h.ops.status[uid] = SandboxStatus{Active: true}
			kept := []string{
				filepath.Join(l.DataDir, "sandbox", "registrations", fmt.Sprint(uid)+".json"),
				decisions,
				filepath.Join(l.DataDir, "redaction-correlation.key"),
			}

			r := h.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			for _, path := range append(kept, daemonRecord) {
				if !h.exists(path) {
					t.Fatalf("a non-purge uninstall that keeps a sandbox removed %s", path)
				}
			}
			// The service account is gone: the kept store is root's, so an
			// account created later with its uid cannot read it.
			if _, ok := h.accounts.accounts[l.ServiceUser]; ok {
				t.Fatal("uninstall kept the service account")
			}
			for _, path := range append([]string{l.DataDir}, kept...) {
				if uid, gid, err := h.env.OwnerOf(h.env.P(path)); err != nil || uid != 0 || gid != 0 {
					t.Errorf("%s is owned by %d:%d (%v), want root", path, uid, gid, err)
				}
			}
			// Only the store and its key stay of the machine state.
			for _, path := range []string{filepath.Join(l.DataDir, "audit.db"), l.ConfigDir, l.GuardianAuthDir, l.LogDir} {
				if h.exists(path) {
					t.Errorf("uninstall kept %s", path)
				}
			}
			if !containsLine(r.Changes, "kept the gateway's sandbox registrations ("+filepath.Join(l.DataDir, "sandbox")+") and their key ("+
				filepath.Join(l.DataDir, "redaction-correlation.key")+") for the sandboxes the accounts keep: once the deployment is activated again") {
				t.Errorf("changes = %v", r.Changes)
			}

			// The documented reactivation adopts the kept folder and gives it
			// to the service account it creates.
			again := h.ensure(cfg)
			requireOK(t, again)
			service, ok := h.accounts.accounts[l.ServiceUser]
			if !ok {
				t.Fatal("ensure created no service account")
			}
			for _, path := range append([]string{l.DataDir}, kept...) {
				if uid, _, err := h.env.OwnerOf(h.env.P(path)); err != nil || uid != service.UID {
					t.Errorf("after ensure %s is owned by uid %d (%v), want the service account %d", path, uid, err, service.UID)
				}
			}
			// The gateway of the new activation has the same key and knows
			// the kept registration, whose subject is still alice's: the
			// daemon's id resolves, so the sandbox starts.
			if again := gatewayKey(t, data); again.ID() != key.ID() {
				t.Fatalf("the correlation key changed across the uninstall: %s, was %s", again.ID(), key.ID())
			}
			reg, found, err := sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(data)).Get(uid, id)
			if err != nil || !found {
				t.Fatalf("the next activation's gateway does not know registration %s: found=%v err=%v", id, found, err)
			}
			if reg.SubjectKey != subjectKey(material[:], uid, "alice") || reg.State == sandboxreg.StateRevoked {
				t.Fatalf("registration = %+v", reg)
			}
			if !h.exists(daemonRecord) {
				t.Fatal("the daemon's record of the sandbox is gone")
			}

			// A purge removes the store with the rest.
			requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
			if h.exists(l.DataDir) {
				t.Fatalf("purge left %s", l.DataDir)
			}
		})
	}
	t.Run("without kept sandboxes the data folder goes", func(t *testing.T) {
		h := newOSHost(t, "darwin")
		l := h.env.Layout
		requireOK(t, h.ensure(sandboxConfig(t, "darwin", true, setupVMSettings)))
		gatewayKey(t, h.env.P(l.DataDir))
		r := h.run(Options{Action: ActionUninstall})
		requireOK(t, r)
		if h.exists(l.DataDir) || containsLine(r.Changes, "kept the gateway's sandbox registrations") {
			t.Fatalf("an uninstall that keeps no sandbox kept %s: %v", l.DataDir, r.Changes)
		}
	})
	t.Run("a later purge of the uninstalled deployment removes the kept store", func(t *testing.T) {
		h := newOSHost(t, "linux")
		l := h.env.Layout
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVMSettings)))
		h.registerSandboxUser(t, h.alice)
		gatewayKey(t, h.env.P(l.DataDir))
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		if !h.exists(filepath.Join(l.DataDir, "redaction-correlation.key")) {
			t.Fatal("the uninstall did not keep the key")
		}
		requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
		if h.exists(l.DataDir) || exists(h.env.retainedStatePath()) {
			t.Fatalf("the purge left %s or the retained-state record", l.DataDir)
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
	h.installTarballFiles(t, h.alice, "0.1.5")
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
	h.installTarballFiles(t, h.alice, "0.1.5")
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

// GAP-0598 verify 2: rpm -e or apt remove (the MDM uninstall script runs
// rpm -e) then an install. The non-purge uninstall removed the service
// account and handed the kept data folder to root; the package's postinstall
// runs systemd-sysusers, which creates a new account, and systemd-tmpfiles,
// whose `d /var/lib/defenseclaw 0700 defenseclaw defenseclaw` line re-owns
// the folder (not its contents) to that account before ensure runs. Ensure
// must still adopt the kept sandbox store; an owner nobody accounts for is
// still refused.
func TestSandboxKeptStoreSurvivesAPackageReinstall(t *testing.T) {
	for name, tc := range map[string]struct {
		owner func(service Account) int
		ok    bool
	}{
		"re-owned to the new service account": {owner: func(service Account) int { return service.UID }, ok: true},
		"re-owned to an unrelated account":    {owner: func(Account) int { return 4242 }},
	} {
		t.Run(name, func(t *testing.T) {
			h := newOSHost(t, "linux")
			l := h.env.Layout
			cfg := sandboxConfig(t, "linux", true, setupVMSettings)
			requireOK(t, h.ensure(cfg))
			h.registerSandboxUser(t, h.alice)
			if _, err := redaction.LoadOrCreateCorrelationKey(h.env.P(l.DataDir)); err != nil {
				t.Fatal(err)
			}
			registration := filepath.Join(l.DataDir, "sandbox", "registrations", fmt.Sprint(h.alice.UID)+".json")
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if _, ok := h.accounts.accounts[l.ServiceUser]; ok {
				t.Fatal("uninstall kept the service account")
			}
			if uid, _, err := h.env.OwnerOf(h.env.P(l.DataDir)); err != nil || uid != 0 {
				t.Fatalf("the kept data folder is owned by %d (%v), want root", uid, err)
			}

			// The reinstall's systemd-sysusers, then systemd-tmpfiles --create.
			service := Account{Name: l.ServiceUser, UID: 977, GID: 977}
			h.accounts.accounts[l.ServiceUser] = service
			owner := tc.owner(service)
			h.owners[h.env.P(l.DataDir)] = [2]int{owner, owner}

			r := h.ensure(cfg)
			if !tc.ok {
				requireError(t, r, codeUnmanagedLayout)
				if !h.exists(registration) {
					t.Fatal("the refused ensure removed the kept registration")
				}
				return
			}
			requireOK(t, r)
			if !h.exists(registration) || !h.exists(filepath.Join(l.DataDir, "redaction-correlation.key")) {
				t.Fatal("ensure after the package reinstall lost the kept sandbox store")
			}
			for _, path := range []string{l.DataDir, registration} {
				if uid, _, err := h.env.OwnerOf(h.env.P(path)); err != nil || uid != service.UID {
					t.Errorf("after ensure %s is owned by uid %d (%v), want the service account %d", path, uid, err, service.UID)
				}
			}
			if exists(h.env.retainedStatePath()) {
				t.Fatal("the retained-state record survived the reinstall")
			}
		})
	}
}
