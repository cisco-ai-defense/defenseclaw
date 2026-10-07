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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	launchdstandalone "github.com/defenseclaw/defenseclaw/packaging/launchd-standalone"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

func TestLinuxInstallCreatesTheStandaloneDeployment(t *testing.T) {
	h := newTestHost(t, "linux")
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireOK(t, r)
	if !r.Installed || r.InstalledVersion != "1.0.0" || r.Profile != managed.ProfileStandalone {
		t.Fatalf("unexpected result: %+v", r)
	}

	l := h.env.Layout
	for _, name := range []string{binGateway, binHook, binSensorHelper, binACP} {
		if got := h.mode(filepath.Join(l.BinDir, name)); got != 0o755 {
			t.Fatalf("%s mode %04o", name, got)
		}
	}
	if got := h.mode(l.ConfigPath); got != 0o640 {
		t.Fatalf("config mode %04o", got)
	}
	if !strings.Contains(h.read(l.ConfigPath), "profile: standalone") {
		t.Fatal("default config not installed")
	}
	if got := h.mode(l.SecretsDir); got != 0o700 {
		t.Fatalf("secrets dir mode %04o on systemd 255, want 0700", got)
	}
	if got := h.mode(l.LifecycleDir); got != 0o700 {
		t.Fatalf("lifecycle dir mode %04o", got)
	}
	account := h.accounts.accounts["defenseclaw"]
	if owner := h.owners[h.env.P(l.DataDir)]; owner != [2]int{account.UID, account.GID} {
		t.Fatalf("data dir owner %v, want service account", owner)
	}
	// The gateway refuses to create its device key in a non-private dir.
	if got := h.mode(l.DataDir); got != 0o700 {
		t.Fatalf("data dir mode %04o, want 0700", got)
	}
	if owner := h.owners[h.env.P(l.ConfigPath)]; owner != [2]int{0, account.GID} {
		t.Fatalf("config owner %v, want root:defenseclaw", owner)
	}

	descriptor, err := managed.ParseRuntimeDescriptor([]byte(h.read(l.DescriptorPath)))
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.ServiceUID != account.UID || descriptor.HookSocket != l.HookSocketPath || descriptor.ProductVersion != "1.0.0" {
		t.Fatalf("descriptor: %+v", descriptor)
	}
	for _, unit := range h.services.Units() {
		path := h.services.DefinitionPath(unit, ChannelPayload)
		if !exists(h.env.P(path)) {
			t.Fatalf("unit %s not installed", path)
		}
		if unit.Required && !h.services.isActive(unit.Name) {
			t.Fatalf("%s not active", unit.Name)
		}
	}
	if !exists(h.env.P("/etc/tmpfiles.d/defenseclaw.conf")) || !exists(h.env.P("/etc/sysusers.d/defenseclaw.conf")) {
		t.Fatal("tmpfiles/sysusers not installed")
	}
	if !exists(h.env.P(l.ManifestPath)) {
		t.Fatal("initial manifest not seeded")
	}
	// The gateway refuses to start without a rule pack, so the vendor
	// defaults ship read-only and the default config points at them.
	for _, rel := range []string{"guardrail/default/rules/secrets.yaml", "guardrail/strict", "rego/guardrail.rego", "rego/data.json", "default.yaml"} {
		if !exists(h.env.P(filepath.Join(l.VendorPolicyDir, rel))) {
			t.Fatalf("vendor policy %s not installed", rel)
		}
	}
	if exists(h.env.P(filepath.Join(l.VendorPolicyDir, "rego", "guardrail_test.rego"))) {
		t.Fatal("rego unit tests were installed")
	}
	if got := h.mode(filepath.Join(l.VendorPolicyDir, "rego", "guardrail.rego")); got != 0o644 {
		t.Fatalf("vendor policy mode %04o", got)
	}
	if !strings.Contains(h.read(l.ConfigPath), "rule_pack_dir: "+filepath.Join(l.VendorPolicyDir, "guardrail", "default")) {
		t.Fatal("default config does not name the vendor rule pack")
	}

	order := h.services.startOrder()
	index := func(name string) int {
		for i, unit := range order {
			if unit == name {
				return i
			}
		}
		t.Fatalf("%s never started (%v)", name, order)
		return -1
	}
	if !(index(unitSensorHelper) < index(unitAPISocket) && index(unitAPISocket) < index(unitGateway) &&
		index(unitGateway) < index(unitGuardian) && index(unitGuardian) < index(unitEnumerator)) {
		t.Fatalf("activation order wrong: %v", order)
	}

	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("deployment record: %v %+v", err, record)
	}
	if record.Channel != ChannelPayload || record.ServiceUser != "defenseclaw" || !record.CreatedServiceAccount {
		t.Fatalf("record: %+v", record)
	}
	if exists(h.env.pendingPath()) {
		t.Fatal("pending intent left behind")
	}
	if !r.Readiness.Gateway || !r.Readiness.Enumerator || r.Inspection.Local != "active" {
		t.Fatalf("readiness/inspection not described: %+v %+v", r.Readiness, r.Inspection)
	}
}

func TestEnsureIsANoopWhenNothingChanged(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	before := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure, PayloadDir: payload})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "up_to_date" {
		t.Fatalf("expected no-op ensure, got %+v", r)
	}
	for _, call := range h.services.calls[before:] {
		if strings.HasPrefix(call, "stop ") || strings.HasPrefix(call, "start ") {
			t.Fatalf("no-op ensure touched services: %v", h.services.calls[before:])
		}
	}
}

func TestEnsureAppliesAConfigChange(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	changed := strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1)
	if err := os.WriteFile(cfg, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionEnsure, ConfigFile: cfg})
	requireOK(t, r)
	if r.Noop {
		t.Fatal("config change must not be a no-op")
	}
	if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
		t.Fatal("new config not installed")
	}
	record, _ := h.env.loadDeployment()
	if record.ConfigSHA256 != sha256Bytes([]byte(changed)) {
		t.Fatal("record does not reflect the applied config")
	}
}

func TestUpgradeReplacesBinaries(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), ProductVersion: "1.0.1"})
	requireOK(t, r)
	if r.InstalledVersion != "1.0.1" {
		t.Fatalf("installed version %q", r.InstalledVersion)
	}
	if !strings.Contains(h.read(filepath.Join(h.env.Layout.BinDir, binGateway)), "1.0.1") {
		t.Fatal("gateway binary not replaced")
	}
	mismatch := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.2"), ProductVersion: "1.0.3"})
	requireError(t, mismatch, codePayload)
}

func TestFailedActivationRollsBack(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	before := h.read(filepath.Join(h.env.Layout.BinDir, binGateway))
	h.healthy = false
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, r, codeActivate)
	if !hasWarning(r, codeRolledBack) {
		t.Fatalf("expected rollback warning: %+v", r.Warnings)
	}
	if r.ExitCode != enterprisestatus.UnixExitFailure {
		t.Fatalf("exit %d", r.ExitCode)
	}
	if got := h.read(filepath.Join(h.env.Layout.BinDir, binGateway)); got != before {
		t.Fatalf("binary not restored: %q", got)
	}
	record, _ := h.env.loadDeployment()
	if record.ProductVersion != "1.0.0" {
		t.Fatalf("record changed on failure: %+v", record)
	}
	if !h.services.isActive(unitGateway) {
		t.Fatal("previously active gateway not restarted after rollback")
	}
	if exists(h.env.pendingPath()) {
		t.Fatal("pending intent survived a rollback")
	}
}

// A failed first install removes what it created, including state the
// gateway wrote while it briefly ran, so a plain retry succeeds.
func TestFailedFirstInstallCanBeRetried(t *testing.T) {
	h := newTestHost(t, "linux")
	h.healthy = false
	health := h.env.HealthGet
	h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		// The gateway ran long enough to create its audit database.
		_ = os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, "audit.db")), []byte("x"), 0o600)
		return health(ctx)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireError(t, r, codeActivate)
	for _, dir := range []string{h.env.Layout.DataDir, h.env.Layout.VendorPolicyDir, h.env.Layout.BinDir} {
		if exists(h.env.P(dir)) {
			t.Fatalf("rollback left %s", dir)
		}
	}
	h.healthy = true
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
}

func TestInterruptedTransactionIsRecovered(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	gateway := filepath.Join(h.env.Layout.BinDir, binGateway)
	original := h.read(gateway)
	snap, err := h.env.takeSnapshot("crash", []string{gateway}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.savePending(&Pending{Action: ActionUpgrade, SnapshotDir: snap.Dir, Phase: "apply", PreviouslyActive: []string{unitGateway}}); err != nil {
		t.Fatal(err)
	}
	// The interrupted run had already renamed a new binary into place.
	staged := h.env.P(gateway) + ".new"
	if err := os.WriteFile(staged, []byte("defenseclaw-gateway 9.9.9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, h.env.P(gateway)); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !hasWarning(r, codeRecovered) {
		t.Fatalf("expected recovery warning: %+v", r.Warnings)
	}
	if got := h.read(gateway); got != original {
		t.Fatalf("interrupted binary not restored: %q", got)
	}
}

// GAP-0428: an ensure killed in quiesce left the services stopped, the
// verify job unloaded and the transaction pending, and nothing recovered it.
// quiesce leaves the verify timer alone, and a verify that finds the
// transaction pending (and the lock free) starts the apply trigger.
func TestVerifyStartsTheApplyTriggerForAnInterruptedTransaction(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	l := &lifecycle{env: h.env, result: &enterprisestatus.Result{}}
	h.services.active[labelVerify] = true
	l.quiesce(context.Background(), darwinUnits, nil)
	if !h.services.active[labelVerify] {
		t.Fatal("quiesce stopped the verify job")
	}
	gateway := filepath.Join(h.env.Layout.BinDir, binGateway)
	snap, err := h.env.takeSnapshot("killed", []string{gateway}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.savePending(&Pending{Action: ActionEnsure, SnapshotDir: snap.Dir, Phase: "quiesce"}); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionVerify})
	if got := messagesOf(r.Errors, codeVerify); !strings.Contains(got, "started the apply trigger") {
		t.Fatalf("verify errors = %s, want the recovery started", got)
	}
	h.runner.mu.Lock()
	calls := strings.Join(h.runner.calls, "\n")
	h.runner.mu.Unlock()
	if !strings.Contains(calls, "launchctl kickstart system/"+labelApply) {
		t.Fatalf("runner calls = %s, want the apply job kicked", calls)
	}
}

func TestInstallRefusals(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}), codeAlreadyInstalled)

	fresh := newTestHost(t, "linux")
	requireError(t, fresh.run(Options{Action: ActionUpgrade, PayloadDir: fresh.payload("1.0.0")}), codeNotInstalled)
	bad := fresh.run(Options{Action: ActionStatus, PayloadDir: "/tmp/x"})
	if bad.ExitCode != enterprisestatus.UnixExitInvalidArgs {
		t.Fatalf("invalid args exit %d", bad.ExitCode)
	}
	fresh.env.Geteuid = func() int { return 1000 }
	requireError(t, fresh.run(Options{Action: ActionInstall, PayloadDir: fresh.payload("1.0.0")}), codeNotRoot)
}

// GAP-1201: status by a standard user that cannot read the deployment
// record asks for root instead of reporting state_unreadable.
func TestStatusAsAStandardUserAsksForRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any mode")
	}
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	dir := h.env.P(h.env.Layout.LifecycleDir)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	h.env.Geteuid = func() int { return 1000 }
	r := h.run(Options{Action: ActionStatus})
	requireError(t, r, codeNotRoot)
	for _, e := range r.Errors {
		if e.Code == codeState {
			t.Fatalf("status still reports %s: %s", codeState, e.Message)
		}
	}
}

func TestLeftoversNeedAdoption(t *testing.T) {
	h := newTestHost(t, "linux")
	legacy := h.env.P("/etc/systemd/system/defenseclaw-hook-guardian@.service")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := h.payload("1.0.0")
	requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}), codeUnmanagedLayout)
	r := h.run(Options{Action: ActionInstall, PayloadDir: payload, AdoptExisting: true})
	requireOK(t, r)
	if exists(legacy) {
		t.Fatal("legacy template unit not removed")
	}
	archives, _ := filepath.Glob(filepath.Join(h.env.P(h.env.Layout.LifecycleDir), adoptedPrefix+"*.tar.gz"))
	if len(archives) != 1 || !hasWarning(r, "adopted_existing_layout") {
		t.Fatalf("expected one adoption archive, got %v", archives)
	}
}

func TestPreStagedConfigIsNotALeftover(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.MkdirAll(h.env.P(h.env.Layout.ConfigDir), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1)
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(staged), 0o640); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.0")}))
	if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
		t.Fatal("pre-staged MDM config was not kept")
	}
}

func TestInvalidConfigIsRefusedBeforeAnyChange(t *testing.T) {
	h := newTestHost(t, "linux")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	bad := strings.Replace(string(DefaultConfig(h.env.Layout)), "data_dir: /var/lib/defenseclaw", "data_dir: /home/alice/.defenseclaw", 1)
	if err := os.WriteFile(cfg, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	requireError(t, r, codeConfig)
	if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) {
		t.Fatal("binaries installed despite an invalid config")
	}
}

// An observability header naming a protected credential is refused before
// any change until `enterprise secret set` has stored that credential.
func TestObservabilityCredentialMustBeStoredBeforeAnyChange(t *testing.T) {
	h := newTestHost(t, "linux")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	raw := string(DefaultConfig(h.env.Layout)) + `observability:
  destinations:
    - name: galileo
      kind: otlp
      preset: galileo
      endpoint: https://api.galileo.ai/otel/traces
      headers:
        Galileo-API-Key: {credential: galileo-api-key}
`
	if err := os.WriteFile(cfg, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	requireError(t, r, codeConfig)
	if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Message, "enterprise secret set --name galileo-api-key") {
		t.Fatalf("errors = %+v, want the command that stores the credential", r.Errors)
	}
	if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) {
		t.Fatal("binaries installed despite an unresolved credential reference")
	}
	// The credential can be stored before the first install (#1036): it is
	// kept root-only until the install gives the gateway its access.
	staged := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
		return h.env.WriteSecret(ctx, "galileo-api-key", []byte("key"))
	}})
	requireOK(t, staged)
	info, err := os.Stat(h.env.P(filepath.Join(h.env.Layout.SecretsDir, "galileo-api-key")))
	if !staged.Noop || staged.NoopReason != "not_installed" || err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staging before the install = %+v (stat %v), want a stored root-only credential", staged, err)
	}

	// While the installed config references it, the credential is not
	// removed: the gateway could not start without it.
	referenced := h.env.P(filepath.Join(h.env.Layout.SecretsDir, "galileo-api-key"))
	unused := h.env.P(filepath.Join(h.env.Layout.SecretsDir, "unused-key"))
	for path, body := range map[string]string{h.env.P(h.env.Layout.ConfigPath): raw, referenced: "key", unused: "key"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.env.RemoveSecret("galileo-api-key"); err == nil || !exists(referenced) {
		t.Fatalf("RemoveSecret of a referenced credential = %v, want a refusal that keeps it", err)
	}
	if err := h.env.RemoveSecret("unused-key"); err != nil || exists(unused) {
		t.Fatalf("RemoveSecret of an unreferenced credential = %v, want it removed", err)
	}
}

// A refused ensure (invalid config, or a payload it will not install)
// changes nothing, so its result reports the running deployment's services
// and readiness. It printed services [] and readiness all false, which an
// MDM reads as a host that is down. A rolled-back upgrade reports the
// restored deployment the same way.
func TestRefusedChangeReportsTheRunningDeployment(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(cfg, []byte("config_version: 8\nguardrail: [\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			requireRunning := func(name string, r *enterprisestatus.Result) {
				t.Helper()
				if len(r.Services) != len(h.services.Units()) || !r.Readiness.Gateway || !r.Readiness.Enumerator || !r.Readiness.SensorHelper {
					t.Fatalf("%s: result does not describe the running deployment: services=%d readiness=%+v", name, len(r.Services), r.Readiness)
				}
			}
			rejected := h.run(Options{Action: ActionEnsure, ConfigFile: cfg})
			requireError(t, rejected, codeConfig)
			requireRunning("rejected config", rejected)

			health := h.env.HealthGet
			h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
				// The new gateway never becomes healthy; the restored one does.
				h.healthy = strings.Contains(h.read(filepath.Join(h.env.Layout.BinDir, binGateway)), "1.0.0")
				return health(ctx)
			}
			rolledBack := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
			requireError(t, rolledBack, codeActivate)
			if !hasWarning(rolledBack, codeRolledBack) {
				t.Fatalf("upgrade did not roll back: %+v", rolledBack.Warnings)
			}
			requireRunning("rolled back upgrade", rolledBack)
		})
	}
}

// A config error names the file the administrator passed with --config,
// not the installed path (which made the installed config look broken), and
// a missing config_version says to add it: `defenseclaw migrate` is a
// per-user command the enterprise packages do not ship.
func TestConfigErrorsNameTheAdministratorFileAndAFixOnTheHost(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			cfg := filepath.Join(t.TempDir(), "staged-config.yaml")
			unversioned := strings.Replace(string(DefaultConfig(h.env.Layout)), "config_version: 8\n", "", 1)
			if err := os.WriteFile(cfg, []byte(unversioned), 0o600); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
			requireError(t, r, codeConfig)
			message := ""
			for _, e := range r.Errors {
				if e.Code == codeConfig {
					message = e.Message
				}
			}
			if !strings.Contains(message, cfg) || strings.Contains(message, h.env.Layout.ConfigPath) {
				t.Fatalf("the error does not name the --config file: %q", message)
			}
			if !strings.Contains(message, "config_version_required") || !strings.Contains(message, "`config_version: 8`") || strings.Contains(message, "defenseclaw migrate") {
				t.Fatalf("the error does not say how to fix the file on this host: %q", message)
			}
		})
	}
}

// A rule pack the gateway cannot load, or one inside the service-writable
// data_dir, is refused before any change instead of failing activation. A
// missing pack names a source that exists before the first install
// (GAP-1429: the hint named the vendor folder only an install creates).
func TestRulePackDirsAreValidatedBeforeAnyChange(t *testing.T) {
	cases := map[string]struct {
		replace, with, want string
		packMode            os.FileMode
	}{
		"missing admin pack":   {"rule_pack_dir: /opt/defenseclaw/share/policies/guardrail/default", "rule_pack_dir: /etc/defenseclaw/policies/guardrail/custom", "does not exist; create the pack there before you apply the config, starting from a copy of policies/guardrail/default in the DefenseClaw source release", 0},
		"pack under umask 077": {"rule_pack_dir: /opt/defenseclaw/share/policies/guardrail/default", "rule_pack_dir: /etc/defenseclaw/policies/guardrail/custom", "service account cannot read the rule pack", 0o700},
		"service-writable":     {"rule_pack_dir: /opt/defenseclaw/share/policies/guardrail/default", "rule_pack_dir: /var/lib/defenseclaw/packs/custom", "inside data_dir", 0},
		"unknown vendor pack":  {"guardrail/default", "guardrail/nonexistent", "not a rule pack the product ships", 0},
		"missing profile pack": {"guardrail/default\n", "guardrail/default\n  profiles:\n    contractors:\n      rule_pack_dir: /etc/defenseclaw/policies/guardrail/custom\n", `guardrail.profiles.contractors.rule_pack_dir "/etc/defenseclaw/policies/guardrail/custom" does not exist`, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			if tc.packMode != 0 {
				pack := h.env.P("/etc/defenseclaw/policies/guardrail/custom")
				if err := os.MkdirAll(pack, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(pack, tc.packMode); err != nil {
					t.Fatal(err)
				}
			}
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			raw := strings.Replace(string(DefaultConfig(h.env.Layout)), tc.replace, tc.with, 1)
			if err := os.WriteFile(cfg, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
			requireError(t, r, codeConfig)
			if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Message, tc.want) {
				t.Fatalf("errors = %+v, want %q", r.Errors, tc.want)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) {
				t.Fatal("binaries installed despite an unusable rule pack")
			}
		})
	}
}

// `rulepack validate` runs as an administrator, so it asks whether the
// service account could read the pack.
func TestRulePackServiceReadProblemNamesAnUnreadablePack(t *testing.T) {
	h := newTestHost(t, "linux")
	const dir = "/etc/defenseclaw/policies/guardrail/custom"
	if got := h.env.RulePackServiceReadProblem(context.Background(), dir); got != "" {
		t.Fatalf("no service account yet, got %q", got)
	}
	if _, err := h.env.Accounts.Ensure(context.Background(), h.env.Layout.ServiceUser); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := h.env.RulePackServiceReadProblem(context.Background(), dir); !strings.Contains(got, "service account cannot read the rule pack") {
		t.Fatalf("problem = %q", got)
	}
	if err := os.Chmod(h.env.P(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := h.env.RulePackServiceReadProblem(context.Background(), dir); got != "" {
		t.Fatalf("readable pack, got %q", got)
	}
}

// The owner's uninstall scope (2026-10-01): the default uninstall removes
// the services and the machine state (config, secrets, gateway and guardian
// state, logs, lifecycle state, the service account); only --keep-state
// keeps that state for a reinstall. Each account's own data is the purge's.
func TestUninstallRemovesTheMachineStateUnlessKeepState(t *testing.T) {
	h := newTestHost(t, "linux")
	l := h.env.Layout
	install := func() {
		t.Helper()
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		for _, path := range []string{filepath.Join(l.DataDir, "audit.db"), filepath.Join(l.GuardianAuthDir, "authorization.json"), filepath.Join(l.LogDir, "gateway.log")} {
			if err := os.MkdirAll(filepath.Dir(h.env.P(path)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(path), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	install()
	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	// GAP-1227: the result says what went and what stayed.
	summary := strings.Join(r.Changes, "\n")
	for _, want := range []string{"stopped and removed the DefenseClaw services", "removed the machine state",
		"and the service account", "kept: each enrolled account's DefenseClaw per-user data (~/.defenseclaw)", "--purge"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("uninstall summary lacks %q:\n%s", want, summary)
		}
	}
	// GAP-1721: the binaries are gone, so the kept line does not tell the
	// administrator to run the removed gateway binary.
	if !strings.Contains(summary, "install the DefenseClaw enterprise package again and run") || strings.Contains(summary, "--purge` removes them too") {
		t.Fatalf("the kept line names a removed binary:\n%s", summary)
	}
	if exists(h.env.P(filepath.Join(l.BinDir, binGateway))) || exists(h.env.P(l.DescriptorPath)) ||
		exists(h.env.P("/etc/systemd/system/"+unitGateway)) || exists(h.env.deploymentPath()) {
		t.Fatal("uninstall left deployment files behind")
	}
	for _, dir := range []string{l.ConfigDir, l.DataDir, l.LifecycleDir, l.InstallRoot, l.GuardianAuthDir, l.LogDir, l.VendorPolicyDir} {
		if exists(h.env.P(dir)) {
			t.Fatalf("uninstall left %s", dir)
		}
	}
	if _, ok := h.accounts.accounts["defenseclaw"]; ok {
		t.Fatal("uninstall kept the service account")
	}
	if h.services.isActive(unitGateway) || h.services.isActive(unitAPISocket) {
		t.Fatal("uninstall left services running")
	}
	reset := false
	for _, call := range h.runner.calls {
		reset = reset || strings.HasPrefix(call, "systemctl reset-failed ") && strings.Contains(call, unitVerifyService)
	}
	if !reset {
		t.Fatal("uninstall did not clear failed unit state")
	}
	again := h.run(Options{Action: ActionUninstall})
	requireOK(t, again)
	if !again.Noop || again.NoopReason != "not_installed" || hasWarning(again, codeLeftovers) {
		t.Fatalf("second uninstall should be a clean no-op: %+v", again)
	}
	// The rerun (the package preremove after an uninstall, say) leaves no
	// lifecycle directory holding only its lock.
	if exists(h.env.P(l.LifecycleDir)) {
		t.Fatal("a no-op uninstall left the lifecycle directory behind")
	}

	// --keep-state keeps all of it, and the account.
	install()
	kept := h.run(Options{Action: ActionUninstall, KeepState: true})
	requireOK(t, kept)
	if summary := strings.Join(kept.Changes, "\n"); !strings.Contains(summary, "kept for a reinstall") || strings.Contains(summary, "removed the machine state") {
		t.Fatalf("uninstall --keep-state summary:\n%s", summary)
	}
	if !exists(h.env.P(l.ConfigPath)) || !exists(h.env.P(filepath.Join(l.DataDir, "audit.db"))) || !exists(h.env.P(filepath.Join(l.LogDir, "gateway.log"))) {
		t.Fatal("uninstall --keep-state removed the machine state")
	}
	if _, ok := h.accounts.accounts["defenseclaw"]; !ok {
		t.Fatal("uninstall --keep-state removed the service account")
	}

	// --keep-service-account keeps only the account; a purge removes the rest.
	purge := h.run(Options{Action: ActionUninstall, Purge: true, KeepServiceAccount: true})
	requireOK(t, purge)
	if summary := strings.Join(purge.Changes, "\n"); !strings.Contains(summary, "removed the machine state") ||
		!strings.Contains(summary, "kept the service account") || strings.Contains(summary, "kept: each enrolled account") {
		t.Fatalf("purge summary:\n%s", summary)
	}
	for _, dir := range []string{l.ConfigDir, l.DataDir, l.LifecycleDir, l.InstallRoot, l.GuardianAuthDir} {
		if exists(h.env.P(dir)) {
			t.Fatalf("purge left %s", dir)
		}
	}
	if _, ok := h.accounts.accounts["defenseclaw"]; !ok {
		t.Fatal("--keep-service-account removed the service account")
	}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true, RemoveServiceAccount: true}))
	if _, ok := h.accounts.accounts["defenseclaw"]; ok {
		t.Fatal("purge kept the service account")
	}
	if r := h.run(Options{Action: ActionUninstall, Purge: true, KeepState: true}); r.ExitCode == 0 {
		t.Fatal("--keep-state with --purge must be refused")
	}
}

func TestLifecycleLockIsExclusive(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.MkdirAll(h.env.P(h.env.Layout.LifecycleDir), 0o700); err != nil {
		t.Fatal(err)
	}
	held, err := h.env.acquireLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireError(t, r, codeBusy)
	if msg := r.Errors[len(r.Errors)-1].Message; !strings.Contains(msg, "--lock-wait <duration>") ||
		!strings.Contains(msg, "waited "+FormatLockWait(h.env.LockTimeout)+" for it") {
		t.Fatalf("busy must name the wait done and the next step (GAP-1427, GAP-1722): %q", msg)
	}
	// GAP-1722: a run that already waited the longest allowed time is not
	// told to wait longer.
	if got := lockBusyNextStep(MaxLockWait); got != "waited 15m for it; wait for it to finish, then rerun" {
		t.Fatalf("busy after the longest wait: %q", got)
	}
	if got := lockBusyNextStep(time.Second); !strings.HasPrefix(got, "waited 1s for it;") || !strings.Contains(got, "a longer --lock-wait <duration> (at most 15m)") {
		t.Fatalf("busy after --lock-wait 1s: %q", got)
	}
	if r.ExitCode != enterprisestatus.UnixExitBusy {
		t.Fatalf("busy exit %d, want %d", r.ExitCode, enterprisestatus.UnixExitBusy)
	}
	// A daily verify started during another run reports busy, which its
	// unit accepts, instead of failing on the half-changed deployment.
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeBusy)
	if msg := verify.Errors[len(verify.Errors)-1].Message; !strings.Contains(msg, "rerun verify") ||
		!strings.Contains(msg, "; waited "+FormatLockWait(h.env.LockTimeout)+" for it;") {
		t.Fatalf("busy verify must name the next step: %q", msg)
	}
	if verify.ExitCode != enterprisestatus.UnixExitBusy {
		t.Fatalf("verify busy exit %d, want %d", verify.ExitCode, enterprisestatus.UnixExitBusy)
	}
	unit, err := systemdunits.ReadFile(unitVerifyService)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "\nSuccessExitStatus=75\n") {
		t.Fatalf("a busy verify leaves its unit failed:\n%s", unit)
	}
}

// GAP-2246: status during another run (a repair restarting the services)
// says the run is in progress instead of listing every stopped service and
// naming repair; it still reports the recorded deployment, so MDM
// detection sees it installed.
func TestStatusDuringAnotherRunReportsBusy(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			held, err := h.env.acquireLock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			status := h.run(Options{Action: ActionStatus})
			held.release()
			requireError(t, status, codeBusy)
			// GAP-2409: it says how long it waited, as ensure does.
			if len(status.Errors) != 1 || !strings.Contains(status.Errors[0].Message, "rerun status") ||
				!strings.Contains(status.Errors[0].Message, "; waited "+FormatLockWait(h.env.LockTimeout)+" for it;") {
				t.Fatalf("busy status must be the one busy error naming its next step: %+v", status.Errors)
			}
			if !status.Installed || status.InstalledVersion != "1.0.0" || status.ExitCode != enterprisestatus.UnixExitBusy {
				t.Fatalf("busy status: installed=%v version=%q exit=%d", status.Installed, status.InstalledVersion, status.ExitCode)
			}
		})
	}
}

func TestSecretsAndCredentialDropins(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	if err := h.env.WriteSecret(context.Background(), "ai-defense-api-key", []byte("s3cr3t")); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(h.env.Layout.SecretsDir, "ai-defense-api-key")
	if got := h.mode(secret); got != 0o600 {
		t.Fatalf("secret mode %04o on systemd 255", got)
	}
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if r.Noop {
		t.Fatal("a new credential must be applied")
	}
	dropin := h.read("/etc/systemd/system/" + unitGateway + ".d/" + dropinCredentials)
	if !strings.Contains(dropin, "LoadCredential=ai-defense-api-key:/etc/defenseclaw/secrets/ai-defense-api-key") ||
		!strings.Contains(dropin, "InaccessiblePaths=-/etc/defenseclaw/secrets") {
		t.Fatalf("credentials drop-in: %s", dropin)
	}
	states, err := h.env.SecretStatus()
	if err != nil || len(states) != 1 || states[0].SHA256Prefix == "" || strings.Contains(states[0].SHA256Prefix, "s3cr3t") {
		t.Fatalf("status: %+v %v", states, err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	if !h.run(Options{Action: ActionEnsure}).Noop {
		t.Fatal("unchanged credentials should settle to a no-op")
	}

	old := newTestHost(t, "linux")
	old.services.version = 239
	requireOK(t, old.run(Options{Action: ActionInstall, PayloadDir: old.payload("1.0.0")}))
	if err := old.env.WriteSecret(context.Background(), "ai-defense-api-key", []byte("k")); err != nil {
		t.Fatal(err)
	}
	if got := old.mode(filepath.Join(old.env.Layout.SecretsDir, "ai-defense-api-key")); got != 0o640 {
		t.Fatalf("systemd 239 secret mode %04o, want group-readable fallback", got)
	}
	requireOK(t, old.run(Options{Action: ActionEnsure}))
	if exists(old.env.P("/etc/systemd/system/" + unitGateway + ".d/" + dropinCredentials)) {
		t.Fatal("LoadCredential drop-in written for systemd < 247")
	}
}

func TestGuardianPathsDropinCoversHomeRootsAndMachinePolicy(t *testing.T) {
	h := newTestHost(t, "linux")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	body := string(DefaultConfig(h.env.Layout)) + `  connectors:
    codex: {}
    claudecode: {}
    antigravity: {}
    opencode: {}
`
	body = strings.Replace(body, "enterprise:\n  profile: standalone\n", "enterprise:\n  profile: standalone\n  enrollment:\n    home_roots: [/srv/home]\n  network:\n    https_proxy: http://proxy.example.test:3128\n", 1)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	requireOK(t, r)
	dropin := h.read("/etc/systemd/system/" + unitGuardian + ".d/" + dropinPaths)
	for _, want := range []string{"ReadWritePaths=-/srv/home", "ReadWritePaths=-/etc/codex", "ReadWritePaths=-/etc/claude-code", "ReadWritePaths=-/etc/opencode"} {
		if !strings.Contains(dropin, want) {
			t.Fatalf("guardian drop-in lacks %q:\n%s", want, dropin)
		}
	}
	if strings.Contains(dropin, "antigravity") {
		t.Fatal("per-user connector must not add machine policy paths")
	}
	network := h.read("/etc/systemd/system/" + unitGateway + ".d/" + dropinNetwork)
	if !strings.Contains(network, "Environment=HTTPS_PROXY=http://proxy.example.test:3128") {
		t.Fatalf("network drop-in: %s", network)
	}
	if !exists(h.env.P("/etc/codex")) || !exists(h.env.P("/etc/claude-code/managed-settings.d")) || !exists(h.env.P("/etc/opencode")) {
		t.Fatal("machine policy parents not created")
	}
	record, _ := h.env.loadDeployment()
	if !reflect.DeepEqual(record.CreatedDirs, []string{"/etc/claude-code", "/etc/claude-code/managed-settings.d", "/etc/codex", "/etc/opencode"}) {
		t.Fatalf("created dirs %v", record.CreatedDirs)
	}
	descriptor, _ := managed.ParseRuntimeDescriptor([]byte(h.read(h.env.Layout.DescriptorPath)))
	if !reflect.DeepEqual(descriptor.MachinePolicyConnectors, []string{"claudecode", "codex", "opencode"}) {
		t.Fatalf("descriptor machine policy connectors %v", descriptor.MachinePolicyConnectors)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if exists(h.env.P("/etc/codex")) || exists(h.env.P("/etc/opencode")) || exists(h.env.P("/etc/claude-code")) {
		t.Fatal("uninstall kept an empty machine-policy parent it created")
	}
}

// Copilot's machine policy lives two folders deep (/etc/github-copilot/
// policy.d): uninstall removes both folders it created, the deeper one
// first, instead of leaving an empty /etc/github-copilot behind.
func TestUninstallRemovesTheCopilotPolicyFoldersItCreated(t *testing.T) {
	h := newTestHost(t, "linux")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	body := string(DefaultConfig(h.env.Layout)) + "  connectors:\n    copilot: {}\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	record, _ := h.env.loadDeployment()
	for _, dir := range []string{"/etc/github-copilot", "/etc/github-copilot/policy.d"} {
		if !slices.Contains(record.CreatedDirs, dir) || !exists(h.env.P(dir)) {
			t.Fatalf("install did not create and record %s: %v", dir, record.CreatedDirs)
		}
	}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if exists(h.env.P("/etc/github-copilot")) {
		t.Fatal("uninstall kept the empty /etc/github-copilot it created")
	}
}

func TestDarwinInstallWritesLaunchDaemons(t *testing.T) {
	h := newTestHost(t, "darwin")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	body := strings.Replace(string(DefaultConfig(h.env.Layout)), "enterprise:\n  profile: standalone\n", "enterprise:\n  profile: standalone\n  network:\n    https_proxy: http://proxy.example.test:3128\n", 1)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	requireOK(t, r)
	gateway := h.read("/Library/LaunchDaemons/" + labelGateway + ".plist")
	for _, want := range []string{"<string>_defenseclaw</string>", "<key>HTTPS_PROXY</key>", "DEFENSECLAW_ENTERPRISE_PROFILE"} {
		if !strings.Contains(gateway, want) {
			t.Fatalf("gateway plist lacks %q", want)
		}
	}
	if !strings.Contains(h.read(h.env.Layout.ConfigPath), "/opt/cisco/defenseclaw/runtime") {
		t.Fatal("darwin config does not use the darwin data dir")
	}
	if got := h.mode(h.env.Layout.HookSocketDir); got != 0o755 {
		t.Fatalf("hook socket dir mode %04o", got)
	}
	// The gateway binds hook.sock itself on macOS, in a directory under the
	// root-owned install root that survives reboot.
	account := h.accounts.accounts[h.env.Layout.ServiceUser]
	if h.env.Layout.HookSocketDir != "/opt/cisco/defenseclaw/run" || h.owners[h.env.P(h.env.Layout.HookSocketDir)] != [2]int{account.UID, account.GID} {
		t.Fatalf("hook socket dir %s owner %v, want %s:%d:%d", h.env.Layout.HookSocketDir, h.owners[h.env.P(h.env.Layout.HookSocketDir)], account.Name, account.UID, account.GID)
	}
	for _, label := range []string{labelSensorHelper, labelGateway, labelGuardian, labelEnumerator} {
		if !h.services.isActive(label) {
			t.Fatalf("%s not started", label)
		}
	}
}

// TestStandaloneConfigMustDeclareTheProfileOnDarwin: the services pin the
// standalone profile, but hooks and admin tools read the same file without
// the pin, and on macOS an unset profile means secure_client to them. The
// lifecycle refuses such a config instead of installing it unchanged; on
// Linux the default is standalone everywhere, so the line stays optional.
func TestStandaloneConfigMustDeclareTheProfileOnDarwin(t *testing.T) {
	for _, tc := range []struct {
		goos   string
		wantOK bool
	}{{goos: "darwin"}, {goos: "linux", wantOK: true}} {
		t.Run(tc.goos, func(t *testing.T) {
			if tc.wantOK && runtime.GOOS != "linux" {
				// The config loader applies the host OS rule, and a Linux
				// lifecycle only ever runs on Linux.
				t.Skip("the Linux default applies only on a Linux host")
			}
			h := newTestHost(t, tc.goos)
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			body := strings.Replace(string(DefaultConfig(h.env.Layout)), "enterprise:\n  profile: standalone\n", "enterprise:\n  network:\n    https_proxy: http://proxy.example.test:3128\n", 1)
			if strings.Contains(body, "profile: standalone") {
				t.Fatal("test config still declares the profile")
			}
			if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
			if tc.wantOK {
				requireOK(t, r)
				return
			}
			requireError(t, r, codeConfig)
			if exists(h.env.P(h.env.Layout.ConfigPath)) {
				t.Fatal("the undeclared-profile config was installed")
			}
		})
	}
}

func TestDarwinPackageChannelUninstallRemovesBinariesAndReceipt(t *testing.T) {
	h := newTestHost(t, "darwin")
	bin := h.env.P(h.env.Layout.BinDir)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := h.payload("1.2.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	requireOK(t, r)
	if r.InstalledVersion != "1.2.0" {
		t.Fatalf("installed version %q", r.InstalledVersion)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if exists(filepath.Join(bin, binGateway)) {
		t.Fatal("macOS package uninstall kept the gateway binary; a pkg has no uninstaller")
	}
	forgot := false
	for _, call := range h.runner.calls {
		forgot = forgot || call == "pkgutil --forget "+MacOSPackageID
	}
	if !forgot {
		t.Fatalf("uninstall did not forget the pkg receipt: %v", h.runner.calls)
	}
}

func TestDarwinRefusesNextToSecureClient(t *testing.T) {
	h := newTestHost(t, "darwin")
	plist := h.env.P("/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist")
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}), codeProfileConflict)
}

// A WSL distribution is not a boundary the Linux lifecycle can enforce: new
// installs are refused and an existing deployment is reported.
func TestLinuxInsideWSL(t *testing.T) {
	markWSL := func(h *testHost) {
		release := h.env.P("/proc/sys/kernel/osrelease")
		if err := os.MkdirAll(filepath.Dir(release), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(release, []byte("5.15.167.4-microsoft-standard-WSL2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fresh := newTestHost(t, "linux")
	markWSL(fresh)
	requireError(t, fresh.run(Options{Action: ActionEnsure, PayloadDir: fresh.payload("1.0.0")}), codeWSL)

	installed := newTestHost(t, "linux")
	requireOK(t, installed.run(Options{Action: ActionInstall, PayloadDir: installed.payload("1.0.0")}))
	markWSL(installed)
	status := installed.run(Options{Action: ActionStatus})
	requireOK(t, status)
	if !slices.ContainsFunc(status.Warnings, func(m enterprisestatus.Message) bool { return m.Code == codeWSL }) {
		t.Fatalf("status must report the WSL deployment: %+v", status.Warnings)
	}
}

func TestStatusAndVerify(t *testing.T) {
	h := newTestHost(t, "linux")
	status := h.run(Options{Action: ActionStatus})
	requireOK(t, status)
	if status.Installed {
		t.Fatal("status reports installed on a clean host")
	}
	requireError(t, h.run(Options{Action: ActionVerify}), codeNotInstalled)

	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 2, "success_count": 2})
	h.publishLedger(data)
	verify := h.run(Options{Action: ActionVerify})
	requireOK(t, verify)
	if verify.Enrollment.Targets != 2 || !verify.Readiness.Guardian {
		t.Fatalf("verify description: %+v %+v", verify.Enrollment, verify.Readiness)
	}
	// The sensor helper restarts itself when an account is enrolled or
	// revoked; systemd's restart delay is not a verify failure. The restart
	// after a crash is, though the unit comes back for a moment.
	h.services.active[unitSensorHelper] = false
	h.services.restarting[unitSensorHelper] = "success"
	requireOK(t, h.run(Options{Action: ActionVerify}))
	h.services.active[unitSensorHelper] = false
	h.services.restarting[unitSensorHelper] = "exit-code"
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); !strings.Contains(got, unitSensorHelper+" is not active") {
		t.Fatalf("verify waited out the restart of a crashed unit: %s", got)
	}

	unit := h.env.P("/etc/systemd/system/" + unitGateway)
	if err := os.WriteFile(unit, []byte("[Service]\nUser=root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.services.active[unitEnumerator] = false
	tampered := h.run(Options{Action: ActionVerify})
	requireError(t, tampered, codeVerify)
	joined := ""
	for _, e := range tampered.Errors {
		joined += e.Message + "\n"
	}
	if !strings.Contains(joined, unitGateway+" was modified") || !strings.Contains(joined, unitEnumerator+" is not active") {
		t.Fatalf("verify did not name the tampering: %s", joined)
	}
	// Status exits 1 for an unhealthy deployment too, as the docs say.
	if status := h.run(Options{Action: ActionStatus}); status.ExitCode != 1 || !strings.Contains(messagesOf(status.Errors, codeVerify), unitEnumerator+" is not active") {
		t.Fatalf("status of an unhealthy deployment: exit %d, errors %+v", status.ExitCode, status.Errors)
	}
	repair := h.run(Options{Action: ActionRepair})
	requireOK(t, repair)
	requireOK(t, h.run(Options{Action: ActionVerify}))
	// repair says what it repaired, and that there was nothing to repair
	// on a healthy deployment.
	changes := strings.Join(repair.Changes, "\n")
	if !strings.Contains(changes, "rewrote /etc/systemd/system/"+unitGateway) || !strings.Contains(changes, "started "+unitEnumerator+", which was not running") {
		t.Fatalf("repair does not list what it changed: %q", repair.Changes)
	}
	if again := h.run(Options{Action: ActionRepair}); len(again.Changes) != 0 {
		t.Fatalf("a repair of a healthy deployment lists changes: %q", again.Changes)
	}
}

func TestReadSecretValue(t *testing.T) {
	value, err := ReadSecretValue(strings.NewReader("abc\n"))
	if err != nil || string(value) != "abc" {
		t.Fatalf("%q %v", value, err)
	}
	for _, bad := range []string{"", "\n", "a\nb\n", strings.Repeat("x", maxSecretBytes+1)} {
		if _, err := ReadSecretValue(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted %q", bad[:min(len(bad), 10)])
		}
	}
	if err := (&Env{}).RemoveSecret("../x"); err == nil {
		t.Fatal("accepted a traversal name")
	}
}

// The config-apply unit runs ensure itself. Stopping, restarting or
// kickstarting that unit would kill the running transaction (seen live on
// RHEL: SIGTERM mid-apply, pending transaction left behind), so the
// lifecycle leaves the unit it runs inside alone.
func TestConfigApplyTriggerNeverStopsItself(t *testing.T) {
	for goos, self := range map[string]string{"linux": unitApplyService, "darwin": labelApply} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			payload := h.payload("1.0.0")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
			if got := selfUnitFromEnv(h.services, self); got != self {
				t.Fatalf("selfUnitFromEnv(%q) = %q", self, got)
			}
			h.env.SelfUnit = self
			if goos == "darwin" {
				// launchd runs the apply job while it applies.
				h.services.active[self] = true
			}
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			changed := strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1)
			if err := os.WriteFile(cfg, []byte(changed), 0o600); err != nil {
				t.Fatal(err)
			}
			before := len(h.services.calls)
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: cfg, Reason: "path"}))
			for _, call := range h.services.calls[before:] {
				if call == "stop "+self || call == "start "+self {
					t.Fatalf("the trigger unit was touched: %v", h.services.calls[before:])
				}
			}
			if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
				t.Fatal("config change not applied")
			}
		})
	}
}

// Only the config-apply entry point can be exempted; any other value,
// including a real service, is ignored.
func TestSelfUnitAcceptsOnlyTheApplyEntryPoint(t *testing.T) {
	h := newTestHost(t, "linux")
	for _, value := range []string{"", unitGateway, unitGuardian, "sshd.service", labelApply} {
		if got := selfUnitFromEnv(h.services, value); got != "" {
			t.Fatalf("selfUnitFromEnv(%q) = %q, want empty", value, got)
		}
	}
}

// Agents installed under an administrator prefix the discovery does not
// know are enrolled once the prefix is configured: the lifecycle hands it
// to the enumerator and guardian (systemd drop-in, launchd environment).
func TestAgentPrefixesReachDiscovery(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			raw := strings.Replace(string(DefaultConfig(h.env.Layout)), "  profile: standalone\n", "  profile: standalone\n  enrollment:\n    agent_prefixes: [/opt/tools, /opt/agents]\n", 1)
			if err := os.WriteFile(cfg, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
			want := "DEFENSECLAW_TRUSTED_BIN_PREFIXES"
			if goos == "linux" {
				for _, unit := range []string{unitGuardian, unitGuardianOneshot, unitEnumerator} {
					data := h.read(filepath.Join("/etc/systemd/system", unit+".d", dropinAgents))
					if !strings.Contains(data, want+"=/opt/agents:/opt/tools") {
						t.Fatalf("%s drop-in: %q", unit, data)
					}
				}
				if exists(h.env.P(filepath.Join("/etc/systemd/system", unitGateway+".d", dropinAgents))) {
					t.Fatal("the gateway got the discovery prefixes")
				}
				return
			}
			for _, label := range []string{labelGuardian, labelEnumerator} {
				data := h.read(h.services.DefinitionPath(Unit{Name: label}, ChannelPayload))
				if !strings.Contains(data, want) || !strings.Contains(data, "/opt/agents:/opt/tools") {
					t.Fatalf("%s plist lacks the prefixes", label)
				}
			}
		})
	}
}

// A guardian target refused for an agent version without a verified hook
// contract runs with no DefenseClaw hooks. Status names it and reports the
// deployment security-incomplete; verify keeps it a warning for that account
// and fails only for the other failed target.
func TestUnverifiedHookContractIsVisible(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": false, "target_count": 2, "success_count": 1, "failure_count": 1})
	h.publishLedger(data)
	state, _ := json.Marshal(map[string]any{"results": []map[string]any{
		{"user": "alice", "connector": "codex", "ok": true},
		{"user": "bob", "connector": "devin", "ok": false, "error": `enterprise hooks: connector devin agent version "3999.0.0" is not verified against a known hook contract: no hook contract matches normalized agent version`},
		{"user": "carol", "connector": "omnigent", "ok": false, "error": "enterprise hooks: connector omnigent setup failed: interpreter is not in a trusted install prefix"},
	}})
	if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
		t.Fatal(err)
	}
	status := h.run(Options{Action: ActionStatus})
	requireOK(t, status)
	if status.SecurityComplete {
		t.Fatal("status reports security_complete with an unprotected agent")
	}
	found := false
	for _, w := range status.Warnings {
		if w.Code == codeHookContractUnverified && strings.Contains(w.Message, "devin 3999.0.0 for user bob") && strings.Contains(w.Message, "pin a verified agent version") {
			found = true
		}
	}
	if !found {
		t.Fatalf("status warnings do not name the unverified contract: %+v", status.Warnings)
	}
	failedTarget := false
	for _, w := range status.Warnings {
		if w.Code == codeGuardianTargetFailed && strings.Contains(w.Message, "omnigent for user carol is not protected: connector omnigent setup failed") {
			failedTarget = true
		}
	}
	if !failedTarget {
		t.Fatalf("status warnings do not name the failed target: %+v", status.Warnings)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if verify.SecurityComplete {
		t.Fatal("verify reports security_complete with an unprotected agent")
	}
	if errs := messagesOf(verify.Errors, codeVerify); strings.Contains(errs, "user bob") || !strings.Contains(errs, "user carol") {
		t.Fatalf("verify errors = %q, want only carol's failed target", errs)
	}
}

// A guardian target reason names the refused path first and the remedy
// last; status cut it at 240 bytes, which dropped the remedy. An oversized
// reason keeps its remedy clause and stays bounded.
func TestGuardianTargetReasonKeepsItsRemedy(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	remedy := "install it under an administrator-owned prefix listed in enterprise.enrollment.agent_prefixes"
	oversized := "connector omnigent setup failed: " + strings.Repeat("path/segment/", 300) + "python3.12 is refused; " + remedy
	state, _ := json.Marshal(map[string]any{"results": []map[string]any{
		{"user": "alice", "connector": "omnigent", "ok": false, "error": "enterprise hooks: " + oversized},
	}})
	if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
		t.Fatal(err)
	}
	message := strings.TrimSpace(messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeGuardianTargetFailed))
	if !strings.Contains(message, "for user alice") || !strings.HasSuffix(message, remedy) || len(message) > 1200 {
		t.Fatalf("the oversized reason lost its remedy or is unbounded (%d bytes): %q", len(message), message)
	}
}

// A second lifecycle run reports busy (75) within seconds so an MDM retries
// later, while the config-apply trigger waits for the running transaction
// so a change made during it is still applied afterwards.
func TestLockWaitIsShortExceptForTheApplyTrigger(t *testing.T) {
	env := &Env{GOOS: "linux", Layout: mustLayout(t, "linux")}
	env.fillDefaults()
	if env.LockTimeout != DefaultLockWait || DefaultLockWait > 10*time.Second {
		t.Fatalf("default lock wait = %s", env.LockTimeout)
	}
	unit, err := systemdunits.ReadFile(unitApplyService)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "--lock-wait 10m") {
		t.Fatalf("apply unit does not wait for a running transaction:\n%s", unit)
	}
	plist, err := launchdstandalone.ReadPlist(labelApply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plist), "<string>--lock-wait</string>") {
		t.Fatal("apply daemon does not wait for a running transaction")
	}
}

func mustLayout(t *testing.T, goos string) managed.StandaloneLayout {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

// No unit may deny writable-executable memory. The per-user workers run agent
// CLIs, and Node (V8) aborted every cursor-agent --version under it on RHEL,
// so Cursor was never enrolled. The gateway and the sensor helper link
// bytedance/sonic, which on x86_64 makes memory executable in package init:
// with the directive both panicked at start on RHEL 9 x86_64 (mprotect:
// operation not permitted), leaving the host unprotected.
func TestAgentRunningUnitsAllowJITRuntimes(t *testing.T) {
	for unit, want := range map[string]bool{
		unitEnumerator: false, unitGuardian: false, unitGuardianOneshot: false,
		unitGateway: false, unitSensorHelper: false,
	} {
		data, err := systemdunits.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(data), "\nMemoryDenyWriteExecute=true"); got != want {
			t.Fatalf("%s MemoryDenyWriteExecute=true present=%v, want %v", unit, got, want)
		}
	}
}

// The package scripts run the lifecycle under umask 077. Directories the
// install creates must still get their exact modes, or the gateway service
// cannot read the vendor rule pack (seen live on RHEL with the rpm).
func TestInstallUnderRestrictiveUmaskKeepsDirectoryModes(t *testing.T) {
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	l := h.env.Layout
	for _, dir := range []string{
		filepath.Dir(l.VendorPolicyDir), l.VendorPolicyDir,
		filepath.Join(l.VendorPolicyDir, "guardrail"), filepath.Join(l.VendorPolicyDir, "guardrail", "default"),
		filepath.Join(l.VendorPolicyDir, "guardrail", "default", "rules"), filepath.Join(l.VendorPolicyDir, "rego"),
	} {
		if got := h.mode(dir); got != 0o755 {
			t.Fatalf("%s mode %04o under umask 077, want 0755", dir, got)
		}
	}
	if got := h.mode(filepath.Join(l.VendorPolicyDir, "guardrail", "default", "rules", "secrets.yaml")); got != 0o644 {
		t.Fatalf("vendor rule mode %04o under umask 077", got)
	}
}

// GAP-1193: a connector that inherits the global rule pack is not checked
// again, so a refusal names guardrail.rule_pack_dir.
func TestRulePackCheckOrderNamesTheGlobalKey(t *testing.T) {
	got := rulePackCheckOrder(map[string]string{
		"guardrail.rule_pack_dir":                  "/etc/defenseclaw/policies/guardrail/custom",
		"guardrail.connectors.amp.rule_pack_dir":   "/etc/defenseclaw/policies/guardrail/custom",
		"guardrail.connectors.codex.rule_pack_dir": "/etc/defenseclaw/policies/guardrail/codex",
	})
	want := []string{"guardrail.rule_pack_dir", "guardrail.connectors.codex.rule_pack_dir"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
