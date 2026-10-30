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

package connector

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// hermesRestoreFixture is an account whose Hermes config.yaml holds its own
// model and Bedrock settings, enrolled by a first DefenseClaw setup.
func hermesRestoreFixture(t *testing.T, original string) (*hookOnlyConnector, SetupOpts, string) {
	t.Helper()
	dir := testenv.PrivateTempDir(t)
	hermesHome := filepath.Join(dir, ".hermes")
	t.Setenv("HERMES_HOME", hermesHome)
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previousOverride })
	configPath := filepath.Join(hermesHome, "config.yaml")
	if original != "" {
		if err := os.MkdirAll(hermesHome, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	return conn, opts, configPath
}

func hermesTopKeys(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := yamlTopKeys(data)
	if !ok {
		t.Fatalf("%s does not parse:\n%s", path, data)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

var hermesSpec, _ = agentConfigSpecFor("hermes")

const hermesAccountSettings = "# my Hermes\nmodel:\n  default: us.anthropic.claude-haiku-4-5\n  provider: bedrock\nbedrock:\n  region: us-east-1\n"

// GAP-0564: the guardian's repair of a missing config.yaml put back the hooks
// key alone, and the account's model and Bedrock settings were gone. Setup
// now puts back the copy it kept when the file last verified, with every key,
// and registers its hooks in it.
func TestHermesSetupPutsBackAMissingConfigFromTheLastKnownGoodCopy(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, hermesAccountSettings)
	// The account edits its settings after enrollment; the guardian's next
	// verify that passes keeps that file as the copy.
	edited, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	edited = append(edited, []byte("toolsets:\n  - web\n")...)
	if err := os.WriteFile(configPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != "" {
		t.Fatalf("status for an intact config: %q", status)
	}
	if err := os.Rename(configPath, configPath+".bak"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "bedrock,hooks,model,toolsets" {
		t.Fatalf("restored config.yaml keys = %s, want the account's settings and the hooks", got)
	}
	restored, _ := os.ReadFile(configPath)
	if !strings.HasPrefix(string(restored), "# my Hermes\n") || !strings.Contains(string(restored), "us.anthropic.claude-haiku-4-5") {
		t.Fatalf("restored config.yaml lost the account's bytes:\n%s", restored)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		t.Fatalf("hooks after the repair: %t %v", present, err)
	}
	if status := AgentConfigStatus("hermes", opts, started, false); status != AgentConfigRestoredLastGood {
		t.Fatalf("repair status = %q", status)
	}
	// Reported by the repair only: the next verify is clean.
	if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != "" {
		t.Fatalf("status after the next verify: %q", status)
	}
}

// Without a copy of the last verified file (an install from before the copy
// existed) the file as DefenseClaw's first setup found it is put back.
func TestHermesSetupPutsBackAMissingConfigFromThePristineBackup(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, hermesAccountSettings)
	if err := os.Remove(hermesSpec.copyPath(opts.DataDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "bedrock,hooks,model" {
		t.Fatalf("restored config.yaml keys = %s", got)
	}
	if notice, ok := hermesSpec.readNotice(opts.DataDir); !ok || notice.Source != AgentConfigFromPristine || notice.SettingsLost {
		t.Fatalf("notice = %+v %t", notice, ok)
	}
}

// With no copy at all the hooks are restored alone, and status and verify
// keep saying the account's settings were not put back until they are
// entered again.
func TestHermesSetupReportsSettingsItCouldNotPutBack(t *testing.T) {
	// DefenseClaw's first setup created config.yaml (no pristine file); the
	// account added its settings, and the copy DefenseClaw kept no longer
	// reads.
	conn, opts, configPath := hermesRestoreFixture(t, "")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append([]byte(hermesAccountSettings), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hermesSpec.copyPath(opts.DataDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "hooks" {
		t.Fatalf("recreated config.yaml keys = %s", got)
	}
	for pass := 0; pass < 2; pass++ {
		if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != AgentConfigSettingsLost {
			t.Fatalf("verify pass %d status = %q", pass, status)
		}
	}
	// The account enters its settings again: the notice goes.
	data, _ = os.ReadFile(configPath)
	if err := os.WriteFile(configPath, append([]byte("model:\n  default: x\n"), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != "" {
		t.Fatalf("status after the settings are back: %q", status)
	}
	if _, ok := hermesSpec.readNotice(opts.DataDir); ok {
		t.Fatal("the notice stayed after the settings came back")
	}
}

// A first setup on an account without config.yaml creates the hooks-only
// file as before and reports nothing; an edited file keeps every key (the
// hooks field alone is replaced) and is no restore either.
func TestHermesFirstSetupAndEditedConfigAreNoRestore(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, "")
	if got := hermesTopKeys(t, configPath); got != "hooks" {
		t.Fatalf("first setup keys = %s", got)
	}
	if _, ok := hermesSpec.readNotice(opts.DataDir); ok {
		t.Fatal("a first setup wrote a restore notice")
	}
	if err := os.WriteFile(configPath, []byte("model:\n  default: y\nhooks: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "hooks,model" {
		t.Fatalf("edited config keys = %s", got)
	}
	if status := AgentConfigStatus("hermes", opts, started, false); status != "" {
		t.Fatalf("status for an edited config: %q", status)
	}
}

// Teardown removes the copy and the notice with the account's settings in
// them.
func TestHermesTeardownRemovesTheConfigCopy(t *testing.T) {
	conn, opts, _ := hermesRestoreFixture(t, hermesAccountSettings)
	if _, err := os.Stat(hermesSpec.copyPath(opts.DataDir)); err != nil {
		t.Fatalf("no copy after setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, path := range []string{hermesSpec.copyPath(opts.DataDir), hermesSpec.noticePath(opts.DataDir)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived teardown: %v", path, err)
		}
	}
}

// The same for Devin, whose ~/.config/devin/config.json holds the account's
// own settings beside DefenseClaw's hooks: a missing file is put back with
// them before the hooks go in, and teardown removes the copy.
func TestDevinSetupPutsBackAMissingConfigWithTheAccountsSettings(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	configPath := filepath.Join(dir, ".config", "devin", "config.json")
	previous := DevinHooksPathOverride
	DevinHooksPathOverride = configPath
	t.Cleanup(func() { DevinHooksPathOverride = previous })
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"model":"claude-haiku-4-5","permissions":{"allow":["read"]}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := NewDevinConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, ".defenseclaw"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	if status := AgentConfigStatus("devin", opts, time.Time{}, true); status != "" {
		t.Fatalf("status for an intact config: %q", status)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := jsoncTopKeys(data)
	sort.Strings(keys)
	if !ok || strings.Join(keys, ",") != "hooks,model,permissions" {
		t.Fatalf("restored config.json keys = %v %t:\n%s", keys, ok, data)
	}
	if status := AgentConfigStatus("devin", opts, started, false); status != AgentConfigRestoredLastGood {
		t.Fatalf("repair status = %q", status)
	}
	spec, _ := agentConfigSpecFor("devin")
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, path := range []string{spec.copyPath(opts.DataDir), spec.noticePath(opts.DataDir)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived teardown: %v", path, err)
		}
	}
}

// rel-1-0-2 GAP-0612 (1): the copy DefenseClaw kept of a config.yaml its own
// first setup created holds its hooks only. A later loss puts that copy back,
// and the notice says hooks only, not "with that user's settings".
func TestHermesPutBackHooksOnlyCopyIsReportedAsHooksOnly(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, "")
	if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != "" {
		t.Fatalf("status after first setup: %q", status)
	}
	if _, err := os.Stat(hermesSpec.copyPath(opts.DataDir)); err != nil {
		t.Fatalf("no copy of the hooks-only file: %v", err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if status := AgentConfigStatus("hermes", opts, started, false); status != AgentConfigRecreatedHooksOnly {
		t.Fatalf("status = %q, want %q", status, AgentConfigRecreatedHooksOnly)
	}
}

// GAP-0612 clause 1, live on managed 1.0.5: the copy put back held
// DefenseClaw's hooks only, but the file read after the put-back had another
// key (the running agent writes its own), and the notice said the user's
// settings came back. What was put back decides the wording.
func TestHermesHooksOnlyCopyStaysHooksOnlyWhenTheAgentAddsKeysLater(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, "")
	if keys := hermesTopKeys(t, configPath); keys != "hooks" {
		t.Fatalf("first setup without a file wrote %s", keys)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over the missing file: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append(data, []byte("_config_version: 17\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := AgentConfigStatus("hermes", opts, started, false); got != AgentConfigRecreatedHooksOnly {
		t.Fatalf("AgentConfigStatus = %q, want %q", got, AgentConfigRecreatedHooksOnly)
	}
}

// rel-1-0-2 GAP-0612 (2): with the backup record gone, a copy that is there
// but no longer reads is settings DefenseClaw saw: the file is recreated with
// the hooks and reported as settings lost, not silently.
func TestHermesUnreadableCopyWithoutRecordReportsSettingsLost(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, hermesAccountSettings)
	if err := os.Remove(managedFileBackupPath(opts.DataDir, "hermes", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hermesSpec.copyPath(opts.DataDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "hooks" {
		t.Fatalf("recreated config.yaml keys = %s", got)
	}
	if status := AgentConfigStatus("hermes", opts, time.Time{}, false); status != AgentConfigSettingsLost {
		t.Fatalf("status = %q, want %q", status, AgentConfigSettingsLost)
	}
}
