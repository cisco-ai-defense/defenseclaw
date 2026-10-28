// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

// GAP-0995: a second in-memory load of a v8 file with a rotated inline key
// uses the new key; a value set outside the process still wins.
func TestMigrateV8InMemoryAppliesARotatedInlineKey(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := func(key string) []byte {
		return []byte("config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    use_virustotal: true\n" +
			"    virustotal_api_key: " + key + "\nobservability: {}\n")
	}
	for _, key := range []string{"vt-rotation-first", "vt-rotation-second"} {
		if _, err := MigrateV8InMemory(configPath, source(key), nil); err != nil {
			t.Fatal(err)
		}
		if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != key {
			t.Fatalf("after loading %s the variable holds another value", key)
		}
	}
	t.Setenv("VIRUSTOTAL_API_KEY", "vt-set-by-the-operator")
	if _, err := MigrateV8InMemory(configPath, source("vt-rotation-third"), nil); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != "vt-set-by-the-operator" {
		t.Fatal("an in-memory load replaced a value set outside the process")
	}
}

// GAP-1148: data.json edited after the migration read it is not retired
// with the edit lost: the commit refuses, and config.yaml stays v8.
func TestMigrateV9RefusesADataJSONEditedMeanwhile(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(configPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(dir, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"config": {"scan_on_install": false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &v9Migrator{in: MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON}, configPath: configPath}
	migrated, _, err := m.migrate(source)
	if err != nil {
		t.Fatal(err)
	}
	edited := []byte(`{"config": {"scan_on_install": true}}`)
	if err := os.WriteFile(dataJSON, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.commit(context.Background(), source, migrated); err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("commit after a data.json edit = %v, want a refusal", err)
	}
	if got, _ := os.ReadFile(configPath); string(got) != string(source) {
		t.Fatal("config.yaml was rewritten from the stale data.json")
	}
	if got, err := os.ReadFile(dataJSON); err != nil || string(got) != string(edited) {
		t.Fatalf("the edited data.json was moved or changed: %v", err)
	}
}

// GAP-1148: a data.json edited after the commit checked it, while
// config.yaml is written, puts config.yaml back to config_version 8 and
// keeps the edit in data.json, so the next run migrates it.
func TestMigrateV9PutsTheV8ConfigBackWhenDataJSONChangesDuringTheCommit(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(configPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(dir, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"config": {"scan_on_install": false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	edited := []byte(`{"config": {"scan_on_install": true}}`)
	commit := commitV9Config
	t.Cleanup(func() { commitV9Config = commit })
	commitV9Config = func(txn *cfgtxn.Txn, expected, candidate []byte, exists bool, mode os.FileMode, w cfgtxn.Writer) (cfgtxn.GenerationState, error) {
		if err := os.WriteFile(dataJSON, edited, 0o600); err != nil {
			t.Error(err)
		}
		return commit(txn, expected, candidate, exists, mode, w)
	}
	m := &v9Migrator{in: MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON}, configPath: configPath}
	migrated, _, err := m.migrate(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.commit(context.Background(), source, migrated); err == nil || !strings.Contains(err.Error(), "left at config_version 8") {
		t.Fatalf("commit with data.json edited meanwhile = %v, want the v8 config put back", err)
	}
	if got, _ := os.ReadFile(configPath); string(got) != string(source) {
		t.Fatal("config.yaml holds a v9 config without the data.json edit")
	}
	if got, err := os.ReadFile(dataJSON); err != nil || string(got) != string(edited) {
		t.Fatalf("the edited data.json is not in place: %v", err)
	}
	if _, err := os.Stat(dataJSON + DataJSONMigratedSuffix); !os.IsNotExist(err) {
		t.Fatalf("the edited data.json was retired: %v", err)
	}

	commitV9Config = commit
	again := &v9Migrator{in: MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON}, configPath: configPath}
	if migrated, _, err = again.migrate(source); err != nil {
		t.Fatal(err)
	}
	if _, err := again.commit(context.Background(), source, migrated); err != nil {
		t.Fatalf("the next run: %v", err)
	}
	if got, err := os.ReadFile(dataJSON + DataJSONMigratedSuffix); err != nil || string(got) != string(edited) {
		t.Fatalf("the next run did not migrate the edited data.json: %v", err)
	}
}
