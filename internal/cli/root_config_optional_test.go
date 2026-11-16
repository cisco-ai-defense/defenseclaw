// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// writeFailingV8Config writes a config_version 8 config.yaml whose
// config_version 9 migration fails (its data.json does not decode).
func writeFailingV8Config(t *testing.T, home string) {
	t.Helper()
	source := "config_version: 8\ndata_dir: " + home + "\ngateway:\n  api_port: 19555\n"
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	rego := filepath.Join(home, "policies", "rego")
	if err := os.MkdirAll(rego, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rego, "data.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func preserveRootState(t *testing.T) {
	t.Helper()
	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	t.Cleanup(func() {
		if auditStore != nil && auditStore != previousStore {
			_ = auditStore.Close()
		}
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
	})
}

// rel-1-0-6 GAP-0153: a config_version 8 config whose config_version 9
// migration failed aborted `connector teardown`, and with it the whole
// uninstall, before the agent's files were restored. Teardown and verify
// print the load error and go on with what config.yaml names; every other
// subcommand still refuses the file.
func TestConnectorTeardownAndVerifyGoOnWhenTheConfigDoesNotLoad(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(managed.DeploymentModeEnv, "")
	writeFailingV8Config(t, home)
	preserveRootState(t)

	parent := &cobra.Command{Use: "defenseclaw-gateway"}
	plain := &cobra.Command{Use: "status"}
	teardown := &cobra.Command{Use: "teardown", Annotations: connectorTeardownCmd.Annotations}
	verify := &cobra.Command{Use: "verify", Annotations: connectorVerifyCmd.Annotations}
	parent.AddCommand(plain, teardown, verify)

	err := rootPersistentPreRunE(plain, nil)
	if err == nil || !strings.Contains(err.Error(), "failed to load config") ||
		!strings.Contains(err.Error(), "config_version 9 migration failed") {
		t.Fatalf("plain subcommand with a failing v8 config = %v, want the migration error", err)
	}
	for _, command := range []*cobra.Command{teardown, verify} {
		var stderr bytes.Buffer
		command.SetErr(&stderr)
		cfg = nil
		if err := rootPersistentPreRunE(command, nil); err != nil {
			t.Fatalf("%s with a failing v8 config = %v, want it to go on", command.Name(), err)
		}
		out := stderr.String()
		if !strings.Contains(out, "failed to load config") || !strings.Contains(out, "config_version 9 migration failed") {
			t.Fatalf("%s stderr = %q, want the config error reported", command.Name(), out)
		}
		if cfg == nil || cfg.Gateway.APIPort != 19555 {
			t.Fatalf("%s config = %+v, want the api port config.yaml names", command.Name(), cfg)
		}
		if auditStore != nil || auditLog != nil {
			t.Fatalf("%s opened the audit store (%v, %v)", command.Name(), auditStore, auditLog)
		}
	}
}

// A file that does not decode at all still lets teardown run on the data
// directory alone, with the error printed.
func TestConnectorTeardownGoesOnWithAnUnreadableConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(managed.DeploymentModeEnv, "")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preserveRootState(t)

	parent := &cobra.Command{Use: "defenseclaw-gateway"}
	teardown := &cobra.Command{Use: "teardown", Annotations: connectorTeardownCmd.Annotations}
	parent.AddCommand(teardown)
	var stderr bytes.Buffer
	teardown.SetErr(&stderr)
	cfg = nil
	if err := rootPersistentPreRunE(teardown, nil); err != nil {
		t.Fatalf("teardown with an unreadable config = %v, want it to go on", err)
	}
	if cfg != nil {
		t.Fatalf("teardown kept a config (%+v) from a file that does not decode", cfg)
	}
	if !strings.Contains(stderr.String(), "failed to load config") || !strings.Contains(stderr.String(), "data directory only") {
		t.Fatalf("stderr = %q, want the config error and the data-directory note", stderr.String())
	}
}

// A managed host keeps its administrator's config strict, for teardown too.
func TestConnectorTeardownStaysStrictOnAManagedHost(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")
	writeFailingV8Config(t, home)
	preserveRootState(t)

	parent := &cobra.Command{Use: "defenseclaw-gateway"}
	teardown := &cobra.Command{Use: "teardown", Annotations: connectorTeardownCmd.Annotations}
	parent.AddCommand(teardown)
	teardown.SetErr(&bytes.Buffer{})
	if continueWithoutConfig(teardown, filepath.Join(home, "config.yaml"), os.ErrInvalid) {
		t.Fatal("teardown went on without its config on a managed host")
	}
}
