// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const policyPathTestModule = `package defenseclaw

import rego.v1

admission := {
	"verdict": "allowed",
	"reason": "fixture",
	"file_action": "allow",
	"install_action": "allow",
	"runtime_action": "allow",
}
`

func TestResolvePolicyPathsLayoutsAndManagedDefaults(t *testing.T) {
	t.Run("canonical preferred", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical)
		writePolicyPathTestLayout(t, root)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.rootDir != root || paths.regoDir != canonical {
			t.Fatalf("resolved paths = %#v", paths)
		}
	})

	t.Run("legacy flat", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, root)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.regoDir != root {
			t.Fatalf("resolved paths = %#v", paths)
		}
	})

	t.Run("configured data directory", func(t *testing.T) {
		dataDir := t.TempDir()
		root := filepath.Join(dataDir, "policies")
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"))
		setPolicyPathTestConfig(t, &config.Config{DataDir: dataDir})
		paths, err := resolvePolicyPaths()
		if err != nil || paths.rootDir != root {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})

	t.Run("default managed home", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", home)
		root := filepath.Join(home, "policies")
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"))
		setPolicyPathTestConfig(t, nil)
		paths, err := resolvePolicyPaths()
		if err != nil || paths.rootDir != root {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})
}

func TestResolvePolicyPathsSecurityBoundaries(t *testing.T) {
	t.Run("working directory ignored", func(t *testing.T) {
		trustedRoot := filepath.Join(t.TempDir(), "missing-policies")
		untrusted := t.TempDir()
		writePolicyPathTestLayout(t, filepath.Join(untrusted, "policies", "rego"))
		previous, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(untrusted); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chdir(previous) })
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: trustedRoot})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.regoDir != filepath.Join(trustedRoot, "rego") {
			t.Fatalf("regoDir = %q", paths.regoDir)
		}
	})

	for _, test := range []struct {
		name string
		root string
		want string
	}{
		{name: "relative", root: filepath.Join("relative", "policies"), want: "absolute"},
		{name: "parent segment", root: t.TempDir() + string(filepath.Separator) + "scope" + string(filepath.Separator) + ".." + string(filepath.Separator) + "policies", want: "parent segment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setPolicyPathTestConfig(t, &config.Config{PolicyDir: test.root})
			_, err := resolvePolicyPaths()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	t.Run("sibling prefix containment", func(t *testing.T) {
		root := t.TempDir()
		if !policyPathContained(root, filepath.Join(root, "rego", "policy.rego")) {
			t.Fatal("contained path rejected")
		}
		if policyPathContained(root, root+"-sibling"+string(filepath.Separator)+"policy.rego") {
			t.Fatal("sibling prefix accepted")
		}
	})

	t.Run("deeper generation", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical)
		writePolicyPathTestLayout(t, filepath.Join(canonical, "rego"))
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if _, err := resolvePolicyPaths(); err == nil || !strings.Contains(err.Error(), "unsupported nested") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestResolvePolicyPathsIgnoresUnusedFlatResidue(t *testing.T) {
	t.Run("nonregular custom module", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical)
		if err := os.Mkdir(filepath.Join(root, "custom.rego"), 0o700); err != nil {
			t.Fatal(err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if paths, err := resolvePolicyPaths(); err != nil || paths.regoDir != canonical {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})
}

func TestPolicyCommandsUseSelectedLayout(t *testing.T) {
	t.Run("canonical", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"))
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		requirePolicyPathCommandsSucceed(t)
	})

	t.Run("legacy", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, root)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		requirePolicyPathCommandsSucceed(t)
	})
}

func TestPolicyReloadRemainsPathIndependent(t *testing.T) {
	ownGatewayListener(t)
	const token = "reload-fixture-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/policy/reload" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-DefenseClaw-Token") != token {
			http.Error(w, "bad request", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	setPolicyPathTestConfig(t, &config.Config{
		PolicyDir: filepath.Join("relative", "untrusted"),
		Gateway:   config.GatewayConfig{APIBind: host, APIPort: port, Token: token},
	})
	if err := policyReloadCmd.RunE(policyReloadCmd, nil); err != nil {
		t.Fatalf("reload resolved local policy paths: %v", err)
	}
}

func policyPathTestCommands() []struct {
	name string
	cmd  *cobra.Command
} {
	return []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "validate", cmd: policyValidateCmd},
		{name: "show", cmd: policyShowCmd},
		{name: "evaluate", cmd: policyEvaluateCmd},
	}
}

func setPolicyPathTestConfig(t *testing.T, value *config.Config) {
	t.Helper()
	previous := cfg
	cfg = value
	t.Cleanup(func() { cfg = previous })
}

func setPolicyPathTestFlags(t *testing.T) {
	t.Helper()
	setPolicyPathTestFlag(t, policyEvaluateCmd, "target-name", "fixture")
}

func setPolicyPathTestFlag(t *testing.T, command *cobra.Command, name, value string) {
	t.Helper()
	flag := command.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("missing flag %s", name)
	}
	previousValue := flag.Value.String()
	previousChanged := flag.Changed
	if err := command.Flags().Set(name, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Flags().Set(name, previousValue)
		flag.Changed = previousChanged
	})
}

func requirePolicyPathCommandsSucceed(t *testing.T) {
	t.Helper()
	for _, command := range policyPathTestCommands() {
		if _, err := capturePolicyPathTestOutput(t, func() error { return command.cmd.RunE(command.cmd, nil) }); err != nil {
			t.Fatalf("%s failed: %v", command.name, err)
		}
	}
}

func writePolicyPathTestLayout(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policyPathTestModule), 0o600); err != nil {
		t.Fatal(err)
	}
}

func capturePolicyPathTestOutput(t *testing.T, run func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	runErr := run()
	os.Stdout = previous
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(raw), runErr
}
