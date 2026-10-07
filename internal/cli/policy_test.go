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
	"encoding/json"
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

firewall := {
	"action": "allow",
	"rule_name": data.marker,
}
`

func TestResolvePolicyPathsLayoutsAndManagedDefaults(t *testing.T) {
	t.Run("canonical preferred", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.rootDir != root || paths.regoDir != canonical || paths.dataPath != filepath.Join(canonical, "data-sandbox.json") {
			t.Fatalf("resolved paths = %#v", paths)
		}
	})

	t.Run("legacy flat", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.regoDir != root || paths.dataPath != filepath.Join(root, "data-sandbox.json") {
			t.Fatalf("resolved paths = %#v", paths)
		}
	})

	t.Run("canonical data-only evidence", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), false)
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.regoDir != canonical {
			t.Fatalf("regoDir = %q, want %q", paths.regoDir, canonical)
		}
		if err := policyValidateCmd.RunE(policyValidateCmd, nil); err == nil || !strings.Contains(err.Error(), "no .rego files") {
			t.Fatalf("validate error = %v", err)
		}
	})

	t.Run("configured data directory", func(t *testing.T) {
		dataDir := t.TempDir()
		root := filepath.Join(dataDir, "policies")
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"), policyPathTestData(t, "configured"), true)
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
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"), policyPathTestData(t, "default"), true)
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
		writePolicyPathTestLayout(t, filepath.Join(untrusted, "policies", "rego"), policyPathTestData(t, "untrusted"), true)
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
		if paths.dataPath != filepath.Join(trustedRoot, "rego", "data-sandbox.json") {
			t.Fatalf("dataPath = %q", paths.dataPath)
		}
		if err := policyDomainsCmd.RunE(policyDomainsCmd, nil); err == nil || !strings.Contains(err.Error(), "data-sandbox.json") {
			t.Fatalf("domains error = %v", err)
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
		if !policyPathContained(root, filepath.Join(root, "rego", "data-sandbox.json")) {
			t.Fatal("contained path rejected")
		}
		if policyPathContained(root, root+"-sibling"+string(filepath.Separator)+"data-sandbox.json") {
			t.Fatal("sibling prefix accepted")
		}
	})

	t.Run("deeper generation", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		writePolicyPathTestLayout(t, filepath.Join(canonical, "rego"), policyPathTestData(t, "deeper"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if _, err := resolvePolicyPaths(); err == nil || !strings.Contains(err.Error(), "unsupported nested") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("redirected supplemental data", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, nil, true)
		target := filepath.Join(t.TempDir(), "data-sandbox.json")
		if err := os.WriteFile(target, []byte(`{"outside":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(canonical, "data-sandbox.json")); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if _, err := resolvePolicyPaths(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestResolvePolicyPathsIgnoresUnusedFlatResidue(t *testing.T) {
	t.Run("nonregular custom module", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		if err := os.Mkdir(filepath.Join(root, "custom.rego"), 0o700); err != nil {
			t.Fatal(err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if paths, err := resolvePolicyPaths(); err != nil || paths.regoDir != canonical {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})

	t.Run("legacy data alias", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		if err := os.Symlink(filepath.Join(canonical, "data-sandbox.json"), filepath.Join(root, "data-sandbox.json")); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if paths, err := resolvePolicyPaths(); err != nil || paths.regoDir != canonical {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})
}

func TestPolicyCommandsUseSelectedAndEffectiveData(t *testing.T) {
	t.Run("canonical", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"), policyPathTestData(t, "canonical"), true)
		writePolicyPathTestLayout(t, root, []byte("{"), false)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		requirePolicyPathCommandsSucceed(t)
	})

	t.Run("legacy", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		requirePolicyPathCommandsSucceed(t)
	})

	t.Run("sandbox data", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "sandbox"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		if err := policyValidateCmd.RunE(policyValidateCmd, nil); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name string
			cmd  *cobra.Command
			want string
		}{
			{name: "show", cmd: policyShowCmd, want: `"admission"`},
			{name: "evaluate", cmd: policyEvaluateCmd, want: `"reason": "fixture"`},
			{name: "firewall", cmd: policyEvaluateFirewallCmd, want: `"rule_name": "sandbox"`},
			{name: "domains", cmd: policyDomainsCmd, want: "sandbox.example.invalid"},
		} {
			t.Run(test.name, func(t *testing.T) {
				output, err := capturePolicyPathTestOutput(t, func() error { return test.cmd.RunE(test.cmd, nil) })
				if err != nil || !strings.Contains(output, test.want) {
					t.Fatalf("output = %q, error = %v, want %q", output, err, test.want)
				}
			})
		}
	})
}

// The firewall dry runs read data-sandbox.json and fail closed on a missing
// or malformed copy rather than falling back to the legacy flat one.
func TestPolicyCommandsFailClosedOnCanonicalData(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "missing", data: nil},
		{name: "malformed", data: []byte("{")},
		{name: "null", data: []byte("null")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			canonical := filepath.Join(root, "rego")
			writePolicyPathTestLayout(t, canonical, test.data, true)
			writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
			setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
			setPolicyPathTestFlags(t)
			for _, command := range []*cobra.Command{policyEvaluateFirewallCmd, policyDomainsCmd} {
				t.Run(command.Name(), func(t *testing.T) {
					if err := command.RunE(command, nil); err == nil {
						t.Fatalf("%s accepted %s sandbox data", command.Name(), test.name)
					}
				})
			}
		})
	}
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

// TestPolicyReloadErrorIsPlain pins GAP-0160: a failed rebuild shows words, not
// the HTTP status, the JSON body or the internal stage names.
func TestPolicyReloadErrorIsPlain(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	pin := `{"error":"reload failed: config reload rule pack preflight: global rule pack \"p0m\": digest ` + digest +
		` does not match guardrail.custom_packs.p0m.digest","status":"failed"}`
	want := "policy reload failed: rule pack p0m no longer matches its pin (guardrail.custom_packs.p0m.digest). " +
		"The previous policy is still enforcing. Review the pack, then pin it with: " +
		"defenseclaw config set guardrail.custom_packs.p0m.digest " + digest
	if got := policyReloadError(http.StatusInternalServerError, []byte(pin)).Error(); got != want {
		t.Fatalf("pin mismatch:\n got %q\nwant %q", got, want)
	}
	other := policyReloadError(http.StatusInternalServerError, []byte(`{"error":"reload failed: opa: bad rule","status":"failed"}`)).Error()
	if other != "policy reload failed: opa: bad rule. The previous policy is still enforcing" {
		t.Fatalf("other rebuild failure = %q", other)
	}
	if got := policyReloadError(http.StatusServiceUnavailable, []byte(`{"error":"policy_dir not configured"}`)).Error(); got != "policy reload failed: policy_dir not configured" {
		t.Fatalf("unavailable = %q", got)
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
		{name: "evaluate-firewall", cmd: policyEvaluateFirewallCmd},
		{name: "domains", cmd: policyDomainsCmd},
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
	setPolicyPathTestFlag(t, policyEvaluateFirewallCmd, "destination", "example.invalid")
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

func policyPathTestData(t *testing.T, marker string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]interface{}{
		"marker": marker,
		"firewall": map[string]interface{}{
			"default_action": "allow", "blocked_destinations": []string{}, "allowed_domains": []string{marker + ".example.invalid"}, "allowed_ports": []int{443},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writePolicyPathTestLayout(t *testing.T, dir string, data []byte, withModule bool) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if withModule {
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policyPathTestModule), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if data != nil {
		if err := os.WriteFile(filepath.Join(dir, "data-sandbox.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
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
