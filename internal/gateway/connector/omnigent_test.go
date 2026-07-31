// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func omnigentTestPython(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python", "python3"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Skip("Python is required for the OmniGent policy bridge test")
	return ""
}

func withOmnigentPathOverrides(t *testing.T, configPath, sitePackages string) {
	t.Helper()
	previousConfig := OmnigentConfigPathOverride
	previousSite := OmnigentSitePackagesPathOverride
	OmnigentConfigPathOverride = configPath
	OmnigentSitePackagesPathOverride = sitePackages
	t.Cleanup(func() {
		OmnigentConfigPathOverride = previousConfig
		OmnigentSitePackagesPathOverride = previousSite
	})
}

func TestOmnigentSetupAndTeardown(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "defenseclaw")
	configPath := filepath.Join(root, ".omnigent", "config.yaml")
	sitePackages := filepath.Join(root, "venv", "site-packages")
	withOmnigentPathOverrides(t, configPath, sitePackages)

	original := []byte("server: https://example.test\npolicy_modules:\n  - existing.policies\n")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewOmnigentConnector()
	opts := SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     `token-with-"quotes"`,
		HookFailMode: "closed",
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("create data dir: %v", err)
	}
	if _, err := EnsureHookAPIToken(dataDir, conn.Name()); err != nil {
		t.Fatalf("seed scoped hook token: %v", err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if token, err := LoadOTLPPathToken(dataDir, OTLPScopeOmnigent); err != nil || token == "" {
		t.Fatalf("scoped OmniGent OTLP token after setup = %q, %v", token, err)
	}
	// Setup is intentionally idempotent; daemon restarts must not duplicate
	// the module registration or default policy.
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	modules, err := yamlStringList(config["policy_modules"])
	if err != nil {
		t.Fatal(err)
	}
	if !stringSliceContains(modules, "existing.policies") || !stringSliceContains(modules, omnigentPolicyModuleName) || len(modules) != 2 {
		t.Fatalf("policy_modules = %v", modules)
	}
	policies, _ := config["policies"].(map[string]interface{})
	policy, _ := policies[omnigentPolicyConfigKey].(map[string]interface{})
	if got := policy["handler"]; got != omnigentPolicyHandler {
		t.Fatalf("policy handler = %v, want %s", got, omnigentPolicyHandler)
	}

	modulePath := omnigentPolicyModulePath(opts)
	moduleBytes, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	module := string(moduleBytes)
	if strings.Contains(module, `token-with-"quotes"`) {
		t.Fatal("policy module contains the raw gateway token; expected base64 rendering")
	}
	for _, placeholder := range []string{"{{API_ADDR_B64}}", "{{API_TOKEN_B64}}", "{{FAIL_MODE_B64}}"} {
		if strings.Contains(module, placeholder) {
			t.Fatalf("policy module contains unresolved template placeholder %s", placeholder)
		}
	}
	if got := strings.Count(module, `"handler": "defenseclaw_omnigent_policy.defenseclaw_policy"`); got != 1 {
		t.Fatalf("POLICY_REGISTRY handler declarations = %d, want exactly one", got)
	}
	pthBytes, err := os.ReadFile(filepath.Join(sitePackages, "defenseclaw_omnigent.pth"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(pthBytes)), filepath.Dir(modulePath); got != want {
		t.Fatalf(".pth target = %q, want %q", got, want)
	}
	if !OwnsManagedHookRuntime(conn) {
		t.Fatal("OmniGent policy module is not recognized as a guardian-managed hook runtime")
	}
	if paths := HookConfigPathsForConnector(conn, opts); len(paths) != 1 || filepath.Clean(paths[0]) != filepath.Clean(configPath) {
		t.Fatalf("HookConfigPathsForConnector = %v, want [%s]", paths, configPath)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	} else if !present {
		t.Fatal("OwnedHooksPresent = false after OmniGent policy setup")
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatalf("config not restored byte-for-byte:\n%s", restored)
	}
	for _, path := range []string{modulePath, filepath.Join(sitePackages, "defenseclaw_omnigent.pth")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed artifact still exists at %s: %v", path, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if token, err := LoadOTLPPathToken(dataDir, OTLPScopeOmnigent); err != nil || token != "" {
		t.Fatalf("scoped OmniGent OTLP token after teardown = %q, %v; want revoked", token, err)
	}
	if token, err := LoadHookAPIToken(dataDir, conn.Name()); err != nil || token != "" {
		t.Fatalf("scoped OmniGent hook token after teardown = %q, %v; want revoked", token, err)
	}
}

func TestOmnigentSetupRefreshesHookTokenInsideLifecycleTransaction(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "defenseclaw")
	configPath := filepath.Join(root, "config", "config.yaml")
	sitePackages := filepath.Join(root, "site-packages")
	withOmnigentPathOverrides(t, configPath, sitePackages)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldToken, err := EnsureHookAPIToken(dataDir, "omnigent")
	if err != nil {
		t.Fatalf("seed old hook token: %v", err)
	}
	opts := SetupOpts{
		DataDir:            dataDir,
		APIAddr:            "127.0.0.1:18970",
		APIToken:           oldToken,
		HookAPIToken:       oldToken,
		HookAPITokenScoped: true,
		HookFailMode:       "closed",
	}

	lockHeld := make(chan struct{})
	releaseLock := make(chan struct{})
	lockResult := make(chan error, 1)
	go func() {
		lockResult <- withOmnigentLifecycleTransaction(opts, func() error {
			close(lockHeld)
			<-releaseLock
			return nil
		})
	}()
	<-lockHeld
	if err := RemoveHookAPIToken(dataDir, "omnigent"); err != nil {
		t.Fatalf("simulate locked teardown token revocation: %v", err)
	}

	conn := NewOmnigentConnector()
	setupStarted := make(chan struct{})
	setupResult := make(chan error, 1)
	go func() {
		close(setupStarted)
		setupResult <- conn.Setup(context.Background(), opts)
	}()
	<-setupStarted
	close(releaseLock)
	if err := <-lockResult; err != nil {
		t.Fatalf("release lifecycle barrier: %v", err)
	}
	if err := <-setupResult; err != nil {
		t.Fatalf("Setup after locked token revocation: %v", err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })

	newToken, err := LoadHookAPIToken(dataDir, "omnigent")
	if err != nil {
		t.Fatal(err)
	}
	if newToken == "" || newToken == oldToken {
		t.Fatalf("refreshed hook token = %q, want non-empty rotation", newToken)
	}
	if conn.gatewayToken != newToken {
		t.Fatal("connector authentication state did not receive refreshed hook token")
	}
	module, err := os.ReadFile(omnigentPolicyModulePath(opts))
	if err != nil {
		t.Fatal(err)
	}
	oldEncoded := base64.StdEncoding.EncodeToString([]byte(oldToken))
	newEncoded := base64.StdEncoding.EncodeToString([]byte(newToken))
	if bytes.Contains(module, []byte(oldEncoded)) || !bytes.Contains(module, []byte(newEncoded)) {
		t.Fatal("managed policy was not rendered with the token refreshed inside the lifecycle lock")
	}
}

func TestOmnigentSitePackagesIgnoresInterpreterStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell stubs")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	purelib := filepath.Join(root, "Python Env", "lib", "python", "site-packages")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"omnigent": "#!/bin/sh\nexit 0\n",
		"python":   "#!/bin/sh\nprintf 'sitecustomize warning\\n' >&2\nprintf '0.7.0\\n%s\\n' \"$OMNIGENT_TEST_PURELIB\"\n",
	} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)
	t.Setenv("OMNIGENT_TEST_PURELIB", purelib)
	t.Setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", binDir)
	previous := OmnigentSitePackagesPathOverride
	OmnigentSitePackagesPathOverride = ""
	t.Cleanup(func() { OmnigentSitePackagesPathOverride = previous })

	got, err := omnigentSitePackages(context.Background(), SetupOpts{})
	if err != nil {
		t.Fatalf("omnigentSitePackages: %v", err)
	}
	if got != purelib {
		t.Fatalf("site-packages = %q, want %q", got, purelib)
	}
}

func TestOmnigentSitePackagesRejectsUntrustedInterpreter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell stubs")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"omnigent", "python"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)
	t.Setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
	previous := OmnigentSitePackagesPathOverride
	OmnigentSitePackagesPathOverride = ""
	t.Cleanup(func() { OmnigentSitePackagesPathOverride = previous })

	_, err := omnigentSitePackages(context.Background(), SetupOpts{})
	if err == nil || !strings.Contains(err.Error(), "trusted install prefix") {
		t.Fatalf("error = %v, want trusted-prefix refusal", err)
	}
}

func TestOmnigentSitePackagesRejectsShebangArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shebang semantics")
	}
	binDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(binDir, "omnigent"),
		[]byte("#!/usr/bin/env python3 -I\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	previous := OmnigentSitePackagesPathOverride
	OmnigentSitePackagesPathOverride = ""
	t.Cleanup(func() { OmnigentSitePackagesPathOverride = previous })

	_, err := omnigentSitePackages(context.Background(), SetupOpts{})
	if err == nil || !strings.Contains(err.Error(), "unsupported interpreter arguments") {
		t.Fatalf("error = %v, want unsupported shebang arguments", err)
	}
}

func TestOmnigentNativeMetadataProbeTimesOut(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native OmniGent metadata probes are Windows-only")
	}
	previous := omnigentProcessProbeTimeout
	omnigentProcessProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { omnigentProcessProbeTimeout = previous })
	// The package's Windows TestMain turns this test binary into a native
	// stalling parent with an inheriting descendant before Go's test flag
	// parser runs. The metadata helper must terminate the whole process tree.
	t.Setenv("TEST_OMNIGENT_PROBE_MODE", "parent")

	started := time.Now()
	_, err := omnigentCommandOutput(context.Background(), os.Args[0], "tool", "dir", "--bin")
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalling native metadata probe error = %v, want deadline exceeded", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("stalling native metadata probe returned after %s, want prompt bounded termination", elapsed)
	}
}

func TestOmnigentSetupRefreshesBackupsWhenTargetsMove(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "defenseclaw")
	oldConfig := filepath.Join(root, "old-config", "config.yaml")
	newConfig := filepath.Join(root, "new-config", "config.yaml")
	oldSitePackages := filepath.Join(root, "old-python", "site-packages")
	newSitePackages := filepath.Join(root, "new-python", "site-packages")
	oldConfigBytes := []byte("policies:\n  operator_policy: {}\n")
	newConfigBytes := []byte("policies:\n  new_operator_policy: {}\n")
	if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(newConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldConfig, oldConfigBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newConfig, newConfigBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig := OmnigentConfigPathOverride
	previousSite := OmnigentSitePackagesPathOverride
	t.Cleanup(func() {
		OmnigentConfigPathOverride = previousConfig
		OmnigentSitePackagesPathOverride = previousSite
	})
	OmnigentConfigPathOverride = oldConfig
	OmnigentSitePackagesPathOverride = oldSitePackages
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}

	OmnigentConfigPathOverride = newConfig
	OmnigentSitePackagesPathOverride = newSitePackages
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup after target move: %v", err)
	}
	if got, err := os.ReadFile(oldConfig); err != nil || string(got) != string(oldConfigBytes) {
		t.Fatalf("old config after target move = %q, %v; want pristine %q", got, err, oldConfigBytes)
	}
	if _, err := os.Stat(filepath.Join(oldSitePackages, "defenseclaw_omnigent.pth")); !os.IsNotExist(err) {
		t.Fatalf("old import shim survived target move: %v", err)
	}
	for logical, want := range map[string]string{
		"config": newConfig,
		"pth":    filepath.Join(newSitePackages, "defenseclaw_omnigent.pth"),
	} {
		backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, conn.Name(), logical))
		if err != nil {
			t.Fatal(err)
		}
		if backup.Path != want {
			t.Fatalf("%s backup path = %q, want %q", logical, backup.Path, want)
		}
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got, err := os.ReadFile(newConfig); err != nil || string(got) != string(newConfigBytes) {
		t.Fatalf("new config after teardown = %q, %v; want pristine %q", got, err, newConfigBytes)
	}
}

func TestOmnigentRawPolicyTemplateImportsFailOpen(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "omnigent-policy.py")
	if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("raw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({"type": "request", "data": "hello"})))
`
	output, err := exec.Command(python, "-c", script, path).CombinedOutput()
	if err != nil {
		t.Fatalf("raw policy import: %v\n%s", err, output)
	}
	var verdict map[string]string
	if err := json.Unmarshal(output, &verdict); err != nil {
		t.Fatal(err)
	}
	if verdict["result"] != "ALLOW" {
		t.Fatalf("raw template verdict = %v, want fail-open ALLOW", verdict)
	}
}

func TestOmnigentPolicyPayloadRejectsNonFiniteNumbers(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "omnigent-policy.py")
	if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("raw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
payload = module._payload({
    "type": "tool_call",
    "data": {"name": "score", "arguments": {"nan": float("nan"), "inf": float("inf")}},
})
print(json.dumps(payload, allow_nan=False))
`
	output, err := exec.Command(python, "-c", script, path).CombinedOutput()
	if err != nil {
		t.Fatalf("normalize non-finite payload: %v\n%s", err, output)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["tool_input"].(string); !ok {
		t.Fatalf("tool_input = %#v, want safe string fallback", payload["tool_input"])
	}
}

func TestOmnigentPolicyBridgeMapsBlockToDeny(t *testing.T) {
	python := omnigentTestPython(t)

	var received map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if got := r.URL.Path; got != "/api/v1/omnigent/hook" {
			t.Errorf("path = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-test" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Traceparent"); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
			t.Errorf("Traceparent = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"block","reason":"blocked by test"}`))
	}))
	defer server.Close()

	root := t.TempDir()
	configPath := filepath.Join(root, ".omnigent", "config.yaml")
	sitePackages := filepath.Join(root, "site-packages")
	withOmnigentPathOverrides(t, configPath, sitePackages)
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "defenseclaw"),
		APIAddr:      strings.TrimPrefix(server.URL, "http://"),
		APIToken:     "tok-test",
		HookFailMode: "closed",
	}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })

	script := `
import importlib.util, json, sys, types
propagate = types.ModuleType("opentelemetry.propagate")
def inject(carrier):
    carrier["traceparent"] = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    carrier["Content-Type"] = "text/plain"
propagate.inject = inject
opentelemetry = types.ModuleType("opentelemetry")
opentelemetry.propagate = propagate
sys.modules["opentelemetry"] = opentelemetry
sys.modules["opentelemetry.propagate"] = propagate
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({
    "type": "tool_call",
    "target": "shell",
    "data": {"name": "shell", "arguments": {"command": "rm -rf /tmp/x"}},
    "context": {"model": "test-model", "actor": {"run_as": "alice@example.test"}},
})))
`
	output, err := exec.Command(python, "-c", script, omnigentPolicyModulePath(opts)).CombinedOutput()
	if err != nil {
		t.Fatalf("execute policy module: %v\n%s", err, output)
	}
	var verdict map[string]string
	if err := json.Unmarshal(output, &verdict); err != nil {
		t.Fatalf("decode policy verdict %q: %v", output, err)
	}
	if verdict["result"] != "DENY" || verdict["reason"] != "blocked by test" {
		t.Fatalf("verdict = %v", verdict)
	}
	if received["hook_event_name"] != "PreToolUse" || received["tool_name"] != "shell" || received["model"] != "test-model" {
		t.Fatalf("normalized request = %#v", received)
	}
	if _, invented := received["agent_id"]; invented {
		t.Fatalf("actor identity was reclassified as agent_id: %#v", received)
	}
}

func TestOmnigentPolicyBridgeFailMode(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want string
	}{{"open", "ALLOW"}, {"closed", "DENY"}} {
		t.Run(tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(string(templateBytes), "127.0.0.1:1", "", tc.mode)
			if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({"type": "request", "data": "hello"})))
`
			output, err := exec.Command(python, "-c", script, path).CombinedOutput()
			if err != nil {
				t.Fatalf("execute policy: %v\n%s", err, output)
			}
			var verdict map[string]string
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict["result"] != tc.want {
				t.Fatalf("verdict = %v, want %s", verdict, tc.want)
			}
		})
	}
}

func TestOmnigentPolicyBridgeTraceFailureHonorsFailMode(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys, types
propagate = types.ModuleType("opentelemetry.propagate")
def explode(_carrier):
    raise AssertionError("propagator failed")
propagate.inject = explode
opentelemetry = types.ModuleType("opentelemetry")
opentelemetry.__path__ = []
sys.modules["opentelemetry"] = opentelemetry
sys.modules["opentelemetry.propagate"] = propagate
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
event = {"type": "request", "data": {"user_content": "hello", "attachments": []}}
print(json.dumps(module.defenseclaw_policy(event)))
`
	for _, tc := range []struct {
		mode string
		want string
	}{{"open", "ALLOW"}, {"closed", "DENY"}} {
		t.Run(tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(string(templateBytes), "127.0.0.1:1", "", tc.mode)
			if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(python, "-c", script, path).CombinedOutput()
			if err != nil {
				t.Fatalf("execute policy: %v\n%s", err, output)
			}
			var verdict map[string]string
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict["result"] != tc.want {
				t.Fatalf("trace failure verdict = %v, want %s", verdict, tc.want)
			}
		})
	}
}

func TestOmnigentPolicyBridgeRejectsAmbientProxyAndRedirect(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys, urllib.request
# Force a default urllib opener to honor the ambient proxy even for loopback.
# The managed bridge's explicit empty ProxyHandler must remain unaffected.
urllib.request.proxy_bypass = lambda _host: False
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({"type": "request", "data": "hello"})))
`
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			var proxyCalls int
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				proxyCalls++
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"allow"}`))
			}))
			defer proxy.Close()

			var gatewayCalls int
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				gatewayCalls++
				http.Redirect(w, nil, proxy.URL+"/leak", http.StatusFound)
			}))
			defer gateway.Close()
			gatewayAddr := strings.TrimPrefix(gateway.URL, "http://")

			modulePath := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(string(templateBytes), gatewayAddr, "scoped-secret", mode)
			if err := os.WriteFile(modulePath, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(python, "-c", script, modulePath)
			cmd.Env = append(os.Environ(),
				"HTTP_PROXY="+proxy.URL,
				"HTTPS_PROXY="+proxy.URL,
				"NO_PROXY=",
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("execute policy: %v\n%s", err, output)
			}
			var verdict map[string]string
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatal(err)
			}
			want := "ALLOW"
			if mode == "closed" {
				want = "DENY"
			}
			if verdict["result"] != want {
				t.Fatalf("redirect verdict = %v, want %s", verdict, want)
			}
			if gatewayCalls != 1 {
				t.Fatalf("direct gateway calls = %d, want 1", gatewayCalls)
			}
			if proxyCalls != 0 {
				t.Fatalf("ambient proxy/redirect receiver calls = %d, want 0", proxyCalls)
			}
		})
	}
}

func TestOmnigentPolicyBridgeInvalidResponseHonorsFailMode(t *testing.T) {
	python := omnigentTestPython(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({"type": "request", "data": "hello"})))
`
	for _, tc := range []struct {
		mode string
		want string
	}{{"open", "ALLOW"}, {"closed", "DENY"}} {
		t.Run(tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(
				string(templateBytes),
				strings.TrimPrefix(server.URL, "http://"),
				"",
				tc.mode,
			)
			if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(python, "-c", script, path).CombinedOutput()
			if err != nil {
				t.Fatalf("execute policy: %v\n%s", err, output)
			}
			var verdict map[string]string
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict["result"] != tc.want {
				t.Fatalf("verdict = %v, want %s", verdict, tc.want)
			}
		})
	}
}

func TestOmnigentPostPhaseAlertContinuesInFailClosedMode(t *testing.T) {
	python := omnigentTestPython(t)
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		received = append(received, fmt.Sprint(payload["hook_event_name"]))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"alert","reason":"post-phase confirm was audited"}`))
	}))
	defer server.Close()

	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
	rendered := renderOmnigentPolicy(
		string(templateBytes),
		strings.TrimPrefix(server.URL, "http://"),
		"",
		"closed",
	)
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
events = [
    {"type": "tool_result", "target": "shell", "data": {"result": "done"},
     "request_data": {"name": "shell", "arguments": {}}},
    {"type": "response", "data": "assistant response"},
    {"type": "llm_response", "data": {"text_preview": "model response"}},
]
print(json.dumps([module.defenseclaw_policy(event) for event in events]))
`
	output, err := exec.Command(python, "-c", script, path).CombinedOutput()
	if err != nil {
		t.Fatalf("execute post-phase policy: %v\n%s", err, output)
	}
	var verdicts []map[string]string
	if err := json.Unmarshal(output, &verdicts); err != nil {
		t.Fatalf("decode post-phase verdicts %q: %v", output, err)
	}
	if len(verdicts) != 3 {
		t.Fatalf("post-phase verdicts = %v", verdicts)
	}
	for index, verdict := range verdicts {
		if verdict["result"] != "ALLOW" {
			t.Errorf("post-phase verdict %d = %v, want ALLOW", index, verdict)
		}
	}
	wantEvents := []string{"PostToolUse", "AfterAgentResponse", "AfterModel"}
	if !reflect.DeepEqual(received, wantEvents) {
		t.Fatalf("post-phase gateway events = %v, want %v", received, wantEvents)
	}
}

func TestOmnigentConfirmIsNativeOnlyBeforeActions(t *testing.T) {
	profile := NewOmnigentConnector().HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970"})
	response := profile.Respond(HookRespondInput{Req: HookProfileRequest{ConnectorName: "omnigent"}, Action: "allow"})
	if response.FieldName != "" || response.Output != nil || profile.ResponseFieldName != "" {
		t.Fatalf("OmniGent response contract must be top-level only: profile=%q response=%+v", profile.ResponseFieldName, response)
	}
	for _, event := range []string{"UserPromptSubmit", "PreToolUse", "BeforeModel"} {
		out := profile.MapVerdict(HookVerdictInput{RawAction: "confirm", Event: event, Mode: "action", Caps: profile.Capabilities})
		if out.Action != "confirm" {
			t.Errorf("%s confirm mapped to %q, want native confirm", event, out.Action)
		}
	}
	for _, event := range []string{"PostToolUse", "AfterAgentResponse", "AfterModel"} {
		out := profile.MapVerdict(HookVerdictInput{RawAction: "confirm", Event: event, Mode: "action", Caps: profile.Capabilities})
		if out.Action != "alert" {
			t.Errorf("%s confirm mapped to %q, want post-action alert fallback", event, out.Action)
		}
	}
}

func TestOmnigentDenyIsAuthoritativeAcrossAllPolicyPhases(t *testing.T) {
	caps := NewOmnigentConnector().Capabilities(SetupOpts{}).Hooks
	for _, event := range []string{
		"UserPromptSubmit", "PreToolUse", "PostToolUse",
		"AfterAgentResponse", "BeforeModel", "AfterModel",
	} {
		if !stringSliceContains(caps.BlockEvents, event) {
			t.Errorf("%s missing from authoritative DENY events: %v", event, caps.BlockEvents)
		}
	}
}

func TestOmnigentPolicyBridgeVerdictMappingAndEmptyToken(t *testing.T) {
	python := omnigentTestPython(t)
	responses := map[string]string{"deny-case": "block", "ask-case": "confirm", "allow-case": "allow"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("empty configured token emitted Authorization = %q", got)
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		action := responses[fmt.Sprint(payload["tool_name"])]
		_, _ = fmt.Fprintf(w, `{"action":%q,"reason":"mapped"}`, action)
	}))
	defer server.Close()

	root := t.TempDir()
	withOmnigentPathOverrides(t, filepath.Join(root, "config.yaml"), filepath.Join(root, "site-packages"))
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: strings.TrimPrefix(server.URL, "http://")}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })

	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for name in ("deny-case", "ask-case", "allow-case"):
    print(json.dumps(module.defenseclaw_policy({"type": "tool_call", "data": {"name": name, "arguments": {}}})))
`
	output, err := exec.Command(python, "-c", script, omnigentPolicyModulePath(opts)).CombinedOutput()
	if err != nil {
		t.Fatalf("execute policy module: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	want := []string{"DENY", "ASK", "ALLOW"}
	if len(lines) != len(want) {
		t.Fatalf("verdict output = %q", output)
	}
	for i, line := range lines {
		var verdict map[string]string
		if err := json.Unmarshal([]byte(line), &verdict); err != nil {
			t.Fatal(err)
		}
		if verdict["result"] != want[i] {
			t.Errorf("verdict[%d] = %v, want %s", i, verdict, want[i])
		}
	}
}

func TestOmnigentPolicyEventFixture(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	modulePath := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
	if err := os.WriteFile(modulePath, []byte(renderOmnigentPolicy(string(templateBytes), "127.0.0.1:1", "", "open")), 0o600); err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join("testdata", "omnigent-policy-event.json")
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with open(sys.argv[2], encoding="utf-8") as fh:
    print(json.dumps(module._payload(json.load(fh)), sort_keys=True))
`
	output, err := exec.Command(python, "-c", script, modulePath, fixturePath).CombinedOutput()
	if err != nil {
		t.Fatalf("normalize fixture: %v\n%s", err, output)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["hook_event_name"] != "PostToolUse" || payload["tool_name"] != "shell" ||
		payload["omnigent_actor_client_id"] != "client-123" {
		t.Fatalf("normalized fixture = %#v", payload)
	}
	if _, invented := payload["agent_id"]; invented {
		t.Fatalf("official actor client_id was reclassified as an agent identity: %#v", payload)
	}
	input, _ := payload["tool_input"].(map[string]interface{})
	if input["command"] != "pwd" {
		t.Fatalf("tool_input = %#v", input)
	}
}

func TestOmnigentOfficialShapedRequestSchemaFixture(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	modulePath := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
	if err := os.WriteFile(modulePath, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// This is synthetic schema-shaped data, not a captured upstream event. Its
	// fields mirror the request contract pinned at OmniGent v0.7.0 schema.py.
	fixturePath := filepath.Join("testdata", "omnigent-policy-request-schema.json")
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with open(sys.argv[2], encoding="utf-8") as fh:
    print(json.dumps(module._payload(json.load(fh)), sort_keys=True))
`
	output, err := exec.Command(python, "-c", script, modulePath, fixturePath).CombinedOutput()
	if err != nil {
		t.Fatalf("normalize official request fixture: %v\n%s", err, output)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["hook_event_name"] != "UserPromptSubmit" {
		t.Fatalf("normalized official request fixture = %#v", payload)
	}
	prompt, _ := payload["prompt"].(string)
	for _, want := range []string{
		"Review the attached deployment plan.",
		`[OmniGent attachment {"filename":"deployment.txt","content_type":"text/plain"}]`,
		"production=false\nregion=us-east-1\n",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("inspected request prompt %q missing %q", prompt, want)
		}
	}
	attachments, ok := payload["omnigent_attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("normalized official attachments = %#v", payload["omnigent_attachments"])
	}
	attachment, _ := attachments[0].(map[string]interface{})
	if attachment["filename"] != "deployment.txt" ||
		attachment["content_type"] != "text/plain" ||
		attachment["text"] != "production=false\nregion=us-east-1\n" ||
		attachment["truncated"] != false {
		t.Fatalf("normalized official attachment = %#v", attachment)
	}
}

func TestOmnigentOversizedAttachmentHonorsFailMode(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
event = {
    "type": "request",
    "data": {
        "user_content": "review attachment",
        "attachments": [{
            "filename": "oversized.txt",
            "content_type": "text/plain",
            "text": ("A" * module._MAX_ATTACHMENT_TEXT_CHARS) + "MALICIOUS_AFTER_LIMIT",
        }],
    },
}
print(json.dumps(module.defenseclaw_policy(event)))
`
	for _, tc := range []struct {
		mode string
		want string
	}{{"open", "ALLOW"}, {"closed", "DENY"}} {
		t.Run(tc.mode, func(t *testing.T) {
			modulePath := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(string(templateBytes), "127.0.0.1:1", "", tc.mode)
			if err := os.WriteFile(modulePath, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(python, "-c", script, modulePath).CombinedOutput()
			if err != nil {
				t.Fatalf("execute oversized attachment policy: %v\n%s", err, output)
			}
			var verdict map[string]string
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict["result"] != tc.want {
				t.Fatalf("oversized attachment verdict = %v, want %s", verdict, tc.want)
			}
		})
	}
}

func TestOmnigentConfigPathMatchesUpstreamGlobalConfigResolution(t *testing.T) {
	previous := OmnigentConfigPathOverride
	OmnigentConfigPathOverride = ""
	t.Cleanup(func() { OmnigentConfigPathOverride = previous })
	configHome := t.TempDir()
	t.Setenv("OMNIGENT_CONFIG_HOME", configHome)
	t.Setenv("OMNIGENT_DATA_DIR", filepath.Join(t.TempDir(), "state-only"))
	if got, want := omnigentConfigPath(), filepath.Join(configHome, "config.yaml"); got != want {
		t.Fatalf("omnigentConfigPath() = %q, want %q", got, want)
	}
}

func TestOmnigentRuntimeArtifactsAreLockedAndHashed(t *testing.T) {
	root := t.TempDir()
	withOmnigentPathOverrides(t, filepath.Join(root, "config.yaml"), filepath.Join(root, "site-packages"))
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970"}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })
	entry := NewHookContractLockEntry(opts, conn, "test")
	if got := entry.Locations.HookScriptPaths; len(got) != 2 || !strings.HasSuffix(got[0], ".py") || !strings.HasSuffix(got[1], ".pth") {
		t.Fatalf("runtime paths = %v, want policy module and .pth", got)
	}
	if len(entry.HookScriptDigests) != 2 {
		t.Fatalf("runtime digests = %v, want two", entry.HookScriptDigests)
	}
	for name := range entry.HookScriptDigests {
		if strings.HasPrefix(name, "inspect-") {
			t.Fatalf("lock recorded unrelated generic script %q", name)
		}
	}
}

func TestOmnigentFreshLockSurvivesRemovedSetupReceipt(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native protected executable evidence is Windows-only")
	}
	dataDir := t.TempDir()
	executable := filepath.Join(t.TempDir(), "omnigent.exe")
	if err := os.WriteFile(executable, []byte("MZ official omnigent fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	stableExecutable, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("could not create stable executable evidence")
	}
	now := time.Now().UTC()
	rawVersion := "omnigent 0.7.0"
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		Selections: map[string]agentSelectionEvidence{
			"omnigent": {
				Connector:         "omnigent",
				Source:            "setup-selected",
				Executable:        stableExecutable,
				RawVersion:        rawVersion,
				NormalizedVersion: "0.7.0",
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dataDir, agentSelectionFile)
	if err := atomicWriteFile(receiptPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := SetupOpts{
		DataDir:         dataDir,
		AgentExecutable: stableExecutable,
		AgentVersion:    rawVersion,
	}
	entry := NewHookContractLockEntry(opts, NewOmnigentConnector(), "test-build")
	if entry.AgentExecutableSource != "setup-selected" ||
		!strings.EqualFold(entry.AgentExecutable, stableExecutable) ||
		entry.AgentExecutableSHA256 != digest {
		t.Fatalf("sealed OmniGent executable evidence = %+v", entry)
	}
	if err := SaveFreshHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}

	if got := LoadCachedAgentVersion(dataDir, "omnigent"); got != rawVersion {
		t.Fatalf("locked OmniGent version = %q, want %q", got, rawVersion)
	}
	if got := LoadCachedAgentExecutable(dataDir, "omnigent"); !strings.EqualFold(got, stableExecutable) {
		t.Fatalf("locked OmniGent executable = %q, want %q", got, stableExecutable)
	}
	if _, err := validateOmnigentWindowsExecutable(opts, stableExecutable); err != nil {
		t.Fatalf("revalidate locked OmniGent executable after receipt removal: %v", err)
	}
}

func TestOmnigentConfigEditIsPreservedOnTeardown(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	sitePackages := filepath.Join(root, "site-packages")
	withOmnigentPathOverrides(t, configPath, sitePackages)
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970"}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	config, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config["operator_edit"] = true
	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	cleaned, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cleaned["operator_edit"] != true {
		t.Fatalf("operator edit was lost: %#v", cleaned)
	}
	if _, ok := cleaned["policy_modules"]; ok {
		t.Fatalf("managed module registration remains: %#v", cleaned)
	}
	if _, ok := cleaned["policies"]; ok {
		t.Fatalf("managed default policy remains: %#v", cleaned)
	}
}

func TestOmnigentExistingPolicyFieldsArePreserved(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	withOmnigentPathOverrides(t, configPath, filepath.Join(root, "site-packages"))
	original := "policies:\n  defenseclaw_guardrail:\n    type: function\n    handler: defenseclaw_omnigent_policy.defenseclaw_policy\n    ask_timeout: 42\n    config:\n      tenant: example\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970"}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })
	cfg, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	policies := cfg["policies"].(map[string]interface{})
	entry := policies[omnigentPolicyConfigKey].(map[string]interface{})
	if fmt.Sprint(entry["ask_timeout"]) != "42" || entry["config"] == nil {
		t.Fatalf("existing policy fields were clobbered: %#v", entry)
	}
}

func TestOmnigentVerifyCleanFindsEditedImportShimAtCustomPath(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "custom-config.yaml")
	pthPath := filepath.Join(root, "custom-python", "defenseclaw_omnigent.pth")
	withOmnigentPathOverrides(t, configPath, filepath.Dir(pthPath))
	opts := SetupOpts{DataDir: filepath.Join(root, "custom-defenseclaw"), APIAddr: "127.0.0.1:18970"}
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pthPath, []byte("/operator/edited/path\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err == nil ||
		!strings.Contains(err.Error(), "managed pth remains") {
		t.Fatalf("Teardown error = %v, want edited custom .pth residue", err)
	}
	if err := conn.VerifyClean(opts); err == nil || !strings.Contains(err.Error(), "managed pth remains") {
		t.Fatalf("VerifyClean error = %v, want edited custom .pth residue", err)
	}
}

func TestOmnigentSetupRejectsNonMappingPoliciesWithoutClobberingConfig(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	withOmnigentPathOverrides(t, configPath, filepath.Join(root, "site-packages"))
	original := []byte("policies:\n  - operator-owned\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970"}
	if err := NewOmnigentConnector().Setup(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "policies: expected a mapping") {
		t.Fatalf("Setup error = %v, want a policies shape conflict", err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("conflicting config changed:\n%s", got)
	}
	for _, path := range []string{
		omnigentPolicyModulePath(opts),
		filepath.Join(root, "site-packages", "defenseclaw_omnigent.pth"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("rollback left managed artifact %s: %v", path, err)
		}
	}
}
