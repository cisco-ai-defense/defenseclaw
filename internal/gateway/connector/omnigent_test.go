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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type omnigentSynchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *omnigentSynchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *omnigentSynchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func requireOmnigentHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("OmniGent has no supported native Windows policy bridge; platform rejection coverage remains active")
	}
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

func writeOmnigentScopedToken(t *testing.T, dataDir, token string) string {
	t.Helper()
	tokenPath, err := HookAPITokenFilePath(dataDir, "omnigent")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("create hook token directory: %v", err)
	}
	if err := atomicWriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write scoped hook token: %v", err)
	}
	return tokenPath
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
	scopedToken := strings.Repeat("a", 64)
	opts := SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     scopedToken,
		HookFailMode: "closed",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
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
	if strings.Contains(module, scopedToken) || strings.Contains(module, base64.StdEncoding.EncodeToString([]byte(scopedToken))) {
		t.Fatal("policy module embeds the scoped credential instead of loading its sidecar")
	}
	for _, placeholder := range []string{"{{API_ADDR_B64}}", "{{TOKEN_FILE_B64}}", "{{FAIL_MODE_B64}}"} {
		if strings.Contains(module, placeholder) {
			t.Fatalf("policy module contains unresolved template placeholder %s", placeholder)
		}
	}
	tokenPath, err := HookAPITokenFilePath(opts.DataDir, "omnigent")
	if err != nil {
		t.Fatal(err)
	}
	tokenPath, err = filepath.Abs(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(module, base64.StdEncoding.EncodeToString([]byte(tokenPath))) {
		t.Fatal("policy module does not contain the safely encoded stable token-sidecar path")
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
		"python":   "#!/bin/sh\nprintf 'sitecustomize warning\\n' >&2\nprintf '%s\\n' \"$OMNIGENT_TEST_PURELIB\"\n",
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

	got, err := omnigentSitePackages(context.Background())
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

	_, err := omnigentSitePackages(context.Background())
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

	_, err := omnigentSitePackages(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported interpreter arguments") {
		t.Fatalf("error = %v, want unsupported shebang arguments", err)
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

func TestOmnigentRawPolicyTemplateImportsFailClosedWithoutCredential(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the raw-template import test")
	}
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
	if verdict["result"] != "DENY" || !strings.Contains(verdict["reason"], "credential is unavailable") {
		t.Fatalf("raw template verdict = %v, want fail-closed missing-credential denial", verdict)
	}
}

func TestOmnigentPolicyPayloadRejectsNonFiniteNumbers(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy payload test")
	}
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
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy bridge integration test")
	}

	var received map[string]interface{}
	scopedToken := strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if got := r.URL.Path; got != "/api/v1/omnigent/hook" {
			t.Errorf("path = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+scopedToken {
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
		APIToken:     scopedToken,
		HookFailMode: "closed",
	}
	writeOmnigentScopedToken(t, opts.DataDir, scopedToken)
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
	if received["agent_id"] != "" {
		t.Fatalf("agent_id leaked actor.run_as: %#v", received["agent_id"])
	}
}

func TestOmnigentPolicyBridgeReloadsScopedTokenForRotationAndRollback(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy bridge rotation test")
	}
	aToken := strings.Repeat("a", 64)
	bToken := strings.Repeat("b", 64)
	authorizations := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizations <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()

	root := t.TempDir()
	withOmnigentPathOverrides(
		t,
		filepath.Join(root, ".omnigent", "config.yaml"),
		filepath.Join(root, "site-packages"),
	)
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "defenseclaw"),
		APIAddr:      strings.TrimPrefix(server.URL, "http://"),
		APIToken:     aToken,
		HookFailMode: "closed",
	}
	tokenPath := writeOmnigentScopedToken(t, opts.DataDir, aToken)
	conn := NewOmnigentConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })

	modulePath := omnigentPolicyModulePath(opts)
	moduleBytes, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		aToken,
		bToken,
		base64.StdEncoding.EncodeToString([]byte(aToken)),
		base64.StdEncoding.EncodeToString([]byte(bToken)),
	} {
		if strings.Contains(string(moduleBytes), secret) {
			t.Fatal("rendered OmniGent module contains a rotation credential")
		}
	}

	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for _ in sys.stdin:
    print(json.dumps(module.defenseclaw_policy({"type": "tool_call", "data": {"name": "shell", "arguments": {}}})), flush=True)
`
	processCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(processCtx, python, "-u", "-c", script, modulePath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr omnigentSynchronizedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	decoder := json.NewDecoder(stdout)
	for index, token := range []string{aToken, bToken, aToken} {
		if index > 0 {
			if err := atomicWriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
				t.Fatalf("publish sidecar generation %d: %v", index, err)
			}
		}
		if _, err := fmt.Fprintln(stdin, "evaluate"); err != nil {
			t.Fatalf("trigger policy evaluation %d: %v", index, err)
		}
		var verdict map[string]string
		if err := decoder.Decode(&verdict); err != nil {
			t.Fatalf("decode policy evaluation %d: %v; stderr=%s", index, err, stderr.String())
		}
		if verdict["result"] != "ALLOW" {
			t.Fatalf("policy evaluation %d = %v, want ALLOW", index, verdict)
		}
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("policy rotation process: %v; stderr=%s", err, stderr.String())
	}

	for index, want := range []string{"Bearer " + aToken, "Bearer " + bToken, "Bearer " + aToken} {
		if got := <-authorizations; got != want {
			t.Fatalf("policy authorization %d = %q, want restored generation", index, got)
		}
	}
	moduleAfter, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(moduleAfter) != string(moduleBytes) {
		t.Fatal("sidecar rotation rewrote the stable OmniGent module")
	}
}

func TestOmnigentPolicyBridgeFailMode(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy bridge fail-mode test")
	}
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want string
	}{{"open", "ALLOW"}, {"closed", "DENY"}} {
		t.Run(tc.mode, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "defenseclaw_omnigent_policy.py")
			tokenPath := filepath.Join(root, ".hook-omnigent.token")
			if err := os.WriteFile(tokenPath, []byte(strings.Repeat("c", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			rendered := renderOmnigentPolicy(string(templateBytes), "127.0.0.1:1", tokenPath, tc.mode)
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

func TestOmnigentPolicyBridgeVerdictMappingAndScopedToken(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy bridge integration test")
	}
	responses := map[string]string{"deny-case": "block", "ask-case": "confirm", "allow-case": "allow"}
	scopedToken := strings.Repeat("d", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+scopedToken {
			t.Errorf("Authorization = %q, want scoped credential", got)
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
	opts := SetupOpts{
		DataDir:  filepath.Join(root, "dc"),
		APIAddr:  strings.TrimPrefix(server.URL, "http://"),
		APIToken: scopedToken,
	}
	writeOmnigentScopedToken(t, opts.DataDir, scopedToken)
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

func TestOmnigentPolicyBridgeCredentialFailureIsAlwaysClosed(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy bridge credential test")
	}
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({"type": "tool_call", "data": {"name": "shell", "arguments": {}}})))
`
	for _, tc := range []struct {
		name      string
		withPath  bool
		tokenBody []byte
	}{
		{name: "empty path"},
		{name: "missing file", withPath: true},
		{name: "malformed file", withPath: true, tokenBody: []byte("malformed-token\n")},
		{name: "oversized file", withPath: true, tokenBody: []byte(strings.Repeat("x", 4097))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			modulePath := filepath.Join(root, "defenseclaw_omnigent_policy.py")
			tokenPath := ""
			if tc.withPath {
				tokenPath = filepath.Join(root, ".hook-omnigent.token")
			}
			if tc.tokenBody != nil {
				if err := os.WriteFile(tokenPath, tc.tokenBody, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rendered := renderOmnigentPolicy(string(templateBytes), "127.0.0.1:1", tokenPath, "open")
			if err := os.WriteFile(modulePath, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(python, "-c", script, modulePath).CombinedOutput()
			if err != nil {
				t.Fatalf("execute policy module: %v\n%s", err, output)
			}
			var verdict map[string]string
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict["result"] != "DENY" || !strings.Contains(verdict["reason"], "credential is unavailable") {
				t.Fatalf("credential failure verdict = %v, want redacted unconditional DENY", verdict)
			}
			if tokenPath != "" && strings.Contains(string(output), tokenPath) {
				t.Fatal("credential failure exposed the token sidecar path")
			}
		})
	}
}

func TestOmnigentPolicyEventFixture(t *testing.T) {
	requireOmnigentHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the policy event fixture test")
	}
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
	if payload["hook_event_name"] != "PostToolUse" || payload["tool_name"] != "shell" || payload["agent_id"] != "client-123" {
		t.Fatalf("normalized fixture = %#v", payload)
	}
	input, _ := payload["tool_input"].(map[string]interface{})
	if input["command"] != "pwd" {
		t.Fatalf("tool_input = %#v", input)
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
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
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
