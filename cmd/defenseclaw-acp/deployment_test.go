// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// editorProfilePins are values an editor's environment can carry in the
// service-only DEFENSECLAW_ENTERPRISE_PROFILE pin. None of them may choose
// how the guard reaches its gateway (GAP-1162).
var editorProfilePins = []string{
	"", managed.ProfileSecureClient, strings.ToUpper(managed.ProfileSecureClient),
	" " + managed.ProfileSecureClient + " ", managed.ProfileStandalone, "personal",
}

// stubGuardHost points the guard at a fixture host and records which
// gateway client run() would build.
func stubGuardHost(t *testing.T, secureClient bool, guardDir, binDir string, descriptor bool) *[]string {
	t.Helper()
	previousSC, previousGuard := secureClientHost, guardExecutable
	previousLayout, previousLoad := managedACPStandaloneLayout, loadACPStandaloneDescriptor
	previousPerUser, previousManaged := newPerUserEvaluator, newManagedEvaluator
	t.Cleanup(func() {
		secureClientHost, guardExecutable = previousSC, previousGuard
		managedACPStandaloneLayout, loadACPStandaloneDescriptor = previousLayout, previousLoad
		newPerUserEvaluator, newManagedEvaluator = previousPerUser, previousManaged
	})
	secureClientHost = func() bool { return secureClient }
	guardExecutable = func() (string, error) { return filepath.Join(guardDir, "defenseclaw-acp"), nil }
	managedACPStandaloneLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{DescriptorPath: filepath.Join(binDir, "managed-runtime.json"), BinDir: binDir}, nil
	}
	loadACPStandaloneDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		if descriptor {
			return &managed.RuntimeDescriptor{}, nil
		}
		return nil, managed.ErrNoRuntimeDescriptor
	}
	var built []string
	newPerUserEvaluator = func(string, string) (*acp.HTTPEvaluator, error) {
		built = append(built, "per-user")
		return nil, nil
	}
	newManagedEvaluator = func(string, string) (*acp.HTTPEvaluator, error) {
		built = append(built, "managed")
		return nil, nil
	}
	return &built
}

func writeManagedFixture(t *testing.T, dir string) (lock string) {
	t.Helper()
	gateway := filepath.Join(dir, "defenseclaw-gateway")
	if runtime.GOOS == "windows" {
		gateway = filepath.Join(dir, "defenseclaw.exe")
	}
	lock = filepath.Join(dir, "zed-copilot.contract-lock.json")
	for path, body := range map[string]string{gateway: "gateway\n", lock: `{"guard":{"managed_custody":true}}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return lock
}

// On a standalone managed host the guard reaches the administrator's
// gateway service whatever profile the editor's environment names. An
// editor that exported DEFENSECLAW_ENTERPRISE_PROFILE=secure_client made
// the guard check for a gateway in the user's own account, so every
// initialize failed against the managed gateway, and it delivered observe
// frames it could not check (GAP-1162).
func TestEditorProfilePinDoesNotChooseTheGuardDeployment(t *testing.T) {
	dir := t.TempDir()
	lock := writeManagedFixture(t, dir)
	elsewhere := t.TempDir()
	for _, host := range []struct {
		name               string
		secureClient       bool
		guardDir, binDir   string
		descriptor         bool
		perUserLock        bool
		wantClient         string
		wantStandalone     bool
		wantEnterpriseText bool
	}{
		// Windows has no descriptor: the guard in the standalone bin folder.
		{"standalone guard in the managed bin folder", false, dir, dir, false, false, "managed", true, true},
		{"standalone runtime descriptor", false, dir, elsewhere, true, false, "managed", true, true},
		// No per-user gateway may run there: still the managed service.
		{"standalone descriptor, per-user editor entry", false, elsewhere, dir, true, true, "managed", true, false},
		{"per-user install", false, dir, elsewhere, false, true, "per-user", false, false},
		// Secure Client verifies its own root service and keeps main's text.
		{"Secure Client install", true, dir, dir, true, false, "managed", false, false},
	} {
		for _, pin := range editorProfilePins {
			t.Run(host.name+"/pin="+strings.TrimSpace(pin), func(t *testing.T) {
				t.Setenv(managed.EnterpriseProfileEnv, pin)
				built := stubGuardHost(t, host.secureClient, host.guardDir, host.binDir, host.descriptor)
				deployment := currentGuardDeployment()
				if _, err := deployment.evaluator("http://127.0.0.1:18970/api/v1/acp/evaluate", "token"); err != nil {
					t.Fatal(err)
				}
				if len(*built) != 1 || (*built)[0] != host.wantClient {
					t.Fatalf("gateway client = %v, want %s", *built, host.wantClient)
				}
				// Managed (refuse what cannot be checked) is the standalone guard.
				if deployment.standalone != host.wantStandalone {
					t.Fatalf("standalone = %v, want %v", deployment.standalone, host.wantStandalone)
				}
				if guardKeepsMainBehaviour() != host.secureClient {
					t.Fatalf("guardKeepsMainBehaviour = %v on secureClient=%v", guardKeepsMainBehaviour(), host.secureClient)
				}
				entryLock := lock
				if host.perUserLock {
					entryLock = filepath.Join(elsewhere, "per-user.contract-lock.json")
				}
				setup, managedEntry := setupCommand("zed", "copilot", "default", "observe", entryLock)
				if managedEntry != host.wantEnterpriseText || strings.Contains(setup, "enterprise acp setup") != host.wantEnterpriseText {
					t.Fatalf("setup text = %q (managed %v), want enterprise text %v", setup, managedEntry, host.wantEnterpriseText)
				}
			})
		}
	}
}
