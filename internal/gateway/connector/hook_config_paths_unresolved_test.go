// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// fakeHookReferenceOwner owns hook entries by reference needles and
// resolves no hook config path.
type fakeHookReferenceOwner struct {
	stubConnector
	needles []string
}

func (f *fakeHookReferenceOwner) HookConfigReferenceNeedles(SetupOpts) []string { return f.needles }

// fakeConfiguredHookReferenceOwner resolves a hook config path.
type fakeConfiguredHookReferenceOwner struct {
	fakeHookReferenceOwner
	configPath string
}

func (f *fakeConfiguredHookReferenceOwner) HookCapabilities(SetupOpts) HookCapability {
	return HookCapability{ConfigPath: f.configPath}
}

// A connector that owns a managed hook runtime is verified only by reading
// its hook config. When no config path (or no owned command) resolves, the
// generic reader read nothing and must report not verified, not present;
// only a connector that owns no hook runtime is present without a config.
func TestOwnedHooksPresentFailsForAHookOwnerWithoutAResolvedConfig(t *testing.T) {
	dataDir := filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw")
	opts := SetupOpts{DataDir: dataDir}
	copilot, antigravity := NewCopilotConnector(), NewAntigravityConnector()
	for _, conn := range []*hookOnlyConnector{copilot, antigravity} {
		capability := conn.capability
		conn.configPath = func(SetupOpts) string { return "" }
		conn.capability = func(opts SetupOpts) HookCapability {
			resolved := capability(opts)
			resolved.ConfigPath = ""
			return resolved
		}
	}
	pathless := filepath.Join(dataDir, "absent.json")
	for _, tc := range []struct {
		name string
		conn Connector
		want string
	}{
		{"hook script owner", &fakeHookScriptOwner{name: "fakeagent", hooks: []string{"fakeagent-hook.sh"}}, "no hook config path resolved"},
		{"hook reference owner", &fakeHookReferenceOwner{stubConnector: stubConnector{name: "fakeref"}, needles: []string{"hook --connector fakeref"}}, "no hook config path resolved"},
		{"copilot without a config path", copilot, "no hook config path resolved"},
		{"antigravity without a config path", antigravity, "no hook config path resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if paths := HookConfigPathsForConnector(tc.conn, opts); len(paths) != 0 {
				t.Fatalf("fixture resolves hook config paths %v", paths)
			}
			present, err := OwnedHooksPresent(tc.conn, opts)
			if present || err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OwnedHooksPresent = %v, %v; want not verified: %s", present, err, tc.want)
			}
		})
	}

	// A hook owner with a config path but no owned command read nothing
	// either.
	t.Run("hook reference owner without a command", func(t *testing.T) {
		conn := &fakeConfiguredHookReferenceOwner{fakeHookReferenceOwner: fakeHookReferenceOwner{stubConnector: stubConnector{name: "fakeref"}}, configPath: pathless}
		present, err := OwnedHooksPresent(conn, opts)
		if present || err == nil || !strings.Contains(err.Error(), "no owned hook command resolved") {
			t.Fatalf("ownedHooksPresentInConfig = %v, %v; want not verified", present, err)
		}
	})

	for _, conn := range []Connector{NewOpenClawConnector(), NewZeptoClawConnector(), &stubConnector{name: "proxy"}} {
		if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
			t.Errorf("%s owns no hook runtime: OwnedHooksPresent = %v, %v; want present", conn.Name(), present, err)
		}
	}
}
