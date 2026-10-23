// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the removed connectors' teardown leaves every registration of
// them on the stub, sealed in the hook contract lock (T8 smoke review loop
// round 2). Delete with removed.go.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// removedLockEntries reads the raw entries of the hook contract lock.
func removedLockEntries(t *testing.T, dataDir string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, hookContractLockFile))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Connectors map[string]json.RawMessage `json:"connectors"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	return lock.Connectors
}

func (h *removedHost) requireSealed(t *testing.T, c removedOnlyConnector, want string) {
	t.Helper()
	entry := LoadHookContractLockEntry(h.dataDir, c.name)
	got, has := entry.HookScriptDigests[c.script]
	if want == "" {
		if has {
			t.Fatalf("the lock still seals %s as %q, which is gone", c.script, got)
		}
	} else if got != want {
		t.Fatalf("the lock seals %s as %q, want %q", c.script, got, want)
	}
	if len(entry.Locations.HookConfigPaths) != 1 {
		t.Fatalf("the seal dropped the entry's config path: %+v", entry.Locations)
	}
}

func removedStubDigest(c removedOnlyConnector) string {
	return "sha256:" + sha256Hex([]byte(c.tombstone))
}

// Upgrading a 1.0.3 install: the lock entry an older setup wrote sealed the
// old hook, and the teardown left it so next to the stub. It now seals the
// stub; no other lock entry changes, a second run writes nothing, and
// VerifyClean fails while the lock seals anything else.
func TestRemovedTeardownSealsTheStubInTheLock(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			codexBefore := LoadHookContractLockEntry(h.dataDir, "codex")
			conn, _ := RetiredConnector(c.name)
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			h.requireStub(t, c)
			h.requireSealed(t, c, removedStubDigest(c))
			if got := LoadHookContractLockEntry(h.dataDir, "codex"); !reflect.DeepEqual(got, codexBefore) {
				t.Fatalf("the seal changed the codex entry:\n got %+v\nwant %+v", got, codexBefore)
			}
			if entries := removedLockEntries(t, h.dataDir); len(entries) != 2 {
				t.Fatalf("lock entries after the seal = %d, want codex and %s", len(entries), c.name)
			}
			sealed, _ := os.ReadFile(filepath.Join(h.dataDir, hookContractLockFile))
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			if again, _ := os.ReadFile(filepath.Join(h.dataDir, hookContractLockFile)); string(again) != string(sealed) {
				t.Fatal("a second teardown rewrote the sealed lock")
			}
			if err := conn.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean after the teardown: %v", err)
			}
			// A host an earlier 1.0.4 build tore down: the stub is in place,
			// the tokens are gone, and the lock still seals the old hook.
			if err := sealRemovedConnectorScript(h.dataDir, c.name, c.script, "sha256:00", false); err != nil {
				t.Fatal(err)
			}
			if err := conn.VerifyClean(h.opts); err == nil || !strings.Contains(err.Error(), "the hook contract lock seals "+c.script) {
				t.Fatalf("VerifyClean with the old hook sealed = %v, want the seal named", err)
			}
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			h.requireSealed(t, c, removedStubDigest(c))
			if err := conn.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean after the second teardown: %v", err)
			}
		})
	}
}

// A script that is gone while the agent config a 1.0.3 setup patched still
// runs or imports it passed as clean, and that agent no longer blocked:
// OpenHands lets a call through when its hook command fails to start. The
// teardown now writes the stub there and seals it; VerifyClean fails until it
// is there.
func TestRemovedTeardownPutsTheStubUnderALiveRegistrationWhoseScriptIsGone(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		for _, tc := range []struct {
			name  string
			plant func(t *testing.T, h *removedHost)
		}{
			{"the 1.0.3 registration", func(*testing.T, *removedHost) {}},
			{"a config that cannot be checked", func(t *testing.T, h *removedHost) {
				writeRemovedFile(t, h.agentConfig, "{not json or yaml: [", 0o600)
			}},
			{"the hooks folder gone too", func(t *testing.T, h *removedHost) {
				for _, path := range append([]string{filepath.Join(h.dataDir, "hooks")}, h.tokens(c)...) {
					_ = os.RemoveAll(path)
				}
			}},
		} {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				conn, _ := RetiredConnector(c.name)
				// Torn down by an earlier build, then the script deleted.
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(h.script(c)); err != nil {
					t.Fatal(err)
				}
				tc.plant(t, h)
				err := conn.VerifyClean(h.opts)
				if err == nil || !strings.Contains(err.Error(), "is gone, but") || !strings.Contains(err.Error(), c.teardownCommand()) {
					t.Fatalf("VerifyClean with the registration live and no script = %v, want it incomplete with the step", err)
				}
				gone := false
				for _, left := range c.leftovers(h.opts) {
					gone = gone || (left.Path == h.script(c) && left.What == RemovedScriptGoneWhat)
				}
				if !gone {
					t.Fatalf("leftovers do not say the script is gone under a live registration: %+v", c.leftovers(h.opts))
				}
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatal(err)
				}
				h.requireStub(t, c)
				h.requireSealed(t, c, removedStubDigest(c))
				if err := conn.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean after the teardown: %v", err)
				}
			})
		}
	}
}

// With no registration left that runs or imports the script (the user took
// it out, or a Windows hooks.json runs the native launcher, which reaches the
// retired route), a gone script is clean: nothing is written, and the lock
// stops sealing it.
func TestRemovedTeardownLeavesAGoneScriptGoneWithoutARegistration(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		configs := map[string]string{"no registration": removedOmnigentOperatorConfig}
		if c.name == removedOpenHandsID {
			configs = map[string]string{
				"no registration":     removedOpenHandsOperatorHooks,
				"the native launcher": `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\Users\\u\\.defenseclaw\\bin\\defenseclaw-hook.exe hook --connector openhands"}]}]}`,
			}
		}
		for name, config := range configs {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				h := newRemovedHost(t)
				h.stage(t, c)
				writeRemovedFile(t, h.agentConfig, config, 0o600)
				if err := os.Remove(h.script(c)); err != nil {
					t.Fatal(err)
				}
				conn, _ := RetiredConnector(c.name)
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(h.script(c)); !os.IsNotExist(err) {
					t.Fatalf("the teardown wrote %s with no registration: %v", h.script(c), err)
				}
				h.requireSealed(t, c, "")
				if err := conn.VerifyClean(h.opts); err != nil {
					t.Fatalf("VerifyClean: %v", err)
				}
			})
		}
	}
}

// A hooks path that is not a folder is never written through: the teardown
// fails with the step, and the tokens stay.
func TestRemovedTeardownRefusesAHooksPathThatIsNotAFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	c := removedOpenHands
	h := newRemovedHost(t)
	h.stage(t, c)
	hooks := filepath.Join(h.dataDir, "hooks")
	if err := os.RemoveAll(hooks); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(h.home, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, hooks); err != nil {
		t.Fatal(err)
	}
	conn, _ := RetiredConnector(c.name)
	if err := conn.Teardown(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "is not a folder") {
		t.Fatalf("Teardown through a linked hooks folder = %v, want a refusal", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("the teardown wrote through the link: %v", entries)
	}
}
