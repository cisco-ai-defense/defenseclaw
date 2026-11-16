// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// copilotRebindPatchPermission is a native preToolUse apply_patch body and
// the argumentless permission callback that follows it.
func copilotRebindPatchPermission(t *testing.T, session, project, patch string) (string, string) {
	t.Helper()
	pre := `{"sessionId":"` + session + `","cwd":` + copilotJoinQuote(t, project) +
		`,"toolCalls":[{"id":"call_rebind","name":"apply_patch","args":` + copilotJoinQuote(t, patch) + `}]}`
	return pre, copilotJoinPermission(t, session, project)
}

// An argumentless permission callback carries no call id or target, so it
// stands for the call of the audited preToolUse allow it follows. It is
// decided again, now, as that call: a project file that turns into a link
// to authorized_keys between the preToolUse and the callback is judged
// where it points now. The callback's answer equals a fresh preToolUse of
// the same call made now (T12b round e review, loop round 1).
func TestNativeCopilotPermissionJoinRechecksTheCallNow(t *testing.T) {
	keys := copilotRebindHome(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}

	update := "*** Begin Patch\n*** Update File: notes.txt\n@@\n-old\n+ssh-ed25519 AAAA marker\n*** End Patch\n"
	move := "*** Begin Patch\n*** Update File: notes.txt\n*** Move to: out.txt\n@@\n-old\n+ssh-ed25519 AAAA marker\n*** End Patch\n"
	for _, tc := range []struct {
		name, patch string
		swap        func(t *testing.T, project string)
		want        string
	}{
		{"unchanged project file", update, func(*testing.T, string) {}, "allow"},
		{"file becomes a symlink to authorized_keys", update, func(t *testing.T, project string) {
			copilotRebindRemove(t, filepath.Join(project, "notes.txt"))
			copilotRebindLink(t, keys, filepath.Join(project, "notes.txt"))
		}, "block"},
		{"file becomes a relative symlink chain to authorized_keys", update, func(t *testing.T, project string) {
			copilotRebindLink(t, keys, filepath.Join(project, "hop"))
			copilotRebindRemove(t, filepath.Join(project, "notes.txt"))
			copilotRebindLink(t, "hop", filepath.Join(project, "notes.txt"))
		}, "block"},
		{"move destination becomes a symlink to authorized_keys", move, func(t *testing.T, project string) {
			copilotRebindLink(t, keys, filepath.Join(project, "out.txt"))
		}, "block"},
		{"file becomes a hard link of authorized_keys", update, func(t *testing.T, project string) {
			copilotRebindRemove(t, filepath.Join(project, "notes.txt"))
			if err := os.Link(keys, filepath.Join(project, "notes.txt")); err != nil {
				t.Skipf("hard link: %v", err)
			}
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			if err := os.WriteFile(filepath.Join(project, "notes.txt"), []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			session := "rebind-" + strings.ReplaceAll(tc.name, " ", "-")
			pre, permission := copilotRebindPatchPermission(t, session, project, tc.patch)
			if action, body := copilotJoinPost(t, api, "preToolUse", pre); action != "allow" {
				t.Fatalf("preToolUse of the ordinary file action=%s: %s", action, body)
			}
			tc.swap(t, project)
			// The oracle: the same call, judged fresh now in another session.
			oracle, _ := copilotRebindPatchPermission(t, session+"-oracle", project, tc.patch)
			fresh, freshBody := copilotJoinPost(t, api, "preToolUse", oracle)
			if tc.want != "" && fresh != tc.want {
				t.Fatalf("a fresh preToolUse now action=%s, want %s: %s", fresh, tc.want, freshBody)
			}
			action, body := copilotJoinPost(t, api, "permissionRequest", permission)
			if action != fresh {
				t.Fatalf("permission callback action=%s, a fresh decision of its call now is %s: %s", action, fresh, body)
			}
		})
	}
}

// copilotRebindHome is a home with an authorized_keys file, for the
// gateway's user on every OS.
func copilotRebindHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return keys
}

// copilotRebindLink makes a symbolic link, or skips where the account may
// not (Windows without the symlink privilege).
func copilotRebindLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink: %v", err)
		}
		t.Fatal(err)
	}
}

func copilotRebindRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// The callback is decided under the policy live when it arrives, not the
// one the preToolUse was allowed under: an observe allow of a write to
// authorized_keys is refused once the generation turns to action.
func TestNativeCopilotPermissionJoinDecidesUnderTheLivePolicy(t *testing.T) {
	keys := copilotRebindHome(t)
	project := t.TempDir()
	copilotRebindLink(t, keys, filepath.Join(project, "deploy.cfg"))
	patch := "*** Begin Patch\n*** Update File: deploy.cfg\n@@\n-old\n+ssh-ed25519 AAAA marker\n*** End Patch\n"
	observe := &config.Config{}
	observe.Guardrail.Mode = "observe"
	observe.Guardrail.Connector = "copilot"
	action := &config.Config{}
	action.Guardrail.Mode = "action"
	action.Guardrail.Connector = "copilot"
	store, logger := testStoreAndLogger(t)
	var current atomic.Pointer[Generation]
	current.Store(&Generation{N: 1, Config: observe, Digest: "sha256:observe"})
	api := &APIServer{scannerCfg: observe, health: NewSidecarHealth(), store: store, logger: logger,
		generationSource: func() *Generation { return current.Load() }}

	// Control: under the same observe generation the callback is allowed
	// like its preToolUse.
	pre, permission := copilotRebindPatchPermission(t, "same", project, patch)
	if got, body := copilotJoinPost(t, api, "preToolUse", pre); got != "allow" {
		t.Fatalf("observe preToolUse action=%s: %s", got, body)
	}
	if got, body := copilotJoinPost(t, api, "permissionRequest", permission); got != "allow" {
		t.Fatalf("observe permission action=%s: %s", got, body)
	}

	pre, permission = copilotRebindPatchPermission(t, "swapped", project, patch)
	if got, body := copilotJoinPost(t, api, "preToolUse", pre); got != "allow" {
		t.Fatalf("observe preToolUse action=%s: %s", got, body)
	}
	current.Store(&Generation{N: 2, Config: action, Digest: "sha256:action"})
	if got, body := copilotJoinPost(t, api, "permissionRequest", permission); got != "block" {
		t.Fatalf("permission callback kept the observe allow under the action generation: %s", body)
	}
}

// A managed Unix gateway cannot traverse the enrolled user's private home:
// the user-side hook proves patch targets there, and it has no call to prove
// for an argumentless callback. The gateway cannot place the callback's
// directory either, so nothing is bound or rechecked and the callback keeps
// its own unparsed decision (closed in action, an audited warning in observe
// under the balanced defaults), never the earlier allow.
func TestNativeCopilotPermissionJoinInPrivateManagedHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private-home permissions")
	}
	private := filepath.Join(t.TempDir(), "private")
	project := filepath.Join(private, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Add File: notes.txt\n+ordinary project edit\n*** End Patch\n"
	pre, permission := copilotRebindPatchPermission(t, "private-home", project, patch)
	preHeader := hookpaths.ResolveConnector("copilot", "", "preToolUse", []byte(pre))
	permissionHeader := hookpaths.ResolveConnector("copilot", "", "permissionRequest", []byte(permission))
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	if _, err := os.Stat(project); err == nil {
		t.Skip("test process can still traverse a private directory")
	}
	for _, tc := range []struct{ mode, want string }{{"action", "block"}, {"observe", "allow"}} {
		t.Run(tc.mode, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = tc.mode
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			post := func(event, body, header string) string {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
				req.Header.Set("X-DefenseClaw-Copilot-Event", event)
				req.Header.Set(hookpaths.Header, header)
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				w := httptest.NewRecorder()
				api.handleAgentHook("copilot").ServeHTTP(w, req)
				return w.Body.String()
			}
			if body := post("preToolUse", pre, preHeader); !strings.Contains(body, `"action":"allow"`) ||
				strings.Contains(body, hookToolCallUnparsedRuleID) {
				t.Fatalf("proven private-home preToolUse: %s", body)
			}
			body := post("permissionRequest", permission, permissionHeader)
			var verdict struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal([]byte(body), &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict.Action != tc.want || !strings.Contains(body, hookToolCallUnparsedRuleID) {
				t.Fatalf("%s permission callback action=%s, want its own unparsed decision %s: %s", tc.mode, verdict.Action, tc.want, body)
			}
		})
	}
}
