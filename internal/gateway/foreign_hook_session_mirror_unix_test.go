// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// foreignHookCleanRootForTest points the gateway's clean-session folder at a
// fresh 0711 folder.
func foreignHookCleanRootForTest(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data-foreign-hook-clean")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	previous := foreignHookCleanMirrorRoot
	foreignHookCleanMirrorRoot = func(string) string { return root }
	t.Cleanup(func() { foreignHookCleanMirrorRoot = previous })
	return root
}

// cleanEntries lists the clean-session entries of identity, by key kind.
func cleanEntries(t *testing.T, root, identity string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	entries, err := os.ReadDir(filepath.Join(root, identity))
	if errors.Is(err, os.ErrNotExist) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(root, identity, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		out[body["kind"].(string)] = body
	}
	return out
}

func foreignHookSessionRequest(identity, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
	ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	return req.WithContext(ctx)
}

// An allowed exchange publishes the entries of its process and session keys
// before it answers; a later denial of the same keys removes both.
func TestForeignHookSessionPublishesCleanEntriesOnlyForAnAllow(t *testing.T) {
	foreignHookGuardianDirForTest(t)
	root := foreignHookCleanRootForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := foreignHookTestIdentities(1)[0]
	allow := newDeadlineRecorder()
	api.handleForeignHookSession(allow, foreignHookAllowRequest(identity, "s-1"))
	if allow.Code != http.StatusOK || !strings.Contains(allow.Body.String(), `"deny":false`) {
		t.Fatalf("allow: %d %s", allow.Code, allow.Body.String())
	}
	entries := cleanEntries(t, root, identity)
	process := runtime.GOOS + ":b:4242:100"
	if p := entries["p"]; p == nil || p["id"] != process || p["process_started"] != process || p["identity"] != identity || p["connector"] != "claudecode" {
		t.Fatalf("process entry after an allow: %+v", entries)
	}
	if s := entries["s"]; s == nil || s["id"] != "s-1" {
		t.Fatalf("session entry after an allow: %+v", entries)
	}
	if info, err := os.Lstat(filepath.Join(root, identity)); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("account folder: %v %v", info, err)
	}
	// The same agent process starts a session with an unapproved hook: the
	// block is recorded and both entries go.
	body := `{"key":{"connector":"claudecode","session":"s-1","process":"` + process + `"},"session_start":true,"decision":{"deny":true,"reason":"enterprise_foreign_hook_blocked: project hook","findings":[{"connector":"claudecode","scope":"project","path":"/p/.claude/settings.json","event":"PreToolUse","digest":"abc","allowed":false,"reason":"unapproved"}]}}`
	deny := newDeadlineRecorder()
	api.handleForeignHookSession(deny, foreignHookSessionRequest(identity, body))
	if !strings.Contains(deny.Body.String(), `"deny":true`) {
		t.Fatalf("denial: %d %s", deny.Code, deny.Body.String())
	}
	if entries := cleanEntries(t, root, identity); len(entries) != 0 {
		t.Fatalf("a denial must remove both entries: %+v", entries)
	}
	// The blocked process stays blocked, and gets no entry back.
	again := newDeadlineRecorder()
	api.handleForeignHookSession(again, foreignHookAllowRequestWith(identity, "s-2", ""))
	if !strings.Contains(again.Body.String(), `"deny":true`) {
		t.Fatalf("the blocked process must stay blocked: %s", again.Body.String())
	}
	if entries := cleanEntries(t, root, identity); len(entries) != 0 {
		t.Fatalf("a blocked process must get no entry: %+v", entries)
	}
}

// An exchange whose account lock cannot be taken, or whose allow comes too
// late for its hold, leaves no entry.
func TestForeignHookSessionLeavesNoCleanEntryWithoutAnAnsweredAllow(t *testing.T) {
	t.Run("lock error", func(t *testing.T) {
		foreignHookGuardianDirForTest(t)
		root := foreignHookCleanRootForTest(t)
		api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
		identity := foreignHookTestIdentities(1)[0]
		previous := foreignHookAccountExchangeLock
		foreignHookAccountExchangeLock = func(context.Context, string, string) (func(), error) {
			return nil, errors.New("lock unavailable")
		}
		t.Cleanup(func() { foreignHookAccountExchangeLock = previous })
		denied := newDeadlineRecorder()
		api.handleForeignHookSession(denied, foreignHookAllowRequest(identity, "s-1"))
		if !strings.Contains(denied.Body.String(), `"deny":true`) {
			t.Fatalf("a lock error must deny: %s", denied.Body.String())
		}
		if entries := cleanEntries(t, root, identity); len(entries) != 0 {
			t.Fatalf("a lock error must leave no entry: %+v", entries)
		}
	})
	t.Run("allow past its hold", func(t *testing.T) {
		foreignHookGuardianDirForTest(t)
		root := foreignHookCleanRootForTest(t)
		previousHold := foreignHookExchangeHold
		foreignHookExchangeHold = 0
		t.Cleanup(func() { foreignHookExchangeHold = previousHold })
		api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
		identity := foreignHookTestIdentities(1)[0]
		denied := newDeadlineRecorder()
		api.handleForeignHookSession(denied, foreignHookAllowRequest(identity, "s-1"))
		if !strings.Contains(denied.Body.String(), `"deny":true`) {
			t.Fatalf("an allow past its hold must deny: %s", denied.Body.String())
		}
		if entries := cleanEntries(t, root, identity); len(entries) != 0 {
			t.Fatalf("an allow past its hold must leave no entry: %+v", entries)
		}
	})
	t.Run("unreadable removal ledger", func(t *testing.T) {
		guardianDir := foreignHookGuardianDirForTest(t)
		root := foreignHookCleanRootForTest(t)
		if err := os.WriteFile(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
		identity := foreignHookTestIdentities(1)[0]
		denied := newDeadlineRecorder()
		api.handleForeignHookSession(denied, foreignHookAllowRequest(identity, "s-1"))
		if !strings.Contains(denied.Body.String(), `"deny":true`) {
			t.Fatalf("an unreadable ledger must deny: %s", denied.Body.String())
		}
		if entries := cleanEntries(t, root, identity); len(entries) != 0 {
			t.Fatalf("an unreadable ledger must leave no entry: %+v", entries)
		}
	})
	t.Run("write failure", func(t *testing.T) {
		foreignHookGuardianDirForTest(t)
		root := foreignHookCleanRootForTest(t)
		if err := os.Chmod(root, 0o777); err != nil { // refused by the writer
			t.Fatal(err)
		}
		api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
		identity := foreignHookTestIdentities(1)[0]
		allowed := newDeadlineRecorder()
		api.handleForeignHookSession(allowed, foreignHookAllowRequest(identity, "s-1"))
		if !strings.Contains(allowed.Body.String(), `"deny":false`) {
			t.Fatalf("a failed entry write must not change the answer: %s", allowed.Body.String())
		}
		if entries := cleanEntries(t, root, identity); len(entries) != 0 {
			t.Fatalf("a failed write must leave no entry: %+v", entries)
		}
	})
}
