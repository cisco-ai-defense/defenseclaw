// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// Review P1 (1.0.4 guard loop round 2): after a clean allow, the key folder
// and alice's record folder stop taking changes from the gateway. A block
// of alice then fails to remove her key, to mark it revoked and to publish
// the block record. During an outage the hook must still not allow her: it
// refuses every allow while the gateway could not add a revocation mark
// (bob's too, for the folder is shared). Once the folders take changes
// again, the gateway's retry of the owed revocation ends alice's key, and
// bob's allow counts again.
func TestForeignHookSessionEarlierAllowDiesWhenNoFolderTakesAChange(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root changes a folder whatever its mode")
	}
	server := newForeignHookRealPublishTestServer(t)
	process := runtime.GOOS + ":b:1:500"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	for _, identity := range []struct{ id, token string }{{server.alice, server.aliceToken}, {server.bob, server.bobToken}} {
		if got := server.call(identity.token, foreignHookTestCall("s-1", process, true)); got.Deny {
			t.Fatalf("%s's clean session start: %+v", identity.id, got)
		}
		if got, err := foreignHookOutageCheck(server, identity.id, key); err != nil || got.Deny {
			t.Fatalf("%s's allow during an outage: %+v %v", identity.id, got, err)
		}
	}
	aliceKey := server.keyID(server.alice)
	keyDir := filepath.Dir(server.root)
	aliceDir, _ := enterprisepolicy.PublishedSessionIdentityDir(server.root, server.alice)
	lock := func(keyMode, dirMode os.FileMode) {
		t.Helper()
		if err := os.Chmod(keyDir, keyMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(aliceDir, dirMode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { lock(0o755, 0o700) })
	lock(0o555, 0o500)

	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	if server.keyID(server.alice) != aliceKey {
		t.Fatal("a key folder that takes no change keeps the key")
	}
	if _, err := foreignHookOutageCheck(server, server.alice, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("alice's earlier allow after a block no folder took: %v, want ErrPublishedSessionUnavailable", err)
	}
	if _, err := foreignHookOutageCheck(server, server.bob, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("no allow passes while the gateway could not add a mark: %v", err)
	}

	lock(0o755, 0o700)
	server.api.payOwedForeignHookRevocations()
	if server.keyID(server.alice) != "" {
		t.Fatal("the owed revocation must end alice's key once the folder takes a change")
	}
	if _, err := foreignHookOutageCheck(server, server.alice, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("alice's earlier allow after the retry: %v, want ErrPublishedSessionUnavailable", err)
	}
	if got, err := foreignHookOutageCheck(server, server.bob, key); err != nil || got.Deny {
		t.Fatalf("bob's allow counts again: %+v %v", got, err)
	}
}
