// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-2028: the gateway took a guardian home proof as current while
// /etc/passwd kept its stamp, also after a systemd-userdb account was deleted
// and created again under the same name, uid and home path. The proof is
// current only while every local account database the guardian read is.
func TestGuardianHomeProofOfARecreatedUserdbAccountIsNotCurrent(t *testing.T) {
	previousDatabases, previousStamp := enterprisehooks.LocalAccountDatabases, localAccountsStamp
	t.Cleanup(func() { enterprisehooks.LocalAccountDatabases, localAccountsStamp = previousDatabases, previousStamp })
	localAccountsStamp = func() string { return enterprisehooks.LocalAccountsStamp() }
	userdb := filepath.Join(t.TempDir(), "userdb")
	enterprisehooks.LocalAccountDatabases = []string{userdb}
	if err := os.Mkdir(userdb, 0o755); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(userdb, "pod.user")
	if err := os.WriteFile(record, []byte(`{"userName":"pod","uid":2601}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stamp := enterprisehooks.LocalAccountsStamp()
	if stamp == "" {
		t.Skip("/etc/passwd cannot be read here")
	}
	proof := enterprisehooks.IdentitySpoolRecord{Key: "2601", User: "pod", UpdatedAt: time.Now().UTC(), AccountsStamp: stamp}
	if !guardianHomeProofCurrent(proof) {
		t.Fatal("a proof read at the current stamp is not current")
	}
	time.Sleep(30 * time.Millisecond)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"userName":"pod","uid":2601}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if guardianHomeProofCurrent(proof) {
		t.Fatal("the earlier holder's home proof stayed current after the userdb account was created again")
	}
}
