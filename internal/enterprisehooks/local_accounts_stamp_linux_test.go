// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-2028: a systemd-userdb (or altfiles) account deleted and created again
// under the same name, uid and home path left /etc/passwd as it was, so the
// stamp did not change and the gateway took the earlier holder's home proof
// as current until the guardian's next pass. The stamp follows the other
// local account databases that exist; absent ones add nothing.
func TestLocalAccountsStampFollowsTheOtherLocalAccountDatabases(t *testing.T) {
	previous := LocalAccountDatabases
	t.Cleanup(func() { LocalAccountDatabases = previous })
	userdb := filepath.Join(t.TempDir(), "userdb")
	LocalAccountDatabases = []string{userdb, filepath.Join(t.TempDir(), "absent", "passwd")}

	plain := LocalAccountsStamp()
	if plain == "" {
		t.Skip("/etc/passwd cannot be read here")
	}
	if strings.Contains(plain, "+") {
		t.Fatalf("absent databases changed the stamp: %q", plain)
	}
	record := filepath.Join(userdb, "pod.user")
	if err := os.Mkdir(userdb, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"userName":"pod","uid":2601}`), 0o644); err != nil {
		t.Fatal(err)
	}
	created := LocalAccountsStamp()
	if created == plain || !strings.HasPrefix(created, plain+"+") {
		t.Fatalf("a userdb record did not enter the stamp: %q then %q", plain, created)
	}
	time.Sleep(30 * time.Millisecond)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"userName":"pod","uid":2601}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if recreated := LocalAccountsStamp(); recreated == created {
		t.Fatalf("a userdb account deleted and created again kept the stamp %q", created)
	}
}
