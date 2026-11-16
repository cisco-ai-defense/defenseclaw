// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0267: a warm registered hook ran one program more than its budget of
// eight: the credential-cache check ran find on every call, also for the
// default cache in the local /tmp. With a fresh session-facts record and no
// named cache (KRB5CCNAME unset), the shell's own test decides: the cached
// header is sent and no program runs.
func TestWarmSessionFactsRunNoProgramForTheDefaultCredentialCache(t *testing.T) {
	if _, err := os.Stat(fmt.Sprintf("/tmp/krb5cc_%d", os.Geteuid())); err == nil {
		t.Skip("a real default credential cache exists on this host")
	}
	dir := t.TempDir()
	helper := writeBridgeReviewHelper(t, dir)
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	record := fmt.Sprintf(`{"expires_at":%d,"env_key":"|||","header":"v1;user=dev"}`, time.Now().Unix()+120)
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "session-facts.json"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "programs")
	// Shell functions shadow the programs and are inherited by the
	// subshells the helper starts, so every find or gateway run is logged.
	script := `set -euo pipefail; . "$1"; _dc_log="$2"
find() { echo "find $*" >> "$_dc_log"; command find "$@"; }
defenseclaw_gateway_binary() { echo gateway >> "$_dc_log"; return 1; }
unset KRB5CCNAME XDG_SESSION_ID SSH_CONNECTION SSH_TTY
out="$(defenseclaw_session_facts_full)"
printf '%s' "$out"`
	cmd := exec.Command("bash", "-c", script, "bash", helper, log)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("session facts: %v: %s", err, out)
	}
	programs, _ := os.ReadFile(log)
	// macOS bash 3.2 has no epoch clock and dates the record with find;
	// only the credential-cache check is under test.
	if string(out) != "v1;user=dev" || strings.Contains(string(programs), "krb5cc") || strings.Contains(string(programs), "gateway") {
		t.Fatalf("warm call: out=%q programs=%q, want the cached header and no cache check program", out, programs)
	}
}
