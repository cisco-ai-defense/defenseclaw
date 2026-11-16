// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The legacy native post encodes its envelope in the shell (GAP-1755). On
// Bash 3.2 (macOS) ${v//x/y} is quadratic in the value, so a 110 KB body took
// minutes and the hook gave up before it sent anything (GAP-2274). A large
// value must encode exactly like encoding/json and well inside the budget.
func TestShellJSONEscapeOfALargeBodyIsExactAndFast(t *testing.T) {
	dir := t.TempDir()
	helper := writeBridgeReviewHelper(t, dir)
	var b strings.Builder
	for b.Len() < 220*1024 {
		b.WriteString("{\"cmd\":\"printf '%s\\\\n' \\\"a\\\"\"}\r\n\tC:\\Users\\dev x-y é\n")
	}
	b.WriteString("\n")
	value := b.String()
	in := filepath.Join(dir, "value")
	if err := os.WriteFile(in, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	script := `set -u; . "$1"; v="$(cat "$2"; printf x)"; v="${v%x}"; _dc_json_escape_shell "$v"; printf '%s' "$_DC_JSON_ESCAPED"`
	cmd := exec.CommandContext(ctx, "bash", "-c", script, "bash", helper, in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	out, err := cmd.Output()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("escape failed after %s: %v\n%s", elapsed, err, stderr.String())
	}
	if elapsed > 10*time.Second {
		t.Fatalf("escaping %d bytes took %s", len(value), elapsed)
	}
	var want bytes.Buffer
	enc := json.NewEncoder(&want)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		t.Fatal(err)
	}
	wantInner := strings.TrimSuffix(strings.TrimSuffix(want.String(), "\n"), "\"")[1:]
	if string(out) != wantInner {
		t.Fatalf("escaped value differs from encoding/json (got %d bytes, want %d)", len(out), len(wantInner))
	}
	var round string
	if err := json.Unmarshal([]byte("\""+string(out)+"\""), &round); err != nil || round != value {
		t.Fatalf("escaped value does not decode back to the input: %v", err)
	}
}

// A socket table with no LISTEN row leaves _DC_SOCKET_ROWS empty; Bash 3.2
// treats "${a[@]}" of an empty array as unbound under set -u (GAP-2273).
func TestProcfsListenerStatusWithNoListeningRowIsNotUnbound(t *testing.T) {
	dir := t.TempDir()
	helper := writeBridgeReviewHelper(t, dir)
	netDir := filepath.Join(dir, "net")
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		t.Fatal(err)
	}
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:4A38 0100007F:D2F0 06 00000000:00000000 03:00000F6B 00000000     0        0 0 3 0000000000000000\n"
	for _, name := range []string{"tcp", "tcp6"} {
		if err := os.WriteFile(filepath.Join(netDir, name), []byte(table), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -u; . "$1"; defenseclaw_procfs_listener_status 127.0.0.1 19000 "$2" "$(id -u)"; printf 'rc=%s' "$?"`
	cmd := exec.Command("bash", "-c", script, "bash", helper, netDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || strings.Contains(stderr.String(), "unbound") || !strings.HasPrefix(string(out), "rc=") {
		t.Fatalf("listener status with no LISTEN row: err=%v out=%q stderr=%q", err, out, stderr.String())
	}
}
