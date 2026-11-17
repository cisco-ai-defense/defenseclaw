// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0362: a process a test leaves behind is found also when it cleared
// its environment (env -i drops the run's mark) and its parent exited.
func TestLeakCheckFindsAProcessThatClearedItsEnvironment(t *testing.T) {
	out, err := exec.Command("sh", "-c", "env -i sleep 300 >/dev/null 2>&1 & echo $!").Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 1 {
		t.Fatalf("pid %q", out)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	// Wait until env has exec'd sleep with the empty environment.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		cmd, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if bytes.HasPrefix(cmd, []byte("sleep\x00")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the process did not start sleep: %q", cmd)
		}
	}
	if env, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ"); bytes.Contains(env, []byte(leakMarkEnv)) {
		t.Fatalf("env -i kept the mark: %q", env)
	}
	if got := leftBehind(); !slices.Contains(got, pid) {
		t.Fatalf("the leak check misses process %d (env -i sleep 300, parent gone): found %v", pid, got)
	}
}

// GAP-0375: a files-get of a path the reader may not read all of (a file, or
// a folder with such a file) is refused before the first byte: 403 and no
// tar, through the relay and through the files-get child of a separated
// relay; nothing about the file is sent.
func TestFilesGetOfAnUnreadablePathIsRefusedBeforeTheFirstByte(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o000); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(dir, "proj")
	_ = os.Mkdir(proj, 0o755)
	_ = os.WriteFile(filepath.Join(proj, "ok.txt"), []byte("fine"), 0o644)
	_ = os.WriteFile(filepath.Join(proj, "secret.key"), []byte("s3cr3t"), 0o000)

	e := newFileEnv(t)
	for _, p := range []string{secret, proj} {
		code, body := e.status("GET", "/dcrelay/1/files?path="+url.QueryEscape(p), nil)
		if code != 403 || strings.Contains(body, "ustar") || strings.Contains(body, "s3cr3t") {
			t.Fatalf("files-get %s: %d %q", p, code, body)
		}
	}
	sp := &separation{exe: os.Args[0]}
	for _, p := range []string{secret, proj} {
		var out bytes.Buffer
		ready := false
		err := sp.tarTo(context.Background(), &out, p, func() { ready = true })
		if ready || out.Len() > 0 || err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("files-get child %s: ready=%v %d bytes, %v", p, ready, out.Len(), err)
		}
	}
	// A readable folder still copies.
	_ = os.Remove(filepath.Join(proj, "secret.key"))
	if code, body := e.status("GET", "/dcrelay/1/files?path="+url.QueryEscape(proj), nil); code != 200 || !strings.Contains(body, "fine") {
		t.Fatalf("readable folder: %d", code)
	}
}

// GAP-0412: every actor of a template is restored from one golden snapshot
// that holds the relay (PID 1 answers the wake-up probe), so the relay's
// process start time is the snapshot's in all of them. The relay reports
// when it began serving this actor: the first authenticated request after
// the actor's first resume, after the snapshot, never before.
func TestStatusSaysWhenTheRelayBeganServingTheActor(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	resumed := time.Now()
	s.opts.Now = func() time.Time { return resumed }
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/dcrelay/1/status", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status: %v %v", resp, err)
	}
	defer resp.Body.Close()
	var st map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	got, _ := st["serving_since"].(string)
	at, err := time.Parse(time.RFC3339Nano, got)
	if err != nil || !at.Equal(resumed.UTC()) {
		t.Fatalf("serving_since %q, want the first request after the resume %s", got, resumed.UTC())
	}
}
