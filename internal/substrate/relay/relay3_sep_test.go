// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// "kill-probe PID SIG" sends one signal and prints the result; the GAP-0116
// separation test runs it as another user.
func init() {
	if len(os.Args) > 3 && os.Args[1] == "kill-probe" {
		pid, _ := strconv.Atoi(os.Args[2])
		sig, _ := strconv.Atoi(os.Args[3])
		fmt.Println("kill", syscall.Kill(pid, syscall.Signal(sig)))
		os.Exit(0)
	}
}

// GAP-0116: a relay of the agent's own user, or one that names an agent
// user but is not root, is not separated and says so; a bad agent_user is
// refused.
func TestSeparationNeedsARootRelayAndAnAgentUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root: TestSeparatedAgentCannotSignalTheRelay covers it")
	}
	sp, warn, err := separate(kit.RelayConfig{})
	if sp != nil || err != nil || !strings.Contains(warn, "the agent runs as the relay's own user") {
		t.Fatalf("no agent_user: %v %q %v", sp, warn, err)
	}
	sp, warn, err = separate(kit.RelayConfig{AgentUser: "1000:1000"})
	if sp != nil || err != nil || !strings.Contains(warn, "not root") {
		t.Fatalf("agent_user, relay not root: %v %q %v", sp, warn, err)
	}
	for _, bad := range []string{"0:0", "root", "1000", "-1:5"} {
		if _, _, err := separate(kit.RelayConfig{AgentUser: bad}); err == nil {
			t.Errorf("agent_user %q accepted", bad)
		}
	}
}

// GAP-0116: as root with agent_user set, the agent (here the probe, started
// the way the relay starts every process) runs as the agent's user and gets
// EPERM for SIGKILL and SIGSTOP to the relay. Needs root (the gate boxes run
// it when the suite runs as root; the E4 live check covers gVisor).
func TestSeparatedAgentCannotSignalTheRelay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a process as another user")
	}
	if !inRelayChild(t) {
		return
	}
	sp, _, err := separate(kit.RelayConfig{AgentUser: "65534:65534"})
	if err != nil || sp == nil {
		t.Fatalf("separate as root: %v %v", sp, err)
	}
	// The test binary sits in a folder only root may enter: a copy the
	// agent's user can run.
	dir, err := os.MkdirTemp("", "relay-sep-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	_ = os.Chmod(dir, 0o755)
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sig := range []syscall.Signal{syscall.SIGKILL, syscall.SIGSTOP} {
		cmd := exec.Command(probe, "kill-probe", strconv.Itoa(os.Getpid()), strconv.Itoa(int(sig)))
		cmd.Dir = dir
		setProcessGroup(cmd)
		sp.asAgent(cmd)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v probe: %v", sig, err)
		}
		if !strings.Contains(string(out), "operation not permitted") {
			t.Fatalf("%v from the agent's user: %q", sig, out)
		}
	}
}

// GAP-0116, end to end as root: the separated relay runs the agent as the
// agent's user, the agent's SIGKILL to the relay fails, and an upload lands
// as the agent's files.
func TestSeparatedRelayRunsTheAgentAsItsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a process as another user")
	}
	if !inRelayChild(t) {
		return
	}
	sp, _, err := separate(kit.RelayConfig{AgentUser: "65534:65534"})
	if err != nil || sp == nil {
		t.Fatalf("separate as root: %v %v", sp, err)
	}
	dir, err := os.MkdirTemp("", "relay-sep-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	_ = os.Chmod(dir, 0o777)
	bin, _ := os.ReadFile(os.Args[0])
	sp.exe = filepath.Join(dir, "relay")
	if err := os.WriteFile(sp.exe, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(dir, "work")
	// The agent owns its working directory; 0777 lets the test (root
	// without DAC_OVERRIDE once separated) remove what the agent wrote.
	_ = os.Mkdir(work, 0o777)
	_ = os.Chmod(work, 0o777)
	_ = os.Chown(work, 65534, 65534)
	agent := "echo uid:$(id -u); kill -KILL " + strconv.Itoa(os.Getpid()) + " 2>/dev/null; echo rc:$?; while read l; do echo got:$l; done"
	s, _, ec := testServer(t, []string{"sh", "-c", agent})
	s.opts.sep = sp
	s.opts.Config.Relay.Workdir = work
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	c, _, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out := readUntil(t, c, "rc:", nil)
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("x\r")))
	out += readUntil(t, c, "got:x", nil)
	if !strings.Contains(out, "uid:65534") || strings.Contains(out, "rc:0") {
		t.Fatalf("the agent: %q", out)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	req, _ := http.NewRequest("PUT", srv.URL+"/dcrelay/1/files?dir="+work, &buf)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("upload: %d %s", resp.StatusCode, body)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(work, "a.txt"), &st); err != nil || st.Uid != 65534 {
		t.Fatalf("the upload is owned by %d (%v)", st.Uid, err)
	}
}

// A separated relay copies files as the agent's user through its child
// commands; here the child runs as the test's user, the path the same.
func TestFileCopiesThroughTheAgentChild(t *testing.T) {
	sp := &separation{exe: os.Args[0]}
	dir := filepath.Join(t.TempDir(), "proj")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "proj/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "proj/a.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	res, err := sp.extract(context.Background(), &buf, dir, 1<<20)
	if err != nil || res.Files != 1 {
		t.Fatalf("extract: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "proj", "a.txt")); string(b) != "hi" {
		t.Fatalf("extracted %q", b)
	}
	var bad bytes.Buffer
	tw = tar.NewWriter(&bad)
	_ = tw.WriteHeader(&tar.Header{Name: "../x", Mode: 0o644, Typeflag: tar.TypeReg})
	_ = tw.Close()
	if _, err := sp.extract(context.Background(), &bad, dir, 1<<20); err == nil || !strings.Contains(err.Error(), ErrUnsafePath.Error()) {
		t.Fatalf("an unsafe archive: %v", err)
	}
	var out bytes.Buffer
	ready := false
	if err := sp.tarTo(context.Background(), &out, filepath.Join(dir, "proj"), func() { ready = true }); err != nil || !ready {
		t.Fatalf("tar: %v ready=%v", err, ready)
	}
	if !bytes.Contains(out.Bytes(), []byte("hi")) {
		t.Fatal("the tar does not hold the file")
	}
	if err := sp.tarTo(context.Background(), io.Discard, filepath.Join(dir, "missing"), func() {}); err != errChildNotFound {
		t.Fatalf("a missing path: %v", err)
	}
	home := t.TempDir()
	if got := sp.stateDir(home, filepath.Join(home, "work")); got != filepath.Join(home, ".local", "state", "defenseclaw", "copies") {
		t.Fatalf("state dir: %q", got)
	}
}
