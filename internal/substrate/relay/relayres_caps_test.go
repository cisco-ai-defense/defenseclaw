// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
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
	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// relayChildEnv names the test a child of the test binary runs as a
// separated relay (inRelayChild).
const relayChildEnv = "DC_RELAY_TEST_SEPARATED"

// inRelayChild runs the calling root test again in a child of the test
// binary and reports whether this process is that child. separate() changes
// the capabilities of the whole process (GAP-0376), so a test that calls it
// runs alone in its own process, as a relay does.
func inRelayChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(relayChildEnv) == t.Name() {
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), relayChildEnv+"="+t.Name())
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: "+t.Name())) {
		t.Fatalf("%s as a separated relay (child process): %v\n%s", t.Name(), err, out)
	}
	t.Logf("child:\n%s", out)
	return false
}

// procCaps reads the capability sets of a /proc status file.
func procCaps(t *testing.T, status string) map[string]uint64 {
	t.Helper()
	b, err := os.ReadFile(status)
	if err != nil {
		t.Fatal(err)
	}
	return parseCaps(string(b))
}

func parseCaps(s string) map[string]uint64 {
	out := map[string]uint64{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || !strings.HasPrefix(k, "Cap") {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64); err == nil {
			out[k] = n
		}
	}
	return out
}

// GAP-0376: a separated relay keeps only CAP_SETUID, CAP_SETGID, CAP_KILL,
// CAP_CHOWN and CAP_DAC_READ_SEARCH, on every thread and in its bounding
// set, and every spawn path still works: the agent's PTY, a headless task,
// exec, the files-put, files-get and state-dir children, stopping the
// agent's processes, and the guard's watch of a 0700 HOME. Each process it
// starts runs as the agent's user with no capabilities and the relay's
// bounding set. Needs root; runs in a child process.
func TestSeparatedRelayKeepsOnlyItsCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a process as another user")
	}
	if !inRelayChild(t) {
		return
	}
	before := procCaps(t, "/proc/self/status")
	sp, _, err := separate(kit.RelayConfig{AgentUser: "65534:65534"})
	if err != nil || sp == nil {
		t.Fatalf("separate as root: %v %v", sp, err)
	}
	var want uint64
	for _, c := range []int{unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL, unix.CAP_CHOWN, unix.CAP_DAC_READ_SEARCH} {
		want |= 1 << uint(c)
	}
	want &= before["CapPrm"]
	bnd := want
	if before["CapEff"]&(1<<unix.CAP_SETPCAP) == 0 {
		bnd = before["CapBnd"]
	}
	tasks, _ := filepath.Glob("/proc/self/task/*/status")
	if len(tasks) < 2 {
		t.Fatalf("threads: %v", tasks)
	}
	for _, st := range append([]string{"/proc/self/status"}, tasks...) {
		c := procCaps(t, st)
		if c["CapEff"] != want || c["CapPrm"] != want || c["CapInh"] != 0 || c["CapAmb"] != 0 || c["CapBnd"] != bnd {
			t.Fatalf("%s: relay capabilities %x, want effective and permitted %x, bounding %x, no inheritable or ambient", st, c, want, bnd)
		}
	}

	// The agent's user owns its HOME (0700, as many base images make it) and
	// its working directory; the relay binary is copied where it may run.
	dir, err := os.MkdirTemp("", "relay-caps-")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o777)
	home, work := filepath.Join(dir, "home"), filepath.Join(dir, "work")
	for _, d := range []string{home, work} {
		_ = os.Mkdir(d, 0o700)
		_ = os.Chown(d, 65534, 65534)
	}
	t.Cleanup(func() {
		// The agent's files are removed as the agent (the relay has no
		// DAC_OVERRIDE now).
		rm := exec.Command("rm", "-rf", home, work)
		sp.asAgent(rm)
		_ = rm.Run()
		_ = os.RemoveAll(dir)
	})
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	sp.exe = filepath.Join(dir, "relay")
	if err := os.WriteFile(sp.exe, bin, 0o755); err != nil {
		t.Fatal(err)
	}

	// A process the relay starts: the agent's user, no capabilities, the
	// relay's bounding set.
	childOK := func(path, out string) {
		t.Helper()
		c := parseCaps(out)
		if !strings.Contains(out, "uid:65534") || c["CapEff"] != 0 || c["CapPrm"] != 0 || c["CapInh"] != 0 || c["CapAmb"] != 0 {
			t.Fatalf("%s: %q", path, out)
		}
		if b, ok := c["CapBnd"]; !ok || b != bnd {
			t.Fatalf("%s: bounding set %x, want %x", path, b, bnd)
		}
	}
	report := `echo uid:$(id -u); grep ^Cap /proc/self/status`

	// The agent's PTY.
	s, _, ec := testServer(t, []string{"sh", "-c", report + `; echo tty:$(stat -c %u $(tty)); echo end; while read l; do echo got:$l; done`})
	s.opts.sep = sp
	s.opts.Config.Relay.Workdir = work
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	tok := func() string { return ec.token(t, claims(time.Now(), nil), TokenType) }
	c, _, err := dialWS(t, srv.URL, tok(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := readUntil(t, c, "end", nil)
	childOK("agent", strings.ReplaceAll(out, "\r", ""))
	if !strings.Contains(out, "tty:65534") {
		t.Fatalf("the agent's terminal is not the agent's (CAP_CHOWN): %q", out)
	}
	_ = c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("x\r")))
	readUntil(t, c, "got:x", nil)
	c.Close()

	do := func(method, path string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set("Authorization", "Bearer "+tok())
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// exec, and a timeout that stops the agent user's process group (CAP_KILL).
	e := &fileEnv{t: t, s: s, srv: srv, tok: tok()}
	r := e.exec(ExecRequest{Argv: []string{"sh", "-c", report}})
	childOK("exec", string(r.stdout))
	start := time.Now()
	r = e.exec(ExecRequest{Argv: []string{"sh", "-c", "sleep 30 & sleep 30"}, TimeoutSeconds: 1})
	if time.Since(start) > 15*time.Second || r.code == 0 {
		t.Fatalf("exec timeout did not stop the agent's processes: code %d after %v", r.code, time.Since(start))
	}

	// files-put, files-get and state-dir: children of the relay binary.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	if resp, b := do("PUT", "/dcrelay/1/files?dir="+work, &buf, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("files-put: %d %s", resp.StatusCode, b)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(work, "a.txt"), &st); err != nil || st.Uid != 65534 {
		t.Fatalf("files-put: owned by %d (%v)", st.Uid, err)
	}
	if resp, b := do("GET", "/dcrelay/1/files?path="+filepath.Join(work, "a.txt"), nil, nil); resp.StatusCode != http.StatusOK || !bytes.Contains(b, []byte("hi")) {
		t.Fatalf("files-get: %d %q", resp.StatusCode, b)
	}
	if got := sp.stateDir(home, work); got != filepath.Join(home, ".local", "state", "defenseclaw", "copies") {
		t.Fatalf("state-dir as the agent: %q", got)
	}
	probe := sp.child(context.Background(), "caps-probe")
	b, _ := probe.CombinedOutput()
	childOK("relay child", string(b))

	// A headless task.
	s.opts.Config.Relay.Headless = []string{"sh", "-c", report + `; echo prompt:$0`, "{prompt}"}
	taskTok := ec.token(t, claims(time.Now(), func(c map[string]any) { c["dc.task_sha256"] = TaskDigest("go") }), TokenType)
	req, _ := http.NewRequest("POST", srv.URL+"/dcrelay/1/task", strings.NewReader(`{"prompt":"go"}`))
	req.Header.Set("Authorization", "Bearer "+taskTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	dec := json.NewDecoder(resp.Body)
	for {
		var ev TaskEvent
		if dec.Decode(&ev) != nil {
			break
		}
		text.WriteString(ev.Data)
	}
	resp.Body.Close()
	if !strings.Contains(text.String(), "prompt:go") {
		t.Fatalf("task: %q", text.String())
	}
	childOK("task", text.String())

	// The guard reads the agent's 0700 HOME (CAP_DAC_READ_SEARCH).
	gem := filepath.Join(home, ".gemini")
	mk := exec.Command("mkdir", gem)
	sp.asAgent(mk)
	if err := mk.Run(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := watchGuarded(ctx, []string{gem}, func(string) {}); err != nil {
		t.Fatalf("the guard cannot watch a folder in the agent's 0700 HOME: %v", err)
	}
}

// "caps-probe" prints the identity and capabilities of the process, as a
// child of the relay binary (TestSeparatedRelayKeepsOnlyItsCapabilities).
func init() {
	if len(os.Args) > 1 && os.Args[1] == "caps-probe" {
		b, _ := os.ReadFile("/proc/self/status")
		fmt.Printf("uid:%d\n%s", os.Getuid(), b)
		os.Exit(0)
	}
}
