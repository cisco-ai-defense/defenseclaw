// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

func shortConnectedWait(t *testing.T, wait time.Duration) {
	t.Helper()
	previous := perUserConnectedWait
	perUserConnectedWait = wait
	t.Cleanup(func() { perUserConnectedWait = previous })
}

// procTables writes fake tcp and tcp6 tables with the given rows.
func procTables(t *testing.T, tcp, tcp6 []string) string {
	t.Helper()
	dir := t.TempDir()
	header := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	for name, rows := range map[string][]string{"tcp": tcp, "tcp6": tcp6} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(header+strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// recordedStart is the start_identity the gateway writes for process pid: the
// same text, from the same helper, that the gateway and the hook compare.
func recordedStart(t *testing.T, pid int) string {
	t.Helper()
	identity, ok := procidentity.Recorded(pid)
	if !ok {
		t.Fatalf("no start identity for process %d", pid)
	}
	return identity
}

// recordGateway writes the gateway.pid record of this account in a new data
// folder, naming process pid, and returns the folder.
func recordGateway(t *testing.T, pid int, mutate func(*gatewayRecord)) string {
	t.Helper()
	dir := t.TempDir()
	record := gatewayRecord{PID: pid, Executable: "/usr/local/bin/defenseclaw-gateway", DataDir: dir,
		StartTime: time.Now().Unix(), StartIdentity: recordedStart(t, pid)}
	if mutate != nil {
		mutate(&record)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gateway.pid"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// otherProcess starts a process of this account that is not the listener of
// the test: the stand-in for a process the record could name instead.
func otherProcess(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("no second process: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd.Process.Pid
}

// The listeners of a port are the gateway's only when the process the record
// names holds every one of them: a socket of the same account that another
// process holds, a mix, or nothing found is no proof.
func TestListenersHeldOnlyByTheRecordedGateway(t *testing.T) {
	const gateway = 4242
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	const loop = "0100007F:4A1A"
	const anyV4 = "00000000:4A1A"
	const anyV6 = "00000000000000000000000000000000:4A1A"
	const mapped = "0000000000000000FFFF00000100007F:4A1A"
	listen := func(key string, inode int) string {
		return fmt.Sprintf("0: %s 00000000:0000 0A 0 0 0 1000 0 %d", key, inode)
	}
	for _, tc := range []struct {
		name  string
		tcp   []string
		tcp6  []string
		held  []int
		other bool
		want  bool
		// shared lists the inodes a second process of the account also holds;
		// hidden adds a process whose descriptor list is permission-denied.
		shared []int
		hidden bool
		// private lists the inodes only a second thread of a second process
		// holds, in a descriptor table of its own (the leader holds none).
		private []int
	}{
		{"loopback listener of the gateway", []string{listen(loop, 11)}, nil, []int{11}, false, true, nil, false, nil},
		{"wildcard listener of the gateway", []string{listen(anyV4, 11)}, nil, []int{11}, false, true, nil, false, nil},
		{"dual-stack listener of the gateway", nil, []string{listen(anyV6, 11)}, []int{11}, false, true, nil, false, nil},
		{"mapped listener of the gateway", nil, []string{listen(mapped, 11)}, []int{11}, false, true, nil, false, nil},
		{"loopback and wildcard both of the gateway", []string{listen(loop, 11), listen(anyV4, 12)}, nil, []int{11, 12}, false, true, nil, false, nil},
		{"listener of another process of the account", []string{listen(loop, 11)}, nil, []int{99}, false, false, nil, false, nil},
		{"gateway holds one, another process the other", []string{listen(loop, 11), listen(anyV4, 12)}, nil, []int{11}, false, false, nil, false, nil},
		{"no listener", nil, nil, []int{11}, false, false, nil, false, nil},
		{"listener on another port", []string{"0: 0100007F:1234 00000000:0000 0A 0 0 0 1000 0 11"}, nil, []int{11}, false, false, nil, false, nil},
		{"an established row is not a listener", []string{"0: 0100007F:4A1A 0100007F:CB20 01 0 0 0 1000 0 11"}, nil, []int{11}, false, false, nil, false, nil},
		{"descriptors of the process unreadable", []string{listen(loop, 11)}, nil, nil, true, false, nil, false, nil},
		{"another process of the account also holds the listener", []string{listen(loop, 11)}, nil, []int{11}, false, false, []int{11}, false, nil},
		{"another process holds only the wildcard listener", []string{listen(loop, 11), listen(anyV4, 12)}, nil, []int{11, 12}, false, false, []int{12}, false, nil},
		{"another process holds an unrelated socket", []string{listen(loop, 11)}, nil, []int{11}, false, true, []int{77}, false, nil},
		{"a thread of another process holds the listener in a table of its own", []string{listen(loop, 11)}, nil, []int{11}, false, false, nil, false, []int{11}},
		{"a thread of another process holds only the wildcard listener in a table of its own", []string{listen(loop, 11), listen(anyV4, 12)}, nil, []int{11, 12}, false, false, nil, false, []int{12}},
		{"a thread of another process holds an unrelated socket in a table of its own", []string{listen(loop, 11)}, nil, []int{11}, false, true, nil, false, []int{77}},
		{"a process of the account the kernel will not let us read, like an sshd child", []string{listen(loop, 11)}, nil, []int{11}, false, true, nil, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			if !tc.other {
				fds := filepath.Join(procRoot, strconv.Itoa(gateway), "task", strconv.Itoa(gateway), "fd")
				if err := os.MkdirAll(fds, 0o755); err != nil {
					t.Fatal(err)
				}
				for i, inode := range tc.held {
					if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fds, strconv.Itoa(i+3))); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(tc.shared) != 0 {
				writeHeldSockets(t, procRoot, 5151, tc.shared)
			}
			if len(tc.private) != 0 {
				writeThreadSockets(t, procRoot, 5353, 5353, nil)
				writeThreadSockets(t, procRoot, 5353, 5354, tc.private)
			}
			if tc.hidden {
				if os.Geteuid() == 0 {
					t.Skip("root reads every descriptor list")
				}
				writeFakeProcess(t, procRoot, 5252, fakeThread{tid: 5252, state: "S", ids: "own"})
			}
			if got := listenersHeldOnlyBy(procTables(t, tc.tcp, tc.tcp6), procRoot, gateway, server); got != tc.want {
				t.Fatalf("listenersHeldOnlyBy = %v, want %v", got, tc.want)
			}
		})
	}
}

// writeHeldSockets gives a fake process the socket descriptors inodes.
func writeHeldSockets(t *testing.T, procRoot string, pid int, inodes []int) {
	t.Helper()
	writeThreadSockets(t, procRoot, pid, pid, inodes)
}

// writeThreadSockets gives thread tid of a fake process the socket descriptors
// inodes; the process is listed even when its own thread holds none.
func writeThreadSockets(t *testing.T, procRoot string, pid, tid int, inodes []int) {
	t.Helper()
	fds := filepath.Join(procRoot, strconv.Itoa(pid), "task", strconv.Itoa(tid), "fd")
	if err := os.MkdirAll(fds, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, inode := range inodes {
		if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fds, strconv.Itoa(i+3))); err != nil {
			t.Fatal(err)
		}
	}
}

// A connection nobody accepts proves nothing by itself: the wait ends with
// the not-accepted error, never with a foreign or an own verdict. A socket
// another account accepted is a different, final answer.
func TestUnacceptedConnectionEndsAsNotAcceptedAlone(t *testing.T) {
	self := os.Geteuid()
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0x4A1A}
	queued := "1: 0100007F:4A1A 0100007F:CB20 01 0 0 0 0 0 0"
	own := fmt.Sprintf("0: 0100007F:4A1A 00000000:0000 0A 0 0 0 %d 0 100", self)
	err := verifyPerUserConnectedTupleIn(procTables(t, []string{own, queued}, nil), self, 80*time.Millisecond, client, server)
	if !errors.Is(err, errPerUserNotAccepted) || errors.Is(err, errPerUserListenerUnanswered) {
		t.Fatalf("a queued connection did not end as not accepted: %v", err)
	}
	accepted := fmt.Sprintf("1: 0100007F:4A1A 0100007F:CB20 01 0 0 0 %d 0 101", self+1)
	err = verifyPerUserConnectedTupleIn(procTables(t, []string{own, accepted}, nil), self, 80*time.Millisecond, client, server)
	if err == nil || errors.Is(err, errPerUserNotAccepted) {
		t.Fatalf("a socket accepted by another account was not refused as foreign: %v", err)
	}
}

// frozenListener is a listener of this account that accepts nothing: what a
// SIGSTOPped gateway looks like to the kernel.
func frozenListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

// recordedFrozenGateway is a frozen listener that the record of this account
// names as its gateway (the test process stands for it).
func recordedFrozenGateway(t *testing.T) (addr, dataDir string) {
	t.Helper()
	return frozenListener(t), recordGateway(t, os.Getpid(), nil)
}

// The transport tells the three holders of a listener that takes no accept
// apart: this account's recorded gateway is an unanswered own listener; a
// process of this account that is not the recorded gateway, a gateway the
// record no longer describes, and a folder with no record all stay unverified.
func TestFrozenListenerIsOwnOnlyWhenItIsTheRecordedGateway(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	decoy := otherProcess(t)
	for _, tc := range []struct {
		name   string
		dir    func(t *testing.T) string
		wantOK bool
	}{
		{"recorded gateway", func(t *testing.T) string { return recordGateway(t, os.Getpid(), nil) }, true},
		{"record names another process of the account", func(t *testing.T) string { return recordGateway(t, decoy, nil) }, false},
		{"record of a process that was replaced", func(t *testing.T) string {
			return recordGateway(t, os.Getpid(), func(r *gatewayRecord) { r.StartIdentity = "not-this-process" })
		}, false},
		{"record for another folder", func(t *testing.T) string {
			return recordGateway(t, os.Getpid(), func(r *gatewayRecord) { r.DataDir = "/elsewhere" })
		}, false},
		{"no record", func(t *testing.T) string { return t.TempDir() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := frozenListener(t)
			ctx := WithPerUserGatewayDataDir(context.Background(), tc.dir(t))
			_, err := PostPerUserHook(ctx, addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err == nil {
				t.Fatal("a frozen listener answered")
			}
			if got := PerUserPostListenerUnanswered(err); got != tc.wantOK {
				t.Fatalf("unanswered own listener = %v, want %v: %v", got, tc.wantOK, err)
			}
			if tc.wantOK {
				if PerUserPostPeerUnverified(err) || PerUserPostOutage(err) || PerUserPostNoAnswer(err) || gatewayRestartShaped(err) {
					t.Fatalf("an unanswered own listener was classified as foreign or an outage: %v", err)
				}
			} else if !PerUserPostPeerUnverified(err) {
				t.Fatalf("a listener that is not the recorded gateway was not refused as unverified: %v", err)
			}
		})
	}
}

// A frozen gateway of this account is an outage, not a listener of another
// account, at the production wait: the default tiers let an ordinary call and
// a post-tool event run with the outage warning before the restart budget
// ends, the strict tier blocks them with the outage text, and a tool call
// that names a protected file stays blocked in every tier.
func TestFrozenOwnGatewayFollowsTheOutageMode(t *testing.T) {
	requireFrozenGatewayJob(t)
	addr, dataDir := recordedFrozenGateway(t)
	assertFrozenGatewayFollowsOutageMode(t, addr, dataDir)
}

// assertFrozenGatewayFollowsOutageMode runs the calls of a Claude Code turn
// against a listener at addr that takes no accept and that the gateway.pid
// record in dataDir names as this account's gateway.
func assertFrozenGatewayFollowsOutageMode(t *testing.T, addr, dataDir string) {
	t.Helper()
	project := lateOrdinaryProject(t)
	for _, tc := range []struct {
		name    string
		event   string
		payload string
		mode    string
		blocks  bool
	}{
		{"ordinary call, open tier", "PreToolUse", lateOrdinaryPayload(t, project, "echo hi"), "open", false},
		{"ordinary call, strict tier", "PreToolUse", lateOrdinaryPayload(t, project, "echo hi"), "closed", true},
		{"link to keys, open tier", "PreToolUse", lateOrdinaryPayload(t, project, "cat keylink"), "open", true},
		{"direct keys path, open tier", "PreToolUse", lateOrdinaryPayload(t, project, "cat ../.ssh/authorized_keys"), "open", true},
		{"prompt submit, open tier", "UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`, "open", false},
		{"prompt submit, strict tier", "UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`, "closed", true},
		{"post-tool event, open tier", "PostToolBatch", `{"hook_event_name":"PostToolBatch"}`, "open", false},
		{"post-tool event, strict tier", "PostToolBatch", `{"hook_event_name":"PostToolBatch"}`, "closed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewPerUserGatewayHTTPClient(10*time.Second, addr)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			result := run(t, "claudecode", nil, func(opts *Options) {
				opts.APIAddr = addr
				opts.HTTPClient = client
				opts.Event = tc.event
				opts.Home = dataDir
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return tc.mode }
				opts.Stdin = strings.NewReader(tc.payload)
			})
			output := result.stdout + result.stderr
			if strings.Contains(output, "another account") || strings.Contains(output, "could not prove") {
				t.Fatalf("a frozen gateway of this account was blamed on another process: %q", output)
			}
			if got := nativeOutageBlocked(result); got != tc.blocks {
				t.Fatalf("blocks=%v, want %v: code=%d stdout=%.400q stderr=%.400q", got, tc.blocks, result.code, result.stdout, result.stderr)
			}
			if tc.blocks && !strings.Contains(output, "did not answer") {
				t.Fatalf("the block does not say the gateway did not answer: %q", output)
			}
			if elapsed := time.Since(started); elapsed > gatewayRestartBudget+500*time.Millisecond {
				t.Fatalf("the call ended after %s, past the restart budget %s", elapsed, gatewayRestartBudget)
			}
		})
	}
}

// A listener of this account that is not the recorded gateway stays blocked
// in every fail mode at the production wait: nothing proves it is the gateway,
// whoever the account is.
func TestUnrecordedListenerOfThisAccountStaysBlockedInEveryMode(t *testing.T) {
	project := lateOrdinaryProject(t)
	decoy := otherProcess(t)
	addr := frozenListener(t)
	dataDir := recordGateway(t, decoy, nil)
	for _, tc := range []struct {
		name, event, payload string
	}{
		{"ordinary call", "PreToolUse", lateOrdinaryPayload(t, project, "echo hi")},
		{"post-tool event", "PostToolBatch", `{"hook_event_name":"PostToolBatch"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewPerUserGatewayHTTPClient(10*time.Second, addr)
			if err != nil {
				t.Fatal(err)
			}
			result := run(t, "claudecode", nil, func(opts *Options) {
				opts.APIAddr = addr
				opts.HTTPClient = client
				opts.Event = tc.event
				opts.Home = dataDir
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Stdin = strings.NewReader(tc.payload)
			})
			if !nativeOutageBlocked(result) || strings.Contains(result.stdout+result.stderr, "did not answer in time") {
				t.Fatalf("a listener that is not the recorded gateway was not kept closed: code=%d stdout=%.300q stderr=%.300q", result.code, result.stdout, result.stderr)
			}
		})
	}
}

// The benign twin: a gateway that accepts and answers is untouched.
func TestAnsweringGatewayStillAllowsTheCall(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	addr := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow"}`))
	})
	ctx := WithPerUserGatewayDataDir(context.Background(), recordGateway(t, os.Getpid(), nil))
	reply, err := PostPerUserHook(ctx, addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err != nil || reply.Status != http.StatusOK {
		t.Fatalf("an answering gateway was refused: status=%d err=%v", reply.Status, err)
	}
}

// A listener the recorded gateway shares with another process of the account
// (a forked or inherited descriptor: the same socket, one accept queue) is not
// the gateway's alone, so it stays refused as unverified in every fail mode.
func TestSharedListenerOfTheRecordedGatewayStaysUnverified(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	file, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command("sleep", "60")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		t.Skipf("no second process: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ctx := WithPerUserGatewayDataDir(context.Background(), recordGateway(t, os.Getpid(), nil))
	_, err = PostPerUserHook(ctx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err == nil {
		t.Fatal("a listener that accepts nothing answered")
	}
	if PerUserPostListenerUnanswered(err) || !PerUserPostPeerUnverified(err) {
		t.Fatalf("a listener shared with another process was not refused as unverified: %v", err)
	}
}
