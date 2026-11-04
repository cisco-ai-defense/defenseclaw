// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// cowork-1-0-8 GAP-0055: a transparent wrapper (timeout, nice, env) around
// the verified Claude client repeats the client's argv, which names an MCP
// package. The wrapper's record is dropped only when its child exec is the
// signed client image with the wrapper's argv tail and is not reported
// itself; everything else is reported as before.
func TestTransparentWrapperOfTheVerifiedClientIsNotReported(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	signed, unsigned := hex.EncodeToString(release[:]), hex.EncodeToString(other[:])
	const client = `/sessions/cwk-v1/.local/bin/claude -p --dangerously-skip-permissions Add a project-scoped MCP server named docs running npx -y @modelcontextprotocol/server-filesystem`
	type exec struct {
		pid, ppid       int
		name, cmdline   string
		digest, version string
	}
	const agent, wrapper, child = 500, 501, 502
	for _, tc := range []struct {
		name          string
		keepClientMCP bool
		execs         []exec
		// want counts the wrappers record and the childs own: a child that
		// is not the verified client is reported on its own exec as well.
		want int64
	}{
		{"timeout forks the verified client", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			// The fork still runs timeout until it execs.
			{child, wrapper, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", client, signed, "2.1.317"},
		}, 0},
		{"timeout with options, child exec seen without its fork", false, []exec{
			{wrapper, agent, "timeout", "timeout --preserve-status -k 5 -s TERM 5m " + client, "", ""},
			{child, wrapper, "claude", client, signed, "2.1.317"},
		}, 0},
		{"nice execs the verified client in place", false, []exec{
			{wrapper, agent, "nice", "nice -n 10 " + client, "", ""},
			{wrapper, agent, "claude", client, signed, "2.1.317"},
		}, 0},
		{"env sets a variable and execs the verified client", false, []exec{
			{wrapper, agent, "env", "env -u TERM CLAUDE_CODE_USE_BEDROCK=1 " + client, "", ""},
			{wrapper, agent, "claude", client, signed, "2.1.317"},
		}, 0},
		{"child is another image", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", client, unsigned, "2.1.317"},
		}, 2},
		{"child image not read", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", client, "", ""},
		}, 2},
		{"child release of another version", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", client, signed, "2.1.318"},
		}, 2},
		{"no child exec before the hold ends", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
		}, 1},
		{"child argv is not the wrapper's tail", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", client + " --extra", signed, "2.1.317"},
		}, 1},
		{"child argv drops the wrapper's tail program", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", "claude -p hello", signed, "2.1.317"},
		}, 1},
		{"wrapper not on the allowlist", false, []exec{
			{wrapper, agent, "nohup", "nohup " + client, "", ""},
			{child, wrapper, "claude", client, signed, "2.1.317"},
		}, 1},
		{"program named timeout run under another name", false, []exec{
			{wrapper, agent, "timeout", "/tmp/x/fake 300 " + client, "", ""},
			{child, wrapper, "claude", client, signed, "2.1.317"},
		}, 1},
		{"env with a loader variable", false, []exec{
			{wrapper, agent, "env", "env LD_PRELOAD=/tmp/x.so " + client, "", ""},
			{wrapper, agent, "claude", client, signed, "2.1.317"},
		}, 1},
		{"signal in the wrapper's own arguments", false, []exec{
			{wrapper, agent, "env", "env MCP_SERVER_CMD=npx /sessions/cwk-v1/.local/bin/claude -p hello", "", ""},
			{wrapper, agent, "claude", "/sessions/cwk-v1/.local/bin/claude -p hello", signed, "2.1.317"},
		}, 1},
		{"wrapped client starts a positional server", false, []exec{
			{wrapper, agent, "timeout", "timeout 300 claude @modelcontextprotocol/server-filesystem /workspace", "", ""},
			{child, wrapper, "claude", "claude @modelcontextprotocol/server-filesystem /workspace", signed, "2.1.317"},
		}, 2},
		{"Secure Client profile", true, []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, "", ""},
			{child, wrapper, "claude", client, signed, "2.1.317"},
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.wrapperHold = 30 * time.Millisecond
			host.coldHold, host.coldPoll = 30*time.Millisecond, 5*time.Millisecond
			host.indicators.KeepClientMCP = tc.keepClientMCP
			host.clientChecksums = func(version string) ([][32]byte, bool) {
				if version != "2.1.317" {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			uid := os.Getuid() + 1000
			at := time.Unix(1_760_000_000, 0)
			host.handle(plane.Event{Kind: plane.KindExec, PID: agent, PPID: 1, Name: "claude",
				Cmdline: "claude", UID: &uid, At: at})
			for _, e := range tc.execs {
				host.handle(plane.Event{
					Kind: plane.KindExec, PID: e.pid, PPID: e.ppid, Name: e.name, Cmdline: e.cmdline,
					UID: &uid, At: at, ImageSHA256: e.digest, ImageVersion: e.version,
				})
			}
			time.Sleep(4 * host.wrapperHold)
			classified, _, _, _ := host.stats()
			host.mu.Lock()
			held := len(host.wrappers)
			host.mu.Unlock()
			if classified != tc.want || held != 0 {
				t.Fatalf("classified=%d held=%d, want %d and 0", classified, held, tc.want)
			}
		})
	}
}

// A child that is not the verified client records the held wrapper at once,
// not when the hold ends.
func TestWrapperWithAnUnverifiedChildIsRecordedAtOnce(t *testing.T) {
	host := newHost(newFake(fullCoverage()))
	host.wrapperHold = time.Hour
	host.clientChecksums = func(string) ([][32]byte, bool) { return nil, false }
	uid := os.Getuid() + 1000
	cmd := "/home/u/.local/bin/claude -p use @modelcontextprotocol/server-filesystem"
	host.handle(plane.Event{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: "claude", UID: &uid})
	host.handle(plane.Event{Kind: plane.KindExec, PID: 501, PPID: 500, Name: "timeout", Cmdline: "timeout 300 " + cmd, UID: &uid})
	if classified, _, _, _ := host.stats(); classified != 0 {
		t.Fatalf("classified=%d before the child exec, want the wrapper held", classified)
	}
	host.handle(plane.Event{Kind: plane.KindExec, PID: 502, PPID: 501, Name: "claude", Cmdline: cmd, UID: &uid})
	// The unverified child is reported on its own exec, and the wrapper with it.
	if classified, _, _, _ := host.stats(); classified != 2 {
		t.Fatalf("classified=%d, want the wrapper and the unverified child", classified)
	}
}

func TestWrapperTail(t *testing.T) {
	for _, tc := range []struct {
		name, cmdline, tail string
		ok                  bool
	}{
		{"timeout", "timeout 300 claude -p x", "claude -p x", true},
		{"timeout", "/usr/bin/timeout 1.5m claude", "claude", true},
		{"timeout", "timeout -k5 --signal=KILL -- 10s claude -p", "claude -p", true},
		{"timeout", "timeout --foreground -v 300 claude", "claude", true},
		{"timeout", "timeout claude -p x", "", false},
		{"timeout", "timeout 300", "", false},
		{"timeout", "timeout --unknown 300 claude", "", false},
		{"nice", "nice claude", "claude", true},
		{"nice", "nice -n 5 claude", "claude", true},
		{"nice", "nice -n5 claude", "claude", true},
		{"nice", "nice -10 claude", "claude", true},
		{"nice", "nice --adjustment=3 -- claude", "claude", true},
		{"nice", "nice -n x claude", "", false},
		{"nice", "nice", "", false},
		{"env", "env A=1 B=2 claude -p", "claude -p", true},
		{"env", "env -i -u HOME -- claude", "claude", true},
		{"env", "env -S 'claude -p' x", "", false},
		{"env", "env -C /tmp claude", "", false},
		{"env", "env DYLD_INSERT_LIBRARIES=x claude", "", false},
		{"env", "env A=1", "", false},
		{"env", "env  claude", "", false},
		{"stdbuf", "stdbuf -o0 claude", "", false},
		{"timeout", "nice 300 claude", "", false},
	} {
		tail, ok := wrapperTail(tc.name, tc.cmdline)
		if tail != tc.tail || ok != tc.ok {
			t.Errorf("wrapperTail(%q, %q) = %q, %t; want %q, %t", tc.name, tc.cmdline, tail, ok, tc.tail, tc.ok)
		}
	}
}
