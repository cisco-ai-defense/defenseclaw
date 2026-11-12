// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// Tetragon is a Linux event source, and this test installs /bin/true under
// wrapper names with POSIX modes, symlinks and hard links.

// On a Tetragon source argv[0] is the resolved binary, so the tail of a
// wrapper never equals its child's command line, and neither the process
// name nor argv[0] says which program ran. There the wrapper is matched by
// the image identity of its resolved binary with an installed wrapper, and
// its child by the tail's arguments after the child's own binary. The rules
// are the native ones otherwise: the child must be the verified client with
// exactly that argv.
func TestTetragonWrapperIsMatchedByItsInstalledImage(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	signed, unsigned := hex.EncodeToString(release[:]), hex.EncodeToString(other[:])
	program, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	install := func(dir, name string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, program, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	bin := t.TempDir()
	timeout, nice := install(bin, "timeout", 0o755), install(bin, "nice", 0o755)
	install(bin, "env", 0o755)
	copied := install(t.TempDir(), "timeout", 0o755)
	linked := filepath.Join(t.TempDir(), "timeout")
	if err := os.Symlink(timeout, linked); err != nil {
		t.Fatal(err)
	}
	multi := t.TempDir()
	multiTimeout := install(multi, "timeout", 0o755)
	if err := os.Link(multiTimeout, filepath.Join(multi, "env")); err != nil {
		t.Fatal(err)
	}
	writable := t.TempDir()
	writableTimeout := install(writable, "timeout", 0o775)

	const exe = "/sessions/cwk-v1/.local/share/claude/versions/2.1.317"
	const args = `-p --dangerously-skip-permissions Add a project-scoped MCP server named docs running npx -y @modelcontextprotocol/server-filesystem`
	const typed = "/sessions/cwk-v1/.local/bin/claude " + args
	const client = exe + " " + args
	type exec struct {
		pid, ppid    int
		exe, cmdline string
		digest       string
		source       plane.EventSource
	}
	const agent, wrapper, child = 500, 501, 502
	tg := plane.SourceTetragon
	for _, tc := range []struct {
		name          string
		dirs          []string
		keepClientMCP bool
		execs         []exec
		want          int64
	}{
		{"timeout forks the verified client", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 0},
		{"nice execs the verified client in place", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: nice, cmdline: nice + " -n 10 " + typed, source: tg},
			{pid: wrapper, ppid: agent, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 0},
		{"timeout forks nice, which execs the verified client", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 nice -n 5 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: nice, cmdline: nice + " -n 5 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 0},
		{"a copy of the installed timeout", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: copied, cmdline: copied + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 1},
		{"a link to the installed timeout", []string{bin, filepath.Dir(linked)}, false, []exec{
			{pid: wrapper, ppid: agent, exe: linked, cmdline: linked + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 1},
		{"a multi-call binary installed as two wrappers", []string{multi}, false, []exec{
			{pid: wrapper, ppid: agent, exe: multiTimeout, cmdline: multiTimeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 1},
		{"an installed wrapper others can write", []string{writable}, false, []exec{
			{pid: wrapper, ppid: agent, exe: writableTimeout, cmdline: writableTimeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 1},
		{"command line does not start with the binary", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: "timeout 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 1},
		{"child arguments are not the tail's", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client + " --extra", digest: signed, source: tg},
		}, 1},
		{"child command line does not start with its binary", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: typed, digest: signed, source: tg},
		}, 1},
		{"child from another source", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: plane.SourceCNProc},
		}, 1},
		{"child is another image", []string{bin}, false, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: unsigned, source: tg},
		}, 2},
		{"Secure Client profile", []string{bin}, true, []exec{
			{pid: wrapper, ppid: agent, exe: timeout, cmdline: timeout + " 300 " + typed, source: tg},
			{pid: child, ppid: wrapper, exe: exe, cmdline: client, digest: signed, source: tg},
		}, 2},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.wrapperHold = 30 * time.Millisecond
			host.coldHold = 0
			host.wrapperDirs = tc.dirs
			host.indicators.KeepClientMCP = tc.keepClientMCP
			host.clientChecksums = func(version string) ([][32]byte, bool) {
				return [][32]byte{release}, version == "2.1.317"
			}
			uid := os.Getuid() + 1000
			at := time.Unix(1_760_000_000, 0)
			host.handle(plane.Event{Kind: plane.KindExec, PID: agent, PPID: 1, Name: "claude",
				Cmdline: "claude", UID: &uid, At: at})
			for _, e := range tc.execs {
				version := ""
				if e.digest != "" {
					version = "2.1.317"
				}
				host.handle(plane.Event{
					Kind: plane.KindExec, PID: e.pid, PPID: e.ppid, Name: filepath.Base(e.exe), Exe: e.exe,
					Cmdline: e.cmdline, Source: e.source, UID: &uid, At: at, ImageSHA256: e.digest, ImageVersion: version,
				})
			}
			time.Sleep(4 * host.wrapperHold)
			classified, _, _, _ := host.stats()
			host.mu.Lock()
			held, linked := len(host.wrappers), host.linkedWrappers
			host.mu.Unlock()
			if classified != tc.want || held != 0 || linked != 0 {
				t.Fatalf("classified=%d held=%d linked=%d, want %d and 0, 0", classified, held, linked, tc.want)
			}
		}))
	}
}
