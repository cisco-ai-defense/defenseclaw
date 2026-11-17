// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// RELAY4 acceptance (RKRELAY3 GAP-0369, TestRK3GuardReportsALostWatch): a
// watch that cannot be set (ENOSPC/EMFILE from inotify limits, EACCES, a
// filesystem without inotify) is an error, not a silent fallback to the
// 1 s identity check that misses a swap-and-restore.
func TestGuardFailsClosedWhenAWatchCannotBeSet(t *testing.T) {
	for _, errno := range []error{unix.ENOSPC, unix.EMFILE, unix.EACCES} {
		for _, failOn := range []int{1, 2} { // the parent's watch, the folder's own
			home := t.TempDir()
			gem := filepath.Join(home, ".gemini")
			_ = os.Mkdir(gem, 0o755)
			calls := 0
			inotifyAddWatch = func(fd int, p string, mask uint32) (int, error) {
				if calls++; calls == failOn {
					return -1, errno
				}
				return unix.InotifyAddWatch(fd, p, mask)
			}
			ctx, cancel := context.WithCancel(context.Background())
			err := watchGuarded(ctx, []string{gem}, func(string) {})
			cancel()
			inotifyAddWatch = unix.InotifyAddWatch
			var degraded *guardDegraded
			if !errors.As(err, &degraded) || !errors.Is(err, errno) {
				t.Errorf("%v on watch %d: watchGuarded = %v, want a guardDegraded error", errno, failOn, err)
			}
		}
	}
}

// The RKRELAY3 probe as it ran: a folder the test user cannot read
// (EACCES from inotify_add_watch) must not leave a guard that misses a
// RENAME_EXCHANGE there and back.
func TestGuardFailsClosedOnAnUnreadableFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder: EACCES cannot be provoked")
	}
	home := t.TempDir()
	gem := filepath.Join(home, ".gemini")
	_ = os.Mkdir(gem, 0o755)
	if err := os.Chmod(gem, 0o311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(gem, 0o755) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := watchGuarded(ctx, []string{gem}, func(string) {})
	var degraded *guardDegraded
	if !errors.As(err, &degraded) {
		t.Fatalf("watchGuarded on a folder it cannot watch = %v, want a guardDegraded error", err)
	}
}

// GAP-0369: a reader that ends before the context (a read error) trips the
// guard with a reason that says the watch ended; one that ends because the
// context did is no trip.
func TestGuardTripsWhenItsWatchEnds(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if cancelFirst {
			cancel()
		}
		got := make(chan string, 1)
		done := make(chan struct{})
		go func() {
			readGuardEvents(ctx, r, nil, nil, func(reason string) { got <- reason })
			close(done)
		}()
		w.Close()
		<-done
		r.Close()
		cancel()
		select {
		case reason := <-got:
			if cancelFirst {
				t.Errorf("a reader that ended with its context tripped: %q", reason)
			} else if !strings.HasPrefix(reason, guardWatchEnded) {
				t.Errorf("trip reason %q does not say the watch ended", reason)
			}
		default:
			if !cancelFirst {
				t.Error("a reader that ended before its context did not trip the guard")
			}
		}
	}
}

// The guard's reader goroutine ends when the context does (the inotify
// file is non-blocking, so closing it ends the read), and the trip
// closes it too.
func TestGuardReaderEndsWithItsContext(t *testing.T) {
	gem := filepath.Join(t.TempDir(), ".gemini")
	_ = os.Mkdir(gem, 0o755)
	var tripped atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	if err := watchGuarded(ctx, []string{gem}, func(string) { tripped.Store(true) }); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(300 * time.Millisecond)
	if tripped.Load() {
		t.Fatal("cancelling the guard's context tripped it")
	}
}

// GAP-0369 at the relay: a guard that cannot set its watch refuses the
// agent (403 with the reason, like a missing folder), logs
// relay.guard_degraded and reports it on the tamper route (HIGH audit row).
func TestRelayRefusesTheAgentWhenTheGuardCannotWatch(t *testing.T) {
	inotifyAddWatch = func(int, string, uint32) (int, error) { return -1, unix.ENOSPC }
	t.Cleanup(func() { inotifyAddWatch = unix.InotifyAddWatch })
	s, rec, ec, _, srv := guardServer(t, []string{"sh", "-c", "while read l; do echo got:$l; done"})
	logs := &lockedBuf{}
	s.log = slog.New(slog.NewTextHandler(logs, nil))
	_, resp, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("attach with a guard that cannot watch: %v %v", resp, err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/dcrelay/1/status", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "cannot watch the hook folder") {
		t.Errorf("status with a guard that cannot watch: %d %q", r.StatusCode, body)
	}
	waitRecorded(t, rec, "tamper antigravity: the guard cannot watch the hook folder")
	if !strings.Contains(logs.String(), "relay.guard_degraded") {
		t.Errorf("no relay.guard_degraded log line: %q", logs.String())
	}
	if s.agent.pid() != 0 {
		t.Error("the agent was started")
	}
}

// GAP-0368 behind admission: a mount over the kit's files (for example
// through a symlink in the image that admission cannot see) refuses the
// agent, says why and is reported for the audit log.
func TestRelayRefusesTheAgentUnderAMountOverTheKit(t *testing.T) {
	s, rec, ec, _, srv := guardServer(t, []string{"sh", "-c", "while read l; do echo got:$l; done"})
	s.opts.mountinfo = func() ([]byte, error) {
		return []byte("1 0 0:1 / / rw - overlay overlay rw\n" +
			"40 1 0:40 / " + kit.HookDir + " rw - tmpfs tmpfs rw\n"), nil
	}
	_, resp, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("attach under a mount over the hook folder: %v %v", resp, err)
	}
	waitRecorded(t, rec, "tamper antigravity: a volume is mounted at, above or below "+kit.LibDir)
	if s.agent.pid() != 0 {
		t.Error("the agent was started")
	}
}

// kitMountRefusal reads mountinfo as the kernel writes it: at, above or
// below the kit library or /etc/defenseclaw, at or below a guarded folder.
func TestKitMountRefusal(t *testing.T) {
	line := func(mp string) string { return "36 1 0:36 / " + mp + " rw,relatime - tmpfs tmpfs rw\n" }
	base := "1 0 0:1 / / rw - overlay overlay rw\n" + line("/proc") + line("/dev") + line("/dev/shm") +
		line("/etc/hosts") + line("/etc/resolv.conf") + line("/etc/hostname") + line("/run/ate") + line("/tmp") + line("/work") + line("/work/cache")
	guarded := []string{"/sandbox/.gemini"}
	if got := kitMountRefusal([]byte(base), guarded); got != "" {
		t.Errorf("the ordinary mounts of an actor are refused (%s)", got)
	}
	for mp, want := range map[string]string{
		kit.HookDir:              kit.LibDir,
		kit.KitDir:               kit.LibDir,
		kit.LibDir:               kit.LibDir,
		"/usr/local/lib":         kit.LibDir,
		"/usr":                   kit.LibDir,
		"/etc/defenseclaw":       "/etc/defenseclaw",
		"/etc":                   "/etc/defenseclaw",
		"/etc/defenseclaw/x":     "/etc/defenseclaw",
		"/sandbox/.gemini":       "/sandbox/.gemini",
		"/sandbox/.gemini/hooks": "/sandbox/.gemini",
		`/usr/local/lib/defense\134claw/../defenseclaw/hooks`: kit.LibDir,
	} {
		if got := kitMountRefusal([]byte(base+line(mp)), guarded); got != want {
			t.Errorf("mount at %s: refusal %q, want %q", mp, got, want)
		}
	}
	if got := kitMountRefusal([]byte(base+line(`/work/with\040space`)), guarded); got != "" {
		t.Errorf("an escaped data mount is refused (%s)", got)
	}
}

func waitRecorded(t *testing.T, rec *recorder, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(strings.Join(rec.list(), "\n"), want) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := strings.Join(rec.list(), "\n"); !strings.Contains(got, want) {
		t.Fatalf("not reported for the audit log (%q): %q", want, got)
	}
}

// lockedBuf is a log sink the relay's goroutines may write to.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
