// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tmux holds the agent in one tmux session that outlives every attachment.
type Tmux struct {
	Bin     string
	Socket  string
	Name    string
	Workdir string
	Argv    []string
	Env     []string

	mu        sync.Mutex
	serverPID int
}

func (t *Tmux) cmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, t.Bin, append([]string{"-S", t.Socket}, args...)...)
	c.Env = t.Env
	return c
}

func (t *Tmux) out(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := t.cmd(ctx, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

// Alive reports whether the session exists.
func (t *Tmux) Alive(ctx context.Context) bool {
	_, err := t.out(ctx, "has-session", "-t", t.Name)
	return err == nil
}

// RecoverSocket brings back a tmux server's socket file when it is gone but
// the server still runs: on microVM a restored rootfs loses socket inodes
// (GAP-0001), and tmux recreates its socket on SIGUSR1.
func (t *Tmux) RecoverSocket() bool {
	t.mu.Lock()
	pid := t.serverPID
	t.mu.Unlock()
	if pid <= 0 {
		return false
	}
	if _, err := os.Stat(t.Socket); err == nil {
		return false
	}
	if !processAlive(pid) {
		return false
	}
	signalRecreateSocket(pid)
	// The file comes back before the server listens on it again: wait
	// until a client gets an answer, or an attachment right after a
	// resume finds no server and ends at once.
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(t.Socket); err == nil && t.Alive(context.Background()) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// Ensure starts the agent's session if it is not running and reports
// whether it started one.
func (t *Tmux) Ensure(ctx context.Context, cols, rows uint16) (bool, error) {
	if t.Alive(ctx) {
		return false, nil
	}
	if t.RecoverSocket() && t.Alive(ctx) {
		return false, nil
	}
	if len(t.Argv) == 0 {
		return false, errors.New("relay: no agent command configured")
	}
	args := []string{"-f", "/dev/null", "new-session", "-d", "-s", t.Name,
		"-x", strconv.Itoa(int(cols)), "-y", strconv.Itoa(int(rows))}
	if t.Workdir != "" {
		args = append(args, "-c", t.Workdir)
	}
	args = append(args, t.Argv...)
	// The options make tmux invisible: no status line, no escape delay, the
	// newest client's size, and a dead pane kept so its exit status can be
	// read.
	args = append(args, ";", "set-option", "-g", "status", "off",
		";", "set-option", "-s", "escape-time", "0",
		";", "set-option", "-g", "window-size", "latest",
		";", "set-option", "-g", "remain-on-exit", "on",
		";", "set-option", "-g", "history-limit", "10000")
	if out, err := t.out(ctx, args...); err != nil {
		return false, fmt.Errorf("relay: start tmux session: %v: %s", err, out)
	}
	if pid, err := t.out(ctx, "display-message", "-p", "-t", t.Name, "#{pid}"); err == nil {
		if n, err := strconv.Atoi(pid); err == nil {
			t.mu.Lock()
			t.serverPID = n
			t.mu.Unlock()
		}
	}
	return true, nil
}

// PaneExit reports the agent's exit status once its pane is dead.
func (t *Tmux) PaneExit(ctx context.Context) (int, bool) {
	s, err := t.out(ctx, "display-message", "-p", "-t", t.Name, "#{pane_dead} #{pane_dead_status}")
	if err != nil {
		// No session: the agent is gone without a status.
		return -1, true
	}
	f := strings.Fields(s)
	if len(f) == 0 || f[0] != "1" {
		return 0, false
	}
	code := -1
	if len(f) > 1 {
		if n, err := strconv.Atoi(f[1]); err == nil {
			code = n
		}
	}
	return code, true
}

// Kill ends the session.
func (t *Tmux) Kill(ctx context.Context) { _, _ = t.out(ctx, "kill-session", "-t", t.Name) }

// AttachCmd is a tmux client attached to the session.
func (t *Tmux) AttachCmd() *exec.Cmd {
	c := exec.Command(t.Bin, "-S", t.Socket, "attach-session", "-t", t.Name)
	c.Env = append(append([]string{}, t.Env...), "TERM=xterm-256color")
	return c
}
