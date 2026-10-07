// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// The sandbox kernel feed (package sandboxfeed) is a root service an
// administrator may install on a Linux host with docker sandboxes (`sudo
// defenseclaw-gateway sandbox kernel-feed install`). It reads the host's
// Tetragon and streams the exec and exit of every process in this user's
// docker sandboxes. The manager holds at most one connection to it, only
// while a ready docker sandbox has its process tree on, and adds what it
// streams to those sandboxes' trees (observeKernelFrame). Nothing here is
// required: without the feed, or with one this gateway cannot read (a
// protocol it does not speak: kernel_feed_version_skew), the tree is the
// sample and OpenShell's records, as before.

// KernelFeedStream is one open stream of the feed (*sandboxfeed.Conn).
type KernelFeedStream interface {
	Header() sandboxfeed.Header
	Next() (sandboxfeed.Frame, error)
	Close() error
}

// KernelFeedDialer opens the feed. Its errors are sandboxfeed's
// (sandboxfeed.ReasonFor names them).
type KernelFeedDialer func(ctx context.Context) (KernelFeedStream, error)

// DefaultKernelFeedDialer opens the feed's fixed socket; nil off Linux,
// where there is no feed.
func DefaultKernelFeedDialer() KernelFeedDialer {
	if runtime.GOOS != "linux" {
		return nil
	}
	return func(ctx context.Context) (KernelFeedStream, error) { return sandboxfeed.Dial(ctx, "") }
}

// Pacing of the feed connection.
const (
	// kernelFeedPoll is how often the manager looks whether a sandbox wants
	// the feed, and kernelFeedIdle how long a connection outlives the last
	// one that did.
	kernelFeedPoll = 5 * time.Second
	kernelFeedIdle = time.Minute
	// kernelFeedRetry paces a feed that is missing or refused us;
	// kernelFeedSkewRetry one that speaks another protocol (only an update
	// changes that).
	kernelFeedRetry     = 30 * time.Second
	kernelFeedSkewRetry = 5 * time.Minute
)

// kernelFeed is the manager's view of the feed.
type kernelFeed struct {
	dial    KernelFeedDialer
	version string
	logf    func(string, ...any)
	// The pacing (kernelFeedPoll and the others); tests shorten it before
	// the manager runs.
	poll, idle, retry, skewRetry time.Duration

	mu     sync.Mutex
	state  sandboxapi.ProcessKernelFeed
	logged map[string]bool
}

func newKernelFeed(dial KernelFeedDialer, version string, logf func(string, ...any)) *kernelFeed {
	return &kernelFeed{dial: dial, version: version, logf: logf, logged: map[string]bool{},
		poll: kernelFeedPoll, idle: kernelFeedIdle, retry: kernelFeedRetry, skewRetry: kernelFeedSkewRetry,
		state: sandboxapi.ProcessKernelFeed{Source: audit.SandboxProcessSourceTetragon, Reason: sandboxfeed.ReasonNotInstalled}}
}

// kernelFeedApplies reports whether a sandbox's tree can take the feed: a
// docker sandbox on Linux (the vm driver's guest kernel is not the host's).
// Callers hold Manager.mu.
func kernelFeedApplies(b *box) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	d, ok := openshell.LookupDriver(b.rec.Driver)
	return ok && d.Name == openshell.DriverDocker
}

// kernelFeedWanted reports whether a ready docker sandbox has its process
// tree on.
func (m *Manager) kernelFeedWanted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.boxes {
		if b.processTreeOn() && b.phase == audit.SandboxPhaseReady && !b.deleted && !b.retained && kernelFeedApplies(b) {
			return true
		}
	}
	return false
}

// boxBySandboxID is the live box OpenShell knows by id.
func (m *Manager) boxBySandboxID(id string) *box {
	if id == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.boxes {
		if b.rec.ID == id && !b.deleted {
			return b
		}
	}
	return nil
}

// run holds the connection while a sandbox wants it, until ctx ends.
func (k *kernelFeed) run(ctx context.Context, m *Manager) {
	if k == nil || k.dial == nil {
		return
	}
	for ctx.Err() == nil {
		if !m.kernelFeedWanted() {
			if !sleepCtx(ctx, k.poll) {
				return
			}
			continue
		}
		stream, err := k.dial(ctx)
		if err != nil {
			wait := k.down(err)
			if !sleepCtx(ctx, wait) {
				return
			}
			continue
		}
		k.up(stream.Header())
		err = k.pump(ctx, m, stream)
		_ = stream.Close()
		if ctx.Err() != nil {
			return
		}
		k.down(err)
		if !sleepCtx(ctx, k.poll) {
			return
		}
	}
}

// pump hands the stream's frames to the trees until it ends, ctx ends, or no
// sandbox has wanted it for kernelFeedIdle.
func (k *kernelFeed) pump(ctx context.Context, m *Manager, stream KernelFeedStream) error {
	done := make(chan struct{})
	defer close(done)
	idle := make(chan struct{})
	go func() {
		ticker := time.NewTicker(k.poll)
		defer ticker.Stop()
		last := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				_ = stream.Close()
				return
			case now := <-ticker.C:
				if m.kernelFeedWanted() {
					last = now
				} else if now.Sub(last) >= k.idle {
					close(idle)
					_ = stream.Close()
					return
				}
			}
		}
	}()
	for {
		frame, err := stream.Next()
		if err != nil {
			select {
			case <-idle:
				return errKernelFeedIdle
			default:
			}
			return err
		}
		switch frame.Kind {
		case sandboxfeed.FrameStatus:
			k.status(frame)
		case sandboxfeed.FrameExec, sandboxfeed.FrameExit, sandboxfeed.FrameSummary:
			if b := m.boxBySandboxID(frame.SandboxID); b != nil {
				m.observeKernelFrame(ctx, b, frame)
			}
		}
	}
}

var errKernelFeedIdle = errors.New("no sandbox has its process tree on")

// up records an open stream.
func (k *kernelFeed) up(header sandboxfeed.Header) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.state.Connected, k.state.Reason, k.state.Build = true, "", header.Build
	k.state.Tetragon, k.state.TetragonReason = header.Tetragon, header.Reason
	k.state.UpdateCommand = ""
	k.logf("sandbox kernel feed connected (%s, protocol %d, Tetragon %s): process trees take every exec and exit",
		firstNonEmpty(header.Build, "unknown build"), header.Protocol, firstNonEmpty(header.Tetragon, "unknown"))
	if sandboxfeed.Older(header.Build, k.version) {
		k.state.UpdateCommand = kernelFeedUpdateCommand()
		k.once("older:"+header.Build, "the sandbox kernel feed (%s) is older than this gateway (%s); update it: %s",
			header.Build, k.version, k.state.UpdateCommand)
	}
}

// down records a stream that could not be opened or ended, and returns how
// long to wait before the next attempt.
func (k *kernelFeed) down(err error) time.Duration {
	reason := sandboxfeed.ReasonFor(err)
	if errors.Is(err, errKernelFeedIdle) {
		reason = ""
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.state.Connected && reason != "" {
		k.logf("sandbox kernel feed: the stream ended (%v); process trees fall back to the %s sample", err, processSampleInterval)
	}
	k.state.Connected, k.state.Reason = false, reason
	switch reason {
	case sandboxfeed.ReasonVersionSkew:
		var skew *sandboxfeed.SkewError
		if errors.As(err, &skew) {
			k.state.Build = skew.Build
		}
		k.state.UpdateCommand = kernelFeedUpdateCommand()
		k.once("skew:"+k.state.Build, "%v; process trees use the %s sample until it is updated: %s", err, processSampleInterval, k.state.UpdateCommand)
		return k.skewRetry
	case sandboxfeed.ReasonNotPermitted:
		k.once("permission", "the sandbox kernel feed is installed, but this account is not in the %s group: process trees use the %s sample", sandboxfeed.DockerGroup, processSampleInterval)
	case sandboxfeed.ReasonUntrusted:
		k.once("untrusted", "the sandbox kernel feed is not used: %v", err)
	}
	return k.retry
}

// status records a status frame: the feed's Tetragon stream, and records it
// lost.
func (k *kernelFeed) status(frame sandboxfeed.Frame) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if frame.Tetragon != "" {
		if frame.Tetragon != k.state.Tetragon {
			k.logf("sandbox kernel feed: Tetragon %s %s", frame.Tetragon, frame.Reason)
		}
		k.state.Tetragon, k.state.TetragonReason = frame.Tetragon, frame.Reason
	}
	k.state.Dropped += max(frame.Dropped, 0)
}

// view is the feed's part of a process list; nil while it is not installed
// (or cannot be on this host).
func (k *kernelFeed) view() *sandboxapi.ProcessKernelFeed {
	if k == nil || k.dial == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.state.Connected:
	case k.state.Reason == "", k.state.Reason == sandboxfeed.ReasonNotInstalled, k.state.Reason == sandboxfeed.ReasonUnsupported:
		return nil
	}
	view := k.state
	return &view
}

// once logs a message once per key for the daemon's life. Callers hold k.mu.
func (k *kernelFeed) once(key, format string, args ...any) {
	if k.logged[key] {
		return
	}
	k.logged[key] = true
	k.logf(format, args...)
}

// kernelFeedUpdateCommand is the command that installs this gateway's feed.
func kernelFeedUpdateCommand() string {
	gateway := "defenseclaw-gateway"
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		gateway = exe
	}
	return "sudo " + gateway + " sandbox kernel-feed install"
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
