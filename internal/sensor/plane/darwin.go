// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

//go:build darwin

package plane

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// esloggerPath is the Endpoint Security client that ships with macOS 13+. It
// is the only ES source that does not need a signed system-extension
// entitlement, which is why this is the one the sensor uses.
const esloggerPath = "/usr/bin/eslogger"

// esloggerEvents are the ES event types subscribed to.
//
// Deliberately narrow. Endpoint Security will happily deliver every open() on
// the system, which on a developer machine is tens of thousands a second and
// would make the sensor the most expensive process on the host. These five
// cover the tactics the classifier can actually act on.
var esloggerEvents = []string{"exec", "exit", "open", "create", "rename"}

// darwinSource is Plane C on macOS.
type darwinSource struct {
	buffer   *Buffer
	cmd      *exec.Cmd
	coverage Coverage
	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup

	// owner names the account of a uid from the process probe's cache,
	// without blocking the event loop (procprobe.CachedOwnerName).
	owner func(uid int) string

	// watched are the path prefixes worth reporting. ES has no path filter, so
	// the filtering happens here, immediately after decode and before the
	// event reaches the buffer.
	watched []string

	// refusal is whatever eslogger said on stderr before giving up. Endpoint
	// Security declines a client that lacks Full Disk Access, and the
	// process exits within milliseconds -- so this is the only place the
	// real reason exists.
	refusalMu sync.Mutex
	refusal   string

	// exited is closed when the eslogger process has been reaped. One
	// goroutine owns cmd.Wait(); everything else waits on this.
	exited chan struct{}
}

// esStartupProbe is how long Start waits to see whether eslogger survives.
//
// Endpoint Security refuses a client and exits immediately, so a process
// still alive after this window has a client and is delivering. Paying it
// once at plane start buys the difference between "running" and "refused",
// which is the difference between a quiet host and a blind one.
const esStartupProbe = 2 * time.Second

// NewSource returns the macOS Plane C source.
func NewSource(homeDirs []string) Source {
	return &darwinSource{buffer: NewBuffer(), watched: watchedPrefixes(homeDirs), owner: procprobe.CachedOwnerName}
}

func watchedPrefixes(homeDirs []string) []string {
	prefixes := make([]string, 0, len(homeDirs)*10+4)
	for _, home := range homeDirs {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		for _, suffix := range []string{
			".aws", ".ssh", ".config/gcloud", ".kube", ".docker",
			".claude", ".codex", ".cursor", ".openclaw",
			"Library/LaunchAgents",
		} {
			prefixes = append(prefixes, filepath.Join(home, suffix))
		}
	}
	return append(prefixes,
		"/Library/LaunchAgents", "/Library/LaunchDaemons", "/etc/sudoers.d", "/etc/master.passwd")
}

func (s *darwinSource) Events() <-chan Event { return s.buffer.Events() }
func (s *darwinSource) Coverage() Coverage   { return s.coverage }

func (s *darwinSource) Start(ctx context.Context) error {
	if _, err := os.Stat(esloggerPath); err != nil {
		return fmt.Errorf(
			"plane: eslogger not found at %s; Endpoint Security needs macOS 13 or later", esloggerPath)
	}
	if os.Geteuid() != 0 {
		// Endpoint Security refuses an unprivileged client outright. Saying so
		// here beats letting the subprocess fail with an error nobody would
		// connect to a checkbox.
		return fmt.Errorf(
			"plane: Endpoint Security needs root; re-run the gateway elevated")
	}

	args := append([]string{}, esloggerEvents...)
	cmd := exec.CommandContext(ctx, esloggerPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("plane: eslogger stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("plane: eslogger stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("plane: eslogger start: %w", err)
	}
	s.cmd = cmd
	s.coverage = Coverage{
		Mechanism: "Endpoint Security (eslogger: " + strings.Join(esloggerEvents, ", ") + ")",
		// Endpoint Security has no account-creation or privilege event of
		// its own, but both tactics are still delivered: they are
		// recognised from the argument vector of the exec that performs
		// them, which is the same path Linux uses when fanotify is absent
		// and which is verified against a live host.
		//
		// So they are covered, not missing. Listing them as MissingKinds
		// marked macOS permanently degraded for a difference in mechanism
		// rather than a difference in what can be seen -- and a permanent
		// degradation is one an operator learns to ignore, which is worse
		// than not reporting it. The fidelity caveat that is real: argv
		// shows the attempt, so a command that failed looks like one that
		// succeeded.
		Kinds: []Kind{
			KindExec, KindExit, KindFileRead, KindFileWrite,
			KindIdentity, KindPrivilege,
		},
	}

	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.readEvents(stdout) }()
	go func() {
		defer s.wg.Done()
		// eslogger writes its Full Disk Access refusal to stderr and exits.
		// Keep the text: it names the exact grant the operator has to make,
		// and discarding it -- which this did -- left the plane reporting
		// itself as running while Endpoint Security had refused it.
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			s.refusalMu.Lock()
			if s.refusal == "" {
				s.refusal = line
			}
			s.refusalMu.Unlock()
		}
	}()

	// A refused client dies at once, so watch for that before claiming the
	// plane is up.
	//
	// This goroutine owns cmd.Wait() for the lifetime of the source. Close
	// kills the process and waits on this instead of calling Wait a second
	// time, which would fail and, worse, race the pipe teardown against the
	// reader.
	exited := make(chan struct{})
	go func() { defer close(exited); _ = cmd.Wait() }()
	s.exited = exited

	select {
	case <-exited:
		s.wg.Wait()
		s.buffer.Close()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		return fmt.Errorf("plane: %s", s.startupRefusal())
	case <-time.After(esStartupProbe):
	case <-ctx.Done():
		return ctx.Err()
	}

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return nil
}

// startupRefusal renders why eslogger gave up.
//
// Endpoint Security's own message names the TCC authorization, which is the
// actionable part, so it is preferred over anything this package could
// invent. The fallback still has to say something an operator can act on:
// an empty reason is the one thing a blinded plane must never report.
func (s *darwinSource) startupRefusal() string {
	s.refusalMu.Lock()
	refusal := s.refusal
	s.refusalMu.Unlock()
	if refusal == "" {
		return "eslogger exited immediately without a reason; Endpoint Security " +
			"needs Full Disk Access -- " + fullDiskAccessHint(currentExecutable())
	}
	if strings.Contains(refusal, "TCC") || strings.Contains(refusal, "NOT_PERMITTED") {
		return refusal + " -- " + fullDiskAccessHint(currentExecutable())
	}
	return refusal
}

// currentExecutable is the running binary, or "" when the OS cannot say.
func currentExecutable() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return executable
}

func (s *darwinSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cmd := s.cmd
	s.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if s.exited != nil {
		<-s.exited
	}
	s.wg.Wait()
	s.buffer.Close()
	return nil
}

func (s *darwinSource) readEvents(stdout interface{ Read([]byte) (int, error) }) {
	scanner := bufio.NewScanner(stdout)
	// ES messages carrying a long argument vector exceed the default 64 KiB.
	scanner.Buffer(make([]byte, 0, 128<<10), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var message esMessage
		if err := json.Unmarshal(line, &message); err != nil {
			// A message this build cannot decode is skipped rather than
			// stopping the stream. One unfamiliar event must not blind the
			// plane for everything after it.
			continue
		}
		if event, ok := s.translate(message); ok {
			s.buffer.Push(event)
		}
	}
}

func (s *darwinSource) translate(message esMessage) (Event, bool) {
	return translateES(message, s.watched, s.owner)
}
