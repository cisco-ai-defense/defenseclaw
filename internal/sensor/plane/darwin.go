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

	// watched are the path prefixes worth reporting. ES has no path filter, so
	// the filtering happens here, immediately after decode and before the
	// event reaches the buffer.
	watched []string
}

// NewSource returns the macOS Plane C source.
func NewSource(homeDirs []string) Source {
	return &darwinSource{buffer: NewBuffer(), watched: watchedPrefixes(homeDirs)}
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
		Kinds:     []Kind{KindExec, KindExit, KindFileRead, KindFileWrite},
		// ES delivers no account-creation event of its own; identity creation
		// is recognised from the exec argument vector instead, so the kind is
		// not claimed here.
		MissingKinds: []Kind{KindIdentity, KindPrivilege},
		Limitations: []string{
			"account creation and privilege escalation are recognised from exec argument " +
				"vectors rather than from a dedicated Endpoint Security event",
		},
	}

	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.readEvents(stdout) }()
	go func() {
		defer s.wg.Done()
		// eslogger writes its Full Disk Access refusal to stderr and exits.
		// Draining it keeps the pipe from filling and lets the reason surface.
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			_ = scanner.Text()
		}
	}()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return nil
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
		_ = cmd.Wait()
	}
	s.wg.Wait()
	s.buffer.Close()
	return nil
}

// esMessage is the subset of the eslogger JSON envelope this sensor reads.
//
// eslogger emits the full ES message, which is large and version-dependent.
// Decoding only these fields means a macOS release that adds a member cannot
// break the parse.
type esMessage struct {
	EventType int             `json:"event_type"`
	Time      string          `json:"time"`
	Process   esProcess       `json:"process"`
	Event     json.RawMessage `json:"event"`
}

type esProcess struct {
	AuditToken      esAuditToken `json:"audit_token"`
	PPID            int          `json:"ppid"`
	ResponsibleAudi esAuditToken `json:"responsible_audit_token"`
	Executable      esFile       `json:"executable"`
}

type esAuditToken struct {
	PID int `json:"pid"`
	EUI int `json:"euid"`
}

type esFile struct {
	Path string `json:"path"`
}

type esEvent struct {
	Exec   *esExec   `json:"exec"`
	Open   *esOpen   `json:"open"`
	Create *esCreate `json:"create"`
	Rename *esRename `json:"rename"`
}

type esExec struct {
	Target esProcess `json:"target"`
	Args   []string  `json:"args"`
}

type esOpen struct {
	File esFile `json:"file"`
}

type esCreate struct {
	Destination struct {
		ExistingFile esFile `json:"existing_file"`
		NewPath      struct {
			Dir      esFile `json:"dir"`
			Filename string `json:"filename"`
		} `json:"new_path"`
	} `json:"destination"`
}

type esRename struct {
	Source esFile `json:"source"`
}

// Endpoint Security event type numbers used here. The numeric form is what
// eslogger emits; the names are from ESMessage.h.
const (
	esEventTypeNotifyExec   = 9
	esEventTypeNotifyOpen   = 10
	esEventTypeNotifyCreate = 12
	esEventTypeNotifyExit   = 31
	esEventTypeNotifyRename = 25
)

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
	at := parseESTime(message.Time)
	base := Event{
		PID:            message.Process.AuditToken.PID,
		PPID:           message.Process.PPID,
		ResponsiblePID: message.Process.ResponsibleAudi.PID,
		Name:           filepath.Base(message.Process.Executable.Path),
		At:             at,
	}

	var payload esEvent
	if len(message.Event) > 0 {
		_ = json.Unmarshal(message.Event, &payload)
	}

	switch message.EventType {
	case esEventTypeNotifyExec:
		if payload.Exec == nil {
			return Event{}, false
		}
		base.Kind = KindExec
		base.PID = payload.Exec.Target.AuditToken.PID
		base.PPID = message.Process.AuditToken.PID
		base.ResponsiblePID = payload.Exec.Target.ResponsibleAudi.PID
		if base.ResponsiblePID == 0 {
			base.ResponsiblePID = base.PPID
		}
		base.Name = filepath.Base(payload.Exec.Target.Executable.Path)
		base.Cmdline = strings.Join(payload.Exec.Args, " ")
		return base, true

	case esEventTypeNotifyExit:
		base.Kind = KindExit
		return base, true

	case esEventTypeNotifyOpen:
		if payload.Open == nil || !s.interesting(payload.Open.File.Path) {
			return Event{}, false
		}
		base.Kind = KindFileRead
		base.Path = payload.Open.File.Path
		return base, true

	case esEventTypeNotifyCreate:
		path := payload.Create.Destination.ExistingFile.Path
		if path == "" && payload.Create.Destination.NewPath.Filename != "" {
			path = filepath.Join(
				payload.Create.Destination.NewPath.Dir.Path,
				payload.Create.Destination.NewPath.Filename,
			)
		}
		if !s.interesting(path) {
			return Event{}, false
		}
		base.Kind = KindFileWrite
		base.Path = path
		return base, true

	case esEventTypeNotifyRename:
		if payload.Rename == nil || !s.interesting(payload.Rename.Source.Path) {
			return Event{}, false
		}
		base.Kind = KindFileWrite
		base.Path = payload.Rename.Source.Path
		return base, true
	}
	return Event{}, false
}

// interesting filters file events down to the watched prefixes. Endpoint
// Security has no path filter, so without this the buffer would be saturated
// by ordinary build and browser traffic within a second.
func (s *darwinSource) interesting(path string) bool {
	if path == "" {
		return false
	}
	for _, prefix := range s.watched {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func parseESTime(value string) time.Time {
	if value == "" {
		return time.Now()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999 -0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Now()
}
