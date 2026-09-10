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

// Package procprobe acquires the process table for the runtime planes.
//
// # Why this does not reuse internal/inventory's process snapshot
//
// The inventory detector's processInfo is deliberately data-minimized: it
// never holds a command line, arguments, environment, or full executable path,
// and it matches on executable basenames alone. That is a reviewed privacy
// choice for a continuously-running inventory.
//
// It is also exactly the blind spot the runtime planes exist to close. An
// agent framework running inside a bare `python3` is invisible to a
// basename-only detector, and the sequence a shell-capable agent walks is
// visible only in argv. So this package reads argv, and that is a deliberate
// privacy expansion rather than an oversight:
//
//   - it is gated by configuration, off unless the runtime planes are enabled;
//   - argv never reaches the wire raw. It is classified as content and passes
//     through the same v8 field-class projection as everything else, so each
//     destination's redaction profile governs it;
//   - only the process's own argv is read. No environment values are read at
//     any point, matching the inventory detector's env-var-names-only rule.
package procprobe

import (
	"time"
	"unicode/utf8"
)

// truncateUTF8 cuts a string to at most limit bytes, on a rune boundary.
//
// Slicing at a byte offset can land inside a multi-byte rune and leave
// invalid UTF-8 behind. Cmdline is emitted as a content-class telemetry
// field, and protobuf string fields reject invalid UTF-8, so one truncated
// rune fails the whole OTLP export of that record.
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// Process is one row of the process table, with the fields the runtime planes
// need and nothing more.
type Process struct {
	PID  int
	PPID int
	// Name is the executable basename.
	Name string
	// Cmdline is the full argument vector, space-joined. This is the field the
	// inventory detector deliberately does not collect; see the package doc.
	Cmdline string
	// User is the owning username, when the platform supplies one cheaply.
	User string
	// CPUTime is cumulative CPU consumed by the process. Plane A works on the
	// delta between two polls, not this absolute value: a long-lived process
	// has a large total and may be entirely idle now.
	CPUTime time.Duration
	// RSSBytes is resident set size. Plane A reads it as "large enough to hold
	// model weights", which is a weak signal on its own and weighted as such.
	RSSBytes int64
}

// Snapshot reads the current process table.
//
// A row the caller is not allowed to inspect is omitted rather than returned
// half-filled, because a half-filled row would be scored as though its missing
// fields were zero. The count of omitted rows is returned so an unprivileged
// run can report how much of the table it could not see, rather than reporting
// a quiet host.
func Snapshot() (rows []Process, skipped int, err error) { return snapshot() }
