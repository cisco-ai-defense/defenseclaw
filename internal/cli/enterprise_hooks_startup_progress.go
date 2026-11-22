// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// hookGuardianStartupFile is the record, in the data directory, of how far
// the startup reconcile of the long-running standalone Windows guardian has
// come. Setup waits for that first reconcile before it lets the gateway
// start. With many signed-in targets on a busy device it can take longer
// than the usual wait, and Setup rolled a healthy install back (GAP-0401).
// The record lets Setup keep waiting, up to a hard limit, while the guardian
// it started is alive and still moving through its targets, and fail at the
// usual time when it is not.
const hookGuardianStartupFile = "hook_guardian_startup.json"

const (
	hookGuardianStartupReconciling = "reconciling"
	hookGuardianStartupFinished    = "finished"
	// hookGuardianStartupTimeFormat keeps to milliseconds, which Windows
	// PowerShell 5.1 parses.
	hookGuardianStartupTimeFormat = "2006-01-02T15:04:05.000Z07:00"
	// hookGuardianStartupErrorMax bounds last_error before it is encoded.
	hookGuardianStartupErrorMax = 1024
	// hookGuardianStartupRecordMax bounds the encoded record, newline
	// included. Setup ignores a record over 4096 bytes
	// (Get-DefenseClawGuardianStartupProgress), so this keeps a margin.
	hookGuardianStartupRecordMax = 3072
)

// enterpriseHookGuardianStartup is the startup record. TargetsDone counts
// the manifest targets the reconcile has finished. LastError is the error of
// a startup reconcile that failed, on one line: Setup adds it to the error of
// a coverage wait that ends without fresh coverage, which otherwise named only
// the earlier guardian's generation (GAP-1506). It is optional, so the record
// stays version 1 for the Setup of every release.
type enterpriseHookGuardianStartup struct {
	Version      int    `json:"version"`
	PID          int    `json:"pid"`
	State        string `json:"state"`
	StartedAt    string `json:"started_at"`
	UpdatedAt    string `json:"updated_at"`
	TargetsDone  int    `json:"targets_done"`
	TargetsTotal int    `json:"targets_total"`
	LastError    string `json:"last_error,omitempty"`
}

// enterpriseHookStartupProgress writes the startup record for one startup
// reconcile: begin before it, target before each manifest target and end
// after it with its error, also when it failed. Outside begin and end, and where enabled is
// false, it writes nothing, so the one-shot reconcile command and the later
// passes of the guardian are unchanged.
type enterpriseHookStartupProgress struct {
	mu      sync.Mutex
	enabled func() bool
	write   func(path string, data []byte) error
	now     func() time.Time
	active  bool
	path    string
	record  enterpriseHookGuardianStartup
	lastErr string
}

// enterpriseHookStartup is enabled for the standalone Windows guardian only.
var enterpriseHookStartup = &enterpriseHookStartupProgress{
	enabled: func() bool { return false },
	write:   writeEnterpriseHookProtectedFile,
	now:     time.Now,
}

func (p *enterpriseHookStartupProgress) begin(stderr io.Writer, dataDir string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dataDir = strings.TrimSpace(dataDir)
	if !p.enabled() || dataDir == "" {
		return
	}
	now := p.now().UTC().Format(hookGuardianStartupTimeFormat)
	p.active = true
	p.path = filepath.Join(dataDir, hookGuardianStartupFile)
	p.record = enterpriseHookGuardianStartup{
		Version:   1,
		PID:       os.Getpid(),
		State:     hookGuardianStartupReconciling,
		StartedAt: now,
		UpdatedAt: now,
	}
	p.publish(stderr)
}

func (p *enterpriseHookStartupProgress) target(stderr io.Writer, done, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return
	}
	p.record.TargetsDone, p.record.TargetsTotal = done, total
	p.record.UpdatedAt = p.now().UTC().Format(hookGuardianStartupTimeFormat)
	p.publish(stderr)
}

func (p *enterpriseHookStartupProgress) end(stderr io.Writer, reconcileErr error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return
	}
	p.active = false
	p.record.State = hookGuardianStartupFinished
	p.record.UpdatedAt = p.now().UTC().Format(hookGuardianStartupTimeFormat)
	if reconcileErr != nil {
		p.record.LastError = boundedHookGuardianStartupError(reconcileErr.Error())
	}
	p.publish(stderr)
}

// boundedHookGuardianStartupError puts an error on one line of at most
// hookGuardianStartupErrorMax bytes, cut at a rune boundary. Control
// characters become spaces: JSON would write each as a 6-byte \u00XX.
func boundedHookGuardianStartupError(message string) string {
	message = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(message, "?"))
	message = strings.Join(strings.Fields(message), " ")
	if message == "" {
		return "the startup reconcile failed without an error message"
	}
	return cutHookGuardianStartupError(message, hookGuardianStartupErrorMax)
}

// cutHookGuardianStartupError cuts message to at most limit bytes at a rune
// boundary, ending in "...". It returns "" when no room is left for text.
func cutHookGuardianStartupError(message string, limit int) string {
	if len(message) <= limit {
		return message
	}
	cut := limit - len("...")
	if cut <= 0 {
		return ""
	}
	for cut > 0 && !utf8.RuneStart(message[cut]) {
		cut--
	}
	return message[:cut] + "..."
}

// encodeHookGuardianStartup encodes the record on one line, without HTML
// escaping (json.Marshal writes each & < > as a 6-byte \u00XX), and shortens
// last_error until the encoded record fits hookGuardianStartupRecordMax, so
// Setup's 4096-byte reader never drops a finished record and its error
// (GAP-1506). Only quotes and backslashes are still escaped, to 2 bytes, so
// a bounded error fits on the first pass; the loop is the backstop. No byte
// of last_error encodes to more than 6, so each pass cuts at least
// ceil(over/6) bytes and never more than the record needs.
func encodeHookGuardianStartup(record enterpriseHookGuardianStartup) ([]byte, error) {
	for {
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(record); err != nil {
			return nil, err
		}
		over := buf.Len() - hookGuardianStartupRecordMax
		if over <= 0 || record.LastError == "" {
			return buf.Bytes(), nil
		}
		record.LastError = cutHookGuardianStartupError(record.LastError, len(record.LastError)-(over+5)/6)
	}
}

// publish writes the record. A failed write is logged once and changes
// nothing else: without the record Setup waits the usual time.
func (p *enterpriseHookStartupProgress) publish(stderr io.Writer) {
	data, err := encodeHookGuardianStartup(p.record)
	if err == nil {
		err = p.write(p.path, data)
	}
	if err == nil {
		p.lastErr = ""
		return
	}
	if message := err.Error(); message != p.lastErr {
		p.lastErr = message
		fmt.Fprintf(stderr, "[hook-guardian] warn: could not write the startup record %s: %v\n", p.path, err)
	}
}
