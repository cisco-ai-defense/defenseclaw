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

// Package launcherpresence lets AI discovery label a running Agent Substrate
// launcher (PLAN E26). While `defenseclaw substrate run|connect|logs` is
// attached to an agent, the launcher keeps a small record of itself under
// the person's DefenseClaw data directory; discovery sees a process named
// defenseclaw whose PID and start time match a record and labels it the
// DefenseClaw Agent Substrate launcher, not an unknown AI process. The agent
// itself runs in the cluster, not on the computer.
//
// A record names the process, the coding agent and the cluster context: no
// token, no address, no folder, nothing the cluster or the agent chose
// except the agent's connector name. Process snapshots keep no command
// lines, which is why the launcher says so itself.
package launcherpresence

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// Dir is the record directory below a DefenseClaw data directory.
const Dir = "substrate/launchers"

// MaxRecordBytes bounds one record.
const MaxRecordBytes = 4 << 10

// StartSkew is how far a record's start time may be from the process start
// time a snapshot reports (ps rounds to the second).
const StartSkew = 5 * time.Second

// Record is one running launcher.
type Record struct {
	PID int `json:"pid"`
	// Started is the launcher's own start time.
	Started time.Time `json:"started"`
	// Command is run, connect or logs.
	Command string `json:"command"`
	// Connector is the coding agent (claudecode, codex, ...), "" if not known.
	Connector string `json:"connector,omitempty"`
	// Context is the cluster context name the person signed in to.
	Context string `json:"context,omitempty"`
}

var word = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Valid reports a record a reader may trust the fields of.
func (r Record) Valid() bool {
	if r.PID <= 0 || r.Started.IsZero() {
		return false
	}
	switch r.Command {
	case "run", "connect", "logs":
	default:
		return false
	}
	for _, v := range []string{r.Connector, r.Context} {
		if v != "" && !word.MatchString(v) {
			return false
		}
	}
	return true
}

// Path is the record file of pid below dataDir.
func Path(dataDir string, pid int) string {
	return filepath.Join(dataDir, filepath.FromSlash(Dir), strconv.Itoa(pid)+".json")
}

// Write records the current process below dataDir (mode 0600 in a 0700
// directory) and returns a function that removes the record. A launcher
// that cannot write it runs anyway: the record is a label, not a check.
func Write(dataDir string, r Record) (remove func(), err error) {
	r.PID = os.Getpid()
	if r.Started.IsZero() {
		r.Started = time.Now().UTC()
	}
	if !r.Valid() {
		return func() {}, errors.New("launcherpresence: invalid record")
	}
	dir := filepath.Join(dataDir, filepath.FromSlash(Dir))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return func() {}, err
	}
	b, _ := json.Marshal(r)
	p := Path(dataDir, r.PID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return func() {}, err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return func() {}, err
	}
	return func() { _ = os.Remove(p) }, nil
}

// Parse reads a record file body. ok is false for anything that is not a
// valid record of pid.
func Parse(data []byte, pid int) (Record, bool) {
	if len(data) > MaxRecordBytes {
		return Record{}, false
	}
	var r Record
	if json.Unmarshal(data, &r) != nil || !r.Valid() || r.PID != pid {
		return Record{}, false
	}
	return r, true
}

// Matches reports whether r describes a process that started at started
// (zero: the snapshot does not know; the PID alone then decides).
func (r Record) Matches(started time.Time) bool {
	if started.IsZero() {
		return true
	}
	d := r.Started.Sub(started)
	return d <= StartSkew && d >= -StartSkew
}
