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

package watcher

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// AdmissionStateFile, in the data folder, lists the skills and plugins the
// install watcher has seen but not decided on yet. skill list and the TUI
// read it to show such an asset as pending or scanning instead of ready
// (GAP-0341); the watcher removes it when it stops.
const AdmissionStateFile = "watcher-admission.json"

// Admission states in AdmissionStateFile.
const (
	AdmissionPending  = "pending"
	AdmissionScanning = "scanning"
)

// Admission problems in AdmissionStateFile (its issues): an asset admission
// blocked but could not finish, which the watcher admits again, and one it
// rejected while enforcement was off. enterprise windows status and verify
// report them; they outlive a watcher restart.
const (
	AdmissionUnscanned      = "unscanned"
	AdmissionNotQuarantined = "not-quarantined"
	AdmissionNotEnforced    = "not-enforced"
)

// Retry delays of an asset whose admission could not finish: it doubles
// from the first to the last.
const (
	admissionRetryFirst = 2 * time.Minute
	admissionRetryLast  = 30 * time.Minute
)

// AdmissionIssue is one problem in AdmissionStateFile.
type AdmissionIssue struct {
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Connector string    `json:"connector,omitempty"`
	Account   string    `json:"account,omitempty"`
	Kind      string    `json:"kind"`
	Detail    string    `json:"detail,omitempty"`
	Since     time.Time `json:"since"`
}

// ReadAdmissionIssues returns the admission problems the watcher of the
// gateway whose data folder is dataDir recorded.
func ReadAdmissionIssues(dataDir string) ([]AdmissionIssue, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, AdmissionStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc admissionStateFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc.Issues, nil
}

// Bounded admission concurrency: a bulk drop of skills is scanned a few at
// a time instead of one after another, and the startup rescan's admissions
// have their own slots, so a new skill never waits behind a full rescan.
const (
	liveAdmissionWorkers    = 3
	startupAdmissionWorkers = 2
)

type admissionStateEntry struct {
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Connector string    `json:"connector,omitempty"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
}

type admissionStateFile struct {
	Updated time.Time             `json:"updated"`
	Assets  []admissionStateEntry `json:"assets"`
	Issues  []AdmissionIssue      `json:"issues,omitempty"`
}

// admissionState is the watcher's view of AdmissionStateFile. A nil
// receiver records nothing (watchers built without New, in tests).
type admissionState struct {
	mu     sync.Mutex
	path   string
	assets map[string]admissionStateEntry
	issues map[string]AdmissionIssue
	// retry is when each unfinished admission runs again, and its delay.
	retry map[string]admissionRetry
}

type admissionRetry struct {
	due   time.Time
	delay time.Duration
}

// newAdmissionState starts from the issues an earlier watcher left; they
// are due at once.
func newAdmissionState(dataDir string) *admissionState {
	if dataDir == "" {
		return nil
	}
	s := &admissionState{
		path: filepath.Join(dataDir, AdmissionStateFile), assets: map[string]admissionStateEntry{},
		issues: map[string]AdmissionIssue{}, retry: map[string]admissionRetry{},
	}
	issues, _ := ReadAdmissionIssues(dataDir)
	for _, issue := range issues {
		if issue.Path != "" {
			s.issues[issue.Path] = issue
			s.retry[issue.Path] = admissionRetry{delay: admissionRetryFirst / 2}
		}
	}
	return s
}

// setIssue records a problem with an asset admission just ran on. One that
// admission retries is due again after a delay that doubles each time.
func (s *admissionState) setIssue(issue AdmissionIssue) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	issue.Since = time.Now().UTC()
	if prev, ok := s.issues[issue.Path]; ok && prev.Kind == issue.Kind {
		issue.Since = prev.Since
	}
	s.issues[issue.Path] = issue
	delay := min(max(s.retry[issue.Path].delay*2, admissionRetryFirst), admissionRetryLast)
	s.retry[issue.Path] = admissionRetry{due: time.Now().Add(delay), delay: delay}
	s.writeLocked()
}

// clearIssue forgets the problem with path: admission finished.
func (s *admissionState) clearIssue(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.issues[path]; !ok {
		return
	}
	delete(s.issues, path)
	delete(s.retry, path)
	s.writeLocked()
}

// dueIssues returns the skills and plugins whose unfinished admission is
// due, and forgets those no longer in their folder. Each waits a full delay
// before it is due again.
func (s *admissionState) dueIssues(now time.Time, kinds ...string) []AdmissionIssue {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var due []AdmissionIssue
	changed := false
	for path, issue := range s.issues {
		retry := s.retry[path]
		if issue.Type == string(InstallMCP) || !slices.Contains(kinds, issue.Kind) || now.Before(retry.due) {
			continue
		}
		if _, err := os.Lstat(addressablePath(path)); err != nil {
			delete(s.issues, path)
			delete(s.retry, path)
			changed = true
			continue
		}
		retry.due = now.Add(max(retry.delay, admissionRetryFirst))
		s.retry[path] = retry
		due = append(due, issue)
	}
	if changed {
		s.writeLocked()
	}
	return due
}

func (s *admissionState) set(evt InstallEvent, state string) {
	if s == nil || evt.Type == InstallMCP {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	since := time.Now().UTC()
	if prev, ok := s.assets[evt.Path]; ok {
		since = prev.Since
	}
	s.assets[evt.Path] = admissionStateEntry{
		Type: string(evt.Type), Name: evt.Name, Path: evt.Path, Connector: evt.Connector, State: state, Since: since,
	}
	s.writeLocked()
}

func (s *admissionState) clear(path string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.assets[path]; !ok {
		return
	}
	delete(s.assets, path)
	s.writeLocked()
}

// reset forgets every asset awaiting admission (the watcher stopped); the
// issues stay for the next watcher.
func (s *admissionState) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets = map[string]admissionStateEntry{}
	s.writeLocked()
}

func (s *admissionState) writeLocked() {
	if len(s.assets) == 0 && len(s.issues) == 0 {
		_ = os.Remove(s.path)
		return
	}
	doc := admissionStateFile{Updated: time.Now().UTC(), Assets: make([]admissionStateEntry, 0, len(s.assets))}
	for _, entry := range s.assets {
		doc.Assets = append(doc.Assets, entry)
	}
	sort.Slice(doc.Assets, func(i, j int) bool { return doc.Assets[i].Path < doc.Assets[j].Path })
	for _, issue := range s.issues {
		doc.Issues = append(doc.Issues, issue)
	}
	sort.Slice(doc.Issues, func(i, j int) bool { return doc.Issues[i].Path < doc.Issues[j].Path })
	raw, err := json.Marshal(doc)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
	}
}
