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
	"os"
	"path/filepath"
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
}

// admissionState is the watcher's view of AdmissionStateFile. A nil
// receiver records nothing (watchers built without New, in tests).
type admissionState struct {
	mu     sync.Mutex
	path   string
	assets map[string]admissionStateEntry
}

func newAdmissionState(dataDir string) *admissionState {
	if dataDir == "" {
		return nil
	}
	return &admissionState{path: filepath.Join(dataDir, AdmissionStateFile), assets: map[string]admissionStateEntry{}}
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

// reset forgets every asset and removes the file (the watcher stopped).
func (s *admissionState) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets = map[string]admissionStateEntry{}
	_ = os.Remove(s.path)
}

func (s *admissionState) writeLocked() {
	if len(s.assets) == 0 {
		_ = os.Remove(s.path)
		return
	}
	doc := admissionStateFile{Updated: time.Now().UTC(), Assets: make([]admissionStateEntry, 0, len(s.assets))}
	for _, entry := range s.assets {
		doc.Assets = append(doc.Assets, entry)
	}
	sort.Slice(doc.Assets, func(i, j int) bool { return doc.Assets[i].Path < doc.Assets[j].Path })
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
