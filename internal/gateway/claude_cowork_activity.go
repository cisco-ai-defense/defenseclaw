// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CoworkActivityFile, in <data_dir>/cowork/ (the folder `defenseclaw setup
// cowork` keeps its plugin state in), is the last Cowork hook call this
// account's gateway took. The health counters are in memory, so without it
// status and doctor read a confirmed Cowork plugin as not protected after
// every gateway restart until the next Cowork event (cowork-1-0-8 GAP-0038).
// cli/defenseclaw/cowork.py reads it.
const CoworkActivityFile = "gateway-activity.json"

// coworkActivityWriteInterval bounds how often a Cowork hook call rewrites
// the file; a SessionStart always does.
const coworkActivityWriteInterval = time.Minute

type coworkActivity struct {
	LastActivityAt     *time.Time `json:"last_activity_at,omitempty"`
	LastSessionStartAt *time.Time `json:"last_session_start_at,omitempty"`
}

var coworkActivityWrites = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// persistCoworkActivity records one Cowork hook call (its native event
// name) at now. It writes only into an existing cowork folder (not a link):
// an account that never ran setup cowork gets no file. Best effort: a write
// that fails leaves the in-memory counters as the only evidence, as before.
func persistCoworkActivity(dataDir, event string, now time.Time) {
	if dataDir == "" {
		return
	}
	dir := filepath.Join(dataDir, "cowork")
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return
	}
	path := filepath.Join(dir, CoworkActivityFile)
	sessionStart := event == "SessionStart"
	coworkActivityWrites.Lock()
	defer coworkActivityWrites.Unlock()
	if last, ok := coworkActivityWrites.at[path]; ok && !sessionStart && now.Sub(last) < coworkActivityWriteInterval {
		return
	}
	var activity coworkActivity
	if data, err := os.ReadFile(path); err == nil && len(data) <= 4096 {
		_ = json.Unmarshal(data, &activity)
	}
	at := now.UTC()
	activity.LastActivityAt = &at
	if sessionStart {
		activity.LastSessionStartAt = &at
	}
	data, err := json.Marshal(activity)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, "."+CoworkActivityFile+".*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	if os.Rename(tmp.Name(), path) == nil {
		coworkActivityWrites.at[path] = now
	}
}
