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
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// unsyncedStopsName is the file, in the data dir's sandboxes folder, where
// the OpenShell gateway's stop sync (sandbox-daemon sync-sandboxes, the
// ExecStop of a sign-out without linger, say) names each MicroVM it could
// not sync before the gateway's stop ended it. That stop runs when no
// sandbox daemon may be there to tell; the next daemon puts each in its
// feed as stop_unflushed, as its own stops do (GAP-2081).
const unsyncedStopsName = "unsynced-stops.jsonl"

// unsyncedStop is one line of that file.
type unsyncedStop struct {
	Sandbox string    `json:"sandbox"`
	Time    time.Time `json:"time"`
}

// maxUnsyncedStops bounds what one daemon start reads back.
const maxUnsyncedStops = 256

func unsyncedStopsPath(dataDir string) string {
	return filepath.Join(dataDir, "sandboxes", unsyncedStopsName)
}

// RecordUnsyncedStops notes that the gateway's stop ended each named
// sandbox at at with its disk not synced.
func RecordUnsyncedStops(dataDir string, names []string, at time.Time) error {
	path := unsyncedStopsPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, name := range names {
		if !openshell.ValidSandboxName(name) {
			continue
		}
		if err := enc.Encode(unsyncedStop{Sandbox: name, Time: at.UTC()}); err != nil {
			_ = f.Close()
			return err
		}
	}
	return f.Close()
}

// unsyncedStopMessage is the feed line of such a stop.
func unsyncedStopMessage(name string) string {
	return "sandbox " + name + ": its disk could not be synced before the OpenShell gateway stopped (a sign-out or a stop of the gateway service); files written since its last sync may come back empty"
}

// publishUnsyncedStops puts each stop RecordUnsyncedStops noted in the feed
// (stop_unflushed, at the time of the stop) and removes the file.
func (m *Manager) publishUnsyncedStops() {
	path := unsyncedStopsPath(m.opts.DataDir)
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.logf("read the unsynced gateway stops: %v", err)
		}
		return
	}
	var stops []unsyncedStop
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(stops) < maxUnsyncedStops {
		var s unsyncedStop
		if json.Unmarshal(sc.Bytes(), &s) == nil && openshell.ValidSandboxName(s.Sandbox) {
			stops = append(stops, s)
		}
	}
	_ = f.Close()
	if err := os.Remove(path); err != nil {
		m.logf("remove the unsynced gateway stops: %v", err)
		return
	}
	for _, s := range stops {
		msg := unsyncedStopMessage(s.Sandbox)
		m.logf("%s", msg)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: s.Sandbox, Reason: "stop_unflushed", Message: msg, Time: s.Time})
	}
}
