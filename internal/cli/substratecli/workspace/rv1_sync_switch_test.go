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

//go:build unix

package workspace

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// refusingFS answers every upload with the gateway refusal reason.
type refusingFS struct {
	sandboxFS
	reason string
}

func (r refusingFS) Upload(context.Context, string, string, string) error {
	return &HTTPError{Op: "the upload", Status: 403, Reason: r.reason}
}

// RV1 P4-3: sync names the switch that is off: files.push for
// push_disabled, files.sync for sync_disabled.
func TestSyncNamesTheSwitchThatIsOff(t *testing.T) {
	for reason, want := range map[string]string{"push_disabled": "substrate.files.push", "sync_disabled": "substrate.files.sync"} {
		t.Run(reason, func(t *testing.T) {
			o, sb, _ := copyInActor(t)
			ev := make(chan string, 4)
			opts := pushOpts(o, sb)
			opts.Transport = refusingFS{sandboxFS: sb, reason: reason}
			r := startSync(context.Background(), SyncOptions{Push: opts, Events: ev, Label: "agent-1"})
			waitFor(t, "the start", func() bool { return strings.Contains(r.text(), "Saved restore point") })
			write(t, o.project, "notes.md", "n\n", 0o644)
			ev <- filepath.Join(o.project, "notes.md")
			err := <-r.done
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("sync = %v, want it to name %s", err, want)
			}
		})
	}
}
