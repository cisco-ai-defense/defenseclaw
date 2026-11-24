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

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// GAP-0528: run on a full pool printed an error at once and returned;
// connect waits with "The cluster is full. Waiting for room (Ctrl-C to
// stop)...". A run now waits the same way and starts by itself when room
// appears; Ctrl-C stops the wait with the no-worker message and nothing is
// left behind.
func TestGAP0528RunWaitsForRoomLikeConnect(t *testing.T) {
	oldWait, oldPoll := substrateRunWorkerWait, substrateRunWorkerPoll
	t.Cleanup(func() { substrateRunWorkerWait, substrateRunWorkerPoll = oldWait, oldPoll })
	substrateRunWorkerWait, substrateRunWorkerPoll = time.Minute, 10*time.Millisecond

	var creates, fullFor atomic.Int32
	// afterRefusal runs inside the fake's handler, once the n-th refusal is
	// written: the Ctrl-C below is sent from the wait itself, never from a
	// wall-clock timer (rel-1-0-10 GAP-1452: a 50 ms timer fired before the
	// first request on a loaded box and the run saw a cancelled context, not
	// the cluster-full answer it asserts).
	var afterRefusal atomic.Pointer[func(n int32)]
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST actors": func(w http.ResponseWriter, r *http.Request) {
			n := creates.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if n <= fullFor.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"Service Unavailable","reason":"no_free_worker"}`))
				if hook := afterRefusal.Load(); hook != nil {
					(*hook)(n)
				}
				return
			}
			var req api.CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.Actor{Atespace: "eng-web", Name: req.Name, Profile: req.Profile})
		},
		"GET actors": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"actors":[]}`))
		},
	}}
	useFakeAdmin(t, f)
	spec, err := sandboxcli.ResolveHarness("claude")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := substrateOpen(nil, nil)
	target := substrateRunTarget{spec: spec, connName: spec.Name, profile: "eng", template: "claude"}
	try := func(ctx context.Context, cmd *cobra.Command) func() (int, error) {
		return func() (int, error) {
			_, err := substrateCreate(ctx, cmd, s, target, &substrateRunFlags{}, api.CreateRequest{Name: "fix"}, "")
			return 0, err
		}
	}

	// Room appears after two refusals: one wait message, then started.
	fullFor.Store(2)
	var errb strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(new(strings.Builder))
	cmd.SetErr(&errb)
	if _, err := substrateRunWaitingForWorker(t.Context(), cmd, try(t.Context(), cmd)); err != nil {
		t.Fatalf("the run did not start once room appeared: %v", err)
	}
	if creates.Load() != 3 || strings.Count(errb.String(), "The cluster is full. Waiting for room (Ctrl-C to stop)...") != 1 {
		t.Fatalf("creates %d, stderr %q", creates.Load(), errb.String())
	}

	// Ctrl-C during the wait: the no-worker message, no actor made.
	creates.Store(0)
	fullFor.Store(1 << 20)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cancelAfterSecondRefusal := func(n int32) {
		if n == 2 {
			cancel()
		}
	}
	afterRefusal.Store(&cancelAfterSecondRefusal)
	errb.Reset()
	// The wait watches ctx; the requests keep the test context, so the cancel
	// is seen between tries and never as a cancelled request.
	_, err = substrateRunWaitingForWorker(ctx, cmd, try(t.Context(), cmd))
	if err == nil || !strings.Contains(err.Error(), "no free worker") {
		t.Fatalf("Ctrl-C during the wait: %v", err)
	}
	if creates.Load() != 2 {
		t.Fatalf("Ctrl-C after the second refusal: %d creates, want 2 (the wait stopped between tries)", creates.Load())
	}
}

func TestRunRefusesOversizeBeforeCreate(t *testing.T) {
	var creates atomic.Int32
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET launcher": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"workspace_max_bytes":1048576}`))
		},
		"POST actors": func(w http.ResponseWriter, _ *http.Request) {
			creates.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		},
	}})
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	project, err := os.MkdirTemp(home, "dc-upload-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(project)
	dir := filepath.Join(project, "assets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "image"), make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := substrateOpen(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetErr(new(strings.Builder))
	spec, err := sandboxcli.ResolveHarness("claude")
	if err != nil {
		t.Fatal(err)
	}
	target := substrateRunTarget{spec: spec, connName: spec.Name, profile: "eng", template: "claude"}
	_, err = substrateCreate(t.Context(), cmd, s, target, &substrateRunFlags{}, api.CreateRequest{}, project)
	if creates.Load() != 0 || err == nil || !strings.Contains(err.Error(), "assets/") || !strings.Contains(err.Error(), "--exclude") {
		t.Fatalf("creates %d, error %v", creates.Load(), err)
	}
}
