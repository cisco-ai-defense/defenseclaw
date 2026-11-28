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
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// gap0420Actor is the unattended --task agent the GAP-0420 tests share: one
// name and UID in one atespace, in the given state ("running" before a crash,
// "crashed" after it), so the record path and the UID check see one actor.
func gap0420Actor(state string) api.Actor {
	return api.Actor{Atespace: "eng-web", Name: "fix-tests-1", UID: "uid-1", State: state, Unattended: true}
}

func gap0420Bearer(context.Context) (string, error) { return "test-bearer", nil }

// gap0420Cluster is a TLS admin listener with one crashed --task agent:
// recover brings it back, its relay answers status with tasks (none after
// the crash) and records the task text posted to it.
type gap0420Cluster struct {
	mu     sync.Mutex
	posted []string
	tasks  map[string]any
}

func (c *gap0420Cluster) serve(t *testing.T) {
	const prefix = "/api/v1/substrate/actors/eng-web/fix-tests-1/"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/substrate/actors":
			_ = json.NewEncoder(w).Encode(map[string]any{"actors": []api.Actor{gap0420Actor("crashed")}})
		case r.Method == http.MethodPost && r.URL.Path == prefix+"recover":
			_ = json.NewEncoder(w).Encode(gap0420Actor("running"))
		case r.URL.Path == prefix+"attach/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "dcrelay/1", "tasks": c.tasks})
		case r.Method == http.MethodPost && r.URL.Path == prefix+"attach/task":
			var req relay.TaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			c.mu.Lock()
			c.posted = append(c.posted, req.Prompt)
			c.mu.Unlock()
			w.Header().Set("Content-Type", "application/x-ndjson")
			fmt.Fprintln(w, `{"type":"start","id":"t-2"}`)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			<-r.Context().Done()
		default:
			http.Error(w, `{"error":"Not Found","reason":"not_found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "admin-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	old := substrateOpen
	substrateOpen = func(*cobra.Command, *substrateCommon) (*substrateSession, error) {
		ctx := auth.Context{AdminURL: srv.URL, AdminCAFile: caFile, Profile: "eng"}
		cl, err := api.New(api.Options{Base: srv.URL, HTTP: srv.Client(), Token: gap0420Bearer})
		if err != nil {
			return nil, err
		}
		return &substrateSession{Name: "test", Ctx: ctx, Client: cl, Bearer: gap0420Bearer}, nil
	}
	t.Cleanup(func() { substrateOpen = old })
}

// gap0420WriteRecord writes the record run --task keeps by hand, so the
// test also builds and runs at the parent, where nothing kept one.
func gap0420WriteRecord(t *testing.T) {
	t.Helper()
	rec := filepath.Join(auth.StateDir(), "substrate", "tasks", substrateCopyName(gap0420Actor("crashed"))+".json")
	if err := os.MkdirAll(filepath.Dir(rec), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rec, []byte(`{"version":1,"atespace":"eng-web","name":"fix-tests-1","uid":"uid-1","prompt":"append step 01 to step 30"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0420: undo of a --task agent whose run was lost in a crash brings it
// back and starts the recorded task again (at least once). Before, the run
// never continued: undo refused (no folder record) and logs said "no
// headless task".
func TestGAP0420UndoStartsALostTaskAgain(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	gap0420WriteRecord(t)
	c := &gap0420Cluster{tasks: map[string]any{}}
	c.serve(t)
	out, errOut, err := runSubstrate(t, newSubstrateUndoCmd(), "fix-tests-1", "--yes")
	if err != nil || len(c.posted) != 1 || c.posted[0] != "append step 01 to step 30" || !strings.Contains(out, "Started the task again") {
		t.Fatalf("undo of a crashed --task agent: err %v, posted %q\nout %s\nerr %s", err, c.posted, out, errOut)
	}
}

// GAP-0420: the task is started again only when it was lost: a relay that
// still knows the task (it finished, or it runs) gets no second copy, and a
// computer without the record (another computer) starts nothing.
func TestGAP0420UndoDoesNotStartAKnownOrForeignTaskAgain(t *testing.T) {
	t.Run("relay still has the task", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_HOME", t.TempDir())
		gap0420WriteRecord(t)
		c := &gap0420Cluster{tasks: map[string]any{"t-1": map[string]any{"exit_code": 0}}}
		c.serve(t)
		_, _, _ = runSubstrate(t, newSubstrateUndoCmd(), "fix-tests-1", "--yes")
		if len(c.posted) != 0 {
			t.Fatalf("a task the relay still had was posted again: %q", c.posted)
		}
	})
	t.Run("no record on this computer", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_HOME", t.TempDir())
		c := &gap0420Cluster{tasks: map[string]any{}}
		c.serve(t)
		_, _, _ = runSubstrate(t, newSubstrateUndoCmd(), "fix-tests-1", "--yes")
		if len(c.posted) != 0 {
			t.Fatalf("a computer without the record started a task: %q", c.posted)
		}
	})
}

// GAP-0420: status of a crashed --task agent on the computer that started
// it names undo as the way to start the task again.
func TestGAP0420StatusOfALostTaskNamesUndo(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	gap0420WriteRecord(t)
	(&gap0420Cluster{tasks: map[string]any{}}).serve(t)
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "fix-tests-1")
	if err != nil || !strings.Contains(out, "undo starts it again from the beginning") || !strings.Contains(out, "defenseclaw substrate undo fix-tests-1") {
		t.Fatalf("status of a lost task with its record: err %v\n%s", err, out)
	}
}
