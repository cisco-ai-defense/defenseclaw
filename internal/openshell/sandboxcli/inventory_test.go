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

package sandboxcli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestProcessTreeNestsChildrenUnderTheirParent(t *testing.T) {
	rows := processTree([]sandboxapi.Process{
		{PID: 43, PPID: 42, Comm: "bash"}, {PID: 1, PPID: 0, Comm: "init"}, {PID: 42, PPID: 1, Comm: "claude"},
		{PID: 9, PPID: 77, Comm: "orphan"}, {PID: 5, PPID: 6, Comm: "a"}, {PID: 6, PPID: 5, Comm: "b"},
	})
	var got []string
	for _, r := range rows {
		got = append(got, strings.Repeat(">", r.depth)+r.p.Comm)
	}
	if want := "init >claude >>bash orphan a >b"; strings.Join(got, " ") != want {
		t.Fatalf("tree = %q, want %q", strings.Join(got, " "), want)
	}
}

// inventoryApp is an App whose daemon answers the processes and discover
// calls with the given values.
func inventoryApp(t *testing.T, list sandboxapi.ProcessList, found sandboxapi.DiscoveryResult) (*App, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/processes"):
			_ = json.NewEncoder(w).Encode(list)
		case strings.HasSuffix(r.URL.Path, "/discover"):
			_ = json.NewEncoder(w).Encode(found)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	out := &bytes.Buffer{}
	return &App{API: sandboxapi.NewClient(srv.URL, testToken), IO: IO{Out: out, Err: out}}, out
}

func TestPsShowsTheTreeOrSaysItIsOff(t *testing.T) {
	app, out := inventoryApp(t, sandboxapi.ProcessList{Name: "box", Enabled: true, IntervalSeconds: 5, Processes: []sandboxapi.Process{
		{PID: 1, Comm: "init"}, {PID: 42, PPID: 1, Comm: "claude", Cmdline: "claude --print"},
	}}, sandboxapi.DiscoveryResult{})
	if err := app.Ps(context.Background(), PsOptions{Name: "box", Tree: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  claude --print") || !strings.Contains(out.String(), "sampled every 5s") {
		t.Fatalf("output:\n%s", out)
	}
	app, out = inventoryApp(t, sandboxapi.ProcessList{Name: "box"}, sandboxapi.DiscoveryResult{})
	if err := app.Ps(context.Background(), PsOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "process tree of sandbox box is off") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestDiscoverListsWhatWasFound(t *testing.T) {
	app, out := inventoryApp(t, sandboxapi.ProcessList{}, sandboxapi.DiscoveryResult{Name: "box", Result: "partial",
		Problems: []string{"sandbox_collect: the collector's answer was cut short"},
		Signals: []sandboxapi.DiscoverySignal{{Category: "mcp_server", Product: "Claude Code", Detector: "mcp",
			Names: []string{"a", "b", "c", "d", "e"}}}})
	if err := app.Discover(context.Background(), DiscoverOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mcp_server", "Claude Code", "a, b, c (+2)", "the scan was partial", "agent usage --sandbox box"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
}
