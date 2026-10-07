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
	"context"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// isCollect reports a collector exec.
func isCollect(call openshelltest.ExecCall) bool {
	return len(call.Command) > 12 && call.Command[0] == "/usr/bin/env" && call.Command[9] == "defenseclaw-collect"
}

// collectPairs are a collector exec's KIND VALUE pairs.
func collectPairs(call openshelltest.ExecCall) [][2]string {
	var out [][2]string
	for i := 13; i+1 < len(call.Command); i += 2 {
		out = append(out, [2]string{call.Command[i], call.Command[i+1]})
	}
	return out
}

// discoveringEnv is a running manager with AI discovery on and one ready
// sandbox whose collector answers discoveryAnswer.
func discoveringEnv(t *testing.T, name string, edit func(*config.Config)) *harnessEnv {
	t.Helper()
	e := newEnv(t, func(c *config.Config) {
		c.AIDiscovery.Enabled = true
		c.AIDiscovery.Mode = "enhanced"
		c.AIDiscovery.IncludeEnvVarNames = true
		c.AIDiscovery.ScanIntervalMin = 60
		if edit != nil {
			edit(c)
		}
	})
	e.fake.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		return discoveryAnswer(call)
	})
	e.live(sandboxapi.CreateRequest{Name: name})
	return e
}

// discoveryAnswer answers a collector call with an MCP configuration naming
// dccert-marker, a running claude process and an environment variable name.
func discoveryAnswer(call openshelltest.ExecCall) openshelltest.ExecResponse {
	if !isCollect(call) {
		return openshelltest.ExecResponse{}
	}
	lines := []string{"T 100 1700000000", "P 42 1 1000 100", "Pc 42 claude", "Pa 42 claude", "V ANTHROPIC_API_KEY"}
	for _, kv := range collectPairs(call) {
		if kv[0] == "C" && strings.HasSuffix(kv[1], "/mcp.json") && strings.HasPrefix(kv[1], "/sandbox/") {
			lines = append(lines, "E f 40 1700000100 "+kv[1], "F "+kv[1], b64(`{"mcpServers":{"dccert-marker":{"command":"true"}}}`))
			break
		}
	}
	return openshelltest.ExecResponse{Stdout: answerOf(append(lines, collectEnd)...)}
}

// discoverCalls are the discover-mode collector calls made of a sandbox.
func discoverCalls(e *harnessEnv, name string) []openshelltest.ExecCall {
	var out []openshelltest.ExecCall
	for _, c := range e.fake.ExecCalls() {
		if isCollect(c) && c.Sandbox == name && c.Command[10] == "discover" {
			out = append(out, c)
		}
	}
	return out
}

func TestDiscoverInventoriesTheSandbox(t *testing.T) {
	e := discoveringEnv(t, "discbox", nil)
	res, err := e.m.Discover(context.Background(), "discbox")
	if err != nil {
		t.Fatal(err)
	}
	detectors := map[string]bool{}
	for _, sig := range res.Signals {
		detectors[sig.Detector] = true
		if sig.Detector == "mcp" && !slices.Contains(sig.Names, "dccert-marker") {
			t.Fatalf("mcp signal %+v, want the server named", sig)
		}
	}
	for _, want := range []string{"mcp", "process", "env"} {
		if !detectors[want] {
			t.Fatalf("signals = %+v, want a %s signal", res.Signals, want)
		}
	}
	record, err := inventory.ReadSandboxScanRecord(e.m.scanRecordPath("discbox"))
	if err != nil {
		t.Fatal(err)
	}
	if record.SandboxName != "discbox" || len(record.Report.Signals) != len(res.Signals) {
		t.Fatalf("record = %+v", record)
	}
	for _, sig := range record.Report.Signals {
		if sig.Source != inventory.AISourceSandbox {
			t.Fatalf("signal source %q", sig.Source)
		}
		for _, ev := range sig.Evidence {
			if ev.RawPath != "" {
				t.Fatalf("raw path %q kept without store_raw_local_paths", ev.RawPath)
			}
		}
	}
	// The collector ran in an empty environment, read-only, as asked.
	calls := discoverCalls(e, "discbox")
	if len(calls) == 0 {
		t.Fatal("no collector call")
	}
	for _, kv := range collectPairs(calls[len(calls)-1]) {
		switch kv[0] {
		case "S", "C", "H", "D1", "D2", "D3", "W", "R":
			if !strings.HasPrefix(kv[1], "/sandbox") && !strings.HasPrefix(kv[1], "/work") && !strings.HasPrefix(kv[1], "/opt/defenseclaw-harness") {
				t.Fatalf("the collector was asked for %s %s, outside the sandbox's roots", kv[0], kv[1])
			}
		}
	}

	// A stop keeps what was found, without the processes it ended.
	e.stopBox("discbox")
	record, err = inventory.ReadSandboxScanRecord(e.m.scanRecordPath("discbox"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range record.Report.Signals {
		if sig.Detector == "process" {
			t.Fatalf("the stopped sandbox's record keeps process %+v", sig)
		}
	}
	if len(record.Report.Signals) == 0 {
		t.Fatal("the stop dropped the static inventory")
	}
	if _, err := e.m.Discover(context.Background(), "discbox"); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("discover of a stopped sandbox = %v, want conflict", err)
	}

	// A delete removes the record and its tree.
	e.deleteBox("discbox", sandboxapi.DeleteRequest{})
	if _, err := os.Stat(e.m.discoveryDir("discbox")); !os.IsNotExist(err) {
		t.Fatalf("discovery folder after delete: %v", err)
	}
}

// A discovery that overlaps a delete leaves nothing of the deleted sandbox:
// the delete's release waits for it, and none writes after the release.
func TestDiscoverOverlappingADeleteLeavesNothing(t *testing.T) {
	e := discoveringEnv(t, "racebox", nil)
	var armed atomic.Bool
	deleted := make(chan error, 1)
	e.fake.HandleExec(func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isCollect(call) && armed.CompareAndSwap(true, false) {
			// The delete runs while the sandbox is read: it removes the
			// sandbox from OpenShell and goes on to release it.
			go func() {
				_, err := e.m.Delete(context.Background(), "racebox", sandboxapi.DeleteRequest{})
				deleted <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := e.client.GetSandbox(ctx, "racebox"); openshell.IsNotFound(err) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			time.Sleep(300 * time.Millisecond)
		}
		return discoveryAnswer(call)
	})
	armed.Store(true)
	_, _ = e.m.Discover(context.Background(), "racebox")
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the delete did not end")
	}
	if _, err := os.Stat(e.m.discoveryDir("racebox")); !os.IsNotExist(err) {
		t.Fatalf("the deleted sandbox's discovery folder: %v", err)
	}
}

// With ai_discovery.include_env_var_names off, the collector does not read
// the workload's environment, and names the sandbox sends are dropped.
func TestDiscoverReadsNoEnvironmentNamesUnlessAsked(t *testing.T) {
	e := discoveringEnv(t, "envbox", func(c *config.Config) { c.AIDiscovery.IncludeEnvVarNames = false })
	res, err := e.m.Discover(context.Background(), "envbox")
	if err != nil {
		t.Fatal(err)
	}
	calls := discoverCalls(e, "envbox")
	if len(calls) == 0 || slices.Contains(collectPairs(calls[len(calls)-1]), [2]string{"O", "env"}) {
		t.Fatalf("collector calls = %d, want none asking for environment names", len(calls))
	}
	for _, sig := range res.Signals {
		if sig.Detector == "env" {
			t.Fatalf("signal %+v from environment names that were not asked for", sig)
		}
	}
	// With it on, they are asked for.
	e = discoveringEnv(t, "envbox2", nil)
	if _, err := e.m.Discover(context.Background(), "envbox2"); err != nil {
		t.Fatal(err)
	}
	if calls = discoverCalls(e, "envbox2"); !slices.Contains(collectPairs(calls[len(calls)-1]), [2]string{"O", "env"}) {
		t.Fatal("the collector was not asked for environment names")
	}
}

func TestDiscoverIsOffWithAIDiscoveryOff(t *testing.T) {
	e := discoveringEnv(t, "offbox", func(c *config.Config) { c.AIDiscovery.Enabled = false })
	if _, err := e.m.Discover(context.Background(), "offbox"); !sandboxapi.IsCode(err, sandboxapi.CodeDisabled) {
		t.Fatalf("discover = %v, want disabled", err)
	}
}

// The tree a discovery writes (copies of the sandbox's MCP configurations
// and history) goes once scanned: only the owner-only scan record stays.
func TestDiscoverKeepsOnlyTheScanRecord(t *testing.T) {
	e := discoveringEnv(t, "treebox", nil)
	res, err := e.m.Discover(context.Background(), "treebox")
	if err != nil || !slices.ContainsFunc(res.Signals, func(s sandboxapi.DiscoverySignal) bool { return s.Detector == "mcp" }) {
		t.Fatalf("discover = %+v, %v, want the MCP configuration read from the tree", res, err)
	}
	entries, err := os.ReadDir(e.m.discoveryDir("treebox"))
	if err != nil || len(entries) != 1 || entries[0].Name() != inventory.SandboxScanRecordName {
		t.Fatalf("discovery folder = %v, %v, want only the scan record", entries, err)
	}
	if info, err := os.Lstat(e.m.scanRecordPath("treebox")); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("scan record: %v, %v", info, err)
	}
}
