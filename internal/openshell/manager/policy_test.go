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
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// privatePack is a custom pack whose allow list opens a private address.
const privatePack = `version: 1
name: lanpack
network: {mode: open}
approvals: {mode: triage}
egress:
  allow: [10.0.0.9]
workspace: {mode: mount}
harness: {yolo: true}
mcp: {import: true, host_ports: false}
hooks: {fail_mode: closed}
`

func writePack(t *testing.T, dir, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestPackInsideTheMountIsRefused pins that a live-mounted sandbox never
// reads its policy from inside its own project: the agent writes the
// project as the host user, who owns the pack, and could edit the pack to
// open private networks or lift the feed on the next resolution.
func TestPackInsideTheMountIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	inside := writePack(t, filepath.Join(e.project, ".defenseclaw", "lanpack"), privatePack)
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{
		Name: "selfpack", Harness: "claudecode", Project: e.project, Pack: inside,
	})
	apiErr := wantCode(t, err, sandboxapi.CodePackInvalid)
	if !strings.Contains(apiErr.Message, "inside the project") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	if len(e.ws.planned) != 0 {
		t.Fatalf("the project was planned for a mount: %v", e.ws.planned)
	}

	// A pack directory inside the project is refused as well.
	e.setConfig(func(c *config.Config) { c.OpenShell.PackDir = filepath.Join(e.project, ".defenseclaw") })
	_, err = e.m.Create(context.Background(), sandboxapi.CreateRequest{
		Name: "selfpack", Harness: "claudecode", Project: e.project, Pack: "lanpack",
	})
	wantCode(t, err, sandboxapi.CodePackInvalid)

	// A copy is not shared back while the agent runs, so it may carry its
	// pack.
	sb := e.create(sandboxapi.CreateRequest{Name: "copypack", Pack: inside, Copy: true})
	if sb.WorkdirMode != config.OpenShellWorkdirCopy {
		t.Fatalf("workdir mode = %s", sb.WorkdirMode)
	}
}

// TestMountProtectsPolicySources pins that the mount plan protects every
// file the sandbox policy is read from, so the workspace refuses a share
// that holds one.
func TestMountProtectsPolicySources(t *testing.T) {
	packDir := filepath.Join(t.TempDir(), "packs")
	file := writePack(t, filepath.Join(packDir, "lanpack"), privatePack)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	e.create(sandboxapi.CreateRequest{Name: "mountbox", Pack: "lanpack"})
	protected := e.ws.lastMount.Protected
	for _, want := range []string{packDir, file} {
		if !slices.Contains(protected, want) {
			t.Fatalf("mount protected = %v, want %s in it", protected, want)
		}
	}
	if !slices.Contains(e.ws.lastSnapshot.Protected, file) {
		t.Fatalf("snapshot protected = %v, want %s in it", e.ws.lastSnapshot.Protected, file)
	}
}

// TestPolicyMovedIntoTheMountFailsClosed pins the re-check on every
// resolution: once the configuration reads a running sandbox's pack from
// inside its mounted project, the agent could rewrite it, so the sandbox
// fails closed (no proxy credential, no triage decisions) instead of
// following the pack. A private-address proposal the pack's allow list
// would approve stays pending.
func TestPolicyMovedIntoTheMountFailsClosed(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "packs")
	writePack(t, filepath.Join(outside, "lanpack"), strings.Replace(privatePack, "allow: [10.0.0.9]", "allow: []", 1))
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = outside })
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "movebox", Pack: "lanpack"})
	e.watch.waitStarted(t, sb.Name)
	binding, _ := e.store.Lookup(sb.Name)
	if _, ok := e.m.creds.Lookup(binding.ID); !ok {
		t.Fatal("no proxy credential")
	}

	// The same pack name now resolves inside the project, where the agent
	// has already opened a private address.
	inside := filepath.Join(e.project, ".defenseclaw")
	writePack(t, filepath.Join(inside, "lanpack"), privatePack)
	e.setConfig(func(c *config.Config) { c.OpenShell.PackDir = inside })
	e.m.refreshEgress()
	if _, ok := e.m.creds.Lookup(binding.ID); ok {
		t.Fatal("the proxy credential survived a pack the sandbox can write")
	}
	e.m.mu.Lock()
	b := e.m.boxes[sb.Name]
	e.m.mu.Unlock()
	id := addChunk(e, sb.Name, chunk("allow_10_0_0_9_443", "10.0.0.9", 443))
	e.m.triageSandbox(context.Background(), b)
	if s := chunkStatus(e, sb.Name, id); s != "pending" {
		t.Fatalf("private proposal under a pack the sandbox can write = %s, want pending", s)
	}
	if asks, _ := e.m.Approvals(context.Background(), sb.Name); len(asks) != 0 {
		t.Fatalf("asks = %+v, want none while the policy is refused", asks)
	}

	// Back to the pack outside the project: triage asks about the private
	// address, as the pack there does not open it.
	e.setConfig(func(c *config.Config) { c.OpenShell.PackDir = outside })
	e.m.refreshEgress()
	if _, ok := e.m.creds.Lookup(binding.ID); !ok {
		t.Fatal("the proxy credential was not restored")
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	if asks[0].Host != "10.0.0.9" || !asks[0].Risky || !strings.Contains(asks[0].Reason, "private network") {
		t.Fatalf("ask = %+v", asks[0])
	}
	if s := chunkStatus(e, sb.Name, id); s != "pending" {
		t.Fatalf("private proposal = %s, want an ask", s)
	}
}
