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

package statecarry

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The per-user config.yaml before `sandbox setup` (1.0.1 wrote it; the
// rollback copy the upgrade kept).
const configBeforeSetup = `config_version: 9
data_dir: @DATA@
# the operator's note stays
guardrail:
  mode: observe
update:
  check: false
`

// The same config after `sandbox setup` on 1.0.2: what the running sandbox
// needs is all in openshell:.
const openShellAfterSetup = `openshell:
  enabled: true
  harnesses:
    - codex
    - claudecode
  upstream_telemetry: false
  workdir:
    mode: mount
`

type testInstall struct{ data, config string }

func newInstall(t *testing.T, root, name, extra string) testInstall {
	t.Helper()
	data := filepath.Join(root, name)
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(data, "config.yaml")
	raw := strings.ReplaceAll(configBeforeSetup, "@DATA@", data) + extra
	if err := os.WriteFile(cfg, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return testInstall{data, cfg}
}

func write(t *testing.T, path, body string, perm fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), perm); err != nil {
		t.Fatal(err)
	}
}

// plantSandboxState writes what 1.0.2 keeps for one running Docker sandbox:
// the daemon record, the hook binding, the image record, a read-only run
// file the container mounts, an undo point and its project shadow.
func plantSandboxState(t *testing.T, data, name, binding string) {
	t.Helper()
	write(t, filepath.Join(data, "sandboxes", "manager", name+".json"), `{"version":1,"name":"`+name+`","harness":"codex"}`, 0o600)
	write(t, filepath.Join(data, "sandboxes", "bindings.json"), `{"bindings":[{"id":"`+binding+`"}]}`, 0o600)
	write(t, filepath.Join(data, "sandboxes", "images.json"), `{"images":[{"tag":"defenseclaw/sandbox:codex"}]}`, 0o600)
	write(t, filepath.Join(data, "sandboxes", name, "run-config", "hooks.json"), `{"hooks":{}}`, 0o400)
	// A secret mask: an empty read-only folder mounted over a secret one.
	mask := filepath.Join(data, "sandboxes", name, "workspace", "masks", "empty")
	if err := os.MkdirAll(mask, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mask, 0o555); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(data, "snapshots", name, "snapshot.json"), `{"kind":"git"}`, 0o600)
	write(t, filepath.Join(data, "shadows", "p1.git", "HEAD"), "ref: refs/heads/main\n", 0o600)
	if runtime.GOOS != "windows" {
		if err := os.Symlink("../p1.git", filepath.Join(data, "shadows", "current")); err != nil {
			t.Fatal(err)
		}
	}
}

// tree lists every entry under root with its mode and content.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range StateDirs {
		base := filepath.Join(root, dir)
		if _, err := os.Lstat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			entry := info.Mode().String()
			switch {
			case info.Mode()&fs.ModeSymlink != 0:
				link, _ := os.Readlink(path)
				entry += " -> " + link
			case info.Mode().IsRegular():
				raw, _ := os.ReadFile(path)
				entry += " " + string(raw)
			}
			out[filepath.ToSlash(rel)] = entry
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func openShellOf(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	section, _ := doc["openshell"].(map[string]any)
	return section
}

// rel-1-0-2:GAP-0483: a sandbox set up on 1.0.2 kept running through
// `defenseclaw rollback` (to 1.0.1) and `defenseclaw upgrade` (to 1.0.2
// again); both restored data from before the setup, so sandboxes were off,
// `sandbox list` refused and every Codex hook of the sandbox was blocked as
// "gateway unreachable". The rollback now keeps the setup, and the upgrade,
// which starts from the data the rollback left, keeps it too.
func TestRollbackThenUpgradeKeepsTheSandboxSetupOfARunningSandbox(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	// Before the rollback: live is 1.0.2 with the sandbox; previous/ is the
	// copy of the 1.0.1 data the upgrade kept (a stale binding of its own).
	live := newInstall(t, root, "live", "")
	plantSandboxState(t, live.data, "old-run", "b-1.0.1")
	newer := newInstall(t, root, "previous-data", openShellAfterSetup)
	plantSandboxState(t, newer.data, "wv102-b-codex", "b-1.0.2")
	before := tree(t, newer.data)
	beforeConfig, err := os.ReadFile(newer.config)
	if err != nil {
		t.Fatal(err)
	}

	// The rollback swapped the two; previous/ now holds the 1.0.2 data.
	res, err := Carry(context.Background(), Options{
		FromDataDir: newer.data, FromConfig: newer.config, DataDir: live.data, Config: live.config,
	})
	if err != nil {
		t.Fatalf("Carry: %v", err)
	}
	if !res.Carried || !reflect.DeepEqual(res.Sandboxes, []string{"wv102-b-codex"}) {
		t.Fatalf("result = %+v, want the wv102-b-codex setup carried", res)
	}
	if !strings.Contains(res.Summary(), "sandbox wv102-b-codex") {
		t.Fatalf("summary = %q", res.Summary())
	}

	// The restored install has the same sandbox state, with each mode.
	if got := tree(t, live.data); !reflect.DeepEqual(got, before) {
		t.Fatalf("live sandbox state differs from the install left:\n got %v\nwant %v", got, before)
	}
	if _, err := os.Lstat(filepath.Join(live.data, "sandboxes", "manager", "old-run.json")); !os.IsNotExist(err) {
		t.Fatalf("the restored install kept its own stale record: %v", err)
	}
	// The install left is untouched, for a roll forward by an installer
	// that carries nothing (1.0.1's).
	if after := tree(t, newer.data); !reflect.DeepEqual(after, before) {
		t.Fatal("the install left changed")
	}
	if raw, _ := os.ReadFile(newer.config); string(raw) != string(beforeConfig) {
		t.Fatal("the config of the install left changed")
	}
	for _, leftover := range []string{".sandboxes.carry", ".sandboxes.carry-old", ".shadows.carry-old"} {
		if _, err := os.Lstat(filepath.Join(live.data, leftover)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", leftover, err)
		}
	}

	// The restored config keeps the rest of 1.0.1's and gets 1.0.2's
	// openshell: section.
	raw, err := os.ReadFile(live.config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "# the operator's note stays") || !strings.Contains(string(raw), "mode: observe") {
		t.Fatalf("the rest of config.yaml changed:\n%s", raw)
	}
	section := openShellOf(t, live.config)
	if section["enabled"] != true || !reflect.DeepEqual(section["harnesses"], []any{"codex", "claudecode"}) ||
		section["upstream_telemetry"] != false {
		t.Fatalf("openshell = %v", section)
	}

	// The upgrade to 1.0.2 again starts from this data (config_version 9 is
	// current): the gateway's loader turns sandboxes on with the same settings.
	t.Setenv("DEFENSECLAW_HOME", live.data)
	cfg, err := config.LoadFromFile(live.config)
	if err != nil {
		t.Fatalf("1.0.2 cannot load the carried config: %v", err)
	}
	if !cfg.OpenShell.Enabled || !reflect.DeepEqual(cfg.OpenShell.Harnesses, []string{"codex", "claudecode"}) ||
		cfg.OpenShell.UpstreamTelemetry {
		t.Fatalf("1.0.2 reads openshell = %+v", cfg.OpenShell)
	}
}

// An install left with sandboxes off has no setup a running sandbox needs:
// the restored install keeps its own.
func TestCarryLeavesTheLiveInstallAloneWhenTheInstallLeftHasSandboxesOff(t *testing.T) {
	root := t.TempDir()
	live := newInstall(t, root, "live", openShellAfterSetup)
	plantSandboxState(t, live.data, "keep", "b-live")
	before, beforeConfig := tree(t, live.data), openShellOf(t, live.config)
	left := newInstall(t, root, "left", "openshell:\n  enabled: false\n")
	plantSandboxState(t, left.data, "torn-down", "b-left")

	res, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
	if err != nil || res.Carried || res.Skipped == "" {
		t.Fatalf("Carry = %+v, %v; want skipped", res, err)
	}
	if !reflect.DeepEqual(tree(t, live.data), before) || !reflect.DeepEqual(openShellOf(t, live.config), beforeConfig) {
		t.Fatal("the live install changed")
	}
}

// An upgrade after a rollback by an earlier release (which carried nothing)
// brings the setup back only to an install without one of its own.
func TestOnlyIfUnsetBringsTheSetupBackOnlyToAnInstallWithoutOne(t *testing.T) {
	root := t.TempDir()
	rolledBack := newInstall(t, root, "rolled-back", openShellAfterSetup)
	plantSandboxState(t, rolledBack.data, "wv102-b-codex", "b-1.0.2")

	bare := newInstall(t, root, "bare", "")
	res, err := Carry(context.Background(), Options{
		FromDataDir: rolledBack.data, FromConfig: rolledBack.config, DataDir: bare.data, Config: bare.config, OnlyIfUnset: true,
	})
	if err != nil || !res.Carried || !reflect.DeepEqual(res.Sandboxes, []string{"wv102-b-codex"}) {
		t.Fatalf("Carry into an install without a setup = %+v, %v", res, err)
	}
	if got := (Result{Carried: true}).Summary(); got != "Kept the sandbox setup (the openshell settings and the sandbox state)" {
		t.Fatalf("summary without sandbox records = %q", got)
	}
	if openShellOf(t, bare.config)["enabled"] != true {
		t.Fatal("sandboxes stayed off")
	}

	own := newInstall(t, root, "own", "openshell:\n  enabled: true\n  harnesses: [claudecode]\n")
	before := tree(t, own.data)
	res, err = Carry(context.Background(), Options{
		FromDataDir: rolledBack.data, FromConfig: rolledBack.config, DataDir: own.data, Config: own.config, OnlyIfUnset: true,
	})
	if err != nil || res.Carried {
		t.Fatalf("Carry over a setup of its own = %+v, %v; want skipped", res, err)
	}
	if !reflect.DeepEqual(tree(t, own.data), before) || !reflect.DeepEqual(openShellOf(t, own.config)["harnesses"], []any{"claudecode"}) {
		t.Fatal("the live install's own setup changed")
	}

	records := newInstall(t, root, "records", "")
	plantSandboxState(t, records.data, "mine", "b-mine")
	res, err = Carry(context.Background(), Options{
		FromDataDir: rolledBack.data, FromConfig: rolledBack.config, DataDir: records.data, Config: records.config, OnlyIfUnset: true,
	})
	if err != nil || res.Carried {
		t.Fatalf("Carry over sandbox records of its own = %+v, %v; want skipped", res, err)
	}
}

// A config.yaml that cannot take the settings leaves the live install's
// state as it was: nothing half-carried.
func TestCarryPutsTheLiveStateBackWhenTheConfigCannotBeWritten(t *testing.T) {
	root := t.TempDir()
	live := newInstall(t, root, "live", "")
	plantSandboxState(t, live.data, "old-run", "b-1.0.1")
	if err := os.WriteFile(live.config, []byte("config_version: 9\nguardrail: [not, a, mapping\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := tree(t, live.data)
	left := newInstall(t, root, "left", openShellAfterSetup)
	plantSandboxState(t, left.data, "wv102-b-codex", "b-1.0.2")

	if _, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config}); err == nil {
		t.Fatal("Carry into an unreadable config.yaml succeeded")
	}
	if got := tree(t, live.data); !reflect.DeepEqual(got, before) {
		t.Fatalf("the live state changed:\n got %v\nwant %v", keys(got), keys(before))
	}
	entries, _ := os.ReadDir(live.data)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".carry") {
			t.Fatalf("%s left behind", e.Name())
		}
	}
}

// A carry stopped between its renames left the live install's own state
// beside an empty place; the next run of the installer puts it back, also
// when that run carries nothing.
func TestCarryRecoversAnInterruptedRename(t *testing.T) {
	root := t.TempDir()
	live := newInstall(t, root, "live", "")
	plantSandboxState(t, live.data, "old-run", "b-1.0.1")
	if err := os.Rename(filepath.Join(live.data, "sandboxes"), oldPath(live.data, "sandboxes")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stagedPath(live.data, "snapshots"), 0o700); err != nil {
		t.Fatal(err)
	}
	left := newInstall(t, root, "left", "openshell:\n  enabled: false\n")

	res, err := Carry(context.Background(), Options{FromDataDir: left.data, FromConfig: left.config, DataDir: live.data, Config: live.config})
	if err != nil || res.Carried {
		t.Fatalf("Carry = %+v, %v; want skipped", res, err)
	}
	if _, err := os.Stat(filepath.Join(live.data, "sandboxes", "manager", "old-run.json")); err != nil {
		t.Fatalf("the live install's own state was not put back: %v", err)
	}
	for _, leftover := range []string{oldPath(live.data, "sandboxes"), stagedPath(live.data, "snapshots")} {
		if _, err := os.Lstat(leftover); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", leftover, err)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The installer line for kept sandboxes names the stop and start a retained
// guest on an older supervisor needs after a roll forward (GAP-1161), as the
// upgrade guide does; with no sandbox kept there is nothing to start.
func TestTheKeptSandboxLineNamesTheStopAndStartAfterARollForward(t *testing.T) {
	for _, r := range []Result{{Carried: true, Sandboxes: []string{"a-1"}}, {Carried: true, Sandboxes: []string{"a-1", "b-2"}}} {
		got := r.Summary()
		for _, want := range []string{"legacy sandbox running", "`defenseclaw sandbox stop NAME`", "`defenseclaw sandbox start NAME`", "hooks work again once the gateway is up"} {
			if !strings.Contains(got, want) {
				t.Fatalf("Summary() = %q, missing %q", got, want)
			}
		}
	}
	if got := (Result{Carried: true}).Summary(); strings.Contains(got, "sandbox stop") {
		t.Fatalf("no kept sandbox: %q", got)
	}
}
