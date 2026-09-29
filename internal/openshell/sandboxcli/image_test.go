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

//go:build !windows

package sandboxcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// vmSandbox is a copy sandbox on a MicroVM gateway, booting a run image.
func vmSandbox(name, runImage, runImageID string) sandboxapi.Sandbox {
	sb := copySandbox(name)
	sb.Image, sb.ImageID = "defenseclaw/sandbox:claudecode-x-u1000", "sha256:"+strings.Repeat("a", 64)
	sb.RunImage, sb.RunImageID = runImage, runImageID
	return sb
}

// prepareVMDisk makes the disk the MicroVM driver prepares from imageID in
// the fixture home's image cache.
func prepareVMDisk(t *testing.T, ta *testApp, imageID string) {
	t.Helper()
	dir := filepath.Join(ta.home, ".local", "state", "openshell", "vm-driver", "images",
		"sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-configured-1000-1000-sha256-"+strings.TrimPrefix(imageID, "sha256:"))
	writeFile(t, filepath.Join(dir, "rootfs.ext4"), strings.Repeat("x", 4096))
}

// Prune keeps every image the daemon's sandboxes run, by tag and ID, run
// images included, and takes the MicroVM driver's repositories along; it
// says which were kept for a sandbox and what OpenShell keeps of the run
// images it removed.
func TestImagePruneKeepsTheSandboxesImages(t *testing.T) {
	runID := "sha256:" + strings.Repeat("b", 64)
	ta := newTestApp(t, "", vmSandbox("vm-a", "defenseclaw.invalid/sandbox-run:claudecode-y-u1000", runID), sampleSandbox("dk-b"))
	goneID := "sha256:" + strings.Repeat("c", 64)
	prepareVMDisk(t, ta, goneID)
	ta.images.pruneReport = &image.PruneReport{
		Removed: []string{"defenseclaw.invalid/sandbox-run:claudecode-old-u1000"}, RemovedRunImageIDs: []string{goneID},
		Kept:  []string{"defenseclaw.invalid/sandbox-run:claudecode-y-u1000", "defenseclaw/sandbox:claudecode-x-u1000"},
		InUse: []string{"defenseclaw.invalid/sandbox-run:claudecode-y-u1000"},
	}
	ta.ok(t, ta.ImagePrune(bg, false))
	if len(ta.images.pruned) != 1 {
		t.Fatalf("Prune calls = %d", len(ta.images.pruned))
	}
	opts := ta.images.pruned[0]
	for _, ref := range []string{"defenseclaw/sandbox:claudecode-x-u1000", "sha256:" + strings.Repeat("a", 64),
		"defenseclaw.invalid/sandbox-run:claudecode-y-u1000", runID} {
		if !slices.Contains(opts.Keep, ref) {
			t.Fatalf("keep = %v, missing %s", opts.Keep, ref)
		}
	}
	if opts.AliasRepository != "defenseclaw.invalid/sandbox" || opts.DryRun || slices.Contains(opts.Keep, "") {
		t.Fatalf("prune options = %+v", opts)
	}
	out := ta.output()
	for _, want := range []string{
		"removed defenseclaw.invalid/sandbox-run:claudecode-old-u1000",
		"kept defenseclaw.invalid/sandbox-run:claudecode-y-u1000 (a sandbox runs it)",
		"kept defenseclaw/sandbox:claudecode-x-u1000 (current)",
		"OpenShell keeps the 1 MicroVM disk(s) it prepared from these images",
		"~/.local/state/openshell/vm-driver/images",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
}

// Without the daemon's list the MicroVM run images and aliases are left
// alone, and prune says so.
func TestImagePruneWithoutTheDaemonLeavesRunImagesAlone(t *testing.T) {
	ta := newTestApp(t, "")
	ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
	ta.images.pruneReport = &image.PruneReport{RunImagesLeft: []string{"defenseclaw.invalid/sandbox-run:a", "defenseclaw.invalid/sandbox:b"}}
	ta.ok(t, ta.ImagePrune(bg, true))
	if opts := ta.images.pruned[0]; opts.AliasRepository != "" || len(opts.Keep) != 0 || !opts.DryRun {
		t.Fatalf("prune options without the daemon = %+v", opts)
	}
	if out := ta.output(); !strings.Contains(out, "left 2 MicroVM run image(s) and alias(es) (defenseclaw.invalid/sandbox...) alone") {
		t.Fatalf("output:\n%s", out)
	}
}

// Teardown removes the run images and aliases this data dir recorded, run
// images first, and names the MicroVM disks OpenShell keeps of them.
func TestImageRemoveTakesTheRunImages(t *testing.T) {
	ta := newTestApp(t, "")
	store := image.NewStore(ta.dataDir())
	owner, err := store.Owner()
	if err != nil {
		t.Fatal(err)
	}
	baseID, runID := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	doc := map[string]any{"version": 1, "owner": owner,
		"images": []map[string]any{{"tag": "defenseclaw/sandbox:claudecode-x-u1000", "image_id": baseID, "owner": owner}},
		"run_images": []map[string]any{
			{"tag": "defenseclaw.invalid/sandbox-run:claudecode-y-u1000", "image_id": runID, "owner": owner},
			{"tag": "defenseclaw.invalid/sandbox:claudecode-x-u1000", "image_id": baseID, "alias": true, "owner": owner},
			{"tag": "defenseclaw.invalid/sandbox-run:claudecode-other-u1000", "image_id": runID, "owner": "b0b0b0b0b0b0b0b0"},
		},
	}
	data, _ := json.Marshal(doc)
	writeFile(t, store.Path(), string(data))
	tags, err := (&builderImages{app: ta.App}).Remove(bg, true)
	want := []string{"defenseclaw.invalid/sandbox-run:claudecode-y-u1000", "defenseclaw.invalid/sandbox:claudecode-x-u1000", "defenseclaw/sandbox:claudecode-x-u1000"}
	if err != nil || !slices.Equal(tags, want) {
		t.Fatalf("Remove(dry run) = %v, %v; want %v", tags, err, want)
	}
	if ids := ta.storeImageIDs(); !slices.Equal(ids, []string{baseID, runID}) {
		t.Fatalf("store image IDs = %v", ids)
	}

	prepareVMDisk(t, ta, runID)
	ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-x-u1000"}}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{DryRun: true}))
	if out := ta.output(); !strings.Contains(out, "OpenShell keeps the 1 MicroVM disk(s) it prepared from these images") {
		t.Fatalf("teardown plan:\n%s", out)
	}
	if _, err := os.Stat(store.Path()); err != nil {
		t.Fatal(err)
	}
}

// An image removed from Docker (`docker rmi`) keeps its record, built and
// hook-verified: the list names it apart from the images Docker has, JSON
// marks it missing, and prune says it forgets the record (KR-F8, HERMES-7).
func TestImageListNamesImagesGoneFromDocker(t *testing.T) {
	ta := newTestApp(t, "")
	built := ta.Now()
	ta.images.recs = []image.Record{
		{Tag: "defenseclaw/sandbox:kiro-3f7c-u1000", Connector: "kiro", HarnessVersion: "2.24.1", HookFireVerified: true, UID: 1000, BuiltAt: built},
		{Tag: "defenseclaw/sandbox:claudecode-1a2b-u1000", Connector: "claudecode", HarnessVersion: "2.1.156", HookFireVerified: true, UID: 1000, BuiltAt: built},
	}
	ta.images.gone = map[string]bool{"defenseclaw/sandbox:kiro-3f7c-u1000": true}
	ta.ok(t, ta.ImageList(bg, OutputText))
	out := ta.output()
	table, note, _ := strings.Cut(out, "recorded but no longer in Docker")
	if !strings.Contains(table, "defenseclaw/sandbox:claudecode-1a2b-u1000") || strings.Contains(table, "kiro") ||
		!strings.Contains(note, ": defenseclaw/sandbox:kiro-3f7c-u1000 (kiro 2.24.1); the next run of the harness builds its image again, "+
			"and `defenseclaw sandbox image prune` forgets the record") {
		t.Fatalf("image list:\n%s", out)
	}

	ta.ok(t, ta.fresh().ImageList(bg, OutputJSON))
	var doc struct {
		Images []struct {
			Tag              string `json:"tag"`
			HookFireVerified bool   `json:"hook_fire_verified"`
			Missing          bool   `json:"missing"`
		} `json:"images"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &doc); err != nil || len(doc.Images) != 2 {
		t.Fatalf("image list --json = %s, %v", ta.output(), err)
	}
	for _, img := range doc.Images {
		if img.Missing != strings.Contains(img.Tag, "kiro") || !img.HookFireVerified {
			t.Fatalf("image list --json: %+v", img)
		}
	}

	ta.images.pruneReport = &image.PruneReport{ForgottenStale: []string{"defenseclaw/sandbox:kiro-3f7c-u1000"}}
	ta.ok(t, ta.fresh().ImagePrune(bg, true))
	if out := ta.output(); !strings.Contains(out, "would forget the record of defenseclaw/sandbox:kiro-3f7c-u1000 (no longer in Docker)") ||
		strings.Contains(out, "nothing to prune") {
		t.Fatalf("image prune --dry-run:\n%s", out)
	}
}

// The doctor's image check lists every harness built for this user, not
// only the configured ones, and counts no image Docker no longer has
// (KR-F9, MAC-OSH-OH-6).
func TestDoctorImagesCoverEveryBuiltHarness(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor = hostReport(nil)
	ready := func(connector, version string) image.Record {
		r := readyImages(ta)[0]
		r.Tag, r.Connector, r.HarnessVersion = "defenseclaw/sandbox:"+connector, connector, version
		return r
	}
	ta.images.recs = []image.Record{ready("claudecode", "2.1.156"), ready("codex", "0.146.0"), ready("kiro", "2.24.1"), ready("openhands", "1.16.0")}
	ta.images.gone = map[string]bool{"defenseclaw/sandbox:codex": true, "defenseclaw/sandbox:openhands": true}
	c := ta.runDoctor(bg).Get(CheckIDImages)
	if c == nil || c.Status != "warn" || c.Detail != "not built yet: codex (the first run builds it, which takes a while); hook-verified: claudecode 2.1.156, kiro 2.24.1" {
		t.Fatalf("images check = %+v", c)
	}
	ta.images.gone = nil
	if c := ta.runDoctor(bg).Get(CheckIDImages); c.Status != "pass" || c.Detail != "hook-verified: claudecode 2.1.156, codex 0.146.0, kiro 2.24.1, openhands 1.16.0" {
		t.Fatalf("images check = %+v", c)
	}
}
