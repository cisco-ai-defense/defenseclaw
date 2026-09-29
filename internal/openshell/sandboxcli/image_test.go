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

// AG-MAC-F2: an image whose hooks verify but whose harness cannot start
// with a MicroVM's name resolution is built (docker sandboxes run it), and
// the build says a MicroVM gateway refuses it, with the probe's reason.
func TestImageBuildSaysWhatCannotStartInAMicroVM(t *testing.T) {
	const why = `Antigravity cannot resolve localhost in an OpenShell MicroVM: it printed "lookup localhost on 127.0.0.53:53: server misbehaving"`
	ta := newTestApp(t, "")
	ta.images.microVMProblem = map[string]string{"antigravity": why}
	ta.ok(t, ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"antigravity", "claude"}}))
	out := ta.output()
	for _, want := range []string{
		"Antigravity 1.2.12: defenseclaw/sandbox:antigravity, hooks verified",
		"Antigravity cannot start in an OpenShell MicroVM, so a gateway on the vm driver (a Mac's) refuses to run it: " + why,
		"Claude Code ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "cannot start in an OpenShell MicroVM") != 1 {
		t.Fatalf("only Antigravity cannot start in a MicroVM:\n%s", out)
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
