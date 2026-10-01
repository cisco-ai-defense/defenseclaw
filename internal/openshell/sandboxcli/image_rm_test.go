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

const (
	rmBase  = "defenseclaw/sandbox:claudecode-x-u1000"
	rmRun   = "defenseclaw.invalid/sandbox-run:claudecode-y-u1000"
	rmAlias = "defenseclaw.invalid/sandbox:claudecode-x-u1000"
	rmCodex = "defenseclaw/sandbox:codex-z-u1000"
)

var (
	rmBaseID  = "sha256:" + strings.Repeat("a", 64)
	rmRunID   = "sha256:" + strings.Repeat("b", 64)
	rmCodexID = "sha256:" + strings.Repeat("e", 64)
	// rmClaude are the Claude Code images, in the order Remove gives them.
	rmClaude = []string{rmRun, rmAlias, rmBase}
)

// rmFixture is a data dir with the Claude Code overlay image, its MicroVM
// run image and alias, and a Codex overlay image, recorded in the real
// image store and in the fake. With disks it also has the MicroVM disks
// prepared from the Claude Code overlay and run images and from the Codex
// image.
type rmFixture struct {
	*testApp
	claudeDisks []string
	codexDisk   string
}

func newRMFixture(t *testing.T, disks bool, sandboxes ...sandboxapi.Sandbox) *rmFixture {
	t.Helper()
	f := &rmFixture{testApp: newTestApp(t, "", sandboxes...)}
	store := image.NewStore(f.dataDir())
	owner, err := store.Owner()
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"version": 1, "owner": owner,
		"images": []map[string]any{
			{"tag": rmBase, "image_id": rmBaseID, "connector": "claudecode", "owner": owner},
			{"tag": rmCodex, "image_id": rmCodexID, "connector": "codex", "owner": owner},
		},
		"run_images": []map[string]any{
			{"tag": rmRun, "image_id": rmRunID, "connector": "claudecode", "owner": owner},
			{"tag": rmAlias, "image_id": rmBaseID, "alias": true, "connector": "claudecode", "owner": owner},
		},
	}
	data, _ := json.Marshal(doc)
	writeFile(t, store.Path(), string(data))
	f.images.recs = []image.Record{{Tag: rmRun, Connector: "claudecode"}, {Tag: rmAlias, Connector: "claudecode"},
		{Tag: rmBase, Connector: "claudecode"}, {Tag: rmCodex, Connector: "codex"}}
	f.images.presentIDs = map[string]bool{rmCodexID: true}
	if disks {
		f.claudeDisks = []string{prepareVMDisk(t, f.testApp, rmBaseID), prepareVMDisk(t, f.testApp, rmRunID)}
		f.codexDisk = prepareVMDisk(t, f.testApp, rmCodexID)
	}
	return f
}

// codexSandbox is a sandbox of the fixture's Codex image.
func codexSandbox(name string) sandboxapi.Sandbox {
	sb := copySandbox(name)
	sb.Harness, sb.HarnessName, sb.Image, sb.ImageID = "codex", "Codex", rmCodex, rmCodexID
	return sb
}

func exists(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s is gone: %v", p, err)
		}
	}
}

// #960: `image rm <harness>` removes that harness's images (its overlay
// image, and the MicroVM run image and alias made from it) and forgets
// their records, and removes the MicroVM disks prepared from them once
// Docker no longer has their images; another harness's images, disks and
// sandboxes stay, and a dry run removes nothing.
func TestImageRemoveTakesTheHarnessImagesAndTheirMicroVMDisks(t *testing.T) {
	f := newRMFixture(t, true, codexSandbox("cx-a"))
	// The real store's selection: one harness's images and IDs, the
	// alias's among them; none named is every harness's (teardown).
	if tags, err := (&builderImages{app: f.App}).Remove(bg, []string{"claudecode"}, true); err != nil || !slices.Equal(tags, rmClaude) {
		t.Fatalf("Remove(claudecode, dry run) = %v, %v", tags, err)
	}
	if tags, err := (&builderImages{app: f.App}).Remove(bg, nil, true); err != nil || len(tags) != 4 {
		t.Fatalf("Remove(every harness, dry run) = %v, %v", tags, err)
	}
	if ids := f.storeImageIDs("claudecode"); !slices.Equal(ids, []string{rmBaseID, rmRunID}) {
		t.Fatalf("claudecode image IDs = %v", ids)
	}
	if ids := f.storeImageIDs(); !slices.Equal(ids, []string{rmBaseID, rmRunID, rmCodexID}) {
		t.Fatalf("every image ID = %v", ids)
	}

	f.ok(t, f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claude"}, DryRun: true}))
	has(t, f.output(), "Claude Code images", rmRun, rmAlias, rmBase,
		"and the 2 MicroVM disks OpenShell prepared from them (8.0 KiB in ~/.local/state/openshell/vm-driver/images)",
		"dry run: nothing was changed")
	if strings.Contains(f.output(), rmCodex) || len(f.images.removed) != 0 {
		t.Fatalf("dry run removed %v:\n%s", f.images.removed, f.output())
	}
	exists(t, append(f.claudeDisks, f.codexDisk)...)

	f.ok(t, f.fresh().ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claude"}, Yes: true}))
	if !slices.Equal(f.images.removed, rmClaude) || len(f.images.recs) != 1 || f.images.recs[0].Tag != rmCodex {
		t.Fatalf("removed %v, left %v", f.images.removed, f.images.recs)
	}
	has(t, f.output(), "removed image "+rmRun, "removed image "+rmAlias, "removed image "+rmBase,
		"removed the 2 MicroVM disks OpenShell prepared from the Claude Code images in ~/.local/state/openshell/vm-driver/images, freeing 8.0 KiB")
	for _, d := range f.claudeDisks {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("the disk %s is still there: %v", d, err)
		}
	}
	exists(t, f.codexDisk)
}

// #960: a disk of an image Docker still has (another tag holds its ID)
// stays, and says why.
func TestImageRemoveKeepsTheDiskOfAnImageDockerStillHas(t *testing.T) {
	f := newRMFixture(t, true)
	f.images.presentIDs[rmBaseID] = true
	f.ok(t, f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true}))
	has(t, f.output(), "removed the 1 MicroVM disk OpenShell prepared from the Claude Code images",
		"kept the 1 MicroVM disk OpenShell prepared from the Claude Code images in ~/.local/state/openshell/vm-driver/images (4.0 KiB): "+
			"Docker still has the images they were prepared from")
	exists(t, f.claudeDisks[0])
	if _, err := os.Stat(f.claudeDisks[1]); !os.IsNotExist(err) {
		t.Fatalf("the run image's disk is still there: %v", err)
	}
}

// #960: `image rm` refuses, removing nothing, while a sandbox the daemon
// lists or only records uses one of the images, and names it; a deleted
// sandbox kept only for its snapshot uses none.
func TestImageRemoveRefusesWhileASandboxUsesTheImages(t *testing.T) {
	t.Run("the daemon lists it", func(t *testing.T) {
		kept := vmSandbox("kept-a", rmRun, rmRunID)
		kept.Phase = "deleted"
		f := newRMFixture(t, true, vmSandbox("vm-a", rmRun, rmRunID), codexSandbox("cx-a"), kept)
		for _, dry := range []bool{true, false} {
			err := f.fresh().ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true, DryRun: dry})
			wantErr(t, err, "sandbox vm-a uses "+rmBase+": delete it first (`defenseclaw sandbox delete vm-a`); nothing was removed")
			if strings.Contains(err.Error(), "cx-a") || strings.Contains(err.Error(), "kept-a") {
				t.Fatalf("a sandbox that does not use the images was named: %v", err)
			}
		}
		if len(f.images.removed) != 0 {
			t.Fatalf("removed %v", f.images.removed)
		}
		exists(t, append(f.claudeDisks, f.codexDisk)...)
	})
	t.Run("only its record", func(t *testing.T) {
		f := newRMFixture(t, false)
		records := filepath.Join(f.dataDir(), "sandboxes", "manager")
		writeFile(t, filepath.Join(records, "rec-a.json"),
			`{"version":1,"name":"rec-a","harness":"claudecode","image":"`+rmBase+`","image_id":"`+rmBaseID+`"}`)
		writeFile(t, filepath.Join(records, "rec-b.json"),
			`{"version":1,"name":"rec-b","harness":"claudecode","run_image_id":"`+rmRunID+`"}`)
		writeFile(t, filepath.Join(records, "kept-a.json"),
			`{"version":1,"name":"kept-a","harness":"claudecode","image":"`+rmBase+`","retained":true}`)
		err := f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true})
		wantErr(t, err, "sandbox rec-a uses "+rmBase+"; sandbox rec-b uses "+rmRunID+
			": delete them first (`defenseclaw sandbox delete rec-a rec-b`); nothing was removed")
		if strings.Contains(err.Error(), "kept-a") || len(f.images.removed) != 0 {
			t.Fatalf("err = %v, removed %v", err, f.images.removed)
		}
		// Another harness's images do not wait for them.
		f.ok(t, f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"codex"}, Yes: true}))
		if !slices.Equal(f.images.removed, []string{rmCodex}) {
			t.Fatalf("removed %v", f.images.removed)
		}
	})
}

// #960: without the daemon's list the sandboxes that boot the MicroVM
// disks are not known, so `image rm` of images with disks refuses and
// removes nothing; without disks (docker) the records say which sandboxes
// use the images, and it goes ahead.
func TestImageRemoveWithoutTheDaemon(t *testing.T) {
	f := newRMFixture(t, true)
	f.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
	err := f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true})
	wantErr(t, err, "the DefenseClaw daemon did not list its sandboxes, so which of them boot the 2 MicroVM disks OpenShell prepared from these images "+
		"(8.0 KiB in ~/.local/state/openshell/vm-driver/images) is not known, and nothing was removed: the DefenseClaw daemon is not running (start it with `defenseclaw-gateway start`)")
	if len(f.images.removed) != 0 {
		t.Fatalf("removed %v", f.images.removed)
	}
	exists(t, f.claudeDisks...)

	d := newRMFixture(t, false)
	d.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
	d.ok(t, d.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true}))
	if !slices.Equal(d.images.removed, rmClaude) {
		t.Fatalf("removed %v:\n%s", d.images.removed, d.output())
	}
}

// #960: an image Docker no longer has is forgotten, and said so; a harness
// with nothing recorded says it; without a terminal the question needs
// --yes; an unknown harness is refused.
func TestImageRemoveSaysWhatItForgets(t *testing.T) {
	f := newRMFixture(t, false)
	f.images.gone = map[string]bool{rmBase: true}
	f.ok(t, f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode", "opencode"}, DryRun: true}))
	has(t, f.output(), "no OpenCode image is recorded here", rmBase+" (no longer in Docker: its record is forgotten)")

	f.IO.TTY = false
	wantErr(t, f.fresh().ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}}), "pass --yes")
	if len(f.images.removed) != 0 {
		t.Fatalf("removed %v without an answer", f.images.removed)
	}

	f.ok(t, f.fresh().ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true}))
	has(t, f.output(), "removed image "+rmRun, "forgot the record of "+rmBase+" (no longer in Docker)")

	f.ok(t, f.fresh().ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"claudecode"}, Yes: true}))
	has(t, f.output(), "no Claude Code image is recorded here", "nothing to remove")

	wantErr(t, f.ImageRemove(bg, ImageRemoveOptions{Harnesses: []string{"nosuch"}, Yes: true}), "nosuch")
	wantErr(t, f.ImageRemove(bg, ImageRemoveOptions{}), "name the harnesses whose images to remove")
}
