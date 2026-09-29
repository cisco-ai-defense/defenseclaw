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
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
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
// the fixture home's image cache, and returns its directory.
func prepareVMDisk(t *testing.T, ta *testApp, imageID string) string {
	t.Helper()
	dir := filepath.Join(ta.home, ".local", "state", "openshell", "vm-driver", "images",
		"sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-configured-1000-1000-sha256-"+strings.TrimPrefix(imageID, "sha256:"))
	writeFile(t, filepath.Join(dir, "rootfs.ext4"), strings.Repeat("x", 4096))
	return dir
}

// Prune keeps every image the daemon's sandboxes run, by tag and ID, run
// images included, and takes the MicroVM driver's repositories along; it
// says which were kept for a sandbox, and removes the MicroVM disk of each
// image it removed that Docker no longer has and no sandbox boots.
func TestImagePruneKeepsTheSandboxesImages(t *testing.T) {
	runID := "sha256:" + strings.Repeat("b", 64)
	ta := newTestApp(t, "", vmSandbox("vm-a", "defenseclaw.invalid/sandbox-run:claudecode-y-u1000", runID), sampleSandbox("dk-b"))
	goneID, stillID := "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64)
	gone, still, booted := prepareVMDisk(t, ta, goneID), prepareVMDisk(t, ta, stillID), prepareVMDisk(t, ta, runID)
	// OpenShell's own state in the cache, which prune never touches.
	cache := filepath.Dir(gone)
	own := []string{filepath.Join(cache, "overlay-templates"), filepath.Join(cache, "sandbox-bootstrap-rootfs-ext4-openshell-0.1.1"),
		filepath.Join(cache, filepath.Base(gone)+".staging-1")}
	for _, dir := range own {
		writeFile(t, filepath.Join(dir, "rootfs.ext4"), "x")
	}
	ta.images.presentIDs = map[string]bool{stillID: true}
	ta.images.pruneReport = &image.PruneReport{
		Removed:         []string{"defenseclaw.invalid/sandbox-run:claudecode-old-u1000"},
		RemovedImageIDs: []string{goneID, stillID, runID},
		Kept:            []string{"defenseclaw.invalid/sandbox-run:claudecode-y-u1000", "defenseclaw/sandbox:claudecode-x-u1000"},
		InUse:           []string{"defenseclaw.invalid/sandbox-run:claudecode-y-u1000"},
	}
	ta.ok(t, ta.ImagePrune(bg, true))
	if out := ta.output(); !strings.Contains(out, "would remove the 2 MicroVM disks OpenShell prepared from these images in ~/.local/state/openshell/vm-driver/images (8.0 KiB)") {
		t.Fatalf("dry run:\n%s", out)
	}
	for _, dir := range append([]string{gone, still, booted}, own...) {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("the dry run removed %s", dir)
		}
	}
	ta.images.pruned = nil
	ta.ok(t, ta.fresh().ImagePrune(bg, false))
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
		"removed the 1 MicroVM disk OpenShell prepared from these images in ~/.local/state/openshell/vm-driver/images, freeing 4.0 KiB",
		"kept the 1 MicroVM disk OpenShell prepared from these images in ~/.local/state/openshell/vm-driver/images (4.0 KiB): Docker still has the images they were prepared from",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatalf("the disk of the removed image is still there: %v", err)
	}
	for _, dir := range append([]string{still, booted}, own...) {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("prune removed %s", dir)
		}
	}
}

// `sandbox image build` builds the image the gateway's compute driver
// boots: the MicroVM one (which answers localhost itself) when the
// daemon's gateway runs the vm driver, or, when the daemon does not say,
// when the gateway's configuration selects it; the docker one otherwise.
func TestImageBuildTargetsTheGatewayDriver(t *testing.T) {
	for _, tc := range []struct {
		name       string
		daemon     string
		noGateway  bool
		configured openshell.ComputeDriver
		microVM    bool
	}{
		{name: "docker gateway", daemon: "docker", configured: openshell.DriverVM},
		{name: "vm gateway", daemon: "vm", microVM: true},
		{name: "daemon too old to say", configured: openshell.DriverVM, microVM: true},
		{name: "daemon without a gateway", noGateway: true, configured: openshell.DriverVM, microVM: true},
		{name: "nothing says", noGateway: true},
		{name: "a driver DefenseClaw does not drive", daemon: "podman"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Driver = tc.daemon
			if tc.noGateway {
				ta.daemon.status.Gateway = nil
			}
			ta.gateway.state.ComputeDriver = tc.configured
			ta.ok(t, ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"claude"}}))
			if len(ta.images.recs) != 1 || ta.images.recs[0].MicroVM != tc.microVM {
				t.Fatalf("built %+v, want MicroVM=%t", ta.images.recs, tc.microVM)
			}
		})
	}
}

// AG-MAC-F2: an image whose hooks verify but whose harness cannot start
// with a MicroVM's name resolution is built (docker sandboxes run it), and
// the build says a MicroVM gateway refuses it, with the probe's reason.
// A MicroVM run that settled nothing is said as such: the image is not
// checked for a MicroVM yet, and the next run on the vm driver, or a
// forced build, checks it again. Both warnings name the forced build.
func TestImageBuildSaysWhatCannotStartInAMicroVM(t *testing.T) {
	const why = `Antigravity cannot resolve localhost in an OpenShell MicroVM: it printed "lookup localhost on 127.0.0.53:53: server misbehaving"`
	const unsettled = "the hook-fire probe could not run Codex with an OpenShell MicroVM's name resolution: the run timed out"
	ta := newTestApp(t, "")
	ta.daemon.status.Gateway.Driver = "vm"
	ta.images.microVMProblem = map[string]string{"antigravity": why}
	ta.images.microVMInconclusive = map[string]string{"codex": unsettled}
	ta.ok(t, ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"antigravity", "claude", "codex"}}))
	out := ta.output()
	for _, want := range []string{
		"Antigravity 1.2.12: defenseclaw/sandbox:antigravity, hooks verified",
		"Antigravity cannot start in an OpenShell MicroVM, so a gateway on the vm driver (a Mac's) refuses to run it: " + why +
			"; `defenseclaw sandbox image build antigravity --force` checks it again",
		"Codex's image is not checked for an OpenShell MicroVM yet: " + unsettled +
			"; the next `defenseclaw sandbox run codex` on the vm driver checks it again, as does `defenseclaw sandbox image build codex --force`",
		"Claude Code ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "cannot start in an OpenShell MicroVM") != 1 || strings.Count(out, "not checked for an OpenShell MicroVM") != 1 {
		t.Fatalf("only Antigravity cannot start in a MicroVM, and only Codex is not checked:\n%s", out)
	}
	// A docker gateway's images say nothing about MicroVMs.
	ta = newTestApp(t, "")
	ta.images.microVMProblem = map[string]string{"antigravity": why}
	ta.ok(t, ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"antigravity"}}))
	if strings.Contains(ta.output(), "MicroVM") {
		t.Fatalf("a docker image build mentions MicroVMs:\n%s", ta.output())
	}
}

// FIN-A-1: prune supersedes the docker driver's images only on a gateway
// known to boot MicroVM images, and only with the daemon's list of the
// images sandboxes run: a docker gateway, one DefenseClaw does not drive,
// or a daemon that does not answer prunes as before.
func TestImagePruneTakesTheGatewayDriversTarget(t *testing.T) {
	for _, tc := range []struct {
		name, daemon string
		configured   openshell.ComputeDriver
		noDaemon     bool
		want         bool
	}{
		{name: "vm gateway", daemon: "vm", want: true},
		{name: "docker gateway", daemon: "docker", configured: openshell.DriverVM},
		{name: "daemon too old to say", configured: openshell.DriverVM, want: true},
		{name: "a driver DefenseClaw does not drive", daemon: "podman"},
		{name: "no daemon", noDaemon: true, configured: openshell.DriverVM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Driver = tc.daemon
			ta.gateway.state.ComputeDriver = tc.configured
			if tc.noDaemon {
				ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
			}
			ta.ok(t, ta.ImagePrune(bg, true))
			if opts := ta.images.pruned[0]; opts.MicroVMGateway != tc.want {
				t.Fatalf("prune options = %+v, want MicroVMGateway=%t", opts, tc.want)
			}
		})
	}
}

// Without the daemon's list the MicroVM run images and aliases are left
// alone, and so are the disks of the images removed: which sandboxes boot
// them is not known.
func TestImagePruneWithoutTheDaemonLeavesRunImagesAlone(t *testing.T) {
	ta := newTestApp(t, "")
	ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
	id := "sha256:" + strings.Repeat("c", 64)
	disk := prepareVMDisk(t, ta, id)
	ta.images.pruneReport = &image.PruneReport{RunImagesLeft: []string{"defenseclaw.invalid/sandbox-run:a", "defenseclaw.invalid/sandbox:b"},
		Removed: []string{"defenseclaw/sandbox:claudecode-old-u1000"}, RemovedImageIDs: []string{id}}
	ta.ok(t, ta.ImagePrune(bg, false))
	if opts := ta.images.pruned[0]; opts.AliasRepository != "" || len(opts.Keep) != 0 || opts.DryRun {
		t.Fatalf("prune options without the daemon = %+v", opts)
	}
	out := ta.output()
	if !strings.Contains(out, "left 2 MicroVM run image(s) and alias(es) (defenseclaw.invalid/sandbox...) alone") ||
		!strings.Contains(out, "left the 1 MicroVM disk OpenShell prepared from these images (4.0 KiB in ~/.local/state/openshell/vm-driver/images): "+
			"the DefenseClaw daemon did not answer, so which sandboxes boot them is not known") {
		t.Fatalf("output:\n%s", out)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatalf("prune without the daemon removed a MicroVM disk: %v", err)
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

	disk := prepareVMDisk(t, ta, runID)
	ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-x-u1000"}}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{DryRun: true}))
	if out := ta.output(); !strings.Contains(out, "and the 1 MicroVM disk OpenShell prepared from them (4.0 KiB in ~/.local/state/openshell/vm-driver/images)") {
		t.Fatalf("teardown plan:\n%s", out)
	}
	if _, err := os.Stat(store.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatalf("the dry run removed the MicroVM disk: %v", err)
	}
}

// Teardown removes the MicroVM disks prepared from the images it removes
// once no sandbox is left that boots one; one it could not delete keeps
// them.
func TestTeardownRemovesTheMicroVMDisks(t *testing.T) {
	run := func(t *testing.T, failDelete bool) (*testApp, string) {
		ta := newTestApp(t, "", vmSandbox("vm-a", "defenseclaw.invalid/sandbox-run:claudecode-y-u1000", "sha256:"+strings.Repeat("b", 64)))
		store := image.NewStore(ta.dataDir())
		owner, err := store.Owner()
		if err != nil {
			t.Fatal(err)
		}
		runID := "sha256:" + strings.Repeat("b", 64)
		doc := map[string]any{"version": 1, "owner": owner, "images": []map[string]any{},
			"run_images": []map[string]any{{"tag": "defenseclaw.invalid/sandbox-run:claudecode-y-u1000", "image_id": runID, "owner": owner}}}
		data, _ := json.Marshal(doc)
		writeFile(t, store.Path(), string(data))
		disk := prepareVMDisk(t, ta, runID)
		ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-x-u1000"}}
		if failDelete {
			ta.daemon.errors = map[string]*sandboxapi.Error{
				http.MethodDelete + " " + sandboxapi.PathSandboxes + "/vm-a": {Code: sandboxapi.CodeInternal, Message: "the gateway failed"}}
		}
		err = ta.Teardown(bg, TeardownOptions{Yes: true})
		if failDelete != (err != nil) {
			t.Fatalf("teardown: %v\n%s", err, ta.output())
		}
		return ta, disk
	}
	t.Run("sandboxes gone", func(t *testing.T) {
		ta, disk := run(t, false)
		if _, err := os.Stat(disk); !os.IsNotExist(err) {
			t.Fatalf("the MicroVM disk is still there: %v\n%s", err, ta.output())
		}
		if out := ta.output(); !strings.Contains(out, "removed the 1 MicroVM disk OpenShell prepared from them in ~/.local/state/openshell/vm-driver/images, freeing 4.0 KiB") {
			t.Fatalf("teardown:\n%s", out)
		}
	})
	t.Run("a sandbox left", func(t *testing.T) {
		ta, disk := run(t, true)
		if _, err := os.Stat(disk); err != nil {
			t.Fatalf("the MicroVM disk of a sandbox left was removed: %v", err)
		}
		if out := ta.output(); !strings.Contains(out, "kept the 1 MicroVM disk OpenShell prepared from them (4.0 KiB in ~/.local/state/openshell/vm-driver/images): "+
			"1 sandbox that may boot them could not be deleted") {
			t.Fatalf("teardown:\n%s", out)
		}
	})
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

// FIN-A-3: the list says which compute driver each image is for, and on a
// gateway whose driver is known names the images it does not boot, as the
// doctor does not count them: a MicroVM gateway's docker images (those
// recorded before MicroVM images existed too), which prune removes, or a
// docker gateway's MicroVM ones. A driver not known says nothing of it.
func TestImageListSaysWhichImagesTheGatewayBoots(t *testing.T) {
	for _, tc := range []struct {
		name, daemon, want string
		noGateway          bool
	}{
		{name: "vm gateway", daemon: "vm", want: "this gateway runs sandboxes in MicroVMs (the vm driver) and boots only the MicroVM images: " +
			"it does not use the 2 images for the docker driver, which `defenseclaw sandbox image prune` removes unless a sandbox runs one"},
		{name: "docker gateway", daemon: "docker", want: "this gateway runs sandboxes on the docker driver and boots only the docker images: " +
			"it does not use the 1 image for MicroVMs"},
		{name: "driver not known", noGateway: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Driver = tc.daemon
			if tc.noGateway {
				ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
				ta.gateway.stateErr = errors.New("no gateway configuration")
			}
			built := ta.Now()
			ta.images.recs = []image.Record{
				{Tag: "defenseclaw/sandbox:claudecode-vm-u1000", Connector: "claudecode", HarnessVersion: "2.1.156", HookFireVerified: true, MicroVM: true, UID: 1000, BuiltAt: built},
				{Tag: "defenseclaw/sandbox:claudecode-old-u1000", Connector: "claudecode", HarnessVersion: "2.1.156", HookFireVerified: true, UID: 1000, BuiltAt: built.Add(-1)},
				{Tag: "defenseclaw/sandbox:codex-old-u1000", Connector: "codex", HarnessVersion: "0.146.0", HookFireVerified: true, UID: 1000, BuiltAt: built.Add(-2)},
			}
			ta.ok(t, ta.ImageList(bg, OutputText))
			out := ta.output()
			header, rows, _ := strings.Cut(out, "\n")
			if !strings.Contains(header, "FOR") || !regexp.MustCompile(`claudecode-vm-u1000\s+claudecode\s+2\.1\.156\s+MicroVM\s+yes`).MatchString(rows) ||
				!regexp.MustCompile(`codex-old-u1000\s+codex\s+0\.146\.0\s+docker\s+yes`).MatchString(rows) {
				t.Fatalf("image list:\n%s", out)
			}
			if tc.want == "" {
				if strings.Contains(out, "this gateway") {
					t.Fatalf("a driver not known named the images the gateway boots:\n%s", out)
				}
			} else if !strings.Contains(out, tc.want) {
				t.Fatalf("image list lacks %q:\n%s", tc.want, out)
			}
		})
	}
}

// `image build` on a MicroVM gateway warns when the volume the driver
// prepares disks on is short of room for the new image's first start; on
// docker, or with the room, it says nothing of it (OC-F1).
func TestImageBuildWarnsOfTheMicroVMDisk(t *testing.T) {
	for _, tc := range []struct {
		name   string
		driver string
		free   uint64
		want   string
	}{
		{"full", "vm", 3 << 30, "not enough free disk space for the first start of a sandbox from it: the MicroVM driver prepares a disk of about 6.0 GiB " +
			"from its image in ~/.local/state/openshell/vm-driver/images, where 3.0 GiB is free and at least 7.0 GiB is needed"},
		{"low", "vm", 9 << 30, "only 9.0 GiB is free in ~/.local/state/openshell/vm-driver/images, and the first start of a sandbox from it prepares " +
			"a MicroVM disk of about 6.0 GiB there (14.0 GiB or more is recommended"},
		{"room", "vm", 40 << 30, ""},
		{"docker", "docker", 1 << 30, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Driver = tc.driver
			ta.diskFree, ta.images.sizes = tc.free, map[string]uint64{"": 6 << 30}
			ta.ok(t, ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"codex"}}))
			out := ta.output() + ta.err.String()
			if tc.want == "" && strings.Contains(out, "free") || tc.want != "" && !strings.Contains(out, tc.want) {
				t.Fatalf("image build:\n%s", out)
			}
		})
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

// On a MicroVM gateway the doctor's image check covers every built
// harness too, counting only its images for the MicroVM driver, and names
// one whose MicroVM check settled nothing with the command that checks it
// again.
func TestDoctorImagesCoverEveryMicroVMHarness(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) { r.Driver = openshell.DriverVM })
	built := func(connector, version string, microVM, verified bool) image.Record {
		r := readyImages(ta)[0]
		r.Tag, r.Connector, r.HarnessVersion = "defenseclaw/sandbox:"+connector, connector, version
		r.MicroVM, r.MicroVMVerified = microVM, microVM && verified
		if microVM {
			r.Tag += "-microvm"
		}
		return r
	}
	// Codex has only a docker image; Kiro, not configured, is unchecked.
	ta.images.recs = []image.Record{built("claudecode", "2.1.156", true, true), built("codex", "0.146.0", false, false), built("kiro", "2.24.1", true, false)}
	c := ta.runDoctor(bg).Get(CheckIDImages)
	if c == nil || c.Status != "warn" || c.Fix == nil || c.Fix.Command != CommandName+" image build codex" ||
		c.Detail != "not built yet: codex (the first run builds it, which takes a while); not checked for an OpenShell MicroVM yet: kiro "+
			"(the next run checks it first, which takes a while); hook-verified: claudecode 2.1.156" {
		t.Fatalf("images check = %+v", c)
	}
	ta.images.recs = append(ta.images.recs, built("codex", "0.146.0", true, true))
	c = ta.runDoctor(bg).Get(CheckIDImages)
	if c.Status != "warn" || c.Fix == nil || c.Fix.Command != CommandName+" image build kiro --force" ||
		c.Detail != "not checked for an OpenShell MicroVM yet: kiro (the next run checks it first, which takes a while); hook-verified: claudecode 2.1.156, codex 0.146.0" {
		t.Fatalf("images check = %+v", c)
	}
}

// A failed build shows the last lines docker printed, then names the build
// log on a line of its own; the log keeps all of it. A failure of one line
// keeps the log on that line.
func TestImageBuildFailureShowsDockersLastLines(t *testing.T) {
	ta := newTestApp(t, "")
	ta.images.buildOutput = "#1 [internal] load build definition from Dockerfile\n#9 ERROR: boom\nERROR: failed to build\n"
	ta.images.buildErr = fmt.Errorf("openshell image: docker build defenseclaw/sandbox:claudecode-x-u1000: %w",
		&image.BuildError{Err: &image.CommandError{Args: []string{"build"}, ExitCode: 1}, Output: "#9 ERROR: boom\nERROR: failed to build"})
	logPath := filepath.Join(ta.dataDir(), "logs", "sandbox-image-claudecode.log")
	err := ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"claudecode"}})
	want := "Claude Code image: openshell image: docker build defenseclaw/sandbox:claudecode-x-u1000: docker build exited 1; " +
		"the last lines docker printed:\n    #9 ERROR: boom\n    ERROR: failed to build\n(build log: " + logPath + ")"
	var buildErr *image.BuildError
	if err == nil || err.Error() != want || !errors.As(err, &buildErr) {
		t.Fatalf("ImageBuild error:\n%v\nwant:\n%s", err, want)
	}
	if data, err := os.ReadFile(logPath); err != nil || string(data) != ta.images.buildOutput {
		t.Fatalf("build log = %q, %v", data, err)
	}

	ta.images.buildErr = errors.New("openshell image: inspect defenseclaw/sandbox:claudecode-x-u1000 returned no image")
	err = ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"claudecode"}})
	if want := "Claude Code image: " + ta.images.buildErr.Error() + " (build log: " + logPath + ")"; err == nil || err.Error() != want {
		t.Fatalf("ImageBuild error = %v, want %s", err, want)
	}
}

// A build refused because docker would not use BuildKit never ran docker
// build: its error says why and how to fix it, and names no build log.
func TestImageBuildWithoutBuildKitNamesNoBuildLog(t *testing.T) {
	ta := newTestApp(t, "")
	ta.images.buildErr = fmt.Errorf("openshell image: docker build defenseclaw/sandbox:claudecode-x-u1000: %w; install Docker's buildx plugin",
		image.ErrNoBuildKit)
	err := ta.ImageBuild(bg, ImageBuildOptions{Harnesses: []string{"claudecode"}})
	if want := "Claude Code image: " + ta.images.buildErr.Error(); err == nil || err.Error() != want || !errors.Is(err, image.ErrNoBuildKit) {
		t.Fatalf("ImageBuild error = %v, want %s", err, want)
	}
}
