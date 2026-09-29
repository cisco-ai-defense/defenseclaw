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

package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// testAliasRepo is the image repository of the test driver's references.
const testAliasRepo = "defenseclaw.invalid/sandbox"

// layerDaemon is a Docker daemon that knows images by ID with their
// layers and labels: enough to tag, inspect, build a run image FROM a
// local image (one layer per RUN and COPY), list by label and remove.
type layerDaemon struct {
	t      *testing.T
	mu     sync.Mutex
	images map[string]fakeImage // image ID -> image
	tags   map[string]string    // tag -> image ID
	calls  [][]string
	// dockerfiles are the Dockerfiles docker build received.
	dockerfiles []string
	// contexts are the build contexts' files by name, per build.
	contexts []map[string]*tar.Header
	// extraLayers adds layers to what a build makes (a builder that does
	// not build what it was given).
	extraLayers int
}

type fakeImage struct {
	layers []string
	labels map[string]string
}

func newLayerDaemon(t *testing.T) *layerDaemon {
	return &layerDaemon{t: t, images: map[string]fakeImage{}, tags: map[string]string{}}
}

// addBase makes rec's overlay image, tagged, with c's labels.
func (d *layerDaemon) addBase(rec Record, labels map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.images[rec.ImageID] = fakeImage{layers: []string{"sha256:l1", "sha256:l2", "sha256:l3"}, labels: maps.Clone(labels)}
	d.tags[rec.Tag] = rec.ImageID
}

func (d *layerDaemon) count(verb ...string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, call := range d.calls {
		if len(call) >= len(verb) && slices.Equal(call[:len(verb)], verb) {
			n++
		}
	}
	return n
}

// resolve finds an image by tag or ID.
func (d *layerDaemon) resolve(ref string) (string, bool) {
	if id, ok := d.tags[ref]; ok {
		return id, true
	}
	_, ok := d.images[ref]
	return ref, ok
}

func (d *layerDaemon) Run(_ context.Context, stdin io.Reader, stdout, _ io.Writer, args ...string) error {
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, append([]string(nil), args...))
	fail := func() error { return &CommandError{Args: args, ExitCode: 1} }
	switch {
	case args[0] == "tag":
		id, ok := d.resolve(args[1])
		if !ok {
			return fail()
		}
		d.tags[args[2]] = id
		return nil
	case args[0] == "image" && args[1] == "inspect":
		id, ok := d.resolve(args[len(args)-1])
		if !ok {
			return fail()
		}
		img := d.images[id]
		doc := map[string]any{"Id": id, "RootFS": map[string]any{"Layers": img.layers}, "Config": map[string]any{"Labels": img.labels}}
		out, _ := json.Marshal(doc)
		_, _ = stdout.Write(append(out, '\n'))
		return nil
	case args[0] == "build":
		files := map[string]*tar.Header{}
		var dockerfile string
		tr := tar.NewReader(bytes.NewReader(in))
		for {
			hdr, err := tr.Next()
			if err != nil {
				break
			}
			files[hdr.Name] = hdr
			if hdr.Name == "Dockerfile" {
				body, _ := io.ReadAll(tr)
				dockerfile = string(body)
			}
		}
		d.dockerfiles = append(d.dockerfiles, dockerfile)
		d.contexts = append(d.contexts, files)
		labels, tag := map[string]string{}, ""
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "--label":
				k, v, _ := strings.Cut(args[i+1], "=")
				labels[k] = v
			case "-t":
				tag = args[i+1]
			}
		}
		var from fakeImage
		var layers []string
		for _, line := range strings.Split(dockerfile, "\n") {
			switch {
			case strings.HasPrefix(line, "FROM "):
				id, ok := d.resolve(strings.TrimPrefix(line, "FROM "))
				if !ok {
					return fail()
				}
				from = d.images[id]
				layers = append(layers, from.layers...)
			case strings.HasPrefix(line, "RUN "), strings.HasPrefix(line, "COPY "):
				sum := sha256.Sum256([]byte(line))
				layers = append(layers, "sha256:"+hex.EncodeToString(sum[:]))
			}
		}
		for i := 0; i < d.extraLayers; i++ {
			layers = append(layers, "sha256:extra")
		}
		merged := maps.Clone(from.labels)
		if merged == nil {
			merged = map[string]string{}
		}
		maps.Copy(merged, labels)
		raw, _ := json.Marshal([]any{layers, merged})
		sum := sha256.Sum256(raw)
		id := "sha256:" + hex.EncodeToString(sum[:])
		d.images[id] = fakeImage{layers: layers, labels: merged}
		d.tags[tag] = id
		return nil
	case args[0] == "image" && args[1] == "ls":
		var want []string
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "--filter" {
				want = append(want, strings.TrimPrefix(args[i+1], "label="))
			}
		}
		var out []string
		for tag, id := range d.tags {
			match := true
			for _, f := range want {
				k, v, _ := strings.Cut(f, "=")
				match = match && d.images[id].labels[k] == v
			}
			if match {
				out = append(out, tag)
			}
		}
		sort.Strings(out)
		_, _ = io.WriteString(stdout, strings.Join(out, "\n"))
		return nil
	case args[0] == "image" && args[1] == "rm":
		tag := args[len(args)-1]
		if _, ok := d.tags[tag]; !ok {
			return fail()
		}
		delete(d.tags, tag)
		return nil
	}
	d.t.Errorf("unexpected docker call %v", args)
	return fail()
}

// runBase is a verified Claude Code overlay image record, as Build records
// it, in a daemon that holds it.
func runBase(t *testing.T) (*Builder, *layerDaemon, Record) {
	t.Helper()
	return runBaseFor(t, testSpec(harness.ClaudeCode))
}

// runBaseFor is runBase for an overlay image built from spec.
func runBaseFor(t *testing.T, spec BuildSpec) (*Builder, *layerDaemon, Record) {
	t.Helper()
	c := mustContext(t, spec)
	base := recordFor(c, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), true)
	if spec.MicroVM {
		base.MicroVM, base.MicroVMVerified = true, true
	}
	daemon := newLayerDaemon(t)
	labels := maps.Clone(c.Labels)
	daemon.addBase(base, labels)
	store := testStore(t)
	if err := store.Put(base); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	return &Builder{Docker: daemon, Store: store, Now: func() time.Time { return clock }}, daemon, base
}

// claudeRunFiles are the run files of a Claude Code sandbox whose
// project's MCP servers may start: the drop-in and the imported servers,
// whose directory the overlay image lacks.
func claudeRunFiles(dropIn string) []connector.SandboxFile {
	return []connector.SandboxFile{
		{Path: connector.ClaudeCodeSandboxRunMCPServersPath, Mode: 0o644, Owner: connector.SandboxOwnerRoot, Data: []byte(`{"mcpServers":{}}` + "\n")},
		{Path: connector.ClaudeCodeSandboxRunDropInPath, Mode: 0o644, Owner: connector.SandboxOwnerRoot, Data: []byte(dropIn)},
	}
}

// The digest names the files, not their order: another byte, mode or
// owner is another digest.
func TestRunConfigDigest(t *testing.T) {
	files := claudeRunFiles(`{"env":{}}`)
	reversed := []connector.SandboxFile{files[1], files[0]}
	if RunConfigDigest(files) != RunConfigDigest(reversed) || !hashRE.MatchString(RunConfigDigest(files)) {
		t.Fatalf("digest depends on the order: %s / %s", RunConfigDigest(files), RunConfigDigest(reversed))
	}
	seen := map[string]string{"same": RunConfigDigest(files)}
	for name, edit := range map[string]func([]connector.SandboxFile){
		"one byte more": func(fs []connector.SandboxFile) { fs[1].Data = append(append([]byte(nil), fs[1].Data...), ' ') },
		"mode":          func(fs []connector.SandboxFile) { fs[1].Mode = 0o600 },
		"owner":         func(fs []connector.SandboxFile) { fs[1].Owner = connector.SandboxOwnerUser },
		"path":          func(fs []connector.SandboxFile) { fs[1].Path = connector.ClaudeCodeSandboxManagedMCPPath },
	} {
		changed := claudeRunFiles(`{"env":{}}`)
		edit(changed)
		digest := RunConfigDigest(changed)
		for other, d := range seen {
			if d == digest {
				t.Fatalf("%s gives the digest of %s", name, other)
			}
		}
		seen[name] = digest
	}
}

// A run image is FROM the alias of the verified overlay image, makes the
// directory the image lacks root 0755, copies each file root-owned 0644,
// carries its labels, and is recorded with the alias. The same files reuse
// it without a build; one byte more is another run image.
func TestRunImageBuildsRecordsAndReuses(t *testing.T) {
	b, daemon, base := runBase(t)
	ctx := context.Background()
	files := claudeRunFiles(`{"env":{"ANTHROPIC_BASE_URL":""}}` + "\n")
	ri, err := b.RunImage(ctx, base, files, testAliasRepo)
	if err != nil {
		t.Fatalf("RunImage: %v", err)
	}
	digest := RunConfigDigest(files)
	wantTag := "defenseclaw.invalid/sandbox-run:claudecode-" + base.ContentHash[:12] + "-" + digest[:12] + "-u1000"
	if ri.Tag != wantTag || ri.Digest != digest || ri.BaseImageID != base.ImageID || ri.Alias || ri.ImageID == base.ImageID ||
		ri.Owner != testOwner || !slices.Equal(ri.Files, []string{connector.ClaudeCodeSandboxRunDropInPath, connector.ClaudeCodeSandboxRunMCPServersPath}) {
		t.Fatalf("run image = %+v, want tag %s", ri, wantTag)
	}
	_, name, _ := strings.Cut(base.Tag, ":")
	alias := testAliasRepo + ":" + name
	if daemon.tags[alias] != base.ImageID || !slices.ContainsFunc(daemon.calls, func(c []string) bool { return slices.Equal(c, []string{"tag", base.ImageID, alias}) }) {
		t.Fatalf("alias %s -> %q; calls %v", alias, daemon.tags[alias], daemon.calls)
	}
	wantDockerfile := "FROM " + alias + "\nUSER root\n" +
		"RUN install -d -o root -g root -m 0755 /usr/local/lib/defenseclaw/run\n" +
		"COPY --chown=0:0 --chmod=0644 files" + connector.ClaudeCodeSandboxRunDropInPath + " " + connector.ClaudeCodeSandboxRunDropInPath + "\n" +
		"COPY --chown=0:0 --chmod=0644 files" + connector.ClaudeCodeSandboxRunMCPServersPath + " " + connector.ClaudeCodeSandboxRunMCPServersPath + "\n" +
		"USER sandbox\n"
	if len(daemon.dockerfiles) != 1 || !strings.HasSuffix(daemon.dockerfiles[0], wantDockerfile) {
		t.Fatalf("Dockerfile:\n%s\nwant it to end with:\n%s", daemon.dockerfiles, wantDockerfile)
	}
	for name, hdr := range daemon.contexts[0] {
		if !hdr.FileInfo().IsDir() && (hdr.Uid != 0 || hdr.Gid != 0 || hdr.Mode != 0o644) {
			t.Fatalf("context entry %s is %d:%d %o", name, hdr.Uid, hdr.Gid, hdr.Mode)
		}
	}
	labels := daemon.images[ri.ImageID].labels
	for k, v := range map[string]string{
		LabelOwner: testOwner, LabelSandboxImage: "1", LabelRunImage: "1", LabelBaseImageID: base.ImageID,
		LabelRunConfigDigest: digest, LabelContentHash: base.ContentHash,
	} {
		if labels[k] != v {
			t.Fatalf("label %s = %q, want %q (all %v)", k, labels[k], v, labels)
		}
	}
	runs, err := b.Store.RunImages()
	if err != nil || len(runs) != 2 || runs[0].Tag != wantTag || runs[1].Tag != alias || !runs[1].Alias || runs[1].ImageID != base.ImageID {
		t.Fatalf("recorded = %+v, %v", runs, err)
	}

	again, err := b.RunImage(ctx, base, []connector.SandboxFile{files[1], files[0]}, testAliasRepo)
	if err != nil || !reflect.DeepEqual(again, ri) || daemon.count("build") != 1 {
		t.Fatalf("reuse = %+v, %v; builds %d", again, err, daemon.count("build"))
	}
	if found, ok, err := b.RecordedRunImage(ctx, base, files, testAliasRepo); err != nil || !ok || !reflect.DeepEqual(found, ri) {
		t.Fatalf("RecordedRunImage = %+v, %v, %v", found, ok, err)
	}
	more := claudeRunFiles(`{"env":{"ANTHROPIC_BASE_URL":""}}` + "\n ")
	if _, ok, _ := b.RecordedRunImage(ctx, base, more, testAliasRepo); ok {
		t.Fatal("another posture found a recorded run image")
	}
	other, err := b.RunImage(ctx, base, more, testAliasRepo)
	if err != nil || other.Tag == ri.Tag || daemon.count("build") != 2 {
		t.Fatalf("one byte more = %+v, %v; builds %d", other, err, daemon.count("build"))
	}
	// A tag docker moved elsewhere is not reused.
	daemon.tags[ri.Tag] = other.ImageID
	if _, ok, _ := b.RecordedRunImage(ctx, base, files, testAliasRepo); ok {
		t.Fatal("a moved tag was reused")
	}
}

// An overlay image built for the MicroVM driver renders its build context
// again with the MicroVM step, so a run image is made from it: before, the
// rendering left the step out, its content hash never matched the record,
// and every Claude Code and Codex sandbox on a Mac was refused.
func TestRunImageFromAMicroVMImage(t *testing.T) {
	spec := testSpec(harness.ClaudeCode)
	spec.MicroVM = true
	b, _, base := runBaseFor(t, spec)
	files := claudeRunFiles(`{"env":{}}`)
	ri, err := b.RunImage(context.Background(), base, files, testAliasRepo)
	if err != nil {
		t.Fatalf("RunImage of a MicroVM image: %v", err)
	}
	if ri.BaseImageID != base.ImageID || ri.Alias {
		t.Fatalf("run image = %+v", ri)
	}
	if found, ok, err := b.RecordedRunImage(context.Background(), base, files, testAliasRepo); err != nil || !ok || !reflect.DeepEqual(found, ri) {
		t.Fatalf("RecordedRunImage = %+v, %v, %v", found, ok, err)
	}
}

// A build whose layers are not the overlay image's plus exactly the
// planned ones is removed and never recorded.
func TestRunImageRefusesUnexpectedLayers(t *testing.T) {
	b, daemon, base := runBase(t)
	daemon.extraLayers = 1
	files := claudeRunFiles(`{"env":{}}`)
	if _, err := b.RunImage(context.Background(), base, files, testAliasRepo); err == nil || !strings.Contains(err.Error(), "plus 3 layers") {
		t.Fatalf("RunImage = %v", err)
	}
	if daemon.count("image", "rm", "-f") != 1 {
		t.Fatalf("the refused image was not removed: %v", daemon.calls)
	}
	if runs, _ := b.Store.RunImages(); slices.ContainsFunc(runs, func(r RunImage) bool { return !r.Alias }) {
		t.Fatalf("a refused run image was recorded: %+v", runs)
	}
	// A base docker no longer holds as recorded is refused before a build.
	b2, daemon2, base2 := runBase(t)
	daemon2.images[base2.ImageID] = fakeImage{labels: daemon2.images[base2.ImageID].labels}
	if _, err := b2.RunImage(context.Background(), base2, files, testAliasRepo); err == nil || daemon2.count("build") != 0 {
		t.Fatalf("RunImage of a base without layers = %v, builds %d", err, daemon2.count("build"))
	}
}

// Only root-owned 0644 files under /etc or /usr go into a run image, and
// only of a verified overlay image this store recorded, in a repository of
// its own.
func TestRunImageRefusals(t *testing.T) {
	b, daemon, base := runBase(t)
	ctx := context.Background()
	good := claudeRunFiles(`{}`)
	// first edits the first run file.
	first := func(edit func(*connector.SandboxFile)) func([]connector.SandboxFile) []connector.SandboxFile {
		return func(fs []connector.SandboxFile) []connector.SandboxFile { edit(&fs[0]); return fs }
	}
	for name, tc := range map[string]struct {
		base  func(Record) Record
		files func([]connector.SandboxFile) []connector.SandboxFile
		repo  string
		want  string
	}{
		"user-owned":  {files: first(func(f *connector.SandboxFile) { f.Owner = connector.SandboxOwnerUser }), want: "root-owned with mode 0644"},
		"writable":    {files: first(func(f *connector.SandboxFile) { f.Mode = 0o666 }), want: "root-owned with mode 0644"},
		"home":        {files: first(func(f *connector.SandboxFile) { f.Path = "/sandbox/.claude/settings.json" }), want: "outside /etc and /usr"},
		"escape":      {files: first(func(f *connector.SandboxFile) { f.Path = "/etc/../sandbox/x" }), want: "not a safe absolute path"},
		"duplicate":   {files: first(func(f *connector.SandboxFile) { f.Path = good[1].Path }), want: "duplicate"},
		"none":        {files: func([]connector.SandboxFile) []connector.SandboxFile { return nil }, want: "alias"},
		"unverified":  {base: func(r Record) Record { r.HookFireVerified = false; return r }, want: "not verified"},
		"other owner": {base: func(r Record) Record { r.Owner = "b0b0b0b0b0b0b0b0"; return r }, want: "belongs to image store owner"},
		"drifted":     {base: func(r Record) Record { r.IngressPort++; return r }, want: "rebuild it"},
		"same repo":   {repo: "e-defenseclaw-sandbox", want: "invalid run image repository"},
		"no repo":     {repo: "-", want: "invalid run image repository"},
	} {
		t.Run(name, func(t *testing.T) {
			r, files, repo := base, append([]connector.SandboxFile(nil), good...), testAliasRepo
			if tc.base != nil {
				r = tc.base(r)
			}
			if tc.files != nil {
				files = tc.files(files)
			}
			if tc.repo == "-" {
				repo = ""
			} else if tc.repo != "" {
				repo = tc.repo
			}
			if _, err := b.RunImage(ctx, r, files, repo); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("RunImage = %v, want %q", err, tc.want)
			}
		})
	}
	if n := daemon.count("build") + daemon.count("tag"); n != 0 {
		t.Fatalf("a refused run image ran docker: %v", daemon.calls)
	}
}

// The alias is the verified image ID under the driver's repository,
// recorded once; one docker resolves elsewhere is tagged again.
func TestAliasImage(t *testing.T) {
	b, daemon, base := runBase(t)
	ctx := context.Background()
	ri, err := b.AliasImage(ctx, base, testAliasRepo)
	_, name, _ := strings.Cut(base.Tag, ":")
	if err != nil || ri.Tag != testAliasRepo+":"+name || ri.ImageID != base.ImageID || !ri.Alias || ri.BaseTag != base.Tag {
		t.Fatalf("alias = %+v, %v", ri, err)
	}
	if again, err := b.AliasImage(ctx, base, testAliasRepo); err != nil || !reflect.DeepEqual(again, ri) || daemon.count("tag") != 1 {
		t.Fatalf("again = %+v, %v; tags %d", again, err, daemon.count("tag"))
	}
	if found, ok, err := b.RecordedRunImage(ctx, base, nil, testAliasRepo); err != nil || !ok || !reflect.DeepEqual(found, ri) {
		t.Fatalf("RecordedRunImage(alias) = %+v, %v, %v", found, ok, err)
	}
	daemon.tags[ri.Tag] = "sha256:" + strings.Repeat("9", 64)
	if _, err := b.AliasImage(ctx, base, testAliasRepo); err != nil || daemon.tags[ri.Tag] != base.ImageID || daemon.count("tag") != 2 {
		t.Fatalf("re-tag = %v; alias -> %s", err, daemon.tags[ri.Tag])
	}
}

// Prune takes the run images and aliases of the driver's repositories only
// when asked: it keeps the ones a sandbox runs (by tag or ID) and the ones
// of an overlay image it keeps, removes the rest (run images first), and
// leaves foreign and unrecorded images alone.
func TestPruneRunImages(t *testing.T) {
	b, daemon, base := runBase(t)
	ctx := context.Background()
	current, err := b.RunImage(ctx, base, claudeRunFiles(`{"a":1}`), testAliasRepo)
	if err != nil {
		t.Fatal(err)
	}
	// A superseded overlay image with three run images and its alias.
	old := base
	old.Tag, old.ImageID, old.BuiltAt = "e-defenseclaw-sandbox:claudecode-0123456789abcdef-u1000", "sha256:"+strings.Repeat("2", 64), base.BuiltAt.Add(-time.Hour)
	daemon.addBase(old, daemon.images[base.ImageID].labels)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.Store.Put(old))
	var oldRuns []RunImage
	for i, body := range []string{`{"b":1}`, `{"c":1}`, `{"d":1}`} {
		ri := RunImage{Tag: RunRepository(testAliasRepo) + ":claudecode-old-" + string(rune('a'+i)) + "-u1000", ImageID: "sha256:" + strings.Repeat(string(rune('3'+i)), 64),
			Digest: RunConfigDigest(claudeRunFiles(body)), BaseTag: old.Tag, BaseImageID: old.ImageID, Connector: "claudecode", UID: 1000, GID: 1000, Owner: testOwner}
		daemon.images[ri.ImageID] = fakeImage{labels: map[string]string{LabelSandboxImage: "1", LabelOwner: testOwner, LabelRunImage: "1"}}
		daemon.tags[ri.Tag] = ri.ImageID
		must(b.Store.putRunImage(ri))
		oldRuns = append(oldRuns, ri)
	}
	oldAlias := RunImage{Tag: testAliasRepo + ":claudecode-0123456789abcdef-u1000", ImageID: old.ImageID, Alias: true, BaseTag: old.Tag, BaseImageID: old.ImageID, Owner: testOwner}
	daemon.tags[oldAlias.Tag] = old.ImageID
	must(b.Store.putRunImage(oldAlias))
	// Recorded without this store's owner, recorded but gone, and this
	// owner's label without a record.
	foreign := RunImage{Tag: RunRepository(testAliasRepo) + ":claudecode-foreign-u1000", ImageID: oldRuns[0].ImageID, BaseImageID: old.ImageID, Owner: "b0b0b0b0b0b0b0b0"}
	daemon.tags[foreign.Tag] = foreign.ImageID
	must(b.Store.putRunImage(foreign))
	must(b.Store.putRunImage(RunImage{Tag: RunRepository(testAliasRepo) + ":claudecode-gone-u1000", ImageID: "sha256:" + strings.Repeat("8", 64), BaseImageID: old.ImageID, Owner: testOwner}))
	daemon.tags[RunRepository(testAliasRepo)+":claudecode-lost-u1000"] = oldRuns[0].ImageID

	// Without the driver's repository they are all left alone.
	// The old overlay image's ID stays, under its alias: no disk of it is
	// named for removal.
	rep, err := b.Prune(ctx, PruneOptions{Repository: "e-defenseclaw-sandbox", DryRun: true})
	if err != nil || len(rep.RunImagesLeft) != 8 || !slices.Equal(rep.Removed, []string{old.Tag}) || len(rep.RemovedImageIDs) != 0 {
		t.Fatalf("dry prune without the alias repository = %+v, %v", rep, err)
	}

	// A sandbox that runs the old overlay image, named by its ID, keeps it
	// and so its run images.
	rep, err = b.Prune(ctx, PruneOptions{Repository: "e-defenseclaw-sandbox", AliasRepository: testAliasRepo, Keep: []string{old.ImageID}, DryRun: true})
	if err != nil || len(rep.Removed) != 0 || !slices.Equal(rep.InUse, []string{old.Tag, oldAlias.Tag}) {
		t.Fatalf("dry prune keeping the old image = %+v, %v", rep, err)
	}

	// One sandbox runs oldRuns[0] (named by tag), another oldRuns[1] (by ID).
	keep := []string{oldRuns[0].Tag, oldRuns[1].ImageID}
	rep, err = b.Prune(ctx, PruneOptions{Repository: "e-defenseclaw-sandbox", AliasRepository: testAliasRepo, Keep: keep})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	// The old overlay image goes with its alias, so its ID does; the run
	// images kept for sandboxes keep theirs.
	if !slices.Equal(rep.Removed, []string{old.Tag, oldRuns[2].Tag, oldAlias.Tag}) || !slices.Equal(rep.RemovedImageIDs, []string{old.ImageID, oldRuns[2].ImageID}) {
		t.Fatalf("removed = %v (image IDs %v)", rep.Removed, rep.RemovedImageIDs)
	}
	_, name, _ := strings.Cut(base.Tag, ":")
	for _, tag := range []string{current.Tag, testAliasRepo + ":" + name, oldRuns[0].Tag, oldRuns[1].Tag} {
		if !slices.Contains(rep.Kept, tag) {
			t.Fatalf("kept = %v, missing %s", rep.Kept, tag)
		}
	}
	if !slices.Equal(rep.InUse, []string{oldRuns[0].Tag, oldRuns[1].Tag}) {
		t.Fatalf("in use = %v", rep.InUse)
	}
	if !slices.Contains(rep.Foreign, foreign.Tag) || !slices.Equal(rep.Unrecorded, []string{RunRepository(testAliasRepo) + ":claudecode-lost-u1000"}) ||
		!slices.Contains(rep.ForgottenStale, RunRepository(testAliasRepo)+":claudecode-gone-u1000") {
		t.Fatalf("foreign %v, unrecorded %v, stale %v", rep.Foreign, rep.Unrecorded, rep.ForgottenStale)
	}
	var rms []string
	for _, call := range daemon.calls {
		if len(call) > 2 && call[0] == "image" && call[1] == "rm" {
			rms = append(rms, call[len(call)-1])
		}
	}
	if !slices.Equal(rms, []string{old.Tag, oldRuns[2].Tag, oldAlias.Tag}) {
		t.Fatalf("docker image rm ran for %v", rms)
	}
	runs, _ := b.Store.RunImages()
	var tags []string
	for _, r := range runs {
		tags = append(tags, r.Tag)
	}
	want := []string{oldRuns[0].Tag, oldRuns[1].Tag, current.Tag, foreign.Tag, testAliasRepo + ":" + name}
	sort.Strings(want)
	if !slices.Equal(tags, want) {
		t.Fatalf("run images after prune = %v, want %v", tags, want)
	}
}

// A store that never made a run image (a docker gateway's) prunes as
// before: docker is not asked about the driver's repositories.
func TestPruneWithoutRunImagesListsOnlyTheOverlayRepository(t *testing.T) {
	b, daemon, _ := runBase(t)
	rep, err := b.Prune(context.Background(), PruneOptions{Repository: "e-defenseclaw-sandbox", AliasRepository: testAliasRepo})
	if err != nil || len(rep.Removed) != 0 || len(rep.RunImagesLeft) != 0 {
		t.Fatalf("Prune = %+v, %v", rep, err)
	}
	if n := daemon.count("image", "ls"); n != 2 {
		t.Fatalf("docker image ls ran %d times: %v", n, daemon.calls)
	}
	if _, err := os.Stat(b.Store.Path() + ".run.lock"); !os.IsNotExist(err) {
		t.Fatalf("the run image lock was taken: %v", err)
	}
}

// A store that never made a run image keeps the shape older DefenseClaw
// reads; one that did round-trips its records.
func TestStoreRunImagesRoundTrip(t *testing.T) {
	b, _, base := runBase(t)
	data, err := os.ReadFile(b.Store.Path())
	if err != nil || strings.Contains(string(data), "run_images") {
		t.Fatalf("store without run images = %s, %v", data, err)
	}
	ri, err := b.AliasImage(context.Background(), base, testAliasRepo)
	if err != nil {
		t.Fatal(err)
	}
	reopened := NewStore(filepath.Dir(filepath.Dir(b.Store.Path())))
	runs, err := reopened.RunImages()
	if err != nil || len(runs) != 1 || !reflect.DeepEqual(runs[0], ri) {
		t.Fatalf("reopened = %+v, %v", runs, err)
	}
	if err := reopened.Remove(ri.Tag); err != nil {
		t.Fatal(err)
	}
	if runs, _ := reopened.RunImages(); len(runs) != 0 {
		t.Fatalf("after Remove = %+v", runs)
	}
	if recs, _ := reopened.List(); len(recs) != 1 {
		t.Fatalf("Remove of a run image took overlay records: %+v", recs)
	}
}

// The vm driver's prepared disks are found by image ID, with the identity
// they were prepared for and the space they take.
func TestVMDisks(t *testing.T) {
	cache := t.TempDir()
	id := strings.Repeat("ab", 32)
	for _, name := range []string{
		"sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-configured-501-20-sha256-" + id,
		"sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-image-account-sha256-" + id,
		"sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-image-account-sha256-" + strings.Repeat("cd", 32),
		"sandbox-bootstrap-rootfs-ext4-v5-openshell-0.1.1-guest-x-sha256-" + id,
	} {
		if err := os.MkdirAll(filepath.Join(cache, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache, name, "rootfs.ext4"), bytes.Repeat([]byte{1}, 8192), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	disks := VMDisks(cache, "sha256:"+id)
	if len(disks) != 2 || disks[0].UID != 501 || disks[0].GID != 20 || disks[1].UID != -1 || disks[0].Bytes < 8192 {
		t.Fatalf("disks = %+v", disks)
	}
	if VMDisks(cache, id) != nil || VMDisks(filepath.Join(cache, "missing"), "sha256:"+id) != nil {
		t.Fatal("a malformed ID or a missing cache found disks")
	}

	// A link or a file named like a prepared disk is not one.
	other := strings.Repeat("ef", 32)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(cache, "sandbox-prepared-rootfs-ext4-x-sha256-"+other)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "sandbox-prepared-rootfs-ext4-y-sha256-"+other), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := VMDisks(cache, "sha256:"+other); got != nil {
		t.Fatalf("a link or a file counted as a disk: %+v", got)
	}

	// RemoveVMDisk removes a prepared disk, and nothing that is not one.
	for _, d := range disks {
		if err := RemoveVMDisk(d); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(d.Path); !os.IsNotExist(err) {
			t.Fatalf("%s is still there: %v", d.Path, err)
		}
	}
	for _, d := range []VMDisk{
		{Path: filepath.Join(cache, "sandbox-bootstrap-rootfs-ext4-v5-openshell-0.1.1-guest-x-sha256-"+id)},
		{Path: filepath.Join(cache, "sandbox-prepared-rootfs-ext4-x-sha256-"+other)},
		{Path: filepath.Join(cache, "sandbox-prepared-rootfs-ext4-y-sha256-"+other)},
		{Path: filepath.Join(cache, "sandbox-prepared-rootfs-ext4-x-sha256-short")},
	} {
		if err := RemoveVMDisk(d); err == nil {
			t.Fatalf("RemoveVMDisk(%s) removed what is not a prepared disk", d.Path)
		}
	}
	if left, _ := os.ReadDir(cache); len(left) != 4 {
		t.Fatalf("the cache holds %d entries, want the other image's disk, the bootstrap rootfs, the link and the file", len(left))
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("the link's target went: %v", err)
	}
}

// GoneIDs names the image IDs Docker holds no image of, untagged ones
// included; without Docker it names none.
func TestGoneIDs(t *testing.T) {
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	docker := &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
		if strings.Join(args, " ") == "image ls --all --no-trunc --quiet" {
			return a + "\n" + b + "\n", 0
		}
		return "", 1
	}}
	gone, err := (&Builder{Docker: docker, Store: testStore(t)}).GoneIDs(context.Background(), []string{a, c, "not-an-id"})
	if err != nil || len(gone) != 1 || !gone[c] {
		t.Fatalf("GoneIDs = %v, %v", gone, err)
	}
	docker.handler = func([]string, []byte) (string, int) { return "", 1 }
	if gone, err := (&Builder{Docker: docker, Store: testStore(t)}).GoneIDs(context.Background(), []string{c}); err == nil || gone != nil {
		t.Fatalf("GoneIDs without Docker = %v, %v", gone, err)
	}
}
