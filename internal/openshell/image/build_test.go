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

package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// fakeDocker answers docker CLI invocations from a handler and records them.
type fakeDocker struct {
	mu      sync.Mutex
	calls   [][]string
	stdin   map[int][]byte
	handler func(args []string, stdin []byte) (stdout string, exit int)
}

func (f *fakeDocker) Run(_ context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), args...))
	if f.stdin == nil {
		f.stdin = map[int][]byte{}
	}
	f.stdin[len(f.calls)-1] = in
	f.mu.Unlock()
	out, exit := f.handler(args, in)
	if stdout != nil {
		_, _ = io.WriteString(stdout, out)
	}
	if exit != 0 {
		if stderr != nil {
			_, _ = io.WriteString(stderr, "fake failure")
		}
		return &CommandError{Args: args, ExitCode: exit}
	}
	return nil
}

func (f *fakeDocker) count(verb ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, call := range f.calls {
		if len(call) >= len(verb) && strings.Join(call[:len(verb)], " ") == strings.Join(verb, " ") {
			n++
		}
	}
	return n
}

// imageDocker simulates a daemon that builds c and runs its probe.
func imageDocker(t *testing.T, c *Context, probe string) *fakeDocker {
	t.Helper()
	wantTar, err := c.Tar()
	if err != nil {
		t.Fatal(err)
	}
	built := false
	return &fakeDocker{handler: func(args []string, stdin []byte) (string, int) {
		switch {
		case args[0] == "build":
			if !bytes.Equal(stdin, wantTar) {
				t.Errorf("docker build received a different context")
			}
			if args[len(args)-1] != "-" || !containsSeq(args, "-t", c.Tag) || !containsSeq(args, "--label", LabelContentHash+"="+c.ContentHash) {
				t.Errorf("docker build argv = %v", args)
			}
			built = true
			return "", 0
		case args[0] == "image" && args[1] == "inspect":
			if !built {
				return "", 1
			}
			return "sha256:" + strings.Repeat("1", 64) + "\n", 0
		case args[0] == "run" && containsSeq(args, "--network", "none"):
			return probe, 0
		case args[0] == "image" && args[1] == "rm":
			built = false
			return "", 0
		}
		t.Errorf("unexpected docker call %v", args)
		return "", 1
	}}
}

func containsSeq(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

func TestBuildRecordsVerifiedImage(t *testing.T) {
	c := mustContext(t, testSpec(harness.Codex))
	docker := imageDocker(t, c, goodProbeOutput(c))
	store := testStore(t)
	fixed := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	b := &Builder{Docker: docker, Store: store, Now: func() time.Time { return fixed }}

	rec, err := b.Build(context.Background(), testSpec(harness.Codex), BuildOptions{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rec.Tag != c.Tag || rec.ContentHash != c.ContentHash || rec.HookContract != "codex-hooks-v4" || rec.HarnessVersion != "0.146.0" ||
		!rec.BuiltAt.Equal(fixed) || len(rec.NetworkBinaries) != 1 || len(rec.Binaries) != len(c.Artifacts.Binaries) || rec.ImageID == "" {
		t.Fatalf("record = %+v", rec)
	}
	if got := rec.NetworkRealpaths(); len(got) != 1 || !strings.HasSuffix(got[0], "/bin/codex") {
		t.Fatalf("network realpaths = %v", got)
	}
	stored, ok, err := store.Get(c.Tag)
	if err != nil || !ok || stored.ContentHash != c.ContentHash {
		t.Fatalf("store = %+v %t %v", stored, ok, err)
	}

	// A second build of the same inputs reuses the verified image.
	if _, err := b.Build(context.Background(), testSpec(harness.Codex), BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if docker.count("build") != 1 {
		t.Fatalf("cached build ran docker build %d times", docker.count("build"))
	}
	if _, err := b.Build(context.Background(), testSpec(harness.Codex), BuildOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if docker.count("build") != 2 {
		t.Fatal("forced build did not rebuild")
	}
}

func TestBuildRemovesImagesThatFailVerification(t *testing.T) {
	c := mustContext(t, testSpec(harness.ClaudeCode))
	tampered := strings.Replace(goodProbeOutput(c), "version 2.1.156", "version 2.1.999", 1)
	docker := imageDocker(t, c, tampered)
	store := testStore(t)
	b := &Builder{Docker: docker, Store: store}
	if _, err := b.Build(context.Background(), testSpec(harness.ClaudeCode), BuildOptions{}); err == nil || !strings.Contains(err.Error(), "failed verification") {
		t.Fatalf("Build error = %v", err)
	}
	if docker.count("image", "rm") != 1 {
		t.Fatal("unverified image was left behind")
	}
	if records, _ := store.List(); len(records) != 0 {
		t.Fatalf("unverified image recorded: %v", records)
	}
}

func TestBuildRefusesUnknownContractWithoutDocker(t *testing.T) {
	docker := &fakeDocker{handler: func([]string, []byte) (string, int) { return "", 0 }}
	b := &Builder{Docker: docker, Store: testStore(t)}
	spec := testSpec(harness.Codex)
	spec.HarnessVersion = "0.117.0"
	if _, err := b.Build(context.Background(), spec, BuildOptions{}); err == nil {
		t.Fatal("unknown contract built")
	}
	if len(docker.calls) != 0 {
		t.Fatalf("docker was invoked: %v", docker.calls)
	}
}

func TestBuildPropagatesDockerFailure(t *testing.T) {
	docker := &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
		if args[0] == "build" {
			return "", 1
		}
		return "", 1
	}}
	b := &Builder{Docker: docker, Store: testStore(t)}
	if _, err := b.Build(context.Background(), testSpec(harness.ClaudeCode), BuildOptions{}); err == nil || !strings.Contains(err.Error(), "docker build") {
		t.Fatalf("Build error = %v", err)
	}
}

func TestPruneKeepsCurrentImagePerIdentity(t *testing.T) {
	store := testStore(t)
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	own := func(r Record) Record {
		r.Owner = testOwner
		return r
	}
	for _, r := range []Record{
		own(Record{Tag: "e-repo:claudecode-old-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0}),
		own(Record{Tag: "e-repo:claudecode-older-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(-2 * time.Hour)}),
		own(Record{Tag: "e-repo:claudecode-new-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(time.Hour)}),
		// The newest hook-verified image is what Store.Current selects for
		// an unchanged spec, so it survives a newer unverified build.
		own(Record{Tag: "e-repo:claudecode-verified-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(30 * time.Minute), HookFireVerified: true}),
		own(Record{Tag: "e-repo:claudecode-verified-old-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(-time.Hour), HookFireVerified: true}),
		own(Record{Tag: "e-repo:codex-only-u1000", Connector: "codex", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0}),
		own(Record{Tag: "e-repo:codex-gone-u1000", Connector: "codex", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(2 * time.Hour)}),
		own(Record{Tag: "other:claudecode-x-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0}),
		// Recorded here without this store's owner (a record from before
		// store owners), and recorded under the owner but now naming an
		// image without its label: neither is removed.
		{Tag: "e-repo:claudecode-legacy-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(-3 * time.Hour)},
		own(Record{Tag: "e-repo:claudecode-relabelled-u1000", Connector: "claudecode", UID: 1000, GID: 1000, IngressPort: 18971, BuiltAt: t0.Add(-4 * time.Hour)}),
	} {
		if err := store.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	ownedTags := []string{
		"e-repo:claudecode-old-u1000", "e-repo:claudecode-older-u1000", "e-repo:claudecode-new-u1000", "e-repo:codex-only-u1000",
		"e-repo:claudecode-verified-u1000", "e-repo:claudecode-verified-old-u1000",
		// This store's label without a record (images.json restored from an
		// older copy).
		"e-repo:claudecode-lost-record-u1000",
		"e-repo:<none>", "other:claudecode-x-u1000",
	}
	// Another data dir sharing the daemon, the legacy image and the
	// relabelled one.
	foreignTags := []string{"e-repo:claudecode-otherdir-u1000", "e-repo:claudecode-legacy-u1000", "e-repo:claudecode-relabelled-u1000"}
	docker := &fakeDocker{handler: func(args []string, _ []byte) (string, int) {
		if args[0] == "image" && args[1] == "ls" {
			if !containsSeq(args, "--filter", "label="+LabelSandboxImage+"=1") {
				t.Errorf("image ls must filter DefenseClaw images: %v", args)
			}
			if containsSeq(args, "--filter", "label="+LabelOwner+"="+testOwner) {
				return strings.Join(ownedTags, "\n"), 0
			}
			return strings.Join(append(append([]string(nil), ownedTags...), foreignTags...), "\n"), 0
		}
		if args[0] == "image" && args[1] == "rm" {
			if containsSeq(args, "rm", "-f") || containsSeq(args, "rm", "--force") {
				t.Errorf("prune must let docker refuse images in use: %v", args)
			}
			return "", 0
		}
		return "", 1
	}}
	b := &Builder{Docker: docker, Store: store}

	keep := []string{"e-repo:claudecode-older-u1000"}
	dry, err := b.Prune(context.Background(), PruneOptions{Repository: "e-repo", Keep: keep, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if docker.count("image", "rm") != 0 {
		t.Fatal("dry run removed images")
	}
	report, err := b.Prune(context.Background(), PruneOptions{Repository: "e-repo", Keep: keep})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Removed, ",") != "e-repo:claudecode-old-u1000,e-repo:claudecode-verified-old-u1000" ||
		strings.Join(dry.Removed, ",") != strings.Join(report.Removed, ",") {
		t.Fatalf("removed = %v (dry %v)", report.Removed, dry.Removed)
	}
	if docker.count("image", "rm") != 2 {
		t.Fatalf("docker image rm ran %d times", docker.count("image", "rm"))
	}
	if strings.Join(report.Kept, ",") != "e-repo:claudecode-new-u1000,e-repo:claudecode-older-u1000,e-repo:claudecode-verified-u1000,e-repo:codex-only-u1000" {
		t.Fatalf("kept = %v", report.Kept)
	}
	if strings.Join(report.ForgottenStale, ",") != "e-repo:codex-gone-u1000" {
		t.Fatalf("stale = %v", report.ForgottenStale)
	}
	if strings.Join(report.Unrecorded, ",") != "e-repo:claudecode-lost-record-u1000" {
		t.Fatalf("unrecorded = %v", report.Unrecorded)
	}
	if strings.Join(report.Foreign, ",") != "e-repo:claudecode-legacy-u1000,e-repo:claudecode-otherdir-u1000,e-repo:claudecode-relabelled-u1000" {
		t.Fatalf("foreign = %v", report.Foreign)
	}
	records, _ := store.List()
	var tags []string
	for _, r := range records {
		tags = append(tags, r.Tag)
	}
	if strings.Join(tags, ",") != "e-repo:claudecode-legacy-u1000,e-repo:claudecode-new-u1000,e-repo:claudecode-older-u1000,e-repo:claudecode-relabelled-u1000,"+
		"e-repo:claudecode-verified-u1000,e-repo:codex-only-u1000,other:claudecode-x-u1000" {
		t.Fatalf("store after prune = %v", tags)
	}
	if _, err := b.Prune(context.Background(), PruneOptions{Repository: "Bad Repo"}); err == nil {
		t.Fatal("invalid repository accepted")
	}
}

// fakeDaemon is a Docker daemon with a tag table and image labels, enough
// to build, inspect, list by label, run the static probe and remove.
type fakeDaemon struct {
	t        *testing.T
	mu       sync.Mutex
	images   map[string]map[string]string // image ID -> labels
	tags     map[string]string            // tag -> image ID
	contexts map[string]*Context          // tag -> context (for the probe)
	inUse    map[string]bool              // image IDs a container uses
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	return &fakeDaemon{t: t, images: map[string]map[string]string{}, tags: map[string]string{}, contexts: map[string]*Context{}, inUse: map[string]bool{}}
}

func (d *fakeDaemon) expect(c *Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.contexts[c.Tag] = c
}

func (d *fakeDaemon) Run(_ context.Context, stdin io.Reader, stdout, _ io.Writer, args ...string) error {
	if stdin != nil {
		_, _ = io.Copy(io.Discard, stdin)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	fail := func() error { return &CommandError{Args: args, ExitCode: 1} }
	switch {
	case args[0] == "build":
		labels := map[string]string{}
		tag := ""
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "--label":
				k, v, _ := strings.Cut(args[i+1], "=")
				labels[k] = v
			case "-t":
				tag = args[i+1]
			}
		}
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k+"="+labels[k])
		}
		sort.Strings(keys)
		sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
		id := "sha256:" + hex.EncodeToString(sum[:])
		d.images[id] = labels
		d.tags[tag] = id
		return nil
	case args[0] == "image" && args[1] == "inspect":
		id, ok := d.tags[args[len(args)-1]]
		if !ok {
			return fail()
		}
		_, _ = io.WriteString(stdout, id+"\n")
		return nil
	case args[0] == "run" && containsSeq(args, "--network", "none"):
		for i := range args {
			if args[i] == "--entrypoint" && i+2 < len(args) {
				if c, ok := d.contexts[args[i+2]]; ok {
					_, _ = io.WriteString(stdout, goodProbeOutput(c))
					return nil
				}
			}
		}
		return fail()
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
				match = match && d.images[id][k] == v
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
		id, ok := d.tags[tag]
		if !ok || d.inUse[id] {
			return fail()
		}
		delete(d.tags, tag)
		return nil
	}
	d.t.Errorf("unexpected docker call %v", args)
	return fail()
}

// TestPruneLeavesOtherDataDirsAlone shares one daemon between two data
// dirs building the same specs: their images get distinct tags, neither
// accepts the other's spec, and pruning one never removes the other's
// images (docker also refuses an image a container still uses).
func TestPruneLeavesOtherDataDirsAlone(t *testing.T) {
	daemon := newFakeDaemon(t)
	storeA, storeB := testStoreOwnedBy(t, "a0a0a0a0a0a0a0a0"), testStoreOwnedBy(t, "b0b0b0b0b0b0b0b0")
	clock := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	a := &Builder{Docker: daemon, Store: storeA, Now: now}
	b := &Builder{Docker: daemon, Store: storeB, Now: now}
	ctx := context.Background()
	build := func(builder *Builder, spec BuildSpec) Record {
		t.Helper()
		spec.Owner = ""
		c, err := builder.Context(spec)
		if err != nil {
			t.Fatal(err)
		}
		daemon.expect(c)
		clock = clock.Add(time.Minute)
		rec, err := builder.Build(ctx, spec, BuildOptions{})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		return rec
	}
	older := testSpec(harness.Codex)
	older.DefenseClawVersion = "1.2.2"
	current := testSpec(harness.Codex)

	aOld, bOld := build(a, older), build(b, older)
	aCur, bCur := build(a, current), build(b, current)
	if aCur.Tag == bCur.Tag || aOld.Tag == bOld.Tag || aCur.Owner != "a0a0a0a0a0a0a0a0" || bCur.Owner != "b0b0b0b0b0b0b0b0" {
		t.Fatalf("data dirs share tags or owners: %+v / %+v", aCur, bCur)
	}
	foreignSpec := current
	foreignSpec.Owner = "b0b0b0b0b0b0b0b0"
	if _, err := a.Context(foreignSpec); err == nil {
		t.Fatal("a builder accepted a spec owned by another data dir")
	}
	// B's older image still runs a sandbox.
	daemon.inUse[daemon.tags[bOld.Tag]] = true

	report, err := a.Prune(ctx, PruneOptions{Repository: current.Repository})
	if err != nil {
		t.Fatalf("Prune(A): %v", err)
	}
	if strings.Join(report.Removed, ",") != aOld.Tag {
		t.Fatalf("A removed %v, want only its own older image %s", report.Removed, aOld.Tag)
	}
	foreign := []string{bOld.Tag, bCur.Tag}
	sort.Strings(foreign)
	if strings.Join(report.Foreign, ",") != strings.Join(foreign, ",") {
		t.Fatalf("A foreign = %v, want %v", report.Foreign, foreign)
	}
	for _, tag := range []string{bOld.Tag, bCur.Tag, aCur.Tag} {
		if _, ok := daemon.tags[tag]; !ok {
			t.Fatalf("%s was removed", tag)
		}
	}
	// B's own older image is in use: docker refuses and B keeps its record.
	report, err = b.Prune(ctx, PruneOptions{Repository: current.Repository})
	if err == nil || len(report.Removed) != 0 || strings.Join(report.Foreign, ",") != aCur.Tag {
		t.Fatalf("Prune(B) = %+v, %v", report, err)
	}
	if _, ok, _ := storeB.Get(bOld.Tag); !ok {
		t.Fatal("B forgot an image docker refused to remove")
	}
}

func TestStoreOwnerIsCreatedOncePerDataDir(t *testing.T) {
	dir := t.TempDir()
	first, err := NewStore(dir).Owner()
	if err != nil || !ownerRE.MatchString(first) {
		t.Fatalf("owner = %q %v", first, err)
	}
	if again, err := NewStore(dir).Owner(); err != nil || again != first {
		t.Fatalf("owner changed: %q -> %q (%v)", first, again, err)
	}
	if other, _ := NewStore(t.TempDir()).Owner(); other == first {
		t.Fatal("two data dirs share an owner")
	}
	store := NewStore(dir)
	if err := store.Put(Record{Tag: "r:a"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.Owner(); again != first {
		t.Fatal("a write dropped the owner")
	}
	if err := os.WriteFile(store.Path(), []byte(`{"version":1,"owner":"NOT-HEX","images":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Owner(); err == nil {
		t.Fatal("malformed owner accepted")
	}
}

func TestStoreRoundTripAndStrictness(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if records, err := store.List(); err != nil || len(records) != 0 {
		t.Fatalf("empty store = %v %v", records, err)
	}
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a := Record{Tag: "r:a", Connector: "codex", UID: 1, GID: 1, IngressPort: 2, BuiltAt: t0, HookFireVerified: true, HookFireVerifiedAt: t0}
	b := Record{Tag: "r:b", Connector: "codex", UID: 1, GID: 1, IngressPort: 2, BuiltAt: t0.Add(time.Minute), HookFireVerified: true, HookFireVerifiedAt: t0.Add(2 * time.Minute)}
	// The newest build has not passed the hook-fire probe yet.
	unverified := Record{Tag: "r:c", Connector: "codex", UID: 1, GID: 1, IngressPort: 2, BuiltAt: t0.Add(time.Hour)}
	for _, r := range []Record{b, a, a, unverified} {
		if err := store.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.List()
	if err != nil || len(records) != 3 || records[0].Tag != "r:a" || !records[1].HookFireVerifiedAt.Equal(b.HookFireVerifiedAt) {
		t.Fatalf("records = %v %v", records, err)
	}
	if raw, err := os.ReadFile(store.Path()); err != nil || strings.Count(string(raw), "hook_fire_verified_at") != 2 {
		t.Fatalf("an unverified record must omit hook_fire_verified_at: %s %v", raw, err)
	}
	if err := store.Put(Record{}); err == nil {
		t.Fatal("record without tag accepted")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.Path())
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("store mode = %v %v", info.Mode(), err)
		}
		dirInfo, _ := os.Stat(filepath.Dir(store.Path()))
		if dirInfo.Mode().Perm()&0o077 != 0 {
			t.Fatalf("store dir mode = %v", dirInfo.Mode())
		}
	}
	if err := store.Remove("r:a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Get("r:a"); ok {
		t.Fatal("removed record still present")
	}

	for name, body := range map[string]string{
		"unknown-field": `{"version":1,"images":[],"extra":true}`,
		"bad-version":   `{"version":9,"images":[]}`,
		"trailing":      `{"version":1,"images":[]} {}`,
	} {
		if err := os.WriteFile(store.Path(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.List(); err == nil {
			t.Errorf("%s: corrupt store accepted", name)
		}
	}
}

// recordFor is the record Build writes for c.
func recordFor(c *Context, builtAt time.Time, verified bool) Record {
	r := Record{
		Tag: c.Tag, ImageID: "sha256:" + strings.Repeat("1", 64), ContentHash: c.ContentHash,
		Connector: c.Spec.Harness.Name, HarnessVersion: c.HarnessVersion, HookContract: c.Contract,
		BaseImage: c.Spec.BaseImage, UID: c.Spec.UID, GID: c.Spec.GID, IngressPort: c.Spec.IngressPort,
		DefenseClawVersion: c.Spec.DefenseClawVersion, FailMode: c.Spec.FailMode, Owner: c.Spec.Owner, BuiltAt: builtAt,
		HookFireVerified: verified,
	}
	if verified {
		r.HookFireVerifiedAt = builtAt
	}
	return r
}

// TestStoreCurrentSelectsOnlyTheExactVerifiedImage covers an upgrade: an
// older verified image and a newer, not yet verified one coexist. Current
// never falls back to the older image (its hooks may be stale), and never
// selects a record whose recorded inputs drifted from the expected build.
func TestStoreCurrentSelectsOnlyTheExactVerifiedImage(t *testing.T) {
	store := testStore(t)
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	oldSpec := testSpec(harness.ClaudeCode)
	newSpec := testSpec(harness.ClaudeCode)
	newSpec.DefenseClawVersion = "1.2.4"
	newHarness := testSpec(harness.ClaudeCode)
	newHarness.HarnessVersion = "2.1.160"
	oldCtx, newCtx, harnessCtx := mustContext(t, oldSpec), mustContext(t, newSpec), mustContext(t, newHarness)
	for _, r := range []Record{
		recordFor(oldCtx, t0, true),
		recordFor(newCtx, t0.Add(time.Hour), false),
		recordFor(harnessCtx, t0.Add(2*time.Hour), false),
	} {
		if err := store.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	current := func(c *Context) (Record, bool) {
		t.Helper()
		r, ok, err := store.Current(c)
		if err != nil {
			t.Fatal(err)
		}
		return r, ok
	}
	if r, ok := current(newCtx); ok {
		t.Fatalf("Current selected %s for the upgraded DefenseClaw version before its image was verified", r.Tag)
	}
	if r, ok := current(harnessCtx); ok {
		t.Fatalf("Current selected %s for a new harness pin before its image was verified", r.Tag)
	}
	if r, ok := current(oldCtx); !ok || r.Tag != oldCtx.Tag {
		t.Fatalf("Current(old) = %+v %t", r, ok)
	}
	if err := store.Put(recordFor(newCtx, t0.Add(time.Hour), true)); err != nil {
		t.Fatal(err)
	}
	if r, ok := current(newCtx); !ok || r.Tag != newCtx.Tag || r.DefenseClawVersion != "1.2.4" || r.FailMode != "closed" {
		t.Fatalf("Current(new) = %+v %t after verification", r, ok)
	}

	// A record under the expected tag whose recorded inputs differ (a
	// legacy record without a fail mode, a hand-edited store) is not the
	// expected image.
	for name, mutate := range map[string]func(*Record){
		"no-fail-mode": func(r *Record) { r.FailMode = "" },
		"content-hash": func(r *Record) { r.ContentHash = strings.Repeat("0", 64) },
		"dc-version":   func(r *Record) { r.DefenseClawVersion = "1.2.3" },
		"harness":      func(r *Record) { r.HarnessVersion = "2.1.160" },
		"contract":     func(r *Record) { r.HookContract = "claude-hooks-v0" },
		"base-image":   func(r *Record) { r.BaseImage = "ghcr.io/example/base@sha256:" + strings.Repeat("a", 64) },
		"uid":          func(r *Record) { r.UID = 1001 },
		"ingress":      func(r *Record) { r.IngressPort = 18981 },
		"connector":    func(r *Record) { r.Connector = "codex" },
		"not-verified": func(r *Record) { r.HookFireVerified = false },
		"owner":        func(r *Record) { r.Owner = "f0f0f0f0f0f0f0f0" },
	} {
		t.Run(name, func(t *testing.T) {
			r := recordFor(newCtx, t0.Add(time.Hour), true)
			mutate(&r)
			if err := store.Put(r); err != nil {
				t.Fatal(err)
			}
			if _, ok := current(newCtx); ok {
				t.Fatal("Current selected a record whose inputs drifted")
			}
		})
	}
	if _, _, err := store.Current(nil); err == nil {
		t.Fatal("Current(nil) did not fail")
	}
}
