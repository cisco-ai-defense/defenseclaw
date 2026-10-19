// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/idxfile"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type capturedRootsFixture struct {
	capture, output, scratch *os.Root
	outputPath               string
}

func captureEngineFixture(t *testing.T, opts StageOptions) capturedRootsFixture {
	t.Helper()
	base := filepath.Join(opts.DataDir, "engine-"+randomSuffix())
	if created, err := safefile.CreatePrivateDirectory(base); err != nil || !created {
		t.Fatalf("new private engine fixture: %v", err)
	}
	for _, name := range []string{"capture", "output", "scratch"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	open := func(name string) *os.Root {
		root, err := os.OpenRoot(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := root.Close(); err != nil {
				t.Error(err)
			}
		})
		return root
	}
	f := capturedRootsFixture{open("capture"), open("output"), open("scratch"), filepath.Join(base, "output")}
	source, err := openWindowsHostStagePin(opts.Project)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	budget := windowsHostCaptureBudget{maxBytes: opts.MaxBytes, remaining: hostStageMaxEntries}
	if err := captureWindowsHostTree(context.Background(), source.leaf(), f.capture, "", 0, &budget); err != nil {
		t.Fatal(err)
	}
	return f
}

func fixedGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	value, err := fixedGitResult(dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(value))
}

type fixedGitOutput struct {
	bytes.Buffer
}

func (b *fixedGitOutput) Write(p []byte) (int, error) {
	if len(p) > (4<<20)-b.Len() {
		return 0, errors.New("fixed native Git fixture output limit")
	}
	return b.Buffer.Write(p)
}

// Native Git is an independent compatibility oracle, never the staging engine.
// Require its explicit no-lazy-fetch option so a missing guest object fails
// locally; all descendants belong to the bounded, non-breakaway owned Job.
// Held volume paths can exceed MAX_PATH; enable Git's existing Windows support
// only for this fixed test command, without changing host Git configuration.
func fixedGitResult(dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd, cleanup, err := (gitCmd{dir: dir}).command(ctx, append([]string{"--no-lazy-fetch", "-c", "core.longpaths=true"}, args...))
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1")
	var stdout, stderr fixedGitOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := processutil.RunTree(cmd); err != nil {
		return stdout.Bytes(), fmt.Errorf("fixed native Git %s: %w: %.2048s", args[0], err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Copy only the eventual guest tree to an independent private fixture. The
// compatibility oracle gets no host-side .dc-objects, capture or scratch, and
// no alternate-object environment survives gitCmd's inherited-env scrub.
func fixedGuestOnlyFixture(t *testing.T, guest string) string {
	t.Helper()
	from, err := os.OpenRoot(guest)
	if err != nil {
		t.Fatal(err)
	}
	defer from.Close()
	path := filepath.Join(t.TempDir(), "guest-only")
	if created, err := safefile.CreatePrivateDirectory(path); err != nil || !created {
		t.Fatalf("new independent private guest fixture: %v", err)
	}
	to, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer to.Close()
	remaining, entries := int64(16<<20), 0
	err = fs.WalkDir(from.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 10000 {
			return errors.New("fixed guest fixture entry limit")
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			return to.Mkdir(rel, 0o700)
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > remaining {
			return errors.Join(err, errors.New("fixed guest fixture type/byte limit"))
		}
		in, err := from.Open(rel)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := to.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(in, info.Size()+1))
		remaining -= n
		if n != info.Size() {
			err = errors.Join(err, errors.New("fixed guest fixture size changed"))
		}
		return errors.Join(err, out.Close())
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := to.Stat(".git/objects/info/alternates"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guest-only fixture unexpectedly has object alternates")
	}
	return path
}

func setupCapturedGitFixture(t *testing.T, opts StageOptions) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("native Git is required for the controlled compatibility fixture")
	}
	fixedGit(t, opts.Project, "init", "--quiet", "--template=", ".")
	fixedGit(t, opts.Project, "config", "core.autocrlf", "false")
}

func stageEngineFixture(t *testing.T, opts StageOptions, roots capturedRootsFixture) (CopyRecord, error) {
	t.Helper()
	return stageCapturedSHA1(context.Background(), roots.capture, roots.output, roots.scratch, opts, stageSecretOptions(opts, opts.Project), capturedGitSettings{frozen: true, lineEndings: map[string]string{"core.autocrlf": "false"}})
}

func assertCapturedReason(t *testing.T, err error, want string) {
	t.Helper()
	var refusal *CapturedGitError
	if !errors.As(err, &refusal) || refusal.Reason != want {
		t.Fatalf("want refusal %q, got %v", want, err)
	}
}

func TestCapturedSHA1NativeTwoCommitPackedHistoryAndSecretBoundary(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	public := strings.Repeat("fixed public source line\n", 2048)
	writeHostStageFixture(t, opts.Project, "main.txt", public+"first\n")
	writeHostStageFixture(t, opts.Project, ".env", "fixed first private history canary")
	writeHostStageFixture(t, opts.Project, ".env.shared", "fixed public duplicate canary")
	writeHostStageFixture(t, opts.Project, "public.txt", "fixed public duplicate canary")
	writeHostStageFixture(t, opts.Project, ".gitignore", "IGNORED*.TXT\n*.tmp\n")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed first commit")
	first := fixedGit(t, opts.Project, "rev-parse", "HEAD")
	firstRaw := fixedGit(t, opts.Project, "cat-file", "commit", first)
	secret1 := fixedGit(t, opts.Project, "rev-parse", "HEAD:.env")
	shared := fixedGit(t, opts.Project, "rev-parse", "HEAD:public.txt")
	writeHostStageFixture(t, opts.Project, "main.txt", public+"second\n")
	writeHostStageFixture(t, opts.Project, ".env", "fixed second private history canary")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed second commit")
	head := fixedGit(t, opts.Project, "rev-parse", "HEAD")
	secondRaw := fixedGit(t, opts.Project, "cat-file", "commit", head)
	secret2 := fixedGit(t, opts.Project, "rev-parse", "HEAD:.env")
	// This creates real upstream Git pack/index inputs, including delta
	// opportunities, without any network, hooks or arbitrary child command.
	fixedGit(t, opts.Project, "repack", "-adf", "--window=10", "--depth=10")
	inputIndexes, err := filepath.Glob(filepath.Join(opts.Project, ".git", "objects", "pack", "*.idx"))
	if err != nil || len(inputIndexes) != 1 {
		t.Fatal("controlled real input pack missing")
	}
	verified := fixedGit(t, opts.Project, "verify-pack", "-v", inputIndexes[0])
	deltaCount := 0
	for _, line := range strings.Split(verified, "\n") {
		if fields := strings.Fields(line); len(fields) == 7 && isOID(fields[0]) {
			deltaCount++
		}
	}
	if deltaCount == 0 {
		t.Fatal("real pack fixture did not exercise native Git delta reconstruction")
	}
	writeHostStageFixture(t, opts.Project, "ignored-output.txt", "fixed ignored canary")
	writeHostStageFixture(t, opts.Project, "new.txt", "fixed public untracked canary")
	writeHostStageFixture(t, opts.Project, "nested/.gitignore", "!keep.tmp\n")
	writeHostStageFixture(t, opts.Project, "nested/keep.tmp", "fixed included nested canary")
	writeHostStageFixture(t, opts.Project, "nested/drop.tmp", "fixed ignored nested canary")
	fixedGit(t, opts.Project, "config", "remote.origin.url", "https://fixed-user:fixed-password@example.invalid/project.git")
	fixedGit(t, opts.Project, "config", "remote.origin.fetch", "+refs/*:refs/*")
	writeHostStageFixture(t, opts.Project, ".git/hooks/post-checkout", "fixed nonexecutable hook canary")
	roots := captureEngineFixture(t, opts)
	var rec CopyRecord
	err = nil
	t.Run("engine_has_no_ambient_git_or_config_calls", func(t *testing.T) {
		t.Setenv("PATH", "")
		t.Setenv("GIT_CONFIG_PARAMETERS", "'filter.fixed.clean=must-not-run'")
		t.Setenv("HOME", filepath.Join(opts.DataDir, "does-not-exist"))
		rec, err = stageEngineFixture(t, opts, roots)
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != CopyGit || rec.Head != head || rec.Baseline == "" || rec.Withheld != 2 {
		t.Fatalf("lost history or withholding: %+v", rec)
	}
	stage := filepath.Join(roots.outputPath, rec.RepoName)
	if got := fixedGit(t, stage, "show", "HEAD:main.txt"); got != strings.TrimSpace(public+"second\n") {
		t.Fatal("native Git cannot read preserved HEAD content")
	}
	if got := fixedGit(t, stage, "cat-file", "commit", first); got != firstRaw {
		t.Fatal("first raw commit/OID changed")
	}
	if got := fixedGit(t, stage, "cat-file", "commit", head); got != secondRaw {
		t.Fatal("second raw commit/OID changed")
	}
	if got := fixedGit(t, stage, "rev-list", "--count", "HEAD"); got != "2" {
		t.Fatalf("history was flattened: %q", got)
	}
	if got := fixedGit(t, stage, "rev-parse", baselineRef+"^"); got != head {
		t.Fatal("baseline is not parented by original HEAD")
	}
	if rec.Remotes["origin"] != "https://example.invalid/project.git" {
		t.Fatalf("remote was not sanitized: %v", rec.Remotes)
	}
	if got := fixedGit(t, stage, "config", "--get-all", "remote.origin.fetch"); got != "+refs/heads/*:refs/remotes/origin/*" {
		t.Fatalf("source fetch destinations survived: %q", got)
	}
	for _, rel := range []string{".env", ".env.shared", "ignored-output.txt", "nested/drop.tmp", ".git/hooks/post-checkout"} {
		if _, err := os.Stat(filepath.Join(stage, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("private/ignored/executable metadata copied: %s (%v)", rel, err)
		}
	}
	for _, rel := range []string{"new.txt", "nested/keep.tmp", "public.txt"} {
		if _, err := os.Stat(filepath.Join(stage, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("eligible working file omitted: %s (%v)", rel, err)
		}
	}
	idxFiles, err := filepath.Glob(filepath.Join(stage, ".git", "objects", "pack", "*.idx"))
	if err != nil || len(idxFiles) != 1 {
		t.Fatalf("filtered pack missing: %v", err)
	}
	f, err := os.Open(idxFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	idx := idxfile.NewMemoryIndex()
	err = idxfile.NewDecoder(f).Decode(idx)
	err = errors.Join(err, f.Close())
	if err != nil {
		t.Fatal(err)
	}
	for _, oid := range []string{secret1, secret2} {
		present, err := idx.Contains(plumbing.NewHash(oid))
		if err != nil || present {
			t.Fatalf("private historic blob shipped: %s (%v)", oid, err)
		}
		full := withheldObjectsDir + "/" + oid[:2] + "/" + oid[2:]
		if _, err := roots.output.Stat(full); err != nil {
			t.Fatal("host-only full object store was not retained")
		}
	}
	if present, err := idx.Contains(plumbing.NewHash(shared)); err != nil || !present {
		t.Fatal("public duplicate content was incorrectly withheld")
	}
	data, err := os.ReadFile(filepath.Join(stage, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	outIndex := &index.Index{}
	if err = index.NewDecoder(bytes.NewReader(data)).Decode(outIndex); err != nil {
		t.Fatal(err)
	}
	entry, err := outIndex.Entry(".env")
	if err != nil || !entry.SkipWorktree {
		t.Fatal("held tracked secret lost skip-worktree semantics")
	}
	if rec.Bytes > opts.MaxBytes {
		t.Fatal("emitted artifact exceeds declared limit")
	}
}

func TestCapturedSHA1PlainUsesSharedSanitizerAndFrozenCapture(t *testing.T) {
	opts := hostStageFixture(t)
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed captured public bytes")
	writeHostStageFixture(t, opts.Project, ".env", "fixed requested unmask bytes")
	writeHostStageFixture(t, opts.Project, "private.txt", "fixed detector canary")
	writeHostStageFixture(t, opts.Project, "node_modules/opaque.txt", "fixed heavy cache bytes")
	opts.Unmask = []string{filepath.Join(opts.Project, ".env")}
	opts.UnmaskAsked = slices.Clone(opts.Unmask)
	changed := false
	opts.Detector = hostStageDetectorFunc(func(rel string, data []byte) (string, bool) {
		if rel == "main.txt" && !changed {
			changed = true
			writeHostStageFixture(t, opts.Project, "main.txt", "changed original after capture")
		}
		return "fixed", bytes.Contains(data, []byte("detector canary"))
	})
	roots := captureEngineFixture(t, opts)
	rec, err := stageEngineFixture(t, opts, roots)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != CopyPlain || rec.Head != "" || rec.Baseline == "" || !changed {
		t.Fatalf("invalid plain snapshot result: %+v", rec)
	}
	for rel, want := range map[string]string{"main.txt": "fixed captured public bytes", ".env": "fixed requested unmask bytes"} {
		got, err := roots.output.ReadFile(rec.RepoName + "/" + rel)
		if err != nil || string(got) != want {
			t.Fatalf("wrong captured/policy bytes at %s: %q %v", rel, got, err)
		}
	}
	for _, rel := range []string{"private.txt", "node_modules/opaque.txt"} {
		if _, err := roots.output.Stat(rec.RepoName + "/" + rel); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sanitizer bypass for %s: %v", rel, err)
		}
	}
	gitDir := filepath.Join(roots.outputPath, ".dc", "git")
	if got := fixedGit(t, roots.outputPath, "--git-dir="+gitDir, "rev-parse", "HEAD"); got != rec.Baseline {
		t.Fatal("plain synthetic history cannot be read by native Git")
	}
}

func TestCapturedSHA1DepthKeepsOriginalCommitAndShallowBoundary(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	for _, value := range []string{"fixed first", "fixed second"} {
		writeHostStageFixture(t, opts.Project, "main.txt", value)
		fixedGit(t, opts.Project, "add", "--all")
		fixedGit(t, opts.Project, "commit", "--quiet", "-m", value)
	}
	head := fixedGit(t, opts.Project, "rev-parse", "HEAD")
	opts.GitDepth = 1
	roots := captureEngineFixture(t, opts)
	rec, err := stageEngineFixture(t, opts, roots)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(roots.outputPath, rec.RepoName)
	if rec.Head != head || fixedGit(t, stage, "rev-list", "--count", "HEAD") != "1" {
		t.Fatal("configured history depth was not preserved")
	}
	data, err := roots.output.ReadFile(rec.RepoName + "/.git/shallow")
	if err != nil || string(data) != head+"\n" {
		t.Fatalf("wrong shallow boundary: %q %v", data, err)
	}
}

func compressedLooseFixture(t *testing.T, root *os.Root, h plumbing.Hash, body []byte) {
	t.Helper()
	var encoded bytes.Buffer
	writer := zlib.NewWriter(&encoded)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := capturedWrite(root, ".git/objects/"+h.String()[:2]+"/"+h.String()[2:], encoded.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func looseObjectFixture(t *testing.T, root *os.Root, kind plumbing.ObjectType, data []byte) plumbing.Hash {
	t.Helper()
	h := plumbing.ComputeHash(kind, data)
	body := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))), data...)
	compressedLooseFixture(t, root, h, body)
	return h
}

func looseTreeFixture(t *testing.T, root *os.Root, entries []object.TreeEntry) plumbing.Hash {
	t.Helper()
	encoded := &plumbing.MemoryObject{}
	if err := (&object.Tree{Entries: entries}).Encode(encoded); err != nil {
		t.Fatal(err)
	}
	r, err := encoded.Reader()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err = errors.Join(err, r.Close()); err != nil {
		t.Fatal(err)
	}
	return looseObjectFixture(t, root, plumbing.TreeObject, data)
}

func looseCommitFixture(t *testing.T, root *os.Root, tree, parent plumbing.Hash, number int) plumbing.Hash {
	t.Helper()
	parents := ""
	if parent != plumbing.ZeroHash {
		parents = "parent " + parent.String() + "\n"
	}
	data := fmt.Sprintf("tree %s\n%sauthor Fixed Fixture <fixed@example.invalid> 1700000000 +0000\ncommitter Fixed Fixture <fixed@example.invalid> 1700000000 +0000\n\nfixed commit %d\n", tree, parents, number)
	return looseObjectFixture(t, root, plumbing.CommitObject, []byte(data))
}

func TestCapturedSHA1DefaultDepthWithLargeUnchangedSubtree(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	for i := range 1000 {
		writeHostStageFixture(t, opts.Project, fmt.Sprintf("stable/file-%04d.txt", i), "fixed public subtree bytes\n")
	}
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed initial bytes\n")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed initial commit")
	head := plumbing.NewHash(fixedGit(t, opts.Project, "rev-parse", "HEAD"))
	stable := plumbing.NewHash(fixedGit(t, opts.Project, "rev-parse", "HEAD:stable"))
	branch := fixedGit(t, opts.Project, "symbolic-ref", "HEAD")
	root, err := os.OpenRoot(opts.Project)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var final string
	for i := range 110 {
		final = fmt.Sprintf("fixed public change %d\n", i)
		blob := looseObjectFixture(t, root, plumbing.BlobObject, []byte(final))
		tree := looseTreeFixture(t, root, []object.TreeEntry{
			{Name: "main.txt", Mode: filemode.Regular, Hash: blob},
			{Name: "stable", Mode: filemode.Dir, Hash: stable},
		})
		head = looseCommitFixture(t, root, tree, head, i)
	}
	writeHostStageFixture(t, opts.Project, ".git/"+branch, head.String()+"\n")
	writeHostStageFixture(t, opts.Project, "main.txt", final)
	if got := fixedGit(t, opts.Project, "rev-list", "--count", "HEAD"); got != "111" {
		t.Fatalf("native Git rejected source history: %q", got)
	}
	roots := captureEngineFixture(t, opts)
	rec, err := stageEngineFixture(t, opts, roots)
	if err != nil {
		t.Fatal(err)
	}
	guest := fixedGuestOnlyFixture(t, filepath.Join(roots.outputPath, rec.RepoName))
	if rec.Head != head.String() || fixedGit(t, guest, "rev-list", "--count", "HEAD") != "111" ||
		fixedGit(t, guest, "show", "HEAD:main.txt") != strings.TrimSpace(final) ||
		fixedGit(t, guest, "show", "HEAD~110:stable/file-0999.txt") != "fixed public subtree bytes" {
		t.Fatal("large default-depth history or unchanged subtree was lost")
	}
}

func TestCapturedSHA1HistoryMemoIncludesPathPrefix(t *testing.T) {
	store, source, _ := newEmptyObjectFixture(t)
	blob := looseObjectFixture(t, source, plumbing.BlobObject, []byte("fixed historic private bytes"))
	subtree := looseTreeFixture(t, source, []object.TreeEntry{{Name: "fixed.txt", Mode: filemode.Regular, Hash: blob}})
	tree := looseTreeFixture(t, source, []object.TreeEntry{
		{Name: "a", Mode: filemode.Dir, Hash: subtree},
		{Name: "private", Mode: filemode.Dir, Hash: subtree},
	})
	head := looseCommitFixture(t, source, tree, plumbing.ZeroHash, 0)
	if err := store.inventory(); err != nil {
		t.Fatal(err)
	}
	e := capturedStageEngine{ctx: context.Background(), store: store, objects: map[plumbing.Hash]bool{}, shallow: map[plumbing.Hash]bool{}}
	drop := map[plumbing.Hash]bool{}
	if err := e.history(head, DefaultGitDepth, func(rel string) bool { return strings.HasPrefix(rel, "private/") }, drop); err != nil {
		t.Fatal(err)
	}
	if !drop[blob] {
		t.Fatal("public subtree memo bypassed private path withholding")
	}
}

func TestCapturedSHA1NativeCruftAndMultiPackIndexAreOptional(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed reachable bytes\n")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed reachable commit")
	root, err := os.OpenRoot(opts.Project)
	if err != nil {
		t.Fatal(err)
	}
	looseObjectFixture(t, root, plumbing.BlobObject, []byte("fixed unreachable cruft bytes"))
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	fixedGit(t, opts.Project, "repack", "-ad", "--cruft")
	fixedGit(t, opts.Project, "multi-pack-index", "write")
	mtimes, err := filepath.Glob(filepath.Join(opts.Project, ".git", "objects", "pack", "*.mtimes"))
	if err != nil || len(mtimes) == 0 {
		t.Fatal("native Git did not create a real cruft pack")
	}
	if _, err := os.Stat(filepath.Join(opts.Project, ".git", "objects", "pack", "multi-pack-index")); err != nil {
		t.Fatal(err)
	}
	roots := captureEngineFixture(t, opts)
	rec, err := stageEngineFixture(t, opts, roots)
	if err != nil {
		t.Fatal(err)
	}
	guest := fixedGuestOnlyFixture(t, filepath.Join(roots.outputPath, rec.RepoName))
	if fixedGit(t, guest, "show", "HEAD:main.txt") != "fixed reachable bytes" {
		t.Fatal("optional native pack metadata broke object import")
	}
	for _, marker := range []string{"multi-pack-index", filepath.Base(mtimes[0])} {
		if _, err := os.Stat(filepath.Join(guest, ".git", "objects", "pack", marker)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("optional source metadata was copied: %s (%v)", marker, err)
		}
	}
}

func newEmptyObjectFixture(t *testing.T) (*capturedObjectStore, *os.Root, *os.Root) {
	t.Helper()
	base := t.TempDir()
	source, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if err = source.MkdirAll(".git/objects", 0o700); err != nil {
		t.Fatal(err)
	}
	if err = source.Mkdir("scratch", 0o700); err != nil {
		t.Fatal(err)
	}
	scratch, err := source.OpenRoot("scratch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scratch.Close() })
	store, err := newCapturedObjectStore(context.Background(), source, scratch)
	if err != nil {
		t.Fatal(err)
	}
	return store, source, scratch
}

func TestCapturedSHA1LooseObjectBoundsAndIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		body         []byte
	}{
		{"oversize declared", "object_size_limit", []byte("blob 33554433\x00")},
		{"oversize header", "loose_object_header_limit", bytes.Repeat([]byte{'b'}, 4096)},
		{"decompression longer than declared", "loose_object_size_mismatch", []byte("blob 1\x00fixed expanded canary")},
		{"wrong object id", "object_id_mismatch", []byte("blob 5\x00fixed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, source, _ := newEmptyObjectFixture(t)
			h := plumbing.NewHash(strings.Repeat("1", 40))
			compressedLooseFixture(t, source, h, tc.body)
			if err := store.addLocation(h, capturedObjectLocation{file: ".git/objects/" + h.String()[:2] + "/" + h.String()[2:]}); err != nil {
				t.Fatal(err)
			}
			_, err := store.EncodedObject(plumbing.AnyObject, h)
			assertCapturedReason(t, err, tc.reason)
		})
	}
}

func TestCapturedSHA1DeltaAndCumulativeLimits(t *testing.T) {
	t.Run("cumulative decoded bytes", func(t *testing.T) {
		store, source, _ := newEmptyObjectFixture(t)
		data := []byte("fixed")
		h := plumbing.ComputeHash(plumbing.BlobObject, data)
		compressedLooseFixture(t, source, h, append([]byte("blob 5\x00"), data...))
		store.locations[h] = capturedObjectLocation{file: ".git/objects/" + h.String()[:2] + "/" + h.String()[2:]}
		store.inflated = capturedDecodedMaxBytes - 1
		_, err := store.EncodedObject(plumbing.AnyObject, h)
		assertCapturedReason(t, err, "decoded_bytes_limit")
	})
	t.Run("cycle before payload read", func(t *testing.T) {
		store, _, _ := newEmptyObjectFixture(t)
		a, b := plumbing.NewHash(strings.Repeat("1", 40)), plumbing.NewHash(strings.Repeat("2", 40))
		store.locations[a] = capturedObjectLocation{kind: plumbing.REFDeltaObject, base: b, delta: true}
		store.locations[b] = capturedObjectLocation{kind: plumbing.REFDeltaObject, base: a, delta: true}
		_, err := store.EncodedObject(plumbing.AnyObject, a)
		assertCapturedReason(t, err, "delta_cycle")
	})
	t.Run("depth before payload read", func(t *testing.T) {
		store, _, _ := newEmptyObjectFixture(t)
		var ids []plumbing.Hash
		for i := 0; i < capturedDeltaMaxDepth+3; i++ {
			ids = append(ids, plumbing.ComputeHash(plumbing.BlobObject, []byte{byte(i)}))
		}
		for i := 0; i < len(ids)-1; i++ {
			store.locations[ids[i]] = capturedObjectLocation{kind: plumbing.REFDeltaObject, base: ids[i+1], delta: true}
		}
		_, err := store.EncodedObject(plumbing.AnyObject, ids[0])
		assertCapturedReason(t, err, "delta_depth_limit")
	})
	t.Run("cached dependency depth stays bounded", func(t *testing.T) {
		store, _, _ := newEmptyObjectFixture(t)
		a, b := plumbing.NewHash(strings.Repeat("1", 40)), plumbing.NewHash(strings.Repeat("2", 40))
		store.locations[a] = capturedObjectLocation{kind: plumbing.REFDeltaObject, base: b, delta: true}
		store.decoded[b] = capturedObjectLocation{kind: plumbing.BlobObject, size: 1, deltaDepth: capturedDeltaMaxDepth}
		_, err := store.EncodedObject(plumbing.AnyObject, a)
		assertCapturedReason(t, err, "delta_depth_limit")
	})
	t.Run("target size before patch allocation", func(t *testing.T) {
		var delta []byte
		for _, n := range []uint64{1, capturedObjectMaxBytes + 1} {
			for n >= 128 {
				delta = append(delta, byte(n)|128)
				n >>= 7
			}
			delta = append(delta, byte(n))
		}
		_, _, err := capturedDeltaSizes(delta)
		assertCapturedReason(t, err, "object_size_limit")
	})
	t.Run("overflow before patch allocation", func(t *testing.T) {
		_, _, err := capturedDeltaSizes(bytes.Repeat([]byte{255}, 20))
		assertCapturedReason(t, err, "delta_header_overflow")
	})
}

func TestCapturedSHA1PackIndexHeaderBoundBeforeDecoderAllocation(t *testing.T) {
	store, source, _ := newEmptyObjectFixture(t)
	var header [1032]byte
	copy(header[:], []byte{255, 't', 'O', 'c', 0, 0, 0, 2})
	binary.BigEndian.PutUint32(header[1028:], ^uint32(0))
	if err := capturedWrite(source, ".git/objects/pack/owned.idx", header[:]); err != nil {
		t.Fatal(err)
	}
	_, err := store.readPackIndex("owned.idx")
	assertCapturedReason(t, err, "pack_index_count_or_size_limit")
}

func writeSyntheticCapturedPack(t *testing.T, source *os.Root, kind plumbing.ObjectType, size int64, content []byte, reference *plumbing.Hash, badCRC bool) plumbing.Hash {
	t.Helper()
	target := plumbing.ComputeHash(plumbing.BlobObject, []byte("fixed target canary"))
	var entry []byte
	remaining := uint64(size)
	first := byte(kind)<<4 | byte(remaining&15)
	remaining >>= 4
	if remaining > 0 {
		first |= 128
	}
	entry = append(entry, first)
	for remaining > 0 {
		b := byte(remaining & 127)
		remaining >>= 7
		if remaining > 0 {
			b |= 128
		}
		entry = append(entry, b)
	}
	if reference != nil {
		entry = append(entry, reference[:]...)
	}
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	entry = append(entry, compressed.Bytes()...)
	pack := append([]byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 1}, entry...)
	sum := capturedRawHash(pack)
	pack = append(pack, sum[:]...)
	name := ".git/objects/pack/pack-" + sum.String()
	if err := capturedWrite(source, name+".pack", pack); err != nil {
		t.Fatal(err)
	}
	indexWriter := &idxfile.Writer{}
	if err := indexWriter.OnHeader(1); err != nil {
		t.Fatal(err)
	}
	crc := crc32.ChecksumIEEE(entry)
	if badCRC {
		crc ^= 1
	}
	indexWriter.Add(target, 12, crc)
	if err := indexWriter.OnFooter(sum); err != nil {
		t.Fatal(err)
	}
	idx, err := indexWriter.Index()
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if _, err = idxfile.NewEncoder(&encoded).Encode(idx); err != nil {
		t.Fatal(err)
	}
	if err = capturedWrite(source, name+".idx", encoded.Bytes()); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestCapturedSHA1MaliciousPackBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		kind         plumbing.ObjectType
		size         int64
		data         []byte
		ref          bool
		badCRC       bool
	}{
		{"oversize header before inflation", "object_size_limit", plumbing.BlobObject, capturedObjectMaxBytes + 1, nil, false, false},
		{"index CRC mismatch", "pack_index_crc_mismatch", plumbing.BlobObject, 5, []byte("fixed"), false, true},
		{"index OID mismatch", "object_id_mismatch", plumbing.BlobObject, 5, []byte("fixed"), false, false},
		{"thin missing base", "missing_object_or_thin_pack", plumbing.REFDeltaObject, 4, []byte{1, 1, 1, 'b'}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, source, scratch := newEmptyObjectFixture(t)
			var reference *plumbing.Hash
			if tc.ref {
				h := plumbing.ComputeHash(plumbing.BlobObject, []byte("fixed absent base"))
				reference = &h
			}
			target := writeSyntheticCapturedPack(t, source, tc.kind, tc.size, tc.data, reference, tc.badCRC)
			store := &capturedObjectStore{ctx: context.Background(), source: source, scratch: scratch, locations: map[plumbing.Hash]capturedObjectLocation{}, decoded: map[plumbing.Hash]capturedObjectLocation{}}
			err := store.inventory()
			if err == nil {
				_, err = store.EncodedObject(plumbing.AnyObject, target)
			}
			assertCapturedReason(t, err, tc.reason)
		})
	}
	t.Run("inflated stream exceeds declared size", func(t *testing.T) {
		_, source, scratch := newEmptyObjectFixture(t)
		writeSyntheticCapturedPack(t, source, plumbing.BlobObject, 1, []byte("fixed overflow canary"), nil, false)
		store := &capturedObjectStore{ctx: context.Background(), source: source, scratch: scratch, locations: map[plumbing.Hash]capturedObjectLocation{}, decoded: map[plumbing.Hash]capturedObjectLocation{}}
		if err := store.inventory(); !errors.Is(err, packfile.ErrInflatedSizeMismatch) {
			t.Fatalf("inflated overrun accepted: %v", err)
		}
	})
}

func TestCapturedSHA1UnsupportedFeaturesRefuseExplicitly(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*testing.T, StageOptions)
	}{
		{"sha256", "repository_extension_not_supported", func(t *testing.T, o StageOptions) {
			f, err := os.OpenFile(filepath.Join(o.Project, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteString("\n[extensions]\nobjectformat = sha256\n")
			err = errors.Join(err, f.Close())
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"filter", "config_feature_not_supported", func(t *testing.T, o StageOptions) {
			fixedGit(t, o.Project, "config", "filter.fixed.clean", "must-not-execute")
		}},
		{"attributes", "attributes_not_supported", func(t *testing.T, o StageOptions) {
			writeHostStageFixture(t, o.Project, ".gitattributes", "*.txt text=auto\n")
		}},
		{"Windows attributes casing", "attributes_not_supported", func(t *testing.T, o StageOptions) {
			writeHostStageFixture(t, o.Project, ".GiTaTtRiBuTeS", "*.txt text=auto\n")
		}},
		{"Windows metadata alias in index", "git_metadata_path_not_supported", func(t *testing.T, o StageOptions) {
			idx := &index.Index{Version: 2}
			entry := idx.Add(".GiT/config")
			entry.Mode = filemode.Regular
			entry.Hash = plumbing.NewHash(strings.Repeat("1", 40))
			var data bytes.Buffer
			if err := index.NewEncoder(&data).Encode(idx); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(o.Project, ".git", "index"), data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"alternates", "external_or_extended_git_metadata_not_supported", func(t *testing.T, o StageOptions) {
			writeHostStageFixture(t, o.Project, ".git/objects/info/alternates", "fixed public unused canary\n")
		}},
		{"split index", "mandatory_index_extension_not_supported", func(t *testing.T, o StageOptions) {
			data, err := os.ReadFile(filepath.Join(o.Project, ".git", "index"))
			if err != nil {
				t.Fatal(err)
			}
			data = append(data[:len(data)-20], []byte{'l', 'i', 'n', 'k', 0, 0, 0, 0}...)
			sum := capturedRawHash(data)
			data = append(data, sum[:]...)
			if err = os.WriteFile(filepath.Join(o.Project, ".git", "index"), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"submodule index", "symlink_or_submodule_not_supported", func(t *testing.T, o StageOptions) {
			idx := &index.Index{Version: 2}
			entry := idx.Add("module")
			entry.Mode = filemode.Submodule
			entry.Hash = plumbing.NewHash(strings.Repeat("1", 40))
			var data bytes.Buffer
			if err := index.NewEncoder(&data).Encode(idx); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(o.Project, ".git", "index"), data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := hostStageFixture(t)
			setupCapturedGitFixture(t, opts)
			writeHostStageFixture(t, opts.Project, "main.txt", "fixed public bytes")
			fixedGit(t, opts.Project, "add", "--all")
			fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed commit")
			tc.mutate(t, opts)
			roots := captureEngineFixture(t, opts)
			_, err := stageEngineFixture(t, opts, roots)
			assertCapturedReason(t, err, tc.reason)
		})
	}
}

func TestCapturedSHA1WindowsMetadataCasingAndTrackedCasing(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	writeHostStageFixture(t, opts.Project, "Main.txt", "fixed original tracked casing")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed first")
	if err := os.Rename(filepath.Join(opts.Project, "Main.txt"), filepath.Join(opts.Project, "main.txt")); err != nil {
		t.Fatal(err)
	}
	// A directory case-only MoveFileEx can refuse with AccessDenied even
	// without an open handle. Two exact owned names preserve the casing test.
	intermediate := filepath.Join(opts.Project, ".fixed-case-rename")
	if err := os.Rename(filepath.Join(opts.Project, ".git"), intermediate); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(intermediate, filepath.Join(opts.Project, ".GiT")); err != nil {
		t.Fatal(err)
	}
	roots := captureEngineFixture(t, opts)
	rec, err := stageEngineFixture(t, opts, roots)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Files != 1 {
		t.Fatalf("Git metadata was copied as working files or tracked case duplicated: %d", rec.Files)
	}
	data, err := roots.output.ReadFile(rec.RepoName + "/Main.txt")
	if err != nil || string(data) != "fixed original tracked casing" {
		t.Fatalf("tracked index casing was not preserved: %q %v", data, err)
	}
}

func TestCapturedSHA1NativeIgnoreMismatchesRefuseInsteadOfSharing(t *testing.T) {
	for _, tc := range []struct{ name, pattern, rel, reason string }{
		{"UTF8 question mark byte semantics", "??", "é", "nonascii_untracked_path_not_supported"},
		{"embedded double star", "dir/foo**bar", "dir/fooxbar", "double_star_ignore_not_supported"},
		{"whole component double star backtracking", "a/**/b/c/fixed.txt", "a/x/b/x/b/c/fixed.txt", "double_star_ignore_not_supported"},
		{"Git negated character class", "[!a].txt", "b.txt", "ignore_syntax_not_supported"},
		{"POSIX character class", "[[:digit:]].txt", "7.txt", "ignore_syntax_not_supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := hostStageFixture(t)
			setupCapturedGitFixture(t, opts)
			writeHostStageFixture(t, opts.Project, ".gitignore", tc.pattern+"\n")
			writeHostStageFixture(t, opts.Project, tc.rel, "fixed ignored public canary")
			// This independently establishes the native behavior being protected,
			// rather than testing the candidate matcher against itself.
			if got := fixedGit(t, opts.Project, "check-ignore", "-v", "--no-index", "--", tc.rel); got == "" {
				t.Fatal("native Git did not ignore the fixed fixture")
			}
			if got := fixedGit(t, opts.Project, "ls-files", "--others", "--exclude-standard", "--", tc.rel); got != "" {
				t.Fatalf("fixture is not omitted by native staging selection: %q", got)
			}
			roots := captureEngineFixture(t, opts)
			_, err := stageEngineFixture(t, opts, roots)
			assertCapturedReason(t, err, tc.reason)
			if _, err := roots.output.Stat(RepoName(opts.Project) + "/" + tc.rel); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused ignored candidate was emitted: %v", err)
			}
		})
	}
}

func TestCapturedSHA1TrackedUnicodeIsPreservedWithoutIgnoreMatching(t *testing.T) {
	opts := hostStageFixture(t)
	setupCapturedGitFixture(t, opts)
	writeHostStageFixture(t, opts.Project, "é", "fixed tracked Unicode canary")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed Unicode fixture")
	writeHostStageFixture(t, opts.Project, ".gitignore", "??\n")
	roots := captureEngineFixture(t, opts)
	rec, err := stageEngineFixture(t, opts, roots)
	if err != nil {
		t.Fatal(err)
	}
	data, err := roots.output.ReadFile(rec.RepoName + "/é")
	if err != nil || string(data) != "fixed tracked Unicode canary" {
		t.Fatalf("tracked Unicode was incorrectly subjected to ignores: %q %v", data, err)
	}
}

func TestCapturedSHA1IgnoreWorkIsBounded(t *testing.T) {
	_, source, scratch := newEmptyObjectFixture(t)
	if err := capturedWrite(source, ".gitignore", bytes.Repeat([]byte("x\n"), 10_000)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1001; i++ {
		if err := capturedWrite(source, fmt.Sprintf("fixed%d.txt", i), []byte("fixed")); err != nil {
			t.Fatal(err)
		}
	}
	e := &capturedStageEngine{ctx: context.Background(), source: source, scratch: scratch}
	_, _, err := e.candidates(nil, true)
	assertCapturedReason(t, err, "ignore_matching_work_limit")
}

func TestCapturedSHA1RefusesMissingOperatorFactsAndOutputOverflow(t *testing.T) {
	opts := hostStageFixture(t)
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed captured bytes")
	roots := captureEngineFixture(t, opts)
	_, err := stageCapturedSHA1(context.Background(), roots.capture, roots.output, roots.scratch, opts, stageSecretOptions(opts, opts.Project), capturedGitSettings{})
	assertCapturedReason(t, err, "operator_settings_not_frozen")
	opts.MaxBytes = 64
	_, err = stageEngineFixture(t, opts, roots)
	assertCapturedReason(t, err, "emitted_bytes_limit")
}

func TestCapturedSHA1IgnoreBytesAndWeightedWorkAreBounded(t *testing.T) {
	for _, kind := range []string{"one pattern", "aggregate domains and patterns", "weighted comparison"} {
		t.Run(kind, func(t *testing.T) {
			_, source, scratch := newEmptyObjectFixture(t)
			var content string
			want := "ignore_pattern_bytes_limit"
			switch kind {
			case "one pattern":
				content = strings.Repeat("a", capturedPathMaxBytes+1) + "\n"
			case "aggregate domains and patterns":
				content = strings.Repeat("x\n", 40_000)
			case "weighted comparison":
				content = strings.Repeat(strings.Repeat("a", 4000)+"\n", 100)
				want = "ignore_matching_work_limit"
				for i := 0; i < 50; i++ {
					name := fmt.Sprintf("%02d-%s", i, strings.Repeat("b", 247))
					if err := capturedWrite(source, name, []byte("fixed")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := capturedWrite(source, ".gitignore", []byte(content)); err != nil {
				t.Fatal(err)
			}
			e := &capturedStageEngine{ctx: context.Background(), source: source, scratch: scratch}
			_, _, err := e.candidates(nil, true)
			assertCapturedReason(t, err, want)
		})
	}
}

func TestCapturedSHA1TransientSelectionIOCannotBypassScanning(t *testing.T) {
	for _, kind := range []string{"read", "stat"} {
		t.Run(kind, func(t *testing.T) {
			_, source, _ := newEmptyObjectFixture(t)
			if err := capturedWrite(source, "fixed.txt", []byte("fixed detector canary")); err != nil {
				t.Fatal(err)
			}
			stats, reads := 0, 0
			selection := selectionIO{stat: func(rel string) (fs.FileInfo, error) {
				stats++
				if kind == "stat" && stats == 1 {
					return nil, io.ErrUnexpectedEOF
				}
				return source.Lstat(rel)
			}, read: func(rel string, n int64) ([]byte, error) {
				reads++
				if kind == "read" && reads == 1 {
					return nil, io.ErrUnexpectedEOF
				}
				return capturedRead(source, rel, n)
			}}
			scan := secretScanOptions{contentScan: true, detector: hostStageDetectorFunc(func(_ string, data []byte) (string, bool) {
				return "fixed", bytes.Contains(data, []byte("detector canary"))
			})}
			files, _, err := selectCapturedFiles(selection, []string{"fixed.txt"}, scan, 1<<20, &CopyRecord{})
			assertCapturedReason(t, err, "captured_selection_io_failed")
			if !errors.Is(err, io.ErrUnexpectedEOF) || files != nil {
				t.Fatalf("transient failure lost its cause or permitted emission: %v %v", files, err)
			}
			// Prove the same captured file is readable afterward: an unchecked
			// second staging read would have emitted the detector-bearing bytes.
			data, err := selection.read("fixed.txt", 1<<20)
			if err != nil || string(data) != "fixed detector canary" {
				t.Fatalf("fixture did not model read recovery: %q %v", data, err)
			}
		})
	}
}
