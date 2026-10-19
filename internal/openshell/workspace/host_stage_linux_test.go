// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspace

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"golang.org/x/sys/unix"
)

// All fixtures are inert filesystem data. No Git, image, child, namespace,
// mount, filter or native worker is executed by this test file.
func linuxHostStageFixture(t *testing.T) StageOptions {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "operator-home")
	project := filepath.Join(home, "project with spaces")
	data := filepath.Join(base, "private-data")
	for _, name := range []string{project, data} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	// Fixed optional config files make precedence independent of host settings.
	writeLinuxHostFixture(t, home, ".gitconfig", "", 0o600)
	writeLinuxHostFixture(t, home, "xdg/git/config", "", 0o600)
	return StageOptions{Name: "linux-capture", Project: project, DataDir: data, Home: home, MaxBytes: 8 << 20, Masks: []string{".env"}}
}

func writeLinuxHostFixture(t *testing.T, base, name, value string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(base, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}

func linuxHostReadAt(t *testing.T, parent *os.File, name string) []byte {
	t.Helper()
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "fixed-test-child")
	data, readErr := io.ReadAll(io.LimitReader(file, 1024))
	if err = errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHostStageLinuxSanitizedCopyHeldRootAndCleanupBarrier(t *testing.T) {
	opts := linuxHostStageFixture(t)
	writeLinuxHostFixture(t, opts.Project, "public.txt", "fixed public capture bytes", 0o600)
	writeLinuxHostFixture(t, opts.Project, ".env", "fixed-private-canary=withhold", 0o600)
	writeLinuxHostFixture(t, opts.Project, "script.sh", "fixed public executable bytes", 0o700)
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	var lease *RootLease
	t.Cleanup(func() {
		if lease != nil {
			_ = lease.Close()
		}
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	})
	if !slices.Contains(stage.Summary().HeldBack, ".env") || !strings.HasPrefix(stage.Summary().SourceIdentity, "linux:") {
		t.Fatal("shared sanitizer or held source identity was not retained")
	}
	lease, err = stage.AcquireRoot()
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := lease.File()
	if err != nil {
		t.Fatal(err)
	}
	copy, err := lease.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	originalID, err := linuxHostInfo(borrowed, true)
	if err != nil {
		t.Fatal(err)
	}
	copyID, err := linuxHostInfo(copy, true)
	if err != nil || !originalID.sameObject(copyID) || borrowed.Fd() == copy.Fd() {
		t.Fatal("exclusive copy changed identity or reused borrowed descriptor")
	}
	flags, err := unix.FcntlInt(copy.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("exclusive copy was inheritable")
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	if string(linuxHostReadAt(t, borrowed, "public.txt")) != "fixed public capture bytes" {
		t.Fatal("sanitized content changed")
	}
	if fd, err := unix.Openat(int(borrowed.Fd()), ".env", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); !errors.Is(err, unix.ENOENT) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatal("secret-name bytes entered sanitized root")
	}
	var script unix.Stat_t
	if err := unix.Fstatat(int(borrowed.Fd()), "script.sh", &script, unix.AT_SYMLINK_NOFOLLOW); err != nil || script.Mode&0o777 != 0o700 {
		t.Fatal("private executable working-file mode was not materialized")
	}
	// Change the display path and rename its parent. Consumer and cleanup
	// authority must remain with the held original directory, not the decoy.
	moved := opts.DataDir + "-moved"
	if err := os.Rename(opts.DataDir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLinuxHostFixture(t, opts.DataDir, "decoy", "fixed decoy must survive", 0o600)
	stage.record.Stage = filepath.Join(opts.DataDir, "decoy")
	if err := stage.Close(); !errors.Is(err, ErrHostStageInUse) {
		t.Fatal("premature Close did not retain consumer custody")
	}
	if string(linuxHostReadAt(t, borrowed, "public.txt")) != "fixed public capture bytes" {
		t.Fatal("premature Close deleted a still-owned child")
	}
	if _, err := stage.AcquireRoot(); err == nil {
		t.Fatal("close request allowed new acquisition")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 0 {
		t.Fatal("held parent cleanup left stage residue")
	}
	if data, err := os.ReadFile(filepath.Join(opts.DataDir, "decoy")); err != nil || string(data) != "fixed decoy must survive" {
		t.Fatal("cleanup followed the replaced display parent")
	}
}

type linuxHostCaptureMutation struct {
	t       *testing.T
	source  string
	mutated bool
}

func (d *linuxHostCaptureMutation) DetectSecret(rel string, data []byte) (string, bool) {
	if rel == "public.txt" {
		d.mutated = true
		writeLinuxHostFixture(d.t, d.source, "public.txt", "changed original after complete capture", 0o600)
	}
	return "", false
}

func TestHostStageLinuxSanitizerNeverReopensOriginalSource(t *testing.T) {
	opts := linuxHostStageFixture(t)
	writeLinuxHostFixture(t, opts.Project, "public.txt", "fixed captured bytes", 0o600)
	detector := &linuxHostCaptureMutation{t: t, source: opts.Project}
	opts.Detector = detector
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	}()
	path, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(filepath.Join(path, "public.txt")); err != nil || string(value) != "fixed captured bytes" || !detector.mutated {
		t.Fatal("sanitizer read mutable original content instead of retained capture")
	}
}

func TestHostStageLinuxRefusesUnsafeEntriesAndCaptureLimits(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "case-collision", "size", "entries", "private-parent"} {
		t.Run(kind, func(t *testing.T) {
			opts := linuxHostStageFixture(t)
			writeLinuxHostFixture(t, opts.Project, "public.txt", "fixed public bytes", 0o600)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("public.txt", filepath.Join(opts.Project, "link"))
			case "hardlink":
				err = os.Link(filepath.Join(opts.Project, "public.txt"), filepath.Join(opts.Project, "link"))
			case "fifo":
				err = unix.Mkfifo(filepath.Join(opts.Project, "pipe"), 0o600)
			case "case-collision":
				writeLinuxHostFixture(t, opts.Project, "PUBLIC.txt", "other public bytes", 0o600)
			case "size":
				opts.MaxBytes = 1
			case "entries":
				opts.MaxWalkEntries = 1
				writeLinuxHostFixture(t, opts.Project, "second.txt", "fixed second bytes", 0o600)
			case "private-parent":
				err = os.Chmod(opts.DataDir, 0o755)
			}
			if err != nil {
				t.Fatal(err)
			}
			if stage, err := PrepareHostStage(context.Background(), opts); err == nil || stage != nil {
				if stage != nil {
					_ = stage.Close()
				}
				t.Fatal("unsafe entry or capture limit was accepted")
			}
			if entries, err := os.ReadDir(opts.DataDir); err != nil || len(entries) != 0 {
				t.Fatal("safe refusal failed to remove its owned empty/partial capture")
			}
		})
	}
}

func TestHostStageLinuxFrozenGitSettingsAndUnbornRepository(t *testing.T) {
	opts := linuxHostStageFixture(t)
	writeLinuxHostFixture(t, opts.Project, ".git/config", "[core]\nrepositoryformatversion=0\nautocrlf=false\n", 0o600)
	writeLinuxHostFixture(t, opts.Project, ".git/HEAD", "ref: refs/heads/main\n", 0o600)
	if err := os.MkdirAll(filepath.Join(opts.Project, ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeLinuxHostFixture(t, opts.Home, ".gitconfig", "[core]\neol=lf\n", 0o600)
	writeLinuxHostFixture(t, opts.Project, "public.txt", "fixed unborn content\n", 0o600)
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if summary := stage.Summary(); summary.Kind != CopyGit || summary.Baseline == "" || summary.Head != "" || summary.LineEndings["core.eol"] != "lf" {
		t.Fatal("shared captured engine lost unborn repository or frozen fallback settings")
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	writeLinuxHostFixture(t, opts.Home, ".gitconfig", "[include]\npath=must-not-open\n", 0o600)
	if stage, err := PrepareHostStage(context.Background(), opts); err == nil || stage != nil {
		t.Fatal("operator config include was silently ignored")
	}
	if entries, err := os.ReadDir(opts.DataDir); err != nil || len(entries) != 0 {
		t.Fatal("operator settings refusal left owned residue")
	}
}

func TestHostStageLinuxCanceledAndMountCrossingRefuse(t *testing.T) {
	opts := linuxHostStageFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stage, err := PrepareHostStage(ctx, opts); stage != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preparation acquired stage custody")
	}
	access, err := newLinuxHostAccess()
	if err != nil {
		t.Fatal(err)
	}
	defer access.close()
	if file, err := access.absolute("/proc"); err == nil {
		_ = file.Close()
		t.Fatal("root-mount-only floor crossed procfs mount")
	}
	if entries, err := os.ReadDir(opts.DataDir); err != nil || len(entries) != 0 {
		t.Fatal("canceled preparation mutated staging parent")
	}
	// Unsupported lookup is never reinterpreted as an absent config.
	if linuxHostMissing(unix.ELOOP) || linuxHostMissing(unix.EXDEV) || linuxHostMissing(unix.EAGAIN) || !linuxHostMissing(fs.ErrNotExist) {
		t.Fatal("unsupported config lookup was mislabeled absent")
	}
}

func TestHostStageLinuxComponentWalkExistingTreeAndAncestorRefusals(t *testing.T) {
	opts := linuxHostStageFixture(t)
	access, err := newLinuxHostAccess()
	if err != nil {
		t.Fatal(err)
	}
	defer access.close()
	// Fresh ordinary directories need no cached-only preflight or cache warmup.
	nested := filepath.Join(opts.Project, "fresh", "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	pin, err := access.absolute(nested)
	if err != nil {
		t.Fatal(err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(opts.Home, "linked-parent")
	if err := os.Symlink(opts.Project, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{alias, filepath.Join(alias, "fresh", "nested"), "/proc", "/proc/self"} {
		if pin, err := access.absolute(path); err == nil || pin != nil {
			if pin != nil {
				_ = pin.Close()
			}
			t.Fatal("held walk accepted a terminal/ancestor symlink or crossed a mount")
		}
	}
	if pin, err := access.absolute(filepath.Join(opts.Project, "not-created")); pin != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing component became a usable directory")
	}
}

func TestHostStageLinuxComponentBoundaryRejectsTraversalBeforeIO(t *testing.T) {
	for _, name := range []string{"", ".", "..", "/tmp", "parent/child", "child/", "a\x00b", strings.Repeat("a", 256)} {
		// A nil parent is safe only because invalid names refuse before I/O.
		if file, err := linuxHostOpen(nil, name); file != nil || err == nil {
			t.Fatal("unsupported component reached the native open boundary")
		}
	}
	how, err := linuxHostOpenHow("existing-child")
	if err != nil || how.Mode != 0 || how.Flags != unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC ||
		how.Resolve != unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_XDEV {
		t.Fatal("component open acquired directory/open intent or lost a confinement constraint")
	}
}

func TestHostStageLinuxTrackedExecuteModeAgreementAndRefusal(t *testing.T) {
	for _, row := range []struct {
		name       string
		working    os.FileMode
		indexMode  filemode.FileMode
		wantRefuse bool
	}{
		{"regular", 0o600, filemode.Regular, false},
		{"executable", 0o700, filemode.Executable, false},
		{"working-chmod-add", 0o700, filemode.Regular, true},
		{"working-chmod-remove", 0o600, filemode.Executable, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			opts := linuxHostStageFixture(t)
			writeLinuxHostFixture(t, opts.Project, ".git/config", "[core]\nrepositoryformatversion=0\n", 0o600)
			writeLinuxHostFixture(t, opts.Project, ".git/HEAD", "ref: refs/heads/main\n", 0o600)
			if err := os.MkdirAll(filepath.Join(opts.Project, ".git", "objects"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeLinuxHostFixture(t, opts.Project, "script.sh", "fixed public executable mode bytes", row.working)
			// An inert unborn repository needs no process or object discovery.
			// The index mode is independent of the working file's POSIX mode.
			var encoded bytes.Buffer
			idx := &index.Index{Version: 2, Entries: []*index.Entry{{Name: "script.sh", Mode: row.indexMode, Hash: plumbing.NewHash("1111111111111111111111111111111111111111")}}}
			if err := index.NewEncoder(&encoded).Encode(idx); err != nil {
				t.Fatal(err)
			}
			writeLinuxHostFixture(t, opts.Project, ".git/index", encoded.String(), 0o600)
			stage, err := PrepareHostStage(context.Background(), opts)
			if row.wantRefuse {
				var refusal *CapturedGitError
				if stage != nil || !errors.As(err, &refusal) || refusal.Reason != "working_executable_mode_differs_from_index" {
					if stage != nil {
						_ = stage.Close()
					}
					t.Fatalf("chmod-only discrepancy was not explicitly refused: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				path, err := stage.TreePath()
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(filepath.Join(path, "script.sh"))
				if err != nil || info.Mode().Perm() != row.working {
					t.Fatal("accepted copied file mode differs from captured mode")
				}
				file, err := os.Open(filepath.Join(path, ".git", "index"))
				if err != nil {
					t.Fatal(err)
				}
				var decoded index.Index
				decodeErr := index.NewDecoder(file).Decode(&decoded)
				if err := errors.Join(decodeErr, file.Close()); err != nil || len(decoded.Entries) != 0 {
					t.Fatal("guest index no longer represents the original unborn HEAD")
				}
				// The guest index reflects original HEAD, while the separate
				// synthetic baseline records the captured working tree.
				commit := linuxHostReadBaselineObject(t, path, stage.Summary().Baseline, plumbing.CommitObject)
				line, _, ok := bytes.Cut(commit, []byte{'\n'})
				if !ok || len(line) != 45 || !bytes.HasPrefix(line, []byte("tree ")) {
					t.Fatal("synthetic baseline has no exact tree object reference")
				}
				tree := linuxHostReadBaselineObject(t, path, string(line[5:]), plumbing.TreeObject)
				prefix := []byte(fmt.Sprintf("%o script.sh\x00", row.indexMode))
				blob := plumbing.ComputeHash(plumbing.BlobObject, []byte("fixed public executable mode bytes"))
				if len(tree) != len(prefix)+len(blob) || !bytes.Equal(tree[:len(prefix)], prefix) || !bytes.Equal(tree[len(prefix):], blob[:]) {
					t.Fatal("synthetic baseline tree changed the captured mode, path or public blob")
				}
				if err := stage.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if entries, err := os.ReadDir(opts.DataDir); err != nil || len(entries) != 0 {
				t.Fatal("mode-admission or explicit close left owned stage residue")
			}
		})
	}
}

func linuxHostReadBaselineObject(t *testing.T, tree, oid string, kind plumbing.ObjectType) []byte {
	t.Helper()
	if len(oid) != 40 || plumbing.NewHash(oid).String() != oid {
		t.Fatal("invalid fixture baseline object identifier")
	}
	// This unborn fixture has no withheld historical objects, so its public
	// baseline objects are loose in the guest repository's own object store.
	file, err := os.Open(filepath.Join(tree, ".git", "objects", oid[:2], oid[2:]))
	if err != nil {
		t.Fatal(err)
	}
	compressed, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err := errors.Join(readErr, file.Close()); err != nil || len(compressed) > 1<<20 {
		t.Fatal("baseline fixture object is unreadable or exceeds its bound")
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
	if err := errors.Join(readErr, reader.Close()); err != nil || len(decoded) > 1<<20 {
		t.Fatal("baseline fixture object inflate failed or exceeded its bound")
	}
	header, body, ok := bytes.Cut(decoded, []byte{0})
	// SHA1 is the Git-format content address here, not runtime provenance.
	if !ok || string(header) != fmt.Sprintf("%s %d", kind, len(body)) || plumbing.ComputeHash(kind, body).String() != oid {
		t.Fatal("baseline fixture object header or Git content address disagrees")
	}
	return body
}

func TestHostStageLinuxInitialSourceSnapshotChangeRefusesBeforeCopy(t *testing.T) {
	opts := linuxHostStageFixture(t)
	writeLinuxHostFixture(t, opts.Project, "public.txt", "fixed public source bytes", 0o600)
	access, err := newLinuxHostAccess()
	if err != nil {
		t.Fatal(err)
	}
	defer access.close()
	source, err := access.absolute(opts.Project)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	expected, err := linuxHostInfo(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(opts.Project, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(opts.Project, 0o700)
	output, err := os.OpenRoot(opts.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	budget := linuxHostCaptureBudget{limit: 1 << 20, remaining: 100}
	if err := access.capture(context.Background(), source, expected, output, "", 0, &budget); err == nil {
		t.Fatal("source changed after initial admission but was recaptured under a new snapshot")
	}
	if entries, err := os.ReadDir(opts.DataDir); err != nil || len(entries) != 0 {
		t.Fatal("initial source snapshot refusal copied data")
	}
}

func TestHostStageLinuxPartialRootCloseFailureRetainsCleanupOwner(t *testing.T) {
	// Opaque values and injected closer only: no real filesystem operation.
	failure := errors.New("fixed uncertain native root close")
	cause := errors.New("fixed preparation refusal")
	root, parent := new(os.Root), new(os.File)
	calls := 0
	owner := &linuxHostStageOwner{parent: parent, roots: [3]*os.Root{root}, created: true,
		closeRoot: func(*os.Root) error { calls++; return failure }}
	stage, err := owner.refused(cause)
	if stage == nil || !stage.cleanupOnly || !errors.Is(err, cause) || !errors.Is(err, failure) || calls != 1 {
		t.Fatal("pre-return uncertainty dropped its cleanup owner or failure")
	}
	if lease, err := stage.AcquireRoot(); lease != nil || err == nil {
		t.Fatal("cleanup-only stage issued a usable lease")
	}
	if path, err := stage.TreePath(); path != "" || err == nil {
		t.Fatal("cleanup-only stage exposed a prepared tree path")
	}
	first, second := stage.Close(), stage.Close()
	if !errors.Is(first, failure) || !errors.Is(second, failure) || calls != 1 || owner.roots[0] != root || owner.parent != parent || owner.deleted {
		t.Fatal("uncertain close was repeated, lost ownership or allowed deletion")
	}
}

func TestHostStageLinuxCleanupOnlyKnownRefusalCanRetry(t *testing.T) {
	// The concrete owner latches native uncertainty. This pure state test
	// covers retry of a known bounded no-success result, without any I/O.
	calls := 0
	stage := &HostStage{cleanupOnly: true, closeRequested: true, close: func() error {
		calls++
		if calls == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}}
	if err := stage.Close(); !errors.Is(err, context.DeadlineExceeded) || stage.closed {
		t.Fatal("known partial cleanup refusal erased retry ownership")
	}
	if err := stage.Close(); err != nil || !stage.closed || calls != 2 {
		t.Fatal("explicit cleanup-only retry did not finish")
	}
	if err := stage.Close(); err != nil || calls != 2 {
		t.Fatal("completed cleanup was repeated")
	}
}
