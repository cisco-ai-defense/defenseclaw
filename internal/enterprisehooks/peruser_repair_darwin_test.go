//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/unix"
)

type capturedMarker struct {
	marker string
	fields map[string]string
}

// perUserRepairFixture builds a temp "home" owned by the test user with a
// ~/.defenseclaw tree and a Claude config, and runs the repair as if the
// test process were the root guardian.
type perUserRepairFixture struct {
	t       *testing.T
	home    string
	dataDir string
	config  string
	markers []capturedMarker
	mu      sync.Mutex
}

func newPerUserRepairFixture(t *testing.T) *perUserRepairFixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	f := &perUserRepairFixture{
		t:       t,
		home:    home,
		dataDir: filepath.Join(home, ".defenseclaw"),
		config:  filepath.Join(home, ".claude", "settings.json"),
	}
	for _, dir := range []string{home, filepath.Join(f.dataDir, "hooks"), filepath.Dir(f.config)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(home, 0o750); err != nil {
		t.Fatal(err)
	}
	f.write(filepath.Join(f.dataDir, "hooks", "claude-code-hook.sh"), 0o700)
	f.write(filepath.Join(f.dataDir, "hooks", ".hook-claudecode.token"), 0o600)
	f.write(filepath.Join(f.dataDir, ".codex-lifecycle.lock"), 0o600)
	f.write(f.config, 0o600)

	previousPrivileged, previousPaths, previousSink := userRepairPrivileged, userAgentConfigPaths, managed.ReportResilienceEvent
	userRepairPrivileged = func() bool { return true }
	userAgentConfigPaths = func(InstallOptions) []string { return []string{f.config} }
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		copied := map[string]string{}
		for k, v := range fields {
			copied[k] = v
		}
		f.markers = append(f.markers, capturedMarker{marker: marker, fields: copied})
	}
	resetUserRepairState()
	t.Cleanup(func() {
		userRepairPrivileged, userAgentConfigPaths, managed.ReportResilienceEvent = previousPrivileged, previousPaths, previousSink
		resetUserRepairState()
		// Leave nothing immutable behind for TempDir cleanup.
		_ = filepath.Walk(root, func(path string, _ os.FileInfo, _ error) error {
			_ = unix.Chflags(path, 0)
			return nil
		})
	})
	return f
}

func resetUserRepairState() {
	userRepairState.Lock()
	userRepairState.lastRun = map[string]time.Time{}
	userRepairState.skips = map[string]string{}
	userRepairState.Unlock()
}

func (f *perUserRepairFixture) write(path string, mode os.FileMode) {
	f.t.Helper()
	if err := os.WriteFile(path, []byte("content\n"), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *perUserRepairFixture) opts() InstallOptions {
	return InstallOptions{UserHome: f.home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid()}
}

func (f *perUserRepairFixture) repair() error {
	resetUserRepairState()
	f.mu.Lock()
	f.markers = nil
	f.mu.Unlock()
	return RepairUserTarget(f.opts(), "user:fixture")
}

func (f *perUserRepairFixture) marked(marker, path, reasonPart string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.markers {
		if m.marker == marker && m.fields["path"] == path && strings.Contains(m.fields["reason"], reasonPart) {
			return true
		}
	}
	return false
}

func (f *perUserRepairFixture) count(marker string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.markers {
		if m.marker == marker {
			n++
		}
	}
	return n
}

func statOf(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func hasACL(t *testing.T, path string) bool {
	t.Helper()
	out, err := exec.Command("/bin/ls", "-led", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ls -led %s: %v %s", path, err, out)
	}
	return listingHasACL(out)
}

func addWriteACL(t *testing.T, path string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write,append,delete", path).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a %s: %v %s", path, err, out)
	}
}

func TestRepairUserTargetRepairsDefenseClawTreeDrift(t *testing.T) {
	f := newPerUserRepairFixture(t)
	script := filepath.Join(f.dataDir, "hooks", "claude-code-hook.sh")
	token := filepath.Join(f.dataDir, "hooks", ".hook-claudecode.token")
	lock := filepath.Join(f.dataDir, ".codex-lifecycle.lock")
	hooksDir := filepath.Join(f.dataDir, "hooks")

	if err := os.Chmod(f.dataDir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lock, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(token, 0o400); err != nil {
		t.Fatal(err)
	}
	addWriteACL(t, hooksDir)
	addWriteACL(t, token)
	if err := unix.Chflags(script, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}

	if err := f.repair(); err != nil {
		t.Fatalf("repair: %v", err)
	}
	for path, want := range map[string]uint32{
		f.dataDir: 0o700,
		hooksDir:  0o700,
		script:    0o700,
		lock:      0o600,
		token:     0o600,
	} {
		st := statOf(t, path)
		if got := uint32(st.Mode) & 0o7777; got != want {
			t.Errorf("%s mode = %04o, want %04o", path, got, want)
		}
		if st.Flags&(unix.UF_IMMUTABLE|unix.UF_APPEND) != 0 {
			t.Errorf("%s still carries write-blocking flags %#x", path, st.Flags)
		}
		if hasACL(t, path) {
			t.Errorf("%s still has an ACL", path)
		}
	}
	for _, path := range []string{f.dataDir, script, lock, token, hooksDir} {
		if !f.marked(managed.MarkerRepair, path, "") {
			t.Errorf("no defenseclaw_repair marker for %s: %+v", path, f.markers)
		}
	}

	// A second pass over a canonical tree changes and logs nothing.
	if err := f.repair(); err != nil {
		t.Fatalf("second repair: %v", err)
	}
	if n := f.count(managed.MarkerRepair); n != 0 {
		t.Fatalf("idempotent pass logged %d repairs: %+v", n, f.markers)
	}
}

func TestRepairUserTargetRestoresGroupOwnership(t *testing.T) {
	f := newPerUserRepairFixture(t)
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	other := -1
	for _, g := range groups {
		if g != os.Getgid() {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("the test user belongs to no second group")
	}
	script := filepath.Join(f.dataDir, "hooks", "claude-code-hook.sh")
	if err := os.Lchown(script, -1, other); err != nil {
		t.Skipf("cannot change the test file group: %v", err)
	}
	if err := f.repair(); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if st := statOf(t, script); int(st.Gid) != os.Getgid() {
		t.Fatalf("group = %d, want %d", st.Gid, os.Getgid())
	}
}

func TestRepairUserTargetNeverFollowsLinksBelowTheHome(t *testing.T) {
	f := newPerUserRepairFixture(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	addWriteACL(t, outside)

	// A symlink inside ~/.defenseclaw is left alone and never followed.
	link := filepath.Join(f.dataDir, "hooks", "ncat")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	// A hard link to an outside file is moved aside, never stamped.
	hard := filepath.Join(f.dataDir, "hooks", "linked.sh")
	if err := os.Link(outside, hard); err != nil {
		t.Fatal(err)
	}

	if err := f.repair(); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if st := statOf(t, outside); uint32(st.Mode)&0o7777 != 0o644 || !hasACL(t, outside) {
		t.Fatalf("link target was written through: mode %04o", uint32(st.Mode)&0o7777)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink was removed: %v", err)
	}
	if _, err := os.Lstat(hard); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hard link was not moved aside: %v", err)
	}
	if f.count(managed.MarkerBoundary) != 1 {
		t.Fatalf("want one boundary marker, got %+v", f.markers)
	}
}

func TestRepairUserTargetRemovesSymlinkedDataDir(t *testing.T) {
	f := newPerUserRepairFixture(t)
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Rename(f.dataDir, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, f.dataDir); err != nil {
		t.Fatal(err)
	}
	if err := f.repair(); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if _, err := os.Lstat(f.dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked data dir is still present: %v", err)
	}
	if st := statOf(t, elsewhere); uint32(st.Mode)&0o7777 != 0o755 {
		t.Fatalf("link target was re-permissioned: %04o", uint32(st.Mode)&0o7777)
	}
	if !f.marked(managed.MarkerBoundary, f.dataDir, "symlink") {
		t.Fatalf("no boundary marker: %+v", f.markers)
	}
}

func TestRepairUserTargetSkipsUnusableHomeWithoutTouchingIt(t *testing.T) {
	for name, setup := range map[string]func(f *perUserRepairFixture) string{
		"home_group_writable": func(f *perUserRepairFixture) string {
			if err := os.Chmod(f.home, 0o770); err != nil {
				t.Fatal(err)
			}
			return f.home
		},
		"home_symlink": func(f *perUserRepairFixture) string {
			real := f.home + ".real"
			if err := os.Rename(f.home, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, f.home); err != nil {
				t.Fatal(err)
			}
			return f.home
		},
		"home_not_directory": func(f *perUserRepairFixture) string {
			if err := os.Rename(f.home, f.home+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.home, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return f.home
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPerUserRepairFixture(t)
			path := setup(f)
			before := statOf(t, path)
			err := f.repair()
			var skip *UserSkipError
			if !errors.As(err, &skip) || skip.Reason != name {
				t.Fatalf("repair error = %v, want skip %s", err, name)
			}
			after := statOf(t, path)
			if before.Mode != after.Mode || before.Uid != after.Uid {
				t.Fatalf("home was re-permissioned")
			}
			if !f.marked(managed.MarkerSkip, path, name) {
				t.Fatalf("no skip marker: %+v", f.markers)
			}
			// Once per streak: the same skip is not logged again.
			f.mu.Lock()
			f.markers = nil
			f.mu.Unlock()
			_ = RepairUserTarget(f.opts(), "user:fixture")
			if f.count(managed.MarkerSkip) != 0 {
				t.Fatalf("skip logged twice in one streak: %+v", f.markers)
			}
		})
	}
}

func TestRepairUserTargetRepairsAgentConfigFlagsAndMode(t *testing.T) {
	f := newPerUserRepairFixture(t)
	if err := os.Chmod(f.config, 0o664); err != nil {
		t.Fatal(err)
	}
	addWriteACL(t, f.config)
	if err := os.Chmod(filepath.Dir(f.config), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(f.config, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	if err := f.repair(); err != nil {
		t.Fatalf("repair: %v", err)
	}
	st := statOf(t, f.config)
	if st.Flags&unix.UF_IMMUTABLE != 0 {
		t.Fatal("uchg was not cleared")
	}
	if got := uint32(st.Mode) & 0o7777; got != 0o644 {
		t.Fatalf("config mode = %04o, want 0644", got)
	}
	if !hasACL(t, f.config) {
		t.Fatal("the agent's own ACL was stripped")
	}
	if got := uint32(statOf(t, filepath.Dir(f.config)).Mode) & 0o7777; got != 0o755 {
		t.Fatalf("config folder mode = %04o, want 0755", got)
	}
	if !f.marked(managed.MarkerRepair, f.config, "user_immutable_flag") || !f.marked(managed.MarkerRepair, f.config, "mode") {
		t.Fatalf("missing agent config repair markers: %+v", f.markers)
	}
	// Idempotent.
	if err := f.repair(); err != nil || f.count(managed.MarkerRepair) != 0 {
		t.Fatalf("second pass: err=%v markers=%+v", err, f.markers)
	}
}

// The guardian repairs the targets of one user one connector after another in
// the same pass. The second connector's immutable config must be repaired
// although the user's ~/.defenseclaw walk is still inside its interval; that
// walk itself still runs once.
func TestRepairUserTargetRepairsEveryConnectorsConfigWithinTheInterval(t *testing.T) {
	f := newPerUserRepairFixture(t)
	codexConfig := filepath.Join(f.home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	f.write(codexConfig, 0o600)
	userAgentConfigPaths = func(opts InstallOptions) []string {
		if opts.ConnectorName == "codex" {
			return []string{codexConfig}
		}
		return []string{f.config}
	}
	now := time.Unix(1_800_000_000, 0)
	previousNow := userRepairNow
	userRepairNow = func() time.Time { return now }
	t.Cleanup(func() { userRepairNow = previousNow })

	codex := f.opts()
	codex.ConnectorName = "codex"
	if err := RepairUserTarget(codex, "user:fixture"); err != nil {
		t.Fatalf("codex pass: %v", err)
	}

	// The user locks the Claude Code config and drifts a hook script.
	hook := filepath.Join(f.dataDir, "hooks", "claude-code-hook.sh")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(f.config, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	claude := f.opts()
	claude.ConnectorName = "claudecode"
	if err := RepairUserTarget(claude, "user:fixture"); err != nil {
		t.Fatalf("claudecode pass: %v", err)
	}
	if statOf(t, f.config).Flags&unix.UF_IMMUTABLE != 0 {
		t.Fatal("the second connector's config kept uchg inside the interval")
	}
	if !f.marked(managed.MarkerRepair, f.config, "user_immutable_flag") {
		t.Fatalf("missing the repair marker for the second connector's config: %+v", f.markers)
	}
	if got := uint32(statOf(t, hook).Mode) & 0o7777; got != 0o755 {
		t.Fatalf("the shared ~/.defenseclaw walk ran again inside the interval (hook mode %04o)", got)
	}

	// After the interval the walk runs again.
	now = now.Add(userRepairMinInterval)
	if err := RepairUserTarget(claude, "user:fixture"); err != nil {
		t.Fatalf("pass after the interval: %v", err)
	}
	if got := uint32(statOf(t, hook).Mode) & 0o7777; got != 0o700 {
		t.Fatalf("hook mode after the interval = %04o, want 0700", got)
	}
}

// A completed ~/.defenseclaw walk is recorded even when the agent config after
// it skips the user (a symlinked folder above the config), so the user's next
// connector inside the interval does not walk the tree again.
func TestRepairUserTargetRecordsTheWalkWhenAnAgentConfigSkips(t *testing.T) {
	f := newPerUserRepairFixture(t)
	elsewhere := filepath.Join(t.TempDir(), "claude")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(f.config)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Dir(f.config)); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	previousNow := userRepairNow
	userRepairNow = func() time.Time { return now }
	t.Cleanup(func() { userRepairNow = previousNow })

	var skip *UserSkipError
	if err := RepairUserTarget(f.opts(), "user:fixture"); !errors.As(err, &skip) {
		t.Fatalf("first pass: err=%v, want a skip for the symlinked folder above the config", err)
	}
	hook := filepath.Join(f.dataDir, "hooks", "claude-code-hook.sh")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	_ = RepairUserTarget(f.opts(), "user:fixture")
	if got := uint32(statOf(t, hook).Mode) & 0o7777; got != 0o755 {
		t.Fatalf("the walk ran again inside the interval after a skipped config (hook mode %04o)", got)
	}
}

func TestRepairUserTargetLeavesSymlinkedAgentConfigToSetup(t *testing.T) {
	f := newPerUserRepairFixture(t)
	dotfiles := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(dotfiles, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dotfiles, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfiles, f.config); err != nil {
		t.Fatal(err)
	}
	// The user is not skipped: Setup replaces the link with a real config.
	if err := f.repair(); err != nil {
		t.Fatalf("repair error = %v, want the symlinked config left to Setup", err)
	}
	if _, err := os.Lstat(f.config); err != nil {
		t.Fatalf("the user's symlink was removed: %v", err)
	}
	if got := uint32(statOf(t, dotfiles).Mode) & 0o7777; got != 0o666 {
		t.Fatalf("symlink target was re-permissioned: %04o", got)
	}
}

func TestRepairUserTargetDoesNothingUnprivileged(t *testing.T) {
	f := newPerUserRepairFixture(t)
	userRepairPrivileged = func() bool { return false }
	if err := os.Chmod(f.dataDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := f.repair(); err != nil {
		t.Fatal(err)
	}
	if got := uint32(statOf(t, f.dataDir).Mode) & 0o7777; got != 0o777 {
		t.Fatalf("unprivileged caller repaired: %04o", got)
	}
}

func TestListingHasACL(t *testing.T) {
	if listingHasACL([]byte("drwx------  3 u  staff  96 Nov  2 10:00 x\n")) {
		t.Fatal("plain listing reported an ACL")
	}
	if !listingHasACL([]byte("-rw-------+ 1 u  staff  0 Nov  2 10:00 x\n 0: group:everyone allow write\n")) {
		t.Fatal("ACL entry not detected")
	}
}
