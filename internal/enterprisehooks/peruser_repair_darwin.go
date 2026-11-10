//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/unix"
)

// UserSkipError is a per-user condition the guardian cannot repair: the
// user is skipped this tick and the others continue.
type UserSkipError struct {
	Reason string
	Path   string
	Err    error
}

func (e *UserSkipError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("enterprise hooks: skipping user (%s) at %s: %v", e.Reason, e.Path, e.Err)
	}
	return fmt.Sprintf("enterprise hooks: skipping user (%s) at %s", e.Reason, e.Path)
}

func (e *UserSkipError) Unwrap() error { return e.Err }

const (
	// userRepairMinInterval lets the connectors of one user share one walk of
	// ~/.defenseclaw per reconcile instead of walking the same tree once per
	// connector. Each connector's own agent configs are not shared and are
	// repaired on every pass.
	userRepairMinInterval = 20 * time.Second
	// userRepairEntryBudget bounds the walk of a user's ~/.defenseclaw.
	userRepairEntryBudget = 4096
	userRepairMaxDepth    = 8
)

var userRepairState = struct {
	sync.Mutex
	lastRun map[string]time.Time
	skips   map[string]string
}{lastRun: map[string]time.Time{}, skips: map[string]string{}}

// userRepairPrivileged and userRepairNow are replaced in tests.
var userRepairPrivileged = func() bool { return os.Geteuid() == 0 }

var userRepairNow = time.Now

// RepairUserTarget repairs one target user's DefenseClaw objects as root,
// before the guardian drops to the user for Verify and Install:
//
//   - ~/.defenseclaw and everything below it: owner and group back to the
//     user, owner-only mode, ACL stripped, uchg/uappnd cleared. A symlink
//     below it is left alone and never followed; a symlinked or misplaced
//     ~/.defenseclaw is removed or moved aside so Setup recreates it; a
//     hard-linked file is moved aside, never written through.
//   - the agent configs (settings.json, config.toml, hooks.json) and their
//     parent folders below the home: owner back to the user, group and
//     other write removed, uchg/uappnd cleared. Their ACLs are the agent's
//     and are kept.
//
// The home folder itself is never re-permissioned. A symlinked,
// non-directory, group- or other-writable, foreign-owned or non-local home,
// a symlinked folder above an agent config, and an agent config that cannot
// be repaired, return a *UserSkipError (a symlinked config file itself is left
// for Setup to replace) and log defenseclaw_skip once per streak. Every object is
// opened relative to a descriptor of its parent, without following links,
// so a component the user swaps for a symlink can never redirect a root
// write. It does nothing unless the caller is root.
func RepairUserTarget(opts InstallOptions, unit string) error {
	if !userRepairPrivileged() || opts.OwnerUID <= 0 || opts.OwnerGID < 0 {
		return nil
	}
	home := filepath.Clean(strings.TrimSpace(opts.UserHome))
	if home == "" || !filepath.IsAbs(home) || home == string(filepath.Separator) {
		return nil
	}
	key := strconv.Itoa(opts.OwnerUID) + "\x00" + home
	userRepairState.Lock()
	last := userRepairState.lastRun[key]
	userRepairState.Unlock()
	// Only the shared ~/.defenseclaw walk waits for the interval. The agent
	// configs belong to this target's connector, so they are repaired on
	// every pass: throttling the whole repair skipped every connector of the
	// user after the first, and an emptied, immutable settings.json kept the
	// Claude Code hooks out for as long as the user kept it so.
	walkDataDir := last.IsZero() || userRepairNow().Sub(last) >= userRepairMinInterval

	repairer := &userRepairer{
		unit: unit,
		home: home,
		uid:  uint32(opts.OwnerUID),
		gid:  uint32(opts.OwnerGID),
	}
	err := repairer.run(opts, walkDataDir)
	var skip *UserSkipError
	switch {
	case errors.As(err, &skip):
		reportUserSkip(unit, key, skip)
	case err == nil:
		userRepairState.Lock()
		if walkDataDir {
			userRepairState.lastRun[key] = userRepairNow()
		}
		delete(userRepairState.skips, key)
		userRepairState.Unlock()
	}
	return err
}

// RepairUserDataTreeAfterInstall re-runs the ~/.defenseclaw owner, mode,
// ACL and flag repair as root after Install's work as the user, so anything
// that work left owned by another principal is handed back to the user.
func RepairUserDataTreeAfterInstall(home, dataDir string, uid, gid int) error {
	if !userRepairPrivileged() || uid <= 0 || gid < 0 {
		return nil
	}
	repairer := &userRepairer{
		unit: "uid:" + strconv.Itoa(uid),
		home: filepath.Clean(home),
		uid:  uint32(uid),
		gid:  uint32(gid),
	}
	homeFD, err := repairer.openHome()
	if err != nil {
		return err
	}
	defer unix.Close(homeFD)
	return repairer.repairDataDir(homeFD, dataDir)
}

func reportUserSkip(unit, key string, skip *UserSkipError) {
	userRepairState.Lock()
	previous, logged := userRepairState.skips[key]
	userRepairState.skips[key] = skip.Reason
	userRepairState.Unlock()
	if logged && previous == skip.Reason {
		return
	}
	fields := map[string]string{"unit": unit, "reason": skip.Reason, "path": skip.Path}
	if skip.Err != nil {
		fields["detail"] = skip.Err.Error()
	}
	managed.EmitResilienceEvent(managed.MarkerSkip, fields)
}

type userRepairer struct {
	unit    string
	home    string
	uid     uint32
	gid     uint32
	entries int
}

func (r *userRepairer) skip(reason, path string, err error) error {
	return &UserSkipError{Reason: reason, Path: path, Err: err}
}

// run repairs the agent configs of opts, and ~/.defenseclaw first when
// walkDataDir is set.
func (r *userRepairer) run(opts InstallOptions, walkDataDir bool) error {
	homeFD, err := r.openHome()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// An unmounted or deleted home is reported by the validators as
			// pending; there is nothing to repair.
			return nil
		}
		return err
	}
	defer unix.Close(homeFD)

	if walkDataDir {
		dataDir := strings.TrimSpace(opts.DataDir)
		if dataDir == "" {
			dataDir = filepath.Join(r.home, ".defenseclaw")
		}
		if err := r.repairDataDir(homeFD, filepath.Clean(dataDir)); err != nil {
			return err
		}
	}

	for _, path := range userAgentConfigPaths(opts) {
		if err := r.repairAgentConfig(homeFD, path); err != nil {
			return err
		}
	}
	return nil
}

// openHome opens the home without following a link and checks it, never
// changing it.
func (r *userRepairer) openHome() (int, error) {
	info, err := os.Lstat(r.home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return -1, fmt.Errorf("enterprise hooks: user home %s: %w", r.home, err)
		}
		return -1, r.skip("home_unreadable", r.home, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return -1, r.skip("home_symlink", r.home, nil)
	}
	if !info.IsDir() {
		return -1, r.skip("home_not_directory", r.home, nil)
	}
	fd, err := unix.Open(r.home, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return -1, r.skip("home_symlink", r.home, nil)
		}
		return -1, r.skip("home_unreadable", r.home, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, r.skip("home_unreadable", r.home, err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err == nil && fs.Flags&unix.MNT_LOCAL == 0 {
		unix.Close(fd)
		return -1, r.skip("nonlocal_volume", r.home, nil)
	}
	if st.Mode&0o022 != 0 {
		unix.Close(fd)
		return -1, r.skip("home_group_writable", r.home, nil)
	}
	if st.Uid != r.uid {
		unix.Close(fd)
		return -1, r.skip("home_owner_mismatch", r.home, fmt.Errorf("owner uid %d is not the target uid %d", st.Uid, r.uid))
	}
	return fd, nil
}

func (r *userRepairer) ownerOptions(mode os.FileMode) managed.CanonicalOptions {
	return managed.CanonicalOptions{
		UnixOwner:                   &managed.UnixOwnership{UID: r.uid, GID: r.gid},
		UnixMode:                    mode,
		AllowUntrustedOwnerTransfer: true,
		Quiet:                       true,
	}
}

// repairDataDir walks from the home to dataDir one component at a time and
// then repairs everything below it.
func (r *userRepairer) repairDataDir(homeFD int, dataDir string) error {
	if !pathInside(r.home, dataDir) || dataDir == r.home {
		return nil
	}
	rel, err := filepath.Rel(r.home, dataDir)
	if err != nil {
		return nil
	}
	parentFD, parentPath := homeFD, r.home
	var opened []int
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		if name == "" || name == "." {
			continue
		}
		path := filepath.Join(parentPath, name)
		var st unix.Stat_t
		if err := unix.Fstatat(parentFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return r.skip("data_dir_unreadable", path, err)
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
		case unix.S_IFLNK:
			// DefenseClaw's own namespace: drop the link (its target is never
			// touched) so Setup recreates a real folder.
			if err := unix.Unlinkat(parentFD, name, 0); err != nil {
				return r.skip("data_dir_symlink", path, err)
			}
			r.emit(managed.MarkerBoundary, path, "symlink removed from the DefenseClaw folder path; its target was not touched", "")
			return nil
		default:
			if err := r.moveAside(parentFD, parentPath, name, "not a directory"); err != nil {
				return r.skip("data_dir_not_directory", path, err)
			}
			return nil
		}
		if err := r.ensure(parentFD, parentPath, name, managed.ObjectAdminDirectory, 0o700); err != nil {
			return err
		}
		fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return r.skip("data_dir_unreadable", path, err)
		}
		opened = append(opened, fd)
		parentFD, parentPath = fd, path
	}
	return r.walk(parentFD, parentPath, 0)
}

// walk repairs every entry of the folder dirFD names. Only entries that are
// out of their canonical form are written; the folder's ACLs are read with
// one listing.
func (r *userRepairer) walk(dirFD int, dirPath string, depth int) error {
	if depth >= userRepairMaxDepth {
		return nil
	}
	names, err := readDirNames(dirFD)
	if err != nil {
		return r.skip("data_dir_unreadable", dirPath, err)
	}
	aclPresent := userRepairDirHasACL(dirPath)
	for _, name := range names {
		r.entries++
		if r.entries > userRepairEntryBudget {
			r.emitDegraded(dirPath, fmt.Sprintf("more than %d objects; the rest is repaired by Setup", userRepairEntryBudget))
			return nil
		}
		path := filepath.Join(dirPath, name)
		var st unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if aclPresent || r.drifted(&st, 0o700) {
				if err := r.ensure(dirFD, dirPath, name, managed.ObjectAdminDirectory, 0o700); err != nil {
					return err
				}
			}
			child, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			err = r.walk(child, path, depth+1)
			unix.Close(child)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			if st.Nlink > 1 {
				if err := r.moveAside(dirFD, dirPath, name, fmt.Sprintf("%d hard links", st.Nlink)); err != nil {
					return r.skip("hard_link", path, err)
				}
				continue
			}
			mode := os.FileMode(0o600)
			if st.Mode&0o100 != 0 {
				mode = 0o700
			}
			if aclPresent || r.drifted(&st, mode) {
				if err := r.ensure(dirFD, dirPath, name, managed.ObjectAdminFile, mode); err != nil {
					return err
				}
			}
		default:
			// Symlinks (the shim aliases), sockets and FIFOs are never
			// followed or stamped.
		}
	}
	return nil
}

// drifted reports whether st differs from the user-owned canonical form:
// another owner or group, a mode with group or other bits or without the
// owner rights, special bits, or a write-blocking flag.
func (r *userRepairer) drifted(st *unix.Stat_t, mode os.FileMode) bool {
	if st.Uid != r.uid || st.Gid != r.gid {
		return true
	}
	perm := uint32(st.Mode) & 0o7777
	if perm&^uint32(mode.Perm()) != 0 || uint32(mode.Perm())&0o700&^perm != 0 {
		return true
	}
	return st.Flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND) != 0
}

// ensure stamps one DefenseClaw object through managed.EnsureCanonicalAt and
// logs what changed. A structural finding moves the object aside.
func (r *userRepairer) ensure(parentFD int, parentPath, name string, kind managed.ObjectKind, mode os.FileMode) error {
	path := filepath.Join(parentPath, name)
	result, err := managed.EnsureCanonicalAt(parentFD, parentPath, name, kind, r.ownerOptions(mode))
	if err != nil {
		if managed.IsStructuralCanonicalError(err) {
			if moveErr := r.moveAside(parentFD, parentPath, name, err.Error()); moveErr != nil {
				return r.skip("structural", path, moveErr)
			}
			return nil
		}
		return r.skip("repair_failed", path, err)
	}
	reason := strings.Join(result.Drift, "; ")
	switch result.Outcome {
	case managed.CanonicalRepaired:
		r.emit(managed.MarkerRepair, path, reason, "")
	case managed.CanonicalAccepted:
		r.emit(managed.MarkerAccept, path, reason, result.RepairError)
	case managed.CanonicalBoundary:
		r.emit(managed.MarkerBoundary, path, reason, result.RepairError)
		return r.skip(denialReason(path, errors.New(result.RepairError)), path, errors.New(result.RepairError))
	}
	return nil
}

// moveAside renames an entry next to itself relative to its parent's
// descriptor; a rename never follows a link and never touches another hard
// link of the same file.
func (r *userRepairer) moveAside(parentFD int, parentPath, name, reason string) error {
	moved := fmt.Sprintf("%s.defenseclaw-moved-%s", name, time.Now().UTC().Format("20060102T150405.000000000Z"))
	fields := map[string]string{
		"unit":     r.unit,
		"path":     filepath.Join(parentPath, name),
		"reason":   reason,
		"action":   "moved_aside",
		"moved_to": filepath.Join(parentPath, moved),
	}
	if err := unix.Renameat(parentFD, name, parentFD, moved); err != nil {
		fields["repair_error"] = err.Error()
		managed.EmitResilienceEvent(managed.MarkerBoundary, fields)
		return err
	}
	managed.EmitResilienceEvent(managed.MarkerBoundary, fields)
	return nil
}

// repairAgentConfig repairs one agent config and the folders between the
// home and it. The agent owns the content and its ACL; DefenseClaw restores
// only the owner, removes group and other write, and clears the user
// immutable and append-only flags (managed mode treats a pinned config as
// tamper).
func (r *userRepairer) repairAgentConfig(homeFD int, configPath string) error {
	configPath = filepath.Clean(configPath)
	if !pathInside(r.home, configPath) || configPath == r.home {
		return nil
	}
	rel, err := filepath.Rel(r.home, configPath)
	if err != nil {
		return nil
	}
	parts := strings.Split(rel, string(filepath.Separator))
	parentFD, parentPath := homeFD, r.home
	var opened []int
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	for i, name := range parts {
		path := filepath.Join(parentPath, name)
		leaf := i == len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if !leaf {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parentFD, name, flags, 0)
		switch {
		case errors.Is(err, unix.ENOENT):
			return nil
		case errors.Is(err, unix.ELOOP):
			if leaf {
				// A symlinked config is not followed here. The connector's
				// Setup replaces it with a real file without touching the
				// target, so the user stays protected; only a symlinked folder
				// above the config skips the user.
				return nil
			}
			return r.skip("symlink", path, nil)
		case errors.Is(err, unix.ENOTDIR):
			return r.skip("not_directory", path, nil)
		case err != nil:
			return r.skip("agent_config_unreadable", path, err)
		}
		opened = append(opened, fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return r.skip("agent_config_unreadable", path, err)
		}
		if leaf {
			if st.Mode&unix.S_IFMT != unix.S_IFREG {
				return r.skip("not_regular_file", path, nil)
			}
			if st.Nlink > 1 {
				return r.skip("hard_link", path, nil)
			}
		}
		if err := r.repairAgentObject(fd, path, &st); err != nil {
			return err
		}
		parentFD, parentPath = fd, path
	}
	return nil
}

func (r *userRepairer) repairAgentObject(fd int, path string, st *unix.Stat_t) error {
	if blocking := st.Flags & (unix.UF_IMMUTABLE | unix.UF_APPEND); blocking != 0 {
		if err := unix.Fchflags(fd, int(st.Flags&^blocking)); err != nil {
			return r.skip(denialReason(path, err), path, err)
		}
		r.emit(managed.MarkerRepair, path, "user_immutable_flag", "")
	}
	if st.Flags&(unix.SF_IMMUTABLE|unix.SF_APPEND) != 0 {
		return r.skip("system_immutable_flag", path, nil)
	}
	if st.Uid != r.uid {
		if err := unix.Fchown(fd, int(r.uid), int(r.gid)); err != nil {
			return r.skip(denialReason(path, err), path, err)
		}
		r.emit(managed.MarkerRepair, path, "owner", fmt.Sprintf("owner uid %d", st.Uid))
	}
	if perm := uint32(st.Mode) & 0o7777; perm&0o022 != 0 {
		if err := unix.Fchmod(fd, perm&^0o022); err != nil {
			return r.skip(denialReason(path, err), path, err)
		}
		r.emit(managed.MarkerRepair, path, "mode", fmt.Sprintf("mode %04o", perm))
	}
	return nil
}

// denialReason names a failed repair for the skip line: a flag that
// cannot be cleared, an Endpoint Security or TCC denial, SIP, or plain
// permission drift.
func denialReason(path string, err error) string {
	switch managed.ClassifyDenial(path, err) {
	case managed.DenialFlags:
		return "system_immutable_flag"
	case managed.DenialPolicy:
		return "endpoint_security_denied"
	case managed.DenialSystemIntegrity:
		return "system_integrity_protection"
	case managed.DenialAccess:
		return "permission_denied"
	default:
		return "repair_failed"
	}
}

func (r *userRepairer) emit(marker, path, reason, detail string) {
	fields := map[string]string{"unit": r.unit, "path": path, "reason": reason}
	if detail != "" {
		fields["detail"] = detail
	}
	managed.EmitResilienceEvent(marker, fields)
}

func (r *userRepairer) emitDegraded(path, reason string) {
	managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
		"component": "hook-guardian",
		"subsystem": "user_repair",
		"unit":      r.unit,
		"path":      path,
		"reason":    reason,
	})
}

// readDirNames lists the folder fd names without consuming fd's offset.
func readDirNames(dirFD int) ([]string, error) {
	dup, err := unix.Dup(dirFD)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(dup), "")
	defer file.Close()
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}
	return file.Readdirnames(-1)
}

// userRepairDirHasACL reports whether the folder or any entry in it carries
// an ACL, with one `ls -le` per folder instead of one per object. A failed
// or slow listing answers true, so every entry is then read on its own.
var userRepairDirHasACL = func(dirPath string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := commandOutput(ctx, "/bin/ls", "-leA", "--", dirPath)
	if err != nil {
		return true
	}
	self, err := commandOutput(ctx, "/bin/ls", "-led", "--", dirPath)
	if err != nil {
		return true
	}
	return listingHasACL(output) || listingHasACL(self)
}

func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	return cmd.Output()
}

// listingHasACL reports an `ls -le` ACL entry line (" 0: user:... allow ...").
func listingHasACL(output []byte) bool {
	for _, line := range bytes.Split(output, []byte("\n")) {
		trimmed := bytes.TrimLeft(line, " ")
		if len(trimmed) == len(line) {
			continue
		}
		colon := bytes.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		if _, err := strconv.Atoi(string(trimmed[:colon])); err == nil {
			return true
		}
	}
	return false
}

// userAgentConfigPaths returns the agent's own config files for this target
// (the files the agent and DefenseClaw both write).
var userAgentConfigPaths = func(opts InstallOptions) []string {
	ownership, err := WatchOwnedFiles(opts)
	if err != nil {
		return nil
	}
	return ownership.SharedWriter
}
