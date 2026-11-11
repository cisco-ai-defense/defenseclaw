//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// EnsureCanonical re-stamps a managed macOS object to its kind's canonical
// owner, group and mode, clears the flags that block writers (uchg, uappnd,
// and schg or sappnd while kern.securelevel is 0) and strips its ACL. Every
// write goes through a descriptor opened without following links and
// re-checked for type, link count and a local volume, so a planted symlink or
// hard link can never redirect a root repair. Drift that grants no untrusted
// principal write is repaired the same as drift that does. An object owned by
// an untrusted principal is reported as a boundary unless the caller sets
// AllowUntrustedOwnerTransfer. A missing object is reported, not created.
func EnsureCanonical(path string, kind ObjectKind, opts CanonicalOptions) (CanonicalResult, error) {
	return canonicalizeDarwin(path, kind, opts, true)
}

// AssessCanonical is the read-only form of EnsureCanonical.
func AssessCanonical(path string, kind ObjectKind, opts CanonicalOptions) (CanonicalResult, error) {
	return canonicalizeDarwin(path, kind, opts, false)
}

// darwinCanonicalForm is the owner, group and permission bits a kind is
// stamped with on macOS. Every macOS canonical form carries no ACL and no
// write-blocking flag.
type darwinCanonicalForm struct {
	UID  uint32
	GID  uint32
	Mode os.FileMode
}

const (
	darwinGIDWheel = 0
	darwinGIDStaff = 20
	darwinGIDAdmin = 80
)

// darwinCanonicalFormFor matches what the macOS installer stamps: root:wheel
// throughout, 0755 for folders and executables others traverse or run, 0750
// for the runtime, state and log folders, 0640 for config, manifests and
// logs, and 0600 for secrets. The IPC socket folder is root:staff 0750 so the
// console user can traverse to the socket.
func darwinCanonicalFormFor(kind ObjectKind, opts CanonicalOptions) (darwinCanonicalForm, bool) {
	form := darwinCanonicalForm{UID: 0, GID: darwinGIDWheel}
	switch kind {
	case ObjectRuntimeDirectory, ObjectStateDirectory, ObjectAuthorizationDirectory, ObjectLogDirectory:
		form.Mode = 0o750
	case ObjectRuntimeFile, ObjectConfigFile, ObjectAdminFile:
		form.Mode = 0o640
	case ObjectRuntimeSecretFile:
		form.Mode = 0o600
	case ObjectConfigDirectory, ObjectInstallDirectory, ObjectServiceInstallDirectory,
		ObjectSecureClientMarkerDirectory, ObjectAdminDirectory:
		form.Mode = 0o755
	case ObjectInstallFile, ObjectServiceInstallFile:
		form.Mode = 0o755
	case ObjectManagedIPCDirectory:
		form.GID = darwinGIDStaff
		form.Mode = 0o750
	default:
		return form, false
	}
	if opts.UnixOwner != nil {
		form.UID = opts.UnixOwner.UID
		form.GID = opts.UnixOwner.GID
	}
	if opts.UnixMode != 0 {
		form.Mode = opts.UnixMode.Perm()
	}
	return form, true
}

// BSD file flags that block a writer. UF_HIDDEN, UF_NODUMP and the other
// flags are harmless and never judged.
const (
	darwinUserBlockingFlags   = unix.UF_IMMUTABLE | unix.UF_APPEND
	darwinSystemBlockingFlags = unix.SF_IMMUTABLE | unix.SF_APPEND
)

// darwinObjectState is what canonicalizeDarwin read from one object; the
// assessment over it is pure so it can be table tested.
type darwinObjectState struct {
	UID   uint32
	GID   uint32
	Mode  uint32 // st_mode permission and special bits
	Flags uint32
	ACL   darwinACLJudgement
	// ACLError is set when the ACL could not be read.
	ACLError string
}

// darwinTrustedGroup reports a group whose members are already administrators
// or root, so group write for it is drift, never an untrusted writer.
func darwinTrustedGroup(gid uint32) bool {
	return gid == darwinGIDWheel || gid == darwinGIDAdmin
}

// assessDarwinObject decides how state differs from form. It judges effective
// write authority for untrusted principals, not exact equality: a tighter
// group or other mode, root:admin instead of root:wheel, read, deny and
// inherit-only ACL entries, and entries for root, wheel or admin are never a
// boundary. adminMember reports admin group membership for an owner uid.
func assessDarwinObject(state darwinObjectState, form darwinCanonicalForm, adminMember func(uint32) bool) canonicalAssessment {
	var a canonicalAssessment
	switch {
	case state.UID == form.UID:
		a.Owner = ownerCanonical
	case state.UID == 0:
		a.Owner = ownerTrusted
		a.Drift = append(a.Drift, fmt.Sprintf("owner uid 0 is not the canonical owner uid %d", form.UID))
	case adminMember != nil && adminMember(state.UID):
		a.Owner = ownerAdminEquivalent
		a.Drift = append(a.Drift, fmt.Sprintf("owner uid %d is an administrator, not the canonical owner", state.UID))
	default:
		a.Owner = ownerUntrusted
		a.Drift = append(a.Drift, fmt.Sprintf("owner uid %d is not trusted", state.UID))
	}
	groupTrusted := darwinTrustedGroup(state.GID) || state.GID == form.GID
	if state.GID != form.GID && (!darwinTrustedGroup(state.GID) || !darwinTrustedGroup(form.GID)) {
		a.Drift = append(a.Drift, fmt.Sprintf("group gid %d is not the canonical group gid %d", state.GID, form.GID))
	}

	perm := os.FileMode(state.Mode).Perm()
	want := form.Mode.Perm()
	if special := state.Mode & (unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX); special != 0 {
		a.Drift = append(a.Drift, fmt.Sprintf("special mode bits %04o are set", special))
	}
	if want&0o700&^perm != 0 {
		a.Drift = append(a.Drift, fmt.Sprintf("mode %04o lacks owner rights of %04o", perm, want))
	}
	if extra := perm &^ want; extra != 0 {
		a.Drift = append(a.Drift, fmt.Sprintf("mode %04o is looser than %04o", perm, want))
		if extra&0o020 != 0 && !groupTrusted {
			a.UntrustedWriters = append(a.UntrustedWriters, fmt.Sprintf("group:%d", state.GID))
		}
		if extra&0o002 != 0 {
			a.UntrustedWriters = append(a.UntrustedWriters, "other")
		}
	}

	if flags := state.Flags & (darwinUserBlockingFlags | darwinSystemBlockingFlags); flags != 0 {
		a.Drift = append(a.Drift, fmt.Sprintf("write-blocking flags %s are set", darwinFlagNames(flags)))
	}

	if state.ACLError != "" {
		a.Drift = append(a.Drift, "ACL is not readable: "+state.ACLError)
	} else if state.ACL.Entries > 0 {
		a.Drift = append(a.Drift, fmt.Sprintf("ACL has %d entries", state.ACL.Entries))
		for _, principal := range state.ACL.InheritOnlyWriters {
			a.Drift = append(a.Drift, fmt.Sprintf("inheritable ACL entry grants %s write to new children", principal))
		}
		for _, principal := range state.ACL.UntrustedWriters {
			a.UntrustedWriters = append(a.UntrustedWriters, "acl:"+principal)
		}
	}
	for _, writer := range a.UntrustedWriters {
		a.Drift = append(a.Drift, fmt.Sprintf("untrusted principal %s has write access", writer))
	}
	a.Canonical = len(a.Drift) == 0
	return a
}

// darwinRepairMode is the mode a repair stamps: the canonical owner bits, and
// the canonical group and other bits the object already had. A tighter group
// or other mode is kept; owner rights the object needs are restored.
func darwinRepairMode(current uint32, form darwinCanonicalForm) os.FileMode {
	want := form.Mode.Perm()
	return want&0o700 | os.FileMode(current).Perm()&want&0o077
}

func darwinFlagNames(flags uint32) string {
	var names []string
	for _, flag := range []struct {
		bit  uint32
		name string
	}{
		{unix.UF_IMMUTABLE, "uchg"},
		{unix.UF_APPEND, "uappnd"},
		{unix.SF_IMMUTABLE, "schg"},
		{unix.SF_APPEND, "sappnd"},
	} {
		if flags&flag.bit != 0 {
			names = append(names, flag.name)
		}
	}
	return strings.Join(names, ",")
}

// darwinAdminMember is replaced in tests.
var darwinAdminMember = darwinUIDIsAdmin

func canonicalizeDarwin(path string, kind ObjectKind, opts CanonicalOptions, repair bool) (CanonicalResult, error) {
	result := CanonicalResult{Path: path, Kind: kind}
	fail := func(err error) (CanonicalResult, error) {
		result.Outcome = CanonicalStructural
		result.Err = err
		reportCanonicalResult(result, opts)
		return result, err
	}
	form, ok := darwinCanonicalFormFor(kind, opts)
	if !ok {
		return fail(fmt.Errorf("unknown managed object kind %q", kind))
	}
	if strings.TrimSpace(path) == "" {
		return fail(errors.New("managed object path is empty"))
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fail(fmt.Errorf("resolve %s: %w", path, err))
	}
	result.Path = clean
	object, err := openDarwinObject(clean, kind)
	return canonicalizeOpenedDarwin(result, form, object, err, opts, repair)
}

// canonicalizeOpenedDarwin assesses and, when repair is set, re-stamps an
// object canonicalizeDarwin or EnsureCanonicalAt opened. openErr is the
// error from opening it.
func canonicalizeOpenedDarwin(
	result CanonicalResult,
	form darwinCanonicalForm,
	object *darwinObject,
	err error,
	opts CanonicalOptions,
	repair bool,
) (CanonicalResult, error) {
	fail := func(err error) (CanonicalResult, error) {
		result.Outcome = CanonicalStructural
		result.Err = err
		reportCanonicalResult(result, opts)
		return result, err
	}
	if errors.Is(err, unix.ENOENT) {
		result.Outcome = CanonicalMissing
		return result, nil
	}
	if err != nil {
		var structural darwinStructuralError
		if errors.As(err, &structural) {
			return fail(err)
		}
		// The object exists but this caller cannot open it: report it, never
		// guess at its metadata.
		result.Outcome = CanonicalAccepted
		result.Drift = []string{"object could not be opened: " + err.Error()}
		reportCanonicalResult(result, opts)
		return result, nil
	}
	defer object.close()

	state, err := object.read()
	if err != nil {
		return fail(err)
	}
	assessment := assessDarwinObject(state, form, darwinAdminMember)
	result.Drift = assessment.Drift
	result.UntrustedWriters = assessment.UntrustedWriters
	result.Outcome = assessment.outcome()
	if result.Outcome == CanonicalOK || !repair {
		reportCanonicalResult(result, opts)
		return result, nil
	}
	if assessment.Owner == ownerUntrusted && !ownerTransferAllowed(result.Kind, opts) {
		result.Outcome = CanonicalBoundary
		result.RepairError = "owner is not trusted; not adopted"
		reportCanonicalResult(result, opts)
		return result, nil
	}

	var repairErrors []string
	if err := object.stamp(state, form); err != nil {
		repairErrors = append(repairErrors, err.Error())
	}
	after, err := object.read()
	if err != nil {
		repairErrors = append(repairErrors, "re-read repaired object: "+err.Error())
		result.RepairError = strings.Join(repairErrors, "; ")
		reportCanonicalResult(result, opts)
		return result, nil
	}
	verdict := assessDarwinObject(after, form, darwinAdminMember)
	switch {
	case verdict.Canonical:
		result.Outcome = CanonicalRepaired
	case verdict.boundary():
		result.Outcome = CanonicalBoundary
		repairErrors = append(repairErrors, "object still drifted after repair: "+strings.Join(verdict.Drift, "; "))
	default:
		result.Outcome = CanonicalAccepted
		repairErrors = append(repairErrors, "object still drifted after repair: "+strings.Join(verdict.Drift, "; "))
	}
	if result.Outcome == CanonicalRepaired && len(repairErrors) > 0 {
		// A step failed but the object reads canonical anyway; the next
		// pass does not need to repeat it.
		repairErrors = nil
	}
	result.RepairError = strings.Join(repairErrors, "; ")
	reportCanonicalResult(result, opts)
	return result, nil
}

// darwinStructuralError marks a structural finding: a symlink, a wrong object
// type, a hard-linked file, a non-local volume, or an object swapped during
// inspection. Callers handle it by who owns the object: DefenseClaw-owned
// objects are moved aside and recreated (see MoveAsideStructural); anything
// else is never written through.
type darwinStructuralError struct{ err error }

func (e darwinStructuralError) Error() string { return e.err.Error() }
func (e darwinStructuralError) Unwrap() error { return e.err }

func structuralf(format string, args ...any) error {
	return darwinStructuralError{err: fmt.Errorf(format, args...)}
}

// darwinObject is an object pinned by a descriptor opened without following
// links.
type darwinObject struct {
	path string
	kind ObjectKind
	fd   int
	dev  int32
	ino  uint64
	// parentFD and name are set for an object opened relative to a pinned
	// parent (EnsureCanonicalAt); the identity re-check and the ACL strip
	// then go through descriptors instead of the path.
	parentFD int
	name     string
}

func openDarwinObject(path string, kind ObjectKind) (*darwinObject, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if kind.Directory() {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, structuralf("%s is a symlink; managed objects are never followed", path)
	case errors.Is(err, unix.ENOTDIR):
		return nil, structuralf("%s is not a directory", path)
	case err != nil:
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	object := &darwinObject{path: path, kind: kind, fd: fd, parentFD: -1}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		object.close()
		return nil, fmt.Errorf("fstat %s: %w", path, err)
	}
	if err := checkDarwinStructure(path, kind, &st, fd); err != nil {
		object.close()
		return nil, err
	}
	object.dev, object.ino = st.Dev, st.Ino
	return object, nil
}

// checkDarwinStructure rejects the wrong object type, a hard-linked file and
// an object on a non-local volume, where ownership and ACL semantics are not
// the ones DefenseClaw stamps.
func checkDarwinStructure(path string, kind ObjectKind, st *unix.Stat_t, fd int) error {
	format := uint32(st.Mode) & unix.S_IFMT
	if kind.Directory() {
		if format != unix.S_IFDIR {
			return structuralf("%s is not a directory", path)
		}
	} else {
		if format != unix.S_IFREG {
			return structuralf("%s is not a regular file", path)
		}
		if st.Nlink > 1 {
			return structuralf("%s has %d hard links; a managed file must have exactly one", path, st.Nlink)
		}
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	if fs.Flags&unix.MNT_LOCAL == 0 {
		return structuralf("%s is not on a local volume", path)
	}
	return nil
}

func (o *darwinObject) close() { _ = unix.Close(o.fd) }

// sameObject reports whether path still names the pinned object.
func (o *darwinObject) sameObject() bool {
	var st unix.Stat_t
	if err := unix.Lstat(o.path, &st); err != nil {
		return false
	}
	if st.Dev != o.dev || st.Ino != o.ino {
		return false
	}
	if o.parentFD >= 0 {
		if err := unix.Fstatat(o.parentFD, o.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false
		}
		return st.Dev == o.dev && st.Ino == o.ino
	}
	return true
}

func (o *darwinObject) read() (darwinObjectState, error) {
	var st unix.Stat_t
	if err := unix.Fstat(o.fd, &st); err != nil {
		return darwinObjectState{}, fmt.Errorf("fstat %s: %w", o.path, err)
	}
	state := darwinObjectState{UID: st.Uid, GID: st.Gid, Mode: uint32(st.Mode) &^ unix.S_IFMT, Flags: st.Flags}
	// There is no descriptor-based ACL read without cgo, so the ACL is read
	// by path and the path is then checked to still name the pinned object.
	output, err := readDarwinACL(o.path)
	if !o.sameObject() {
		return darwinObjectState{}, structuralf("%s was replaced during inspection", o.path)
	}
	if err != nil {
		state.ACLError = err.Error()
		return state, nil
	}
	entries, err := parseDarwinACLEntries(o.path, output)
	if err != nil {
		state.ACLError = err.Error()
		return state, nil
	}
	state.ACL = judgeDarwinACLEntries(entries)
	return state, nil
}

// stamp clears the write-blocking flags, strips the ACL, then sets owner,
// group and mode on the pinned descriptor. Each step runs even if an earlier
// one failed; the caller re-reads the object to decide the outcome.
func (o *darwinObject) stamp(state darwinObjectState, form darwinCanonicalForm) error {
	var errs []string
	if blocking := state.Flags & (darwinUserBlockingFlags | darwinSystemBlockingFlags); blocking != 0 {
		clear := uint32(darwinUserBlockingFlags)
		if darwinSecureLevel() <= 0 {
			clear |= darwinSystemBlockingFlags
		}
		if err := unix.Fchflags(o.fd, int(state.Flags&^clear)); err != nil {
			errs = append(errs, "clear flags: "+err.Error())
		} else if state.Flags&darwinSystemBlockingFlags&^clear != 0 {
			errs = append(errs, "system immutable flag is set and kern.securelevel is above 0")
		}
	}
	if state.ACL.Entries > 0 || state.ACLError != "" {
		strip := func() error { return stripDarwinACL(o.path) }
		if o.parentFD >= 0 {
			strip = func() error { return stripDarwinACLFD(o.fd) }
		}
		if err := strip(); err != nil {
			errs = append(errs, "strip ACL: "+err.Error())
		}
		if !o.sameObject() {
			return structuralf("%s was replaced during repair", o.path)
		}
	}
	if state.UID != form.UID || state.GID != form.GID {
		if err := unix.Fchown(o.fd, int(form.UID), int(form.GID)); err != nil {
			errs = append(errs, "chown: "+err.Error())
		}
	}
	if mode := darwinRepairMode(state.Mode, form); uint32(mode) != state.Mode {
		if err := unix.Fchmod(o.fd, uint32(mode)); err != nil {
			errs = append(errs, "chmod: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// stripDarwinACL removes every ACL entry from path without following a link.
// There is no descriptor-based ACL write without cgo, so the caller re-checks
// the path still names the pinned object afterwards.
var stripDarwinACL = func(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), darwinACLInspectionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/chmod", "-h", "-N", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %s", darwinACLInspectionTimeout)
		}
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// darwinSecureLevel returns kern.securelevel; above 0 the system immutable
// and append-only flags cannot be cleared until reboot into single-user mode.
func darwinSecureLevel() int {
	level, err := unix.SysctlUint32("kern.securelevel")
	if err != nil {
		return 1
	}
	return int(int32(level))
}
