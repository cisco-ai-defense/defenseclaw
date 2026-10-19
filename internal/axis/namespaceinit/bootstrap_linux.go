// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package namespaceinit

import (
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
const admin = uint32(1 << unix.CAP_SYS_ADMIN)

// Capture creates the fixed, sealed FD3 proof before clone. The parent remains
// alive under the retained creating-thread/pidfd custody for the child's life.
// No namespace handle is used for setns or a mutation of its parent namespace.
func Capture() (_ *os.File, resultErr error) {
	if runtime.GOARCH != "amd64" || os.Getuid() <= 0 || os.Getgid() <= 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() || verifyCaps(false) != nil {
		return nil, errors.New("nonroot capability-free namespace parent required")
	}
	p := proof{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	fds, err := namespaceFDs()
	if err != nil {
		return nil, err
	}
	defer closeFDs(fds[:])
	for i, fd := range fds {
		if p.namespaces[i], err = fdIdentity(fd); err != nil {
			return nil, err
		}
	}
	fd, err := unix.MemfdCreate("defenseclaw-namespace-proof", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private-namespace-proof")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if _, err := file.Write(p.encode()); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	accepted = true
	return file, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}

func fdIdentity(fd int) (identity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return identity{}, err
	}
	return identity{uint64(st.Dev), st.Ino}, nil
}

func namespaceFDs() ([3]int, error) {
	fds := [3]int{-1, -1, -1}
	for i, item := range []struct {
		name string
		kind int
	}{{"user", unix.CLONE_NEWUSER}, {"mnt", unix.CLONE_NEWNS}, {"pid", unix.CLONE_NEWPID}} {
		// These are intentional kernel magic links to the CURRENT task even
		// through an ancestor procfs PID view (Linux fs/proc/self.c). Numeric
		// namespace-local PID lookup is never used before the fresh proc mount.
		fd, err := unix.Open("/proc/self/ns/"+item.name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			closeFDs(fds[:])
			return [3]int{-1, -1, -1}, err
		}
		fds[i] = fd
		var fs unix.Statfs_t
		kind, queryErr := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if queryErr != nil || kind != item.kind || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
			closeFDs(fds[:])
			return [3]int{-1, -1, -1}, errors.New("kernel namespace identity refused")
		}
	}
	return fds, nil
}

func bounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("bounded namespace metadata refused")
	}
	return b, nil
}

type nativeBootstrap struct {
	parent proof
	fds    [3]int
	proc   int
}

func (b *nativeBootstrap) validate() error {
	if uint32(os.Getuid()) != b.parent.uid || uint32(os.Getgid()) != b.parent.gid || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() || verifyCaps(true) != nil {
		return errors.New("namespace bootstrap credentials refused")
	}
	var err error
	b.fds, err = namespaceFDs()
	if err != nil {
		return err
	}
	var children [3]identity
	var owners [2]identity
	for i, fd := range b.fds {
		current, err := fdIdentity(fd)
		if err != nil {
			return err
		}
		children[i] = current
		if i > 0 {
			owner, err := unix.IoctlRetInt(fd, unix.NS_GET_USERNS)
			if err != nil {
				return err
			}
			identity, identityErr := fdIdentity(owner)
			closeErr := unix.Close(owner)
			if identityErr != nil || closeErr != nil {
				return errors.New("namespace owner query refused")
			}
			owners[i-1] = identity
		}
	}
	if !validNamespaces(b.parent.namespaces, children, owners) {
		return errors.New("fresh owned user/mount/PID namespaces required")
	}
	for _, item := range []struct {
		name string
		id   uint32
	}{{"uid_map", b.parent.uid}, {"gid_map", b.parent.gid}} {
		data, err := bounded("/proc/self/"+item.name, 128)
		if err != nil || !validMap(data, item.id) {
			return errors.New("exact single nonroot ID mapping required")
		}
	}
	return nil
}

func (b *nativeBootstrap) privateMounts() error {
	// Identity + kernel ownership above must precede this first mutation. All
	// propagation is disabled recursively before a mount can be attached.
	return unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
}

func (b *nativeBootstrap) mountProc() error {
	// No host pathname is opened as mount authority. /proc is a fixed existing
	// directory in this proven new mount namespace; hold its nonfollowing FD.
	fd, err := unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	context, err := unix.Fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(context)
	if err := unix.FsconfigCreate(context); err != nil {
		return err
	}
	mount, err := unix.Fsmount(context, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NODEV|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(mount)
	if err := unix.MoveMount(mount, "", fd, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return err
	}
	// Reopen only the fixed attachment; the old O_PATH FD still names the
	// covered mount. Kernel fs-type/PID checks verify the new attachment.
	b.proc, err = unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(b.proc, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return errors.New("fresh proc filesystem required")
	}
	return nil
}

func (b *nativeBootstrap) dropCaps() error {
	// Go's CGO0 AllThreadsSyscall stops the world and runs this operation on
	// every existing Go OS thread; newly created threads inherit the cleared
	// state. A foreign/cgo-thread runtime returns ENOTSUP and cannot proceed.
	return clearCapabilities(syscall.AllThreadsSyscall6)
}

func clearCapabilities(all func(uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) (uintptr, uintptr, syscall.Errno)) error {
	if _, _, errno := all(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	// The syscall is injected in inert tests. Pin explicitly rather than rely
	// on uintptr escape annotations surviving an indirect function call.
	var pinned runtime.Pinner
	pinned.Pin(&header)
	pinned.Pin(&data[0])
	defer pinned.Unpin()
	_, _, errno := all(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0, 0, 0, 0)
	runtime.KeepAlive(&header)
	runtime.KeepAlive(&data)
	if errno != 0 {
		return errno
	}
	// This private static route never needs setuid/file capabilities. NNP is
	// per-thread too; no later exec may reacquire them from an image file.
	if _, _, errno := all(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

func verifyCaps(startup bool) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	want := uint32(0)
	if startup {
		want = admin
	}
	if data[0].Effective != want || data[0].Permitted != want || data[0].Inheritable != want || data[1] != (unix.CapUserData{}) {
		return errors.New("namespace capability state refused")
	}
	ambient, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, unix.CAP_SYS_ADMIN, 0, 0)
	if err != nil || ambient != int(boolInt(startup)) {
		return errors.New("namespace ambient capability state refused")
	}
	return nil
}

func boolInt(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}

func (b *nativeBootstrap) verify() error {
	if err := verifyCaps(false); err != nil {
		return err
	}
	// Observe each currently visible runtime thread too. The all-thread
	// barrier above supplies synchronization; any future thread inherits its
	// creator's cleared state. A racing exit or excessive inventory refuses.
	tasks, err := os.Open("/proc/self/task")
	if err != nil {
		return err
	}
	entries, readErr := tasks.ReadDir(257)
	closeErr := tasks.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) == 0 || len(entries) > 256 {
		return errors.New("bounded runtime thread inventory refused")
	}
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil || tid <= 0 || strconv.Itoa(tid) != entry.Name() || !entry.IsDir() {
			return errors.New("runtime thread identity refused")
		}
		status, err := bounded("/proc/self/task/"+entry.Name()+"/status", 16<<10)
		if err != nil || !zeroThreadStatus(status) {
			return errors.New("runtime thread retained startup capabilities")
		}
	}
	var deathSignal int32
	if err := unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&deathSignal)), 0, 0, 0); err != nil || deathSignal != int32(unix.SIGKILL) {
		return errors.New("parent death guard changed during bootstrap")
	}
	runtime.KeepAlive(&deathSignal)
	var link [11]byte
	n, err := unix.Readlink("/proc/self", link[:])
	if err != nil || n <= 0 || n >= len(link) || string(link[:n]) != strconv.Itoa(os.Getpid()) {
		return errors.New("private proc PID view refused")
	}
	current, err := namespaceFDs()
	if err != nil {
		return err
	}
	defer closeFDs(current[:])
	for i, fd := range current {
		before, e1 := fdIdentity(b.fds[i])
		after, e2 := fdIdentity(fd)
		if e1 != nil || e2 != nil || before != after {
			return errors.New("namespace identity changed during bootstrap")
		}
	}
	return nil
}

// Setup consumes FD3 before any READY, command read, backend or workload. The
// admitted CGO0 Go runtime/package initialization is trusted while a single
// namespace-local startup capability exists. It invokes no untrusted callbacks.
// Failure is terminal: caller must exit its owned PID namespace, never continue.
func Setup() (resultErr error) {
	runtime.LockOSThread() // retained for the child lifetime, including PDEATHSIG
	if runtime.GOARCH != "amd64" || os.Getpid() != 1 || os.Getppid() != 0 || unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0) != nil {
		return errors.New("private namespace init required")
	}
	file := os.NewFile(3, "private-namespace-proof")
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	gotSeals, sealErr := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || sealErr != nil || !info.Mode().IsRegular() || info.Size() != proofSize || gotSeals != seals {
		return errors.New("sealed namespace proof required")
	}
	var data [proofSize]byte
	if n, err := file.ReadAt(data[:], 0); err != nil || n != len(data) {
		return errors.New("namespace proof read refused")
	}
	parent, err := decode(data[:])
	if err != nil {
		return err
	}
	b := &nativeBootstrap{parent: parent, fds: [3]int{-1, -1, -1}, proc: -1}
	defer func() {
		closeFDs(b.fds[:])
		if b.proc >= 0 {
			_ = unix.Close(b.proc)
		}
	}()
	return bootstrap(b)
}
