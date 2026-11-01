// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package systemd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// launchd hands a daemon the sockets its plist declares (the Sockets
// dictionary) through launch_activate_socket(3). launchd binds them when it
// loads the job and keeps them bound while the daemon restarts, so a client
// that connects while the gateway is down waits in the socket's queue for
// the next gateway instead of reaching another account that bound the port
// (GAP-0963). Native agent exporters cannot check who accepted their
// connection, so this is what keeps their telemetry and bearer off a peer.
//
// The call lives in libSystem. Release builds are CGO_ENABLED=0, so the
// trampolines in launchd_darwin_*.s reach it the way golang.org/x/sys/unix
// reaches libSystem, through the runtime's libc call path.

//go:cgo_import_dynamic libc_launch_activate_socket launch_activate_socket "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_free free "/usr/lib/libSystem.B.dylib"

var (
	launchActivateSocketTrampolineAddr uintptr
	freeTrampolineAddr                 uintptr
)

//go:linkname syscall_syscall syscall.syscall
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// errLaunchdNoSocket: the process is not a launchd job (ESRCH) or its job
// declares no socket of that name (ENOENT).
var errLaunchdNoSocket = errors.New("launchd: no socket of that name for this process")

// launchdActivation receives the descriptor array launchd allocates. It is a
// heap object, so the addresses handed to libSystem stay put.
type launchdActivation struct {
	fds   *int32
	count uintptr
}

// launchdActivateSocket returns the descriptors launchd holds for the plist
// socket name. Replaceable in tests.
var launchdActivateSocket = func(name string) ([]int, error) {
	cname, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	out := new(launchdActivation)
	r1, _, _ := syscall_syscall(launchActivateSocketTrampolineAddr,
		uintptr(unsafe.Pointer(cname)), uintptr(unsafe.Pointer(&out.fds)), uintptr(unsafe.Pointer(&out.count)))
	// The C function returns an int: only the low 32 bits are defined.
	if code := int32(r1); code != 0 {
		if code == int32(syscall.ESRCH) || code == int32(syscall.ENOENT) {
			return nil, errLaunchdNoSocket
		}
		if code > 0 {
			return nil, fmt.Errorf("launchd: activate socket %q: %w", name, syscall.Errno(code))
		}
		return nil, fmt.Errorf("launchd: activate socket %q: error %d", name, code)
	}
	if out.fds == nil {
		return nil, nil
	}
	defer syscall_syscall(freeTrampolineAddr, uintptr(unsafe.Pointer(out.fds)), 0, 0)
	if out.count > maxListenFDs {
		return nil, fmt.Errorf("launchd: socket %q has %d descriptors, more than %d", name, out.count, maxListenFDs)
	}
	fds := make([]int, 0, out.count)
	for _, fd := range unsafe.Slice(out.fds, out.count) {
		fds = append(fds, int(fd))
	}
	return fds, nil
}

var launchdSockets struct {
	sync.Mutex
	adopted map[string]*sharedListener
	err     map[string]error
	tried   map[string]bool
}

// launchdListener adopts the plist socket name once per process. A socket
// launchd passed as more than one descriptor (one per address family) is
// refused: the gateway's plist declares exactly one IPv4 loopback address.
func launchdListener(name string) (*sharedListener, bool, error) {
	launchdSockets.Lock()
	defer launchdSockets.Unlock()
	if launchdSockets.tried == nil {
		launchdSockets.adopted = map[string]*sharedListener{}
		launchdSockets.err = map[string]error{}
		launchdSockets.tried = map[string]bool{}
	}
	if launchdSockets.tried[name] {
		shared := launchdSockets.adopted[name]
		return shared, shared != nil, launchdSockets.err[name]
	}
	launchdSockets.tried[name] = true
	shared, err := adoptLaunchdSocket(name)
	launchdSockets.adopted[name], launchdSockets.err[name] = shared, err
	return shared, shared != nil, err
}

func adoptLaunchdSocket(name string) (*sharedListener, error) {
	fds, err := launchdActivateSocket(name)
	if errors.Is(err, errLaunchdNoSocket) || (err == nil && len(fds) == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		return nil, fmt.Errorf("launchd: socket %q has %d descriptors, want 1", name, len(fds))
	}
	syscall.CloseOnExec(fds[0])
	file := os.NewFile(uintptr(fds[0]), "launchd:"+name)
	listener, err := net.FileListener(file)
	// FileListener dups the descriptor; launchd keeps its own.
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("launchd: adopt socket %q: %w", name, err)
	}
	return newSharedListener(listener), nil
}
