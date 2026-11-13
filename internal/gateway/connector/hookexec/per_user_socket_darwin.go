// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These proc_info flavors and socket fields are defined in XNU's proc_info.h.
// They let the hook inspect the same account's connected sockets in process.
const (
	darwinSysProcInfo       = 336
	darwinProcPIDInfo       = 2
	darwinProcPIDFDInfo     = 3
	darwinProcPIDListFDs    = 1
	darwinProcPIDFDSocket   = 3
	darwinProcFDSocket      = 2
	darwinSockInfoTCP       = 2
	darwinTCPListen         = 1
	darwinTCPEstablished    = 4
	darwinSocketInfoMinSize = 348
)

type darwinSocketTuple struct {
	local, remote net.TCPAddr
	state         int32
}

// darwinSocketOwnerPIDs lists this account's processes with an exact TCP
// endpoint tuple. A nil remote selects listening sockets.
func darwinSocketOwnerPIDs(ctx context.Context, local, remote *net.TCPAddr, state int32) ([]int, error) {
	if local == nil || local.IP == nil || local.Port < 1 || local.Port > 65535 ||
		(remote != nil && (remote.IP == nil || remote.Port < 1 || remote.Port > 65535)) {
		return nil, errors.New("connected gateway endpoint is invalid")
	}
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("inspect gateway process list: %w", err)
	}
	var owners []int
	seen := make(map[int]bool)
	for _, process := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid := int(process.Proc.P_pid)
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		held, err := darwinProcessHoldsSocket(ctx, pid, process.Proc.P_starttime, local, remote, state)
		if err != nil {
			return nil, err
		}
		if held {
			owners = append(owners, pid)
		}
	}
	return owners, nil
}

// darwinProcessHoldsSocket reports whether process pid, started at
// starttime and still of this account, holds a TCP socket with the exact
// endpoint tuple and state. A process that is gone or cannot be inspected
// holds none.
func darwinProcessHoldsSocket(ctx context.Context, pid int, starttime unix.Timeval, local, remote *net.TCPAddr, state int32) (bool, error) {
	fds, err := darwinProcessFDs(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM) ||
			errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
			return false, nil
		}
		return false, fmt.Errorf("inspect gateway process descriptors: %w", err)
	}
	for _, fd := range fds {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if fd.kind != darwinProcFDSocket {
			continue
		}
		tuple, err := darwinProcessSocket(pid, fd.number)
		if err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.ESRCH) ||
				errors.Is(err, syscall.EINVAL) ||
				errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				continue
			}
			return false, fmt.Errorf("inspect gateway socket: %w", err)
		}
		if tuple.state == state && darwinTCPAddrEqual(&tuple.local, local) &&
			(remote == nil || darwinTCPAddrEqual(&tuple.remote, remote)) {
			current, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
			if err != nil || current == nil || current.Eproc.Ucred.Uid != uint32(os.Geteuid()) ||
				current.Proc.P_starttime != starttime {
				return false, nil
			}
			return true, nil
		}
	}
	return false, nil
}

// darwinRecordedGatewayHoldsSocket reports whether the gateway that the
// gateway record of this account names (still the same live process, of
// this account) holds the exact accepted socket. It proves what the scan of
// every process of the account proves, for the one process that answers
// almost every call, without the descriptors of every other process of the
// account: at a hundred hook calls a second each call scanned the hundreds
// of hook processes in flight beside it (#1384).
func darwinRecordedGatewayHoldsSocket(ctx context.Context, local, remote *net.TCPAddr, state int32) bool {
	for _, home := range perUserGatewayHomes(ctx) {
		pid, ok := recordedGatewayPID(home)
		if !ok {
			continue
		}
		process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil || process == nil || process.Eproc.Ucred.Uid != uint32(os.Geteuid()) {
			continue
		}
		if held, err := darwinProcessHoldsSocket(ctx, pid, process.Proc.P_starttime, local, remote, state); err == nil && held {
			return true
		}
	}
	return false
}

func darwinTCPAddrEqual(a, b *net.TCPAddr) bool {
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

type darwinFD struct {
	number int
	kind   uint32
}

func darwinProcessFDs(pid int) ([]darwinFD, error) {
	for count := 256; count <= 4096; count *= 2 {
		buf := make([]byte, count*8)
		n, err := darwinProcInfo(darwinProcPIDInfo, pid, darwinProcPIDListFDs, 0, buf)
		if err != nil {
			return nil, err
		}
		if n < 0 || n%8 != 0 {
			return nil, errors.New("gateway descriptor list is incomplete")
		}
		if n == len(buf) {
			continue
		}
		fds := make([]darwinFD, 0, n/8)
		for offset := 0; offset < n; offset += 8 {
			fd := int(int32(binary.NativeEndian.Uint32(buf[offset:])))
			if fd >= 0 {
				fds = append(fds, darwinFD{number: fd, kind: binary.NativeEndian.Uint32(buf[offset+4:])})
			}
		}
		return fds, nil
	}
	return nil, errors.New("gateway descriptor list is too large")
}

func darwinProcessSocket(pid, fd int) (darwinSocketTuple, error) {
	// The union in socket_fdinfo includes large Unix socket names. The TCP
	// fields used here are in its fixed prefix.
	buf := make([]byte, 1024)
	n, err := darwinProcInfo(darwinProcPIDFDInfo, pid, darwinProcPIDFDSocket, uintptr(fd), buf)
	if err != nil {
		return darwinSocketTuple{}, err
	}
	if n < darwinSocketInfoMinSize {
		return darwinSocketTuple{}, errors.New("gateway socket information is incomplete")
	}
	if binary.NativeEndian.Uint32(buf[180:]) != syscall.IPPROTO_TCP ||
		binary.NativeEndian.Uint32(buf[256:]) != darwinSockInfoTCP {
		return darwinSocketTuple{}, nil
	}
	family := binary.NativeEndian.Uint32(buf[184:])
	vflag := buf[288]
	var localIP, remoteIP net.IP
	switch {
	case family == syscall.AF_INET6 && vflag&2 != 0:
		remoteIP = net.IP(bytes.Clone(buf[296:312]))
		localIP = net.IP(bytes.Clone(buf[312:328]))
	case (family == syscall.AF_INET || family == syscall.AF_INET6) && vflag&1 != 0:
		remoteIP = net.IP(bytes.Clone(buf[308:312]))
		localIP = net.IP(bytes.Clone(buf[324:328]))
	default:
		return darwinSocketTuple{}, nil
	}
	return darwinSocketTuple{
		local:  net.TCPAddr{IP: localIP, Port: int(binary.BigEndian.Uint16(buf[268:]))},
		remote: net.TCPAddr{IP: remoteIP, Port: int(binary.BigEndian.Uint16(buf[264:]))},
		state:  int32(binary.NativeEndian.Uint32(buf[344:])),
	}, nil
}

func darwinProcInfo(call, pid, flavor int, arg uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, errors.New("gateway process buffer is empty")
	}
	n, _, errno := syscall.Syscall6(darwinSysProcInfo, uintptr(call), uintptr(pid),
		uintptr(flavor), arg, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return 0, errno
	}
	if n > uintptr(len(buf)) {
		return 0, errors.New("gateway process buffer is incomplete")
	}
	return int(n), nil
}
