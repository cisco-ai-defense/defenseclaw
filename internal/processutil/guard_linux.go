// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

var seccompArch = map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}

const (
	seccompNROffset   = 0
	seccompArchOffset = 4
)

func seccompArg(i uint32) uint32 { return 16 + 8*i }

// guardTrackedInit is installed before the trusted PID-namespace init execs
// the scanner. A scanner cannot clear the parent-death signal that links its
// PID 1 to the launcher. Its own children remain signalable by positive PID.
// The gateway and launcher are outside this PID namespace. The scanner still
// sees them, and every other host process, through the host procfs: its
// Landlock domain refuses ptrace access to all of them, and the filter also
// refuses ptrace and cross-process memory and descriptor APIs. Nothing here
// changes the gateway's own process state.
func guardTrackedInit() error {
	return enterScannerGuard(enterScannerDomain, false)
}

// guardPodScanner is guardTrackedInit for the pod-contained scanner, which
// shares the scan worker's user and PID namespace (GAP-0828). Its Landlock
// domain allows writes only beneath writable and to /dev/null, and reads
// only its private job and the runtime (GAP-0873, GAP-0902). It may not
// signal the worker, its PID 1 (GAP-0874):
// with Landlock signal scoping (ABI 6) it signals only its own domain;
// without it the filter also refuses kill, tgkill, rt_sigqueueinfo,
// rt_tgsigqueueinfo and pidfd_open of PID 1, and every tkill,
// pidfd_send_signal and fcntl F_SETOWN, F_SETOWN_EX and F_SETSIG (a SIGIO
// owner). podGuardAvailable tells the worker beforehand whether it can.
func guardPodScanner(writable, readJob string) error {
	abi := podLandlockABI()
	scope := abi >= landlockScopeSignalABI
	return enterScannerGuard(func() error { return enterPodScannerDomain(abi, writable, readJob, scope) }, !scope)
}

// landlockScopeSignalABI is the first Landlock ABI with LANDLOCK_SCOPE_SIGNAL.
const landlockScopeSignalABI = 6

// podLandlockABI is the kernel's Landlock ABI version (0: none); a seam for
// tests of the older kernels.
var podLandlockABI = func() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(v)
}

// podSeccompFilters reports whether this kernel installs seccomp filters
// that answer an errno; a seam for tests.
var podSeccompFilters = func() bool {
	action := uint32(unix.SECCOMP_RET_ERRNO)
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_ACTION_AVAIL, 0, uintptr(unsafe.Pointer(&action)))
	return errno == 0
}

// podGuardAvailable reports why guardPodScanner cannot keep a scanner from
// the scan worker on this kernel; the worker then refuses pod mode, so it
// fails closed (GAP-0874).
func podGuardAvailable() error {
	abi := podLandlockABI()
	switch {
	case abi < 1:
		return errors.New("this kernel has no Landlock for the scanner")
	case !podSeccompFilters():
		return errors.New("this kernel installs no seccomp filter for the scanner")
	}
	return nil
}

// enterScannerGuard sets no_new_privs, enters the Landlock domain, then
// installs the scanner's filter (with the signal rules when blockSignals).
func enterScannerGuard(domain func() error, blockSignals bool) error {
	filter, err := scannerFilter(blockSignals)
	if err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := domain(); err != nil {
		return err
	}
	err = unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
	runtime.KeepAlive(filter)
	return err
}

// scannerFilter is the scanner's seccomp program. Without blockSignals it is
// the filter the laptop's scanner has always had.
func scannerFilter(blockSignals bool) ([]unix.SockFilter, error) {
	arch, ok := seccompArch[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("processutil: no seccomp architecture for %s", runtime.GOARCH)
	}
	var a bpfAssembler
	a.load(seccompArchOffset)
	a.jeq(arch, "", "eperm")
	a.load(seccompNROffset)
	if runtime.GOARCH == "amd64" {
		a.jge(0x40000000, "eperm", "")
	}
	a.jeq(unix.SYS_PRCTL, "prctl", "")
	a.jeq(unix.SYS_PTRACE, "eperm", "")
	a.jeq(unix.SYS_PROCESS_VM_READV, "eperm", "")
	a.jeq(unix.SYS_PROCESS_VM_WRITEV, "eperm", "")
	a.jeq(unix.SYS_PIDFD_GETFD, "eperm", "")
	if blockSignals {
		// The first argument is the target's PID (tgid); only its low
		// 32 bits name a process, so only they are compared.
		for _, nr := range []uint32{unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO, unix.SYS_PIDFD_OPEN} {
			a.jeq(nr, "pid1", "")
		}
		// tkill names a thread of any process, and pidfd_send_signal
		// also takes a /proc/<pid> folder: neither is needed.
		a.jeq(unix.SYS_TKILL, "eperm", "")
		a.jeq(unix.SYS_PIDFD_SEND_SIGNAL, "eperm", "")
		a.jeq(unix.SYS_FCNTL, "fcntl", "")
	}
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("prctl")
	a.load(seccompArg(0))
	a.jeq(unix.PR_SET_PDEATHSIG, "eperm", "allow")
	if blockSignals {
		a.label("pid1")
		a.load(seccompArg(0))
		// kill(0) and kill(-pgid) can reach PID 1 through its process
		// group; all nonpositive targets are refused along with PID 1.
		a.jge(0x80000000, "eperm", "")
		a.jge(2, "allow", "eperm")
		a.label("fcntl")
		a.load(seccompArg(1))
		a.jeq(unix.F_SETOWN, "eperm", "")
		a.jeq(unix.F_SETOWN_EX, "eperm", "")
		a.jeq(unix.F_SETSIG, "eperm", "allow")
	}
	a.label("allow")
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("eperm")
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	return a.assemble()
}

// scannerRuleset is struct landlock_ruleset_attr up to handled_access_fs,
// the one field every Landlock ABI knows.
type scannerRuleset struct{ handledAccessFS uint64 }

// enterScannerDomain puts the scanner in a Landlock domain of its own. Landlock
// refuses ptrace access from a domain to every process outside it: ptrace and
// /proc/<pid>/mem, environ, maps, fd, cwd, root and exe of the gateway, the
// launcher and any other host process. The gateway therefore stays dumpable,
// and same-user status, stop, restart and upgrade checks keep reading its /proc
// entries while a scan runs. The ruleset handles only block-device creation,
// which an unprivileged scanner cannot do anyway, so file access is unchanged.
// Without Landlock (a kernel before 5.13, or one booted without it, or a
// service filter that refuses the calls) the scanner never starts.
func enterScannerDomain() error {
	attr := scannerRuleset{handledAccessFS: unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("processutil: no Landlock for the scanner: %w", errno)
	}
	defer unix.Close(int(fd))
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("processutil: enter the scanner's Landlock domain: %w", errno)
	}
	return nil
}

// podWriteAccess is every Landlock right that writes, removes, makes or
// links a file, as far as Landlock ABI abi knows them.
func podWriteAccess(abi int) uint64 {
	access := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		// IOCTL_DEV can mutate device state without a file write.
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return access
}

// enterPodScannerDomain puts the pod scanner in a Landlock domain that
// handles every write and read right of ABI abi. It allows writes beneath
// writable and to /dev/null, and reads only from the private job, scanner
// runtime and the system files observed in the E1 runtime trace. An empty
// readJob is used for the runtime's version check. With scopeSignals the
// domain may signal only itself (Landlock
// ABI 6): never the scan worker, also not by a SIGIO owner. As
// enterScannerDomain, the domain refuses ptrace access to the processes
// outside it.
func enterPodScannerDomain(abi int, writable, readJob string, scopeSignals bool) error {
	if abi < 1 {
		return errors.New("processutil: no Landlock for the scanner")
	}
	write := podWriteAccess(abi)
	read := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	attr := unix.LandlockRulesetAttr{Access_fs: write | read}
	size := unsafe.Sizeof(attr.Access_fs)
	switch {
	case scopeSignals:
		attr.Scoped = unix.LANDLOCK_SCOPE_SIGNAL
		size = unsafe.Sizeof(attr)
	case abi >= 4:
		size = unsafe.Offsetof(attr.Scoped)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return fmt.Errorf("processutil: no Landlock for the scanner: %w", errno)
	}
	defer unix.Close(int(fd))
	fileWrite := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE)
	if abi >= 3 {
		fileWrite |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	rules := []struct {
		path   string
		access uint64
	}{
		{writable, write | read},
		{"/dev/null", fileWrite | unix.LANDLOCK_ACCESS_FS_READ_FILE},
		{"/opt/defenseclaw", read},
		{"/lib", read},
		{"/lib64", read},
		{"/usr/lib", read},
		{"/usr/local/bin", read},
		{"/bin", read},
		{"/usr/bin", read},
		{"/proc", read},
		{"/sys/devices/system/cpu", read},
		{"/sys/fs/cgroup", read},
		{"/sys/kernel/mm", read},
		{"/dev/shm", read},
	}
	if readJob != "" {
		rules = append(rules, struct {
			path   string
			access uint64
		}{readJob, read})
	}
	for _, rule := range rules {
		pfd, err := unix.Open(rule.path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && rule.path != writable && rule.path != readJob {
			continue // Minimal distroless images omit some host runtime paths.
		}
		if err != nil {
			return fmt.Errorf("processutil: scanner file rule %s: %w", rule.path, err)
		}
		beneath := unix.LandlockPathBeneathAttr{Allowed_access: rule.access, Parent_fd: int32(pfd)}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&beneath)), 0, 0, 0)
		_ = unix.Close(pfd)
		if errno != 0 {
			return fmt.Errorf("processutil: scanner file rule %s: %w", rule.path, errno)
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("processutil: enter the scanner's Landlock domain: %w", errno)
	}
	return nil
}

// bpfAssembler builds a classic BPF program whose jumps name their targets.
// Conditional BPF branches have only eight-bit offsets. Two adjacent JA
// trampolines give each branch the full 32-bit forward range.
type bpfAssembler struct {
	insns  []unix.SockFilter
	jumps  map[int]bpfJumpTarget
	labels map[string]int
}

type bpfJumpTarget struct {
	label         string
	fallthroughTo int
}

func (a *bpfAssembler) emit(code uint16, k uint32) {
	a.insns = append(a.insns, unix.SockFilter{Code: code, K: k})
}

func (a *bpfAssembler) load(offset uint32) { a.emit(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offset) }

func (a *bpfAssembler) ret(k uint32) { a.emit(unix.BPF_RET|unix.BPF_K, k) }

func (a *bpfAssembler) jeq(k uint32, jt, jf string) { a.jump(unix.BPF_JEQ, k, jt, jf) }

func (a *bpfAssembler) jge(k uint32, jt, jf string) { a.jump(unix.BPF_JGE, k, jt, jf) }

func (a *bpfAssembler) jump(op uint16, k uint32, jt, jf string) {
	if a.jumps == nil {
		a.jumps = map[int]bpfJumpTarget{}
	}
	at := len(a.insns)
	a.emit(unix.BPF_JMP|op|unix.BPF_K, k)
	a.insns[at].Jt, a.insns[at].Jf = 0, 1
	a.jumps[at+1] = bpfJumpTarget{label: jt, fallthroughTo: at + 3}
	a.jumps[at+2] = bpfJumpTarget{label: jf, fallthroughTo: at + 3}
	a.emit(unix.BPF_JMP|unix.BPF_JA, 0)
	a.emit(unix.BPF_JMP|unix.BPF_JA, 0)
}

func (a *bpfAssembler) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.insns)
}

func (a *bpfAssembler) assemble() ([]unix.SockFilter, error) {
	for at, target := range a.jumps {
		to := target.fallthroughTo
		if target.label == "" {
			// Both arms fall through beyond the two JA instructions.
		} else {
			var ok bool
			to, ok = a.labels[target.label]
			if !ok || to <= at {
				return nil, fmt.Errorf("processutil: bad seccomp jump to %q", target.label)
			}
		}
		a.insns[at].K = uint32(to - at - 1)
	}
	return a.insns, nil
}
