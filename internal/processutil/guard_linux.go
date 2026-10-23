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
// The gateway and launcher are outside this PID namespace and non-dumpable;
// the filter also refuses APIs that would inspect or inject into their memory.
func guardTrackedInit() error {
	arch, ok := seccompArch[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("processutil: no seccomp architecture for %s", runtime.GOARCH)
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
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("prctl")
	a.load(seccompArg(0))
	a.jeq(unix.PR_SET_PDEATHSIG, "eperm", "allow")
	a.label("allow")
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("eperm")
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	filter, err := a.assemble()
	if err != nil {
		return err
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	err = unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
	runtime.KeepAlive(filter)
	return err
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
