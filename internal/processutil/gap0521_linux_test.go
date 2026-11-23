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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// namespaceRefusedEnv is "<errno>,<result file>" for the helper below.
const namespaceRefusedEnv = "DC_PROCESSUTIL_TEST_NAMESPACE_REFUSED"

// TestRunTrackedNamespaceRefusedHelper runs RunTracked as a gateway on a host
// that refuses user namespaces: a seccomp filter fails every clone or unshare
// that asks for a new user namespace with the errno it is given, as a
// container's default profile does (EPERM) and as user.max_user_namespaces=0
// does (ENOSPC). It writes what RunTracked returned to the result file.
func TestRunTrackedNamespaceRefusedHelper(t *testing.T) {
	spec := os.Getenv(namespaceRefusedEnv)
	if spec == "" {
		t.Skip("helper process")
	}
	code, out, ok := strings.Cut(spec, ",")
	errno, err := strconv.Atoi(code)
	if !ok || err != nil {
		t.Fatalf("bad %s %q", namespaceRefusedEnv, spec)
	}
	refuseUserNamespaces(t, syscall.Errno(errno))
	err = RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", `: > "$1"`, "sh", out+".ran"))
	report := fmt.Sprintf("not-contained=%t containment-unavailable=%t\n%v",
		errors.Is(err, ErrNotContained), errors.Is(err, ErrContainmentUnavailable), err)
	if err := os.WriteFile(out, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0521: on a host that refuses user namespaces (user.max_user_namespaces=0
// on the host that ran the template build) every skill scan failed with
// "scanner custody handshake: EOF": the launcher could not create the
// scanner's namespaces and went away without a word. The scanner must still
// never run, and RunTracked must say that this host refuses the namespaces
// containment needs, and why, so a scan that cannot run is never read as a
// scanner that failed.
func TestRunTrackedReportsAHostThatRefusesTheScannerNamespaces(t *testing.T) {
	for _, tc := range []struct {
		name  string
		errno syscall.Errno
		cause string
	}{
		{"user namespaces off or at their limit (ENOSPC)", syscall.ENOSPC, "user.max_user_namespaces"},
		{"a container's default seccomp profile (EPERM)", syscall.EPERM, "a seccomp profile or sandbox refuses user namespaces"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "result")
			helper := exec.Command(os.Args[0], "-test.run=^TestRunTrackedNamespaceRefusedHelper$", "-test.count=1")
			helper.Env = append(os.Environ(), fmt.Sprintf("%s=%d,%s", namespaceRefusedEnv, int(tc.errno), out))
			if b, err := helper.CombinedOutput(); err != nil {
				t.Fatalf("helper: %v\n%s", err, b)
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("helper wrote no result: %v", err)
			}
			report := string(b)
			if _, err := os.Stat(out + ".ran"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scanner ran without its namespaces (%v); RunTracked said:\n%s", err, report)
			}
			if !strings.HasPrefix(report, "not-contained=true containment-unavailable=true\n") {
				t.Fatalf("RunTracked on a host that refuses user namespaces:\n%s\nwant ErrNotContained and ErrContainmentUnavailable", report)
			}
			for _, want := range []string{"this host refuses the namespaces containment needs", tc.cause} {
				if !strings.Contains(report, want) {
					t.Fatalf("RunTracked error %q does not say %q", report, want)
				}
			}
		})
	}
}

// refuseUserNamespaces installs, on every thread, a seccomp filter that fails
// every clone or unshare asking for a new user namespace with errno, as a container's
// default profile does (EPERM) and as user.max_user_namespaces=0 does
// (ENOSPC).
func refuseUserNamespaces(t *testing.T, errno syscall.Errno) {
	t.Helper()
	arch, ok := seccompArch[runtime.GOARCH]
	if !ok {
		t.Skipf("no seccomp architecture for %s", runtime.GOARCH)
	}
	var a bpfAssembler
	a.load(seccompArchOffset)
	a.jeq(arch, "", "allow")
	a.load(seccompNROffset)
	a.jeq(unix.SYS_CLONE, "flags", "")
	a.jeq(unix.SYS_UNSHARE, "flags", "allow")
	a.label("flags")
	a.load(seccompArg(0))
	a.emit(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, unix.CLONE_NEWUSER)
	a.jeq(0, "allow", "refuse")
	a.label("allow")
	a.ret(unix.SECCOMP_RET_ALLOW)
	a.label("refuse")
	a.ret(unix.SECCOMP_RET_ERRNO | uint32(errno))
	filter, err := a.assemble()
	if err != nil {
		t.Fatal(err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// Every thread: a child started from any goroutine meets the filter.
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog))); errno != 0 {
		t.Fatal(errno)
	}
	runtime.KeepAlive(filter)
}
