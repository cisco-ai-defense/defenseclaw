// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func writeProc(t *testing.T, root string, pid int, comm string, startTicks, nspid string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Fields 3-21 then starttime (22) and the rest.
	stat := strconv.Itoa(pid) + " (" + comm + ") S 1 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 " + startTicks + " 1000 200 18446744073709551615\n"
	status := "Name:\t" + comm + "\nTgid:\t" + strconv.Itoa(pid) + "\n" + nspid + "Uid:\t1000\t1000\t1000\t1000\n"
	for name, data := range map[string]string{"stat": stat, "status": status} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostProcReadsTheInnermostPidAndStart(t *testing.T) {
	root := t.TempDir()
	// A comm with spaces and a parenthesis must not shift the fields.
	writeProc(t, root, 217400, "a) b (c", "412177", "NSpid:\t217400\t57\n")
	writeProc(t, root, 300, "init", "5", "NSpid:\t300\n")
	writeProc(t, root, 301, "odd", "5", "")
	p := HostProc{Root: root}
	if ns, ticks, ok := p.NSPid(217400); !ok || ns != 57 || ticks != 412177 {
		t.Fatalf("217400 = %d %d %v", ns, ticks, ok)
	}
	if ns, _, ok := p.NSPid(300); !ok || ns != 300 {
		t.Fatalf("a host-namespace process = %d %v", ns, ok)
	}
	for _, pid := range []int{301, 999, 0, -1} {
		if _, _, ok := p.NSPid(pid); ok {
			t.Fatalf("pid %d read", pid)
		}
	}
}

// The live /proc of this test process: its own pid namespace's pid.
func TestHostProcOnTheLiveProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is Linux's")
	}
	ns, ticks, ok := HostProc{}.NSPid(os.Getpid())
	if !ok || ns <= 0 || ticks <= 0 {
		t.Fatalf("own process = %d %d %v", ns, ticks, ok)
	}
}
