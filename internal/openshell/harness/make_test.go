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

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// denySetIDs runs its arguments under a seccomp filter that refuses
// setresuid and setresgid with EPERM, as OpenShell's filter for the
// workload does.
const denySetIDs = `#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setresuid, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setresgid, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
	};
	struct sock_fprog prog = {sizeof f / sizeof f[0], f};
	if (argc < 2 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("seccomp");
		return 125;
	}
	execv(argv[1], argv + 1);
	perror("exec");
	return 126;
}
`

// TestWorkloadMakeStep (GAP-0350): under a filter that refuses setresuid
// and setresgid, the image's GNU make cannot start a recipe ("Operation not
// permitted"); the wrapper the image step installs runs them, a make it
// starts too, and a base image's own make at the wrapper's path stays.
func TestWorkloadMakeStep(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the step runs in Linux image builds")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc is required")
	}
	real := ""
	for _, m := range []string{"/usr/bin/make", "/bin/make"} {
		if _, err := os.Stat(m); err == nil {
			real = m
			break
		}
	}
	if real == "" {
		t.Skip("GNU make is required")
	}
	dir := t.TempDir()
	deny := filepath.Join(dir, "deny")
	if err := os.WriteFile(deny+".c", []byte(denySetIDs), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-o", deny, deny+".c").CombinedOutput(); err != nil {
		t.Skipf("cannot build the seccomp helper: %v: %s", err, out)
	}
	mk := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(mk, []byte("all:\n\t@$(MAKE) -s -f "+mk+" inner\ninner:\n\t@printf 'dccert-make-ok\\n'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(deny, real, "-s", "-f", mk, "inner").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Operation not permitted") {
		t.Skipf("this make starts its recipes without setresuid (%v): %s", err, out)
	}

	shim, wrapper := filepath.Join(dir, "lib", "spawn.so"), filepath.Join(dir, "make")
	if out, err := exec.Command("sh", "-c", workloadMakeRun(shim, wrapper, real)).CombinedOutput(); err != nil {
		t.Fatalf("step = %v:\n%s", err, out)
	}
	if out, err := exec.Command(deny, wrapper, "-s", "-f", mk).CombinedOutput(); err != nil || !strings.Contains(string(out), "dccert-make-ok") {
		t.Fatalf("the wrapper's make = %v:\n%s", err, out)
	}

	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command("sh", "-c", workloadMakeRun(shim, wrapper, real)).CombinedOutput()
	if got, _ := os.ReadFile(wrapper); err != nil || string(got) != "#!/bin/sh\n" || !strings.Contains(string(out), "the base image has its own "+wrapper) {
		t.Fatalf("a base image's own make: %v, %q:\n%s", err, got, out)
	}
	if !strings.Contains(WorkloadMakeStep().Run, `/usr/bin/make /bin/make`) {
		t.Fatalf("the step does not look for the image's make: %s", WorkloadMakeStep().Run)
	}
}
