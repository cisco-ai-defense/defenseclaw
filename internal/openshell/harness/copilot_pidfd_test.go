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
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// copilotPidfdProbe refuses pidfd_open with ENOSYS the way the sandbox's
// seccomp filter does, then waits for a child through pidfd_open and poll,
// as the Copilot CLI's runtime does for a hook process.
const copilotPidfdProbe = `#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pidfd_open, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {4, f};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) return 2;
	const char *preload = getenv("LD_PRELOAD") ? "kept" : "dropped";
	pid_t child = fork();
	if (child == 0) { usleep(100000); _exit(7); }
	long fd = syscall(SYS_pidfd_open, child, 0);
	if (fd < 0) { printf("refused %d, LD_PRELOAD %s\n", errno, preload); return 1; }
	struct pollfd p = {(int)fd, POLLIN, 0};
	int st;
	if (poll(&p, 1, 5000) != 1 || waitpid(child, &st, 0) != child || WEXITSTATUS(st) != 7) { puts("no exit event"); return 1; }
	printf("exit seen, not a child %ld, LD_PRELOAD %s\n", syscall(SYS_pidfd_open, 1, 0), preload);
	return 0;
}
`

// TestCopilotPidfdShim builds the shim the Copilot image preloads (#966) and
// runs it under a filter that refuses pidfd_open: in its target it reports
// a child's exit through the descriptor, leaves a non-child refused and
// drops LD_PRELOAD; in any other program it changes nothing. The image
// compiles the same source and the launcher preloads it after the loader
// scrub.
func TestCopilotPidfdShim(t *testing.T) {
	steps, err := Copilot.InstallSteps("")
	if err != nil || len(steps) != 1 || !strings.Contains(steps[0].Run, base64.StdEncoding.EncodeToString([]byte(copilotPidfdSource))) ||
		!strings.Contains(steps[0].Run, "-o '"+CopilotPidfdShim+"'") {
		t.Fatalf("the Copilot install does not build %s: %v, %v", CopilotPidfdShim, steps, err)
	}
	scrub, preload := strings.Index(copilotLauncher, launcherLoaderScrub), strings.Index(copilotLauncher, "dc_pidfd=(LD_PRELOAD="+CopilotPidfdShim+")")
	if scrub < 0 || preload < scrub {
		t.Fatalf("the Copilot launcher does not preload %s after its loader scrub:\n%s", CopilotPidfdShim, copilotLauncher)
	}

	if runtime.GOOS != "linux" {
		t.Skip("the shim is for the Linux sandbox")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("a C compiler is required")
	}
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe")
	for name, src := range map[string]string{"shim.c": copilotPidfdSource, "probe.c": copilotPidfdProbe} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	build := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("cc %v: %v\n%s", args, err, out)
		}
	}
	build("-O2", "-o", probe, filepath.Join(dir, "probe.c"))
	for _, c := range []struct{ target, want string }{
		{probe, "exit seen, not a child -1, LD_PRELOAD dropped"},
		{"/nonexistent/copilot", "refused 38, LD_PRELOAD kept"},
	} {
		shim := filepath.Join(dir, "shim.so")
		build("-O2", "-shared", "-fPIC", `-DDC_TARGET="`+c.target+`"`, "-o", shim, filepath.Join(dir, "shim.c"), "-ldl", "-lpthread")
		cmd := exec.Command(probe)
		cmd.Env = append(os.Environ(), "LD_PRELOAD="+shim)
		out, err := cmd.Output()
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 2 {
			t.Skip("seccomp filters are not available here")
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Fatalf("target %s: probe = %q (%v), want %q", c.target, got, err, c.want)
		}
	}
}
