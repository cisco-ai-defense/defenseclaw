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
)

// CopilotPidfdShim is the in-image preload library that stops the pinned
// Copilot CLI from waiting out its hook timeout on every hook (#966).
//
// The sandbox's seccomp filter makes pidfd_open fail with ENOSYS. The CLI's
// native runtime (Rust, tokio) then falls back to SIGCHLD to learn that a
// hook process exited, and in the TUI the CLI's Node.js side resets SIGCHLD
// to the default disposition, so a finished hook stays a zombie until the
// 30-second hook timeout. The shim answers a pidfd_open the kernel refused,
// for a child of the calling process only, with an eventfd that becomes
// readable when the child exits (a thread waits for it with WNOWAIT, so the
// runtime still reaps the child itself). Every other call, and a pidfd_open
// the kernel serves, is untouched.
//
// The launcher preloads it after its loader scrub. It acts only in the
// pinned native executable (its path is compiled in) and removes
// LD_PRELOAD from that process's environment at load, so hooks, tools and
// every other process the CLI starts run without it.
const CopilotPidfdShim = InstallRootBase + "/copilot/lib/defenseclaw-pidfd.so"

// copilotPidfdSource is the shim's C source, compiled at image build with
// DC_TARGET set to the resolved path of the pinned native executable.
const copilotPidfdSource = `// DefenseClaw pidfd_open fallback for the pinned GitHub Copilot CLI (#966).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

typedef long (*syscall_fn)(long, ...);
static syscall_fn real_syscall;
static int active;

__attribute__((constructor)) static void dc_init(void) {
	char self[4096];
	ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
	if (n <= 0) return;
	self[n] = 0;
	if (strcmp(self, DC_TARGET) != 0) return;
	active = 1;
	unsetenv("LD_PRELOAD");
}

struct watch { pid_t pid; int fd; };

static void *watcher(void *arg) {
	struct watch *w = arg;
	siginfo_t si;
	while (waitid(P_PID, (id_t)w->pid, &si, WEXITED | WNOWAIT) != 0 && errno == EINTR) {
	}
	uint64_t one = 1;
	(void)!write(w->fd, &one, sizeof one);
	close(w->fd);
	free(w);
	return NULL;
}

static long emulate_pidfd_open(pid_t pid, unsigned int flags) {
	siginfo_t si;
	memset(&si, 0, sizeof si);
	if (pid <= 0 || (flags & ~(unsigned int)O_NONBLOCK) != 0 ||
	    waitid(P_PID, (id_t)pid, &si, WEXITED | WNOHANG | WNOWAIT) != 0) {
		errno = ENOSYS;
		return -1;
	}
	int efd = eventfd(0, EFD_CLOEXEC | ((flags & O_NONBLOCK) ? EFD_NONBLOCK : 0));
	if (efd < 0) {
		errno = ENOSYS;
		return -1;
	}
	struct watch *w = malloc(sizeof *w);
	int wfd = fcntl(efd, F_DUPFD_CLOEXEC, 0);
	pthread_attr_t attr;
	sigset_t all, old;
	pthread_t t;
	int ok = w != NULL && wfd >= 0 && pthread_attr_init(&attr) == 0;
	if (ok) {
		w->pid = pid;
		w->fd = wfd;
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_attr_setstacksize(&attr, 65536);
		sigfillset(&all);
		pthread_sigmask(SIG_SETMASK, &all, &old);
		ok = pthread_create(&t, &attr, watcher, w) == 0;
		pthread_sigmask(SIG_SETMASK, &old, NULL);
		pthread_attr_destroy(&attr);
	}
	if (!ok) {
		free(w);
		if (wfd >= 0) close(wfd);
		close(efd);
		errno = ENOSYS;
		return -1;
	}
	return efd;
}

long syscall(long nr, ...) {
	va_list ap;
	va_start(ap, nr);
	long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long);
	long a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
	va_end(ap);
	if (!real_syscall) real_syscall = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
	long r = real_syscall(nr, a1, a2, a3, a4, a5, a6);
	if (active && r == -1 && errno == ENOSYS && nr == SYS_pidfd_open)
		return emulate_pidfd_open((pid_t)a1, (unsigned int)a2);
	return r;
}
`

// copilotPidfdInstall is the install-step fragment that compiles the shim
// for the native executable in $bin (set by npmPin.installRun). The base
// image ships a C toolchain; one without it gets gcc and libc6-dev.
func copilotPidfdInstall() string {
	return `if ! command -v cc >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*; fi; ` +
		`target="$(readlink -f "$bin")"; case "$target" in "$root"/*) ;; *) echo "Copilot native binary $target is outside $root" >&2; exit 1 ;; esac; ` +
		`src="$(mktemp -d)"; printf '%s' ` + shellQuote(base64.StdEncoding.EncodeToString([]byte(copilotPidfdSource))) + ` | base64 -d >"$src/pidfd.c"; ` +
		`cc -O2 -shared -fPIC -DDC_TARGET="\"$target\"" -o ` + shellQuote(CopilotPidfdShim) + ` "$src/pidfd.c" -ldl -lpthread; rm -rf "$src"; ` +
		`chown root:root ` + shellQuote(CopilotPidfdShim) + `; chmod 0644 ` + shellQuote(CopilotPidfdShim)
}
