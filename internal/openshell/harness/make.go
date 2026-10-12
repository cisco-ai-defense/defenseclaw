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
	"path"
	"strings"
)

// MakeSpawnShim is the preload library of the image's make wrapper, and
// MakeWrapper that wrapper: LauncherSystemPATH (and the base image's PATH)
// put /usr/local/bin before /usr/bin, so `make` on the workload's PATH is
// the wrapper, which runs the image's own make.
const (
	MakeSpawnShim = InstallRootBase + "/lib/defenseclaw-spawn.so"
	MakeWrapper   = "/usr/local/bin/make"
)

// makeSpawnSource is the shim's C source. OpenShell's seccomp filter for
// the workload refuses setresuid and setresgid outright, even a call that
// changes nothing, and glibc's posix_spawn makes one for
// POSIX_SPAWN_RESETIDS, which GNU make 4.3 sets for every recipe it starts:
// each recipe failed with "make: <command>: Operation not permitted" (Error
// 127), and with them `make test` and every node-gyp build (GAP-0350). In a
// process whose real and effective ids are the same the flag changes
// nothing, so the shim drops it there. Upstream: NVIDIA/OpenShell#4102 (its
// fix, #4104, lets such calls through); drop the shim and the wrapper once
// the OpenShell floor has it.
const makeSpawnSource = `// DefenseClaw: GNU make starts its recipes in an OpenShell sandbox.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <spawn.h>
#include <unistd.h>

int posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags) {
	static int (*real)(posix_spawnattr_t *, short);
	if (!real)
		real = (int (*)(posix_spawnattr_t *, short))dlsym(RTLD_NEXT, "posix_spawnattr_setflags");
	if ((flags & POSIX_SPAWN_RESETIDS) && getuid() == geteuid() && getgid() == getegid())
		flags &= ~POSIX_SPAWN_RESETIDS;
	return real(attr, flags);
}
`

// makeWrapperScript is MakeWrapper; @MAKE@ becomes the image's make at
// build. A make it starts ($(MAKE) names the image's make) inherits the
// preload.
const makeWrapperScript = `#!/bin/sh
# DefenseClaw: the sandbox's seccomp filter refuses the no-op setresuid that
# GNU make's posix_spawn makes for every recipe; the preloaded shim leaves it
# out where it changes nothing, for this make and every make it starts.
case ":${LD_PRELOAD:-}:" in
*:@SHIM@:*) ;;
*) LD_PRELOAD="@SHIM@${LD_PRELOAD:+:$LD_PRELOAD}"; export LD_PRELOAD ;;
esac
exec @MAKE@ "$@"
`

// WorkloadMakeStep is the image step that lets the workload's GNU make
// start its recipes in a sandbox: it builds makeSpawnSource and installs
// MakeWrapper. Like WorkloadPythonStep it is a compatibility fix, not a
// control. A base image without make or a C compiler, or with a make of its
// own at MakeWrapper, builds on without it.
func WorkloadMakeStep() InstallStep {
	return InstallStep{
		Comment: "GNU make starts its recipes (OpenShell's seccomp filter refuses the no-op setresuid of make's posix_spawn)",
		Run:     workloadMakeRun(MakeSpawnShim, MakeWrapper, "/usr/bin/make /bin/make"),
	}
}

// workloadMakeRun is WorkloadMakeStep's command for the shim and wrapper
// paths and the image's makes to look for (shell words).
func workloadMakeRun(shim, wrapper, makes string) string {
	src := base64.StdEncoding.EncodeToString([]byte(makeSpawnSource))
	wrap := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(makeWrapperScript, "@SHIM@", shim)))
	no := `echo "DefenseClaw: $real cannot start its recipes in a sandbox (`
	return `set -eu; real=""; for m in ` + makes + `; do if [ -x "$m" ]; then real="$m"; break; fi; done; ` +
		`if [ -z "$real" ]; then :; ` +
		`elif [ -e ` + shellQuote(wrapper) + ` ]; then ` + no + `the base image has its own ` + wrapper + `)" >&2; ` +
		`elif ! command -v cc >/dev/null 2>&1; then ` + no + `no C compiler in the base image)" >&2; ` +
		`else src="$(mktemp -d)"; printf '%s' ` + src + ` | base64 -d >"$src/spawn.c"; ` +
		`install -d -m 0755 ` + shellQuote(path.Dir(shim)) + `; ` +
		`cc -O2 -shared -fPIC -o ` + shellQuote(shim) + ` "$src/spawn.c" -ldl; rm -rf "$src"; chmod 0644 ` + shellQuote(shim) + `; ` +
		`printf '%s' ` + wrap + ` | base64 -d | sed "s#@MAKE@#$real#" >` + shellQuote(wrapper) + `; chmod 0755 ` + shellQuote(wrapper) + `; fi`
}
