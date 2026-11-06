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

//go:build !windows

package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// isWorkloadCheck reports the exec of the workload check.
func isWorkloadCheck(call openshelltest.ExecCall) bool {
	return len(call.Command) >= 8 && call.Command[0] == "/usr/bin/env" &&
		(call.Command[7] == "defenseclaw-verify" || call.Command[7] == "defenseclaw-verify-vm")
}

// goodResolverOutput is what the pinned resolver caller prints in a guest
// whose localhost is IPv4 loopback only.
const goodResolverOutput = "unspec 127.0.0.1\ninet 127.0.0.1\nloopback-only\n"

// isResolverCall reports the direct exec of the pinned resolver caller.
func isResolverCall(call openshelltest.ExecCall) bool {
	return slices.Equal(call.Command, []string{localhostResolverPath})
}

// withResolverAnswer answers the direct resolver exec with out and exit
// status code, and hands every other command to h.
func withResolverAnswer(h openshelltest.ExecHandler, out string, code int) openshelltest.ExecHandler {
	return func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isResolverCall(call) {
			return openshelltest.ExecResponse{Stdout: []byte(out), ExitCode: code}
		}
		return h(ctx, call)
	}
}

// workloadAnswer is what a sandbox answers the workload check.
type workloadAnswer struct {
	uid, gid int
	hostname string
	home     string
	capEff   string
	// cpus and memKB are the processors and the MemTotal (kB) it sees.
	cpus                int
	memKB               int64
	files               []answerFile
	localhost           []string
	localhostFailed     bool
	localhostUnreported bool
	rootdir             string
	// cut leaves out the end line.
	cut bool
}

// answerFile is one checked file of a workloadAnswer.
type answerFile struct {
	path, sha256 string
	uid, gid     int
	mode         uint32
	// mount holds the options of a mount on the file ("" for none).
	mount string
}

func (a workloadAnswer) stdout() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "uid %d\ngid %d\nhostname %s\nhome %s\ncapeff %s\ncpus %d\nmemtotal %d\n", a.uid, a.gid, a.hostname, a.home, a.capEff, a.cpus, a.memKB)
	if a.rootdir != "" {
		fmt.Fprintf(&b, "rootdir %s\n", a.rootdir)
	}
	for _, f := range a.files {
		if f.sha256 != "" {
			fmt.Fprintf(&b, "sha256 %s %s\n", f.sha256, f.path)
		}
	}
	for _, f := range a.files {
		if f.sha256 != "" {
			fmt.Fprintf(&b, "stat %d %d %o %s\n", f.uid, f.gid, f.mode, f.path)
		}
	}
	for _, f := range a.files {
		if f.mount != "" {
			fmt.Fprintf(&b, "mount %s %s\n", f.mount, f.path)
		}
	}
	if !a.localhostUnreported {
		for _, line := range a.localhost {
			fmt.Fprintf(&b, "localhost %s\n", line)
		}
		if a.localhostFailed {
			b.WriteString("localhost-failed\n")
		} else {
			b.WriteString("localhost-ok\n")
		}
	}
	if !a.cut {
		b.WriteString("end\n")
	}
	return []byte(b.String())
}

// answerFor is the answer of a sandbox named hostname (a MicroVM's
// hostname is its name) that runs as want expects.
func answerFor(want verifyRecord, hostname string) workloadAnswer {
	a := workloadAnswer{uid: want.UID, gid: want.GID, hostname: hostname, home: "writable", capEff: "0000000000000000", cpus: 2, memKB: 2000000, rootdir: "root",
		localhost: []string{"unspec 127.0.0.1", "inet 127.0.0.1", "loopback-only"}}
	for _, f := range want.Files {
		af := answerFile{path: f.Path, sha256: f.SHA256, uid: f.UID, gid: f.GID, mode: f.Mode}
		if f.ReadOnlyMount {
			af.mount = "ro,nosuid,nodev,relatime"
		}
		a.files = append(a.files, af)
	}
	return a
}

// workloadChecks answers the workload check of each sandbox as its record
// expects, after edit (when set), and hands every other command to other
// (openshelltest.DefaultExec when nil: a stop's flush syncs).
func (e *harnessEnv) workloadChecks(edit func(sandbox string, a *workloadAnswer), other openshelltest.ExecHandler) openshelltest.ExecHandler {
	return func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isResolverCall(call) {
			return openshelltest.ExecResponse{Stdout: []byte(goodResolverOutput)}
		}
		if !isWorkloadCheck(call) {
			if other != nil {
				return other(ctx, call)
			}
			return openshelltest.DefaultExec(call)
		}
		want := verifyRecord{UID: 1000, GID: 1000}
		e.m.mu.Lock()
		if b := e.m.boxes[call.Sandbox]; b != nil && b.rec.Verify != nil {
			want = *b.rec.Verify
		}
		e.m.mu.Unlock()
		a := answerFor(want, call.Sandbox)
		if edit != nil {
			edit(call.Sandbox, &a)
		}
		if call.Command[7] != "defenseclaw-verify-vm" {
			a.localhostUnreported = true
		}
		return openshelltest.ExecResponse{Stdout: a.stdout()}
	}
}

// workloadCheckCalls are the workload checks the gateway ran in sandbox.
func (e *harnessEnv) workloadCheckCalls(sandbox string) []openshelltest.ExecCall {
	var out []openshelltest.ExecCall
	for _, c := range e.fake.ExecCalls() {
		if c.Sandbox == sandbox && isWorkloadCheck(c) {
			out = append(out, c)
		}
	}
	return out
}

// testVerify is a record of a hook, a root-owned setting and a docker run
// file bind-mounted read-only.
func testVerify() verifyRecord {
	return verifyRecord{UID: 501, GID: 20, Files: []verifyFile{
		{Path: "/usr/local/lib/defenseclaw/hooks/claude-code-hook.sh", SHA256: strings.Repeat("1", 64), Mode: 0o755},
		{Path: "/etc/claude-code/managed-settings.d/50-defenseclaw.json", SHA256: strings.Repeat("2", 64), Mode: 0o644},
		{Path: "/etc/claude-code/managed-settings.d/60-defenseclaw-run.json", SHA256: strings.Repeat("3", 64), UID: 501, GID: 20, Mode: 0o644,
			ReadOnlyMount: true},
	}}
}

// The check refuses a sandbox whose workload runs as another identity,
// holds capabilities or cannot write its home, and one whose DefenseClaw
// files are missing, changed or within the workload's reach. A docker run
// file owned by the host user passes on a read-only mount only.
func TestWorkloadProblems(t *testing.T) {
	vm, _ := openshell.LookupDriver("vm")
	docker, _ := openshell.LookupDriver("docker")
	var none config.OpenShellResourcesConfig
	capped := func(cpu, memory string) config.OpenShellResourcesConfig {
		return config.OpenShellResourcesConfig{CPU: cpu, Memory: memory}
	}
	for _, tc := range []struct {
		name   string
		driver openshell.Driver
		edit   func(a *workloadAnswer)
		want   string // "" passes
		// limits is the organization's max_resources.
		limits config.OpenShellResourcesConfig
	}{
		{"as prepared on vm", vm, nil, "", none},
		{"as prepared on docker", docker, nil, "", none},
		{"vm root owned by workload with a fixed boundary", vm, func(a *workloadAnswer) { a.rootdir = "fixed" }, "", none},
		{"vm root writable to workload", vm, func(a *workloadAnswer) { a.rootdir = "writable" }, "can add or rename entries of its root folder", none},
		{"vm root owned by another account", vm, func(a *workloadAnswer) { a.rootdir = "owner 1234" }, "root folder is owned by uid 1234", none},
		{"vm root protection missing", vm, func(a *workloadAnswer) { a.rootdir = "" }, "did not report the root folder's protection", none},
		{"docker root protection tag is ignored", docker, func(a *workloadAnswer) { a.rootdir = "writable" }, "", none},
		{"the vm driver's default identity", vm, func(a *workloadAnswer) { a.uid, a.gid = 1000, 1000 },
			"the OpenShell vm driver runs sandboxes as uid 1000:1000, but DefenseClaw's images are built for 501:20; " +
				"set sandbox_uid = 501 and sandbox_gid = 20 under [openshell.drivers.vm]", none},
		{"another identity on docker", docker, func(a *workloadAnswer) { a.uid = 0 }, "runs as uid 0:20, not 501:20", none},
		{"capabilities", vm, func(a *workloadAnswer) { a.capEff = "00000000a80425fb" }, "holds capabilities (CapEff 00000000a80425fb)", none},
		{"no CapEff", vm, func(a *workloadAnswer) { a.capEff = "" }, "holds capabilities", none},
		{"a home it cannot write", vm, func(a *workloadAnswer) { a.home = "read-only" }, "cannot write its home /sandbox", none},
		{"a changed hook", vm, func(a *workloadAnswer) { a.files[0].sha256 = strings.Repeat("f", 64) },
			"claude-code-hook.sh is not the file DefenseClaw delivered", none},
		{"a missing hook", vm, func(a *workloadAnswer) { a.files[0].sha256 = "" }, "claude-code-hook.sh is missing", none},
		{"a group-writable hook", vm, func(a *workloadAnswer) { a.files[0].mode = 0o775 }, "writable by its group or others (mode 775)", none},
		{"a world-writable setting", vm, func(a *workloadAnswer) { a.files[1].mode = 0o646 }, "writable by its group or others", none},
		{"a hook the workload owns", vm, func(a *workloadAnswer) { a.files[0].uid, a.files[0].gid = 501, 20 }, "is owned by 501:20, not 0:0", none},
		{"another mode", vm, func(a *workloadAnswer) { a.files[0].mode = 0o700 }, "has mode 700, not 755", none},
		{"a run file on a writable mount", docker, func(a *workloadAnswer) { a.files[2].mount = "rw,relatime" }, "60-defenseclaw-run.json is not on a read-only mount", none},
		{"a run file not mounted", docker, func(a *workloadAnswer) { a.files[2].mount = "" }, "60-defenseclaw-run.json is not on a read-only mount", none},
		{"an answer cut short", vm, func(a *workloadAnswer) { a.cut = true }, "cut short", none},
		// What a MicroVM got is judged against the organization's maximum,
		// whatever the gateway's files said at the create.
		{"within the organization's maximum", vm, nil, "", capped("2", "2Gi")},
		{"more processors than the maximum", vm, func(a *workloadAnswer) { a.cpus = 16 },
			"the workload has 16 processors, and your organization caps sandbox cpu at 2; lower vcpus and mem_mib under [openshell.drivers.vm]", capped("2", "")},
		{"more memory than the maximum", vm, func(a *workloadAnswer) { a.memKB = 8 << 20 },
			"the workload has 8192 MiB of memory, and your organization caps sandbox memory at 2Gi", capped("", "2Gi")},
		{"processors not counted", vm, func(a *workloadAnswer) { a.cpus = 0 }, "could not count the workload's processors", capped("2", "")},
		// A container sees the host's processors; docker enforces the
		// template's limits itself.
		{"docker's own limits", docker, func(a *workloadAnswer) { a.cpus = 16 }, "", capped("1", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := answerFor(testVerify(), "vmbox")
			if tc.edit != nil {
				tc.edit(&a)
			}
			facts, err := parseWorkloadFacts(a.stdout())
			must(t, err)
			facts.DirectResolverOK = true
			problems := strings.Join(workloadProblems(testVerify(), facts, tc.driver, adminLimits(tc.limits)), "; ")
			if tc.want == "" {
				if problems != "" || facts.Hostname != "vmbox" {
					t.Fatalf("problems = %q, hostname %q", problems, facts.Hostname)
				}
				return
			}
			if !strings.Contains(problems, tc.want) {
				t.Fatalf("problems = %q, want %q", problems, tc.want)
			}
		})
	}
	// An answer that is not the script's is refused.
	for _, out := range []string{"uid 501\nuid 0\nend\n", "uid 501\nroot yes\nend\n", "end\nuid 0\n", "uid x\nend\n"} {
		if _, err := parseWorkloadFacts([]byte(out)); err == nil {
			t.Fatalf("parsed %q", out)
		}
	}
	for _, out := range []string{"rootdir fixed\nrootdir fixed\nend\n", "rootdir owner\nend\n", "rootdir owner -1\nend\n", "rootdir unknown\nend\n"} {
		if _, err := parseWorkloadFacts([]byte(out)); err == nil {
			t.Fatalf("parsed malformed root directory result %q", out)
		}
	}
}

// GAP-0570: a MicroVM with a workload-owned root and a fixed top-level
// boundary passes the same resolver check as a root-owned guest. This test
// also runs unchanged on the release base, where the new tag is rejected.
func TestGAP0570MicroVMRootOwnerRule(t *testing.T) {
	vm, _ := openshell.LookupDriver("vm")
	raw := answerFor(testVerify(), "vmbox").stdout()
	raw = []byte(strings.Replace(string(raw), "rootdir root\n", "", 1))
	raw = []byte(strings.Replace(string(raw), "end\n", "rootdir fixed\nend\n", 1))
	facts, err := parseWorkloadFacts(raw)
	if err != nil {
		t.Fatal(err)
	}
	facts.DirectResolverOK = true
	if problems := workloadProblems(testVerify(), facts, vm, workloadLimits{}); len(problems) != 0 {
		t.Fatalf("workload-owned root under a fixed boundary: %v", problems)
	}
}

// The running fixture sets ownership after Docker starts, then checks the
// same guest script and filesystem rights as a MicroVM workload.
func TestGAP0570MicroVMRootOwnerRuleInGuestShell(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the guest check uses Linux /proc and Landlock")
	}
	for _, args := range [][]string{{"info", "--format", "{{.ServerVersion}}"}, {"image", "inspect", openshell.DefaultBaseImage}} {
		if err := exec.CommandContext(t.Context(), "docker", args...).Run(); err != nil {
			t.Skipf("local Docker and the pinned base are needed: %v", err)
		}
	}
	dir := t.TempDir()
	var sources []byte
	for _, name := range []string{"landlock-root-check.c", "root-check-selective-denial.c"} {
		source, err := os.ReadFile(filepath.Join("testdata", name))
		must(t, err)
		sources = append(sources, source...)
		must(t, os.WriteFile(filepath.Join(dir, name), source, 0o600))
	}
	resolverSource, err := os.ReadFile(filepath.Join("..", "image", "testdata", "localhost-resolver.c"))
	must(t, err)
	sources = append(sources, resolverSource...)
	must(t, os.WriteFile(filepath.Join(dir, "localhost-resolver.c"), resolverSource, 0o600))
	dockerfile := "FROM " + openshell.DefaultBaseImage + "\nUSER root\n" +
		"COPY landlock-root-check.c root-check-selective-denial.c localhost-resolver.c /tmp/\n" +
		"RUN gcc -O2 -Wall -Wextra -Werror -o /usr/local/bin/landlock-root-check /tmp/landlock-root-check.c && " +
		"gcc -O2 -Wall -Wextra -Werror -o /usr/local/bin/root-check-selective-denial /tmp/root-check-selective-denial.c && " +
		"mkdir -p /usr/local/lib/defenseclaw && gcc -O2 -Wall -Wextra -Werror -o /usr/local/lib/defenseclaw/localhost-resolver /tmp/localhost-resolver.c\n" +
		"USER 1000:1000\n"
	must(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600))
	sum := sha256.Sum256(sources)
	tag := fmt.Sprintf("dc-g570-root:%x", sum[:6])
	if out, err := exec.CommandContext(t.Context(), "docker", "build", "--pull=false", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("build guest fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", tag).Run() })
	run := func(setup string, argv ...string) ([]byte, error) {
		t.Helper()
		args := []string{"run", "--rm", "--network=none", "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=FOWNER",
			"--security-opt=no-new-privileges", "--security-opt=seccomp=unconfined", "--user", "0:0", "--entrypoint", "/bin/sh", tag,
			"-c", "set -eu; chown 1000:1000 /sandbox; " + setup + "; exec /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups \"$@\"", "fixture"}
		args = append(args, argv...)
		return exec.CommandContext(t.Context(), "docker", args...).CombinedOutput()
	}
	check := verifyArgv(verifyRecord{}, true)
	vm, _ := openshell.LookupDriver("vm")
	for _, tc := range []struct {
		name, setup, boundary, rootdir string
		localhostOK                    bool
	}{
		{"root-owned guest", "test \"$(stat -c %u /)\" = 0", "", "root", true},
		{"workload-owned root without a boundary", "chown 1000:1000 /; test \"$(stat -c %u /)\" = 1000", "", "writable", false},
		{"read-only mode without a boundary", "chown 1000:1000 /; chmod 0555 /", "", "writable", false},
		{"workload-owned root under Landlock", "chown 1000:1000 /", "landlock-root-check", "fixed", true},
		{"read-only mode under Landlock", "chown 1000:1000 /; chmod 0555 /", "landlock-root-check", "fixed", true},
		{"preexisting probe entry", "ln -s /tmp \"/.defenseclaw-verify-$$\"; chown 1000:1000 /", "landlock-root-check", "writable", false},
		{"workload-owned usr under Landlock", "chown 1000:1000 / /usr", "landlock-root-check", "fixed", false},
		{"workload-owned etc under Landlock", "chown 1000:1000 / /etc", "landlock-root-check", "fixed", true},
		{"symlinked resolver under Landlock", "chown 1000:1000 /; mv /usr/local/lib/defenseclaw/localhost-resolver /usr/local/lib/defenseclaw/localhost-resolver.real; ln -s localhost-resolver.real /usr/local/lib/defenseclaw/localhost-resolver", "landlock-root-check", "fixed", false},
		{"selective creation denial", "chown 1000:1000 /", "root-check-selective-denial", "writable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := check
			if tc.boundary != "" {
				argv = append([]string{"/usr/local/bin/" + tc.boundary}, argv...)
			}
			out, err := run(tc.setup, argv...)
			var exit *exec.ExitError
			if tc.boundary == "landlock-root-check" && errors.As(err, &exit) && exit.ExitCode() == 77 {
				t.Skip("Landlock ABI 3 is unavailable in this container")
			}
			if err != nil {
				t.Fatalf("guest check: %v\n%s", err, out)
			}
			facts, err := parseWorkloadFacts(out)
			must(t, err)
			if facts.RootDir != tc.rootdir || !facts.LocalhostReported || facts.LocalhostOK != tc.localhostOK {
				t.Fatalf("rootdir %q, localhost %v, want %q and %v; output:\n%s", facts.RootDir, facts.LocalhostOK, tc.rootdir, tc.localhostOK, out)
			}
			facts.DirectResolverOK = true
			problems := workloadProblems(verifyRecord{UID: 1000, GID: 1000, LocalhostResolver: true}, facts, vm, workloadLimits{})
			if (len(problems) == 0) != (tc.rootdir == "root" || tc.rootdir == "fixed" && tc.localhostOK) {
				t.Fatalf("workload problems = %v; output:\n%s", problems, out)
			}
		})
	}
	t.Run("probe entries are removed", func(t *testing.T) {
		argv := append([]string{"/bin/sh", "-c", `"$@"; for p in /.defenseclaw-verify-* /sandbox/.defenseclaw-verify-*; do [ ! -e "$p" ] && [ ! -L "$p" ] || exit 1; done`, "inspect"}, check...)
		out, err := run("chown 1000:1000 /", argv...)
		if err != nil {
			t.Fatalf("guest probe cleanup: %v\n%s", err, out)
		}
	})
	for _, command := range []string{"mv /usr /usr.x", "mkdir /x", "ln -s /usr /x"} {
		out, err := run("chown 1000:1000 /", "/usr/local/bin/landlock-root-check", "/bin/sh", "-c", command)
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 77 {
			t.Skip("Landlock ABI 3 is unavailable in this container")
		}
		if err == nil {
			t.Fatalf("root operation succeeded under Landlock: %s", command)
		}
		_ = out
	}
}

func TestMicroVMResolverResult(t *testing.T) {
	vm, _ := openshell.LookupDriver("vm")
	docker, _ := openshell.LookupDriver("docker")
	const refused = "did not return only its loopback ingress"
	lines := func(l ...string) func(*workloadAnswer) { return func(a *workloadAnswer) { a.localhost = l } }
	for _, tc := range []struct {
		name string
		edit func(*workloadAnswer)
		want string
	}{
		{"IPv4 only", nil, ""},
		{"IPv6 only", lines("unspec ::1", "inet6 ::1", "loopback-only"), ""},
		{"both families", lines("unspec ::1", "unspec 127.0.0.1", "inet 127.0.0.1", "inet6 ::1", "loopback-only"), ""},
		{"no answer", func(a *workloadAnswer) { a.localhost = nil }, "could not resolve localhost"},
		{"command failed", func(a *workloadAnswer) { a.localhost, a.localhostFailed = nil, true }, "could not resolve localhost"},
		{"status missing", func(a *workloadAnswer) { a.localhostUnreported = true }, "could not resolve localhost"},
		{"wrong address", lines("unspec 203.0.113.10", "loopback-only"), refused},
		{"mixed family", lines("unspec 127.0.0.1", "unspec 2001:db8::10", "inet 127.0.0.1", "loopback-only"), refused},
		{"other IPv6 address", lines("unspec ::2", "loopback-only"), refused},
		{"IPv4 answer to the inet6 query", lines("unspec 127.0.0.1", "inet6 127.0.0.1", "loopback-only"), refused},
		{"no unspec answer", lines("inet 127.0.0.1", "loopback-only"), refused},
		{"no final line", lines("unspec 127.0.0.1", "inet 127.0.0.1"), refused},
		{"line after the final line", lines("unspec 127.0.0.1", "loopback-only", "unspec 127.0.0.1"), refused},
		{"repeated answer", lines("unspec 127.0.0.1", "unspec 127.0.0.1", "loopback-only"), refused},
		{"queries out of order", lines("inet 127.0.0.1", "unspec 127.0.0.1", "loopback-only"), refused},
		{"retired caller output", lines("127.0.0.1 STREAM localhost"), refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := answerFor(testVerify(), "vmbox")
			if tc.edit != nil {
				tc.edit(&a)
			}
			facts, err := parseWorkloadFacts(a.stdout())
			must(t, err)
			facts.DirectResolverOK = true
			problems := strings.Join(workloadProblems(testVerify(), facts, vm, workloadLimits{}), "; ")
			if !strings.Contains(problems, tc.want) || (tc.want == "" && problems != "") {
				t.Fatalf("VM problems = %q, want %q", problems, tc.want)
			}
			if dockerProblems := workloadProblems(testVerify(), facts, docker, workloadLimits{}); len(dockerProblems) != 0 {
				t.Fatalf("Docker driver changed: %q", dockerProblems)
			}
		})
	}
	for _, answer := range []string{"localhost " + strings.Repeat("a", 513) + "\nlocalhost-ok\n", "localhost unspec 127.0.0.1\nlocalhost-ok\nlocalhost-ok\n", "localhost-ok\nlocalhost unspec 127.0.0.1\n"} {
		if _, err := parseWorkloadFacts([]byte(answer)); err == nil {
			t.Fatalf("accepted malformed resolver result %q", answer)
		}
	}
}

// The direct exec's output is judged as exactly the caller's report, and a
// refusal keeps the caller's reason for the message.
func TestMicroVMDirectResolverResult(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      bool
		refusal   string
	}{
		{"IPv4 only", goodResolverOutput, true, ""},
		{"IPv6 only", "unspec ::1\ninet6 ::1\nloopback-only\n", true, ""},
		{"both families", "unspec ::1\nunspec 127.0.0.1\ninet 127.0.0.1\ninet6 ::1\nloopback-only\n", true, ""},
		{"mixed family refused by the caller", "unspec 127.0.0.1\nrefused nonloopback\n", false, "nonloopback"},
		{"mixed family as answers", "unspec 127.0.0.1\nunspec 2001:db8::10\nloopback-only\n", false, ""},
		{"other address", "unspec 203.0.113.10\nloopback-only\n", false, ""},
		{"preloaded code", "refused preload\n", false, "preload"},
		{"NSS module", "refused nss\n", false, "nss"},
		{"NSS module loaded by the lookups", "unspec 127.0.0.1\ninet 127.0.0.1\nrefused nss\n", false, "nss"},
		{"no answer", "refused noanswer\n", false, "noanswer"},
		{"answer of another family", "unspec 127.0.0.1\nrefused family\n", false, "family"},
		{"unknown refusal", "refused other\n", false, ""},
		{"retired caller output", "127.0.0.1 STREAM\n", false, ""},
		{"NUL byte", "unspec 127.0.0.1\nloopback-only\n\x00", false, ""},
		{"non ASCII", "unspec 127.0.0.1 caf\xc3\xa9\nloopback-only\n", false, ""},
		{"missing final newline", "unspec 127.0.0.1\nloopback-only", false, ""},
		{"empty", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := directResolverOK([]byte(tc.out)); got != tc.want {
				t.Fatalf("directResolverOK(%q) = %v, want %v", tc.out, got, tc.want)
			}
			if got := directResolverRefusal([]byte(tc.out)); got != tc.refusal {
				t.Fatalf("directResolverRefusal(%q) = %q, want %q", tc.out, got, tc.refusal)
			}
		})
	}
}

// The guest decision is the pinned caller's own report, executed directly:
// a create rolls back a guest whose caller reports another address, a
// mixed-family answer or preloaded code, and keeps one whose localhost is
// loopback of either family or both.
func TestMicroVMGuestResolverDirectExec(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		code         int
		want         string // "" allows
	}{
		{"guest resolver returns another address", "unspec 203.0.113.10\nloopback-only\n", 0, "could not verify localhost"},
		{"guest resolver refuses a mixed-family answer", "unspec 127.0.0.1\nrefused nonloopback\n", 1, "did not return only its loopback ingress"},
		{"guest image preloads code", "refused preload\n", 1, "/etc/ld.so.preload"},
		{"guest image answers hosts with an NSS module", "unspec 127.0.0.1\ninet 127.0.0.1\nrefused nss\n", 1, "`hosts: files dns`"},
		{"guest resolver has no answer", "refused noanswer\n", 1, "could not resolve localhost"},
		{"retired caller output", "127.0.0.1 STREAM\n", 0, "could not verify localhost"},
		{"good report with a failed exit", goodResolverOutput, 1, "could not verify localhost"},
		{"guest resolver returns IPv4 loopback", goodResolverOutput, 0, ""},
		{"guest resolver returns IPv6 loopback", "unspec ::1\ninet6 ::1\nloopback-only\n", 0, ""},
		{"guest resolver returns both families", "unspec ::1\nunspec 127.0.0.1\ninet 127.0.0.1\ninet6 ::1\nloopback-only\n", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			useOpenCode(t, e)
			e.fake.HandleExec(withResolverAnswer(e.workloadChecks(nil, nil), tc.answer, tc.code))
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "resolver-cell", Harness: "opencode", Copy: true})
			if tc.want == "" {
				must(t, err)
				if rec := e.boxOf("resolver-cell").rec; rec.Verify == nil || !rec.Verify.LocalhostResolver {
					t.Fatalf("a MicroVM create did not record the resolver check: %+v", rec.Verify)
				}
			} else {
				apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected)
				if !strings.Contains(apiErr.Detail, tc.want) {
					t.Fatalf("detail = %q, want %q", apiErr.Detail, tc.want)
				}
				assertNothingLeft(t, e)
			}
			var directCalls int
			for _, call := range e.fake.ExecCalls() {
				if isResolverCall(call) {
					directCalls++
					if !slices.Equal(call.Argv, []string{localhostResolverPath}) {
						t.Fatalf("resolver caller was wrapped: %q", call.Argv)
					}
				}
			}
			if directCalls != 1 {
				t.Fatalf("direct resolver calls = %d, want 1", directCalls)
			}
		})
	}
}

func TestMicroVMGuestResolverUsesLibcWithProjectPythonModule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the guest check uses Linux /proc")
	}
	for _, args := range [][]string{{"info", "--format", "{{.ServerVersion}}"}, {"image", "inspect", openshell.DefaultBaseImage}} {
		if err := exec.CommandContext(t.Context(), "docker", args...).Run(); err != nil {
			t.Skipf("local Docker and the pinned base are needed: %v", err)
		}
	}
	imageDir := t.TempDir()
	source, err := os.ReadFile(filepath.Join("..", "image", "testdata", "localhost-resolver.c"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(imageDir, "localhost-resolver.c"), source, 0o600))
	must(t, os.WriteFile(filepath.Join(imageDir, "timeout"), []byte("#!/bin/sh\nprintf '127.0.0.1 STREAM\\n'\n"), 0o755))
	imageFile := "FROM " + openshell.DefaultBaseImage + " AS dc-localhost-tool\n" +
		"USER root\n" +
		"COPY localhost-resolver.c /tmp/localhost-resolver.c\n" +
		"RUN gcc -O2 -Wall -Wextra -Werror -o /tmp/localhost-resolver /tmp/localhost-resolver.c\n" +
		"FROM " + openshell.DefaultBaseImage + "\nUSER root\n" +
		"RUN install -d -o root -g root -m 0755 /usr/local/lib/defenseclaw\n" +
		"COPY --from=dc-localhost-tool --chown=0:0 --chmod=0755 /tmp/localhost-resolver /usr/local/lib/defenseclaw/localhost-resolver\n" +
		"COPY --chmod=0755 timeout /usr/bin/timeout\nUSER sandbox\n"
	if err := os.WriteFile(filepath.Join(imageDir, "Dockerfile"), []byte(imageFile), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(imageDir))
	imageTag := fmt.Sprintf("dc-osmin23-guest:%x", sum[:6])
	if out, err := exec.CommandContext(t.Context(), "docker", "build", "--pull=false", "-t", imageTag, imageDir).CombinedOutput(); err != nil {
		t.Fatalf("build guest fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", imageTag).Run() })
	for _, tc := range []struct {
		name, hosts, module, customAddress string
		want                               string
	}{
		{"ordinary project module", "127.0.0.1 localhost\n", "# project module\n", "", ""},
		{"IPv6-only guest", "::1 localhost\n", "# project module\n", "", ""},
		{"alternate project module", "203.0.113.10 localhost\n", `AF_INET = 2
def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return [(2, 1, 6, "", ("127.0.0.1", 0))]
`, "", "could not resolve localhost to its loopback ingress"},
		{"custom caller benign", "127.0.0.1 localhost\n", "# project module\n", "203.0.113.10", ""},
		{"custom caller protected", "203.0.113.10 localhost\n", "# project module\n", "127.0.0.1", "could not resolve localhost to its loopback ingress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hosts := filepath.Join(dir, "hosts")
			if err := os.WriteFile(hosts, []byte(tc.hosts), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "socket.py"), []byte(tc.module), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.customAddress != "" {
				custom := "#!/bin/sh\ncase \"$1\" in\n" +
					"  hosts) printf '%s\\n' '" + tc.customAddress + " localhost';;\n" +
					"  ahostsv4) printf '%s\\n' '" + tc.customAddress + " STREAM localhost' '" +
					tc.customAddress + " DGRAM' '" + tc.customAddress + " RAW';;\n" +
					"  *) exit 2;;\nesac\n"
				if err := os.WriteFile(filepath.Join(dir, "custom-getent"), []byte(custom), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			argv := verifyArgv(verifyRecord{}, true)
			args := []string{"run", "--rm", "--network=bridge", "--user", "1000:1000", "--workdir", "/sandbox",
				"--mount", "type=bind,src=" + dir + ",dst=/sandbox,readonly",
				"--mount", "type=bind,src=" + hosts + ",dst=/etc/hosts,readonly"}
			if tc.customAddress != "" {
				args = append(args, "--mount", "type=bind,src="+filepath.Join(dir, "custom-getent")+",dst=/usr/bin/getent,readonly")
			}
			args = append(args, "--entrypoint", argv[0], imageTag)
			args = append(args, argv[1:]...)
			out, err := exec.CommandContext(t.Context(), "docker", args...).Output()
			if err != nil {
				t.Fatalf("guest check: %v", err)
			}
			facts, err := parseWorkloadFacts(out)
			if err != nil {
				t.Fatal(err)
			}
			if problem := microVMResolverProblem(facts); !strings.Contains(problem, tc.want) || (tc.want == "" && problem != "") {
				t.Fatalf("resolver problem = %q, want %q", problem, tc.want)
			}
		})
	}
	t.Run("mutable hosts checked again", func(t *testing.T) {
		hosts := filepath.Join(t.TempDir(), "hosts")
		argv := verifyArgv(verifyRecord{}, true)
		check := func(want string) {
			t.Helper()
			args := []string{"run", "--rm", "--network=bridge", "--user", "1000:1000",
				"--mount", "type=bind,src=" + hosts + ",dst=/etc/hosts,readonly",
				"--entrypoint", argv[0], imageTag}
			args = append(args, argv[1:]...)
			out, err := exec.CommandContext(t.Context(), "docker", args...).Output()
			must(t, err)
			facts, err := parseWorkloadFacts(out)
			must(t, err)
			if problem := microVMResolverProblem(facts); !strings.Contains(problem, want) || (want == "" && problem != "") {
				t.Fatalf("resolver problem = %q, want %q", problem, want)
			}
		}
		must(t, os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644))
		check("")
		must(t, os.WriteFile(hosts, []byte("198.51.100.10 localhost\n"), 0o644))
		check("could not resolve localhost to its loopback ingress")
	})
}

// The check runs in an empty environment with every tool by absolute path:
// nothing planted on the image PATH (under /sandbox) answers for itself.
func TestWorkloadCheckRunsNothingFromThePath(t *testing.T) {
	argv := verifyArgv(testVerify(), false)
	if vm := verifyArgv(testVerify(), true); vm[7] != "defenseclaw-verify-vm" || argv[7] != "defenseclaw-verify" {
		t.Fatalf("workload check names: docker=%q vm=%q", argv[7], vm[7])
	}
	if !slices.Equal(argv[:8], []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=" + connector.SandboxHomeDir,
		"/bin/sh", "-c", verifyScript, "defenseclaw-verify"}) || len(argv) != 11 || argv[8] != testVerify().Files[0].Path {
		t.Fatalf("argv = %q", argv)
	}
	for _, line := range strings.Split(verifyScript, "\n") {
		for _, tool := range []string{"id", "sha256sum", "stat", "sed", "cat", "hostname"} {
			for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '(' || r == '|' || r == ';' }) {
				if field == tool {
					t.Fatalf("the script runs %s from the PATH: %q", tool, line)
				}
			}
		}
	}
	if runtime.GOOS != "linux" {
		t.Skip("the script reads /proc, and GNU sha256sum and stat")
	}
	for _, tool := range []string{"/usr/bin/env", "/usr/bin/id", "/usr/bin/sha256sum", "/usr/bin/stat"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	// The real script on this host, with id and sha256sum planted first on
	// the caller's PATH: they must not run.
	planted, marker := t.TempDir(), filepath.Join(t.TempDir(), "ran")
	for _, tool := range []string{"id", "sha256sum", "stat"} {
		writeFile(t, filepath.Join(planted, tool), "#!/bin/sh\necho planted > "+marker+"\necho 0\n")
		must(t, os.Chmod(filepath.Join(planted, tool), 0o755))
	}
	hook := writeFile(t, filepath.Join(t.TempDir(), "hook.sh"), "#!/bin/sh\nexit 0\n")
	must(t, os.Chmod(hook, 0o755))
	sum := sha256.Sum256([]byte("#!/bin/sh\nexit 0\n"))
	want := verifyRecord{UID: os.Getuid(), GID: os.Getgid(), Files: []verifyFile{
		{Path: hook, SHA256: hex.EncodeToString(sum[:]), UID: os.Getuid(), GID: os.Getgid(), Mode: 0o755},
	}}
	argv = verifyArgv(want, false)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + planted + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	must(t, err)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a tool planted on the PATH ran")
	}
	facts, err := parseWorkloadFacts(out)
	must(t, err)
	if facts.LocalhostReported {
		t.Fatal("Docker workload check ran the VM resolver probe")
	}
	vmArgv := verifyArgv(want, true)
	vmOut, err := exec.Command(vmArgv[0], vmArgv[1:]...).Output()
	must(t, err)
	vmFacts, err := parseWorkloadFacts(vmOut)
	must(t, err)
	if !vmFacts.LocalhostReported {
		t.Fatal("VM workload check omitted the resolver result")
	}
	if _, err := os.Stat("/usr/local/lib/defenseclaw/localhost-resolver"); err == nil {
		if problem := microVMResolverProblem(vmFacts); problem != "" {
			t.Fatalf("VM workload check: %s", problem)
		}
	} else if problem := microVMResolverProblem(vmFacts); problem == "" {
		t.Fatal("VM workload check accepted a missing resolver caller")
	}
	if !facts.End || facts.UID != os.Getuid() || facts.GID != os.Getgid() || facts.Hostname == "" || facts.CapEff == "" || facts.CPUs < 1 || facts.MemTotalKB < 1 {
		t.Fatalf("facts = %+v (%s)", facts, out)
	}
	f := facts.Files[hook]
	if f == nil || f.SHA256 != want.Files[0].SHA256 || !f.Stat || f.Mode != 0o755 || f.UID != os.Getuid() || f.MountPoint {
		t.Fatalf("hook facts = %+v (%s)", f, out)
	}
	// HOME is /sandbox, which this host may lack, and the test may run with
	// capabilities: the file and the identity are as recorded.
	problems := strings.Join(workloadProblems(want, facts, openshell.Driver{}, workloadLimits{}), "; ")
	if strings.Contains(problems, hook) || strings.Contains(problems, "runs as uid") {
		t.Fatalf("problems = %q", problems)
	}
}

// A create checks the workload once, after ready, on every driver: on the
// MicroVM driver against the root-owned files its image carries, on docker
// against those and the run files bind-mounted read-only, and records the
// hostname it found.
func TestCreateChecksTheWorkload(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.rootdir = "fixed" }, nil))
	e.create(sandboxapi.CreateRequest{Name: "vmcheck", Harness: "opencode", Copy: true})
	calls := e.workloadCheckCalls("vmcheck")
	if len(calls) != 1 || calls[0].NoLoginShell != true || calls[0].Timeout != verifyTimeout {
		t.Fatalf("workload checks = %+v", calls)
	}
	rec := e.boxOf("vmcheck").rec
	if rec.Verify == nil || rec.Verify.UID != 1000 || rec.Verify.GID != 1000 || rec.Hostname != "vmcheck" {
		t.Fatalf("record verify = %+v, hostname %q", rec.Verify, rec.Hostname)
	}
	var paths []string
	for _, f := range rec.Verify.Files {
		if f.UID != 0 || f.GID != 0 || f.Mode&0o022 != 0 || len(f.SHA256) != 64 {
			t.Fatalf("recorded file = %+v", f)
		}
		paths = append(paths, f.Path)
	}
	if !slices.Contains(paths, "/usr/local/lib/defenseclaw/opencode/index.js") || !slices.Contains(paths, "/etc/opencode/opencode.json") ||
		!slices.Contains(paths, "/usr/local/lib/defenseclaw/bin/opencode-launch") || !slices.Equal(calls[0].Command[8:], paths) {
		t.Fatalf("checked %q, recorded %q", calls[0].Command[8:], paths)
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dkcheck"})
	dcalls := d.workloadCheckCalls("dkcheck")
	rec = d.boxOf("dkcheck").rec
	if len(dcalls) != 1 || rec.Verify == nil || !slices.Equal(dcalls[0].Command, verifyArgv(*rec.Verify, false)) || rec.Hostname != "dkcheck" {
		t.Fatalf("docker workload checks = %+v, record verify = %+v, hostname %q", dcalls, rec.Verify, rec.Hostname)
	}
	if !slices.ContainsFunc(rec.Verify.Files, func(f verifyFile) bool { return f.ReadOnlyMount }) {
		t.Fatalf("docker checks no read-only run file: %+v", rec.Verify.Files)
	}
	// A run file the container sees on a writable mount is refused.
	rw := newEnv(t, nil)
	rw.fake.HandleExec(rw.workloadChecks(func(_ string, a *workloadAnswer) {
		for i := range a.files {
			if a.files[i].mount != "" {
				a.files[i].mount = "rw,relatime"
			}
		}
	}, nil))
	_, err := rw.tryCreate(sandboxapi.CreateRequest{Name: "dkrw"})
	if apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected); !strings.Contains(apiErr.Detail, "is not on a read-only mount") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	assertNothingLeft(t, rw)
}

// A sandbox that does not run as prepared is rolled back like one OpenShell
// rejected, on either driver: nothing is left behind.
func TestCreateRollsBackASandboxNotAsPrepared(t *testing.T) {
	for _, tc := range []struct {
		name   string
		docker bool
		edit   func(a *workloadAnswer)
		fail   error
		code   string
		want   string
	}{
		{"the vm driver's default identity", false, func(a *workloadAnswer) { a.uid, a.gid = 1000, 1000 }, nil,
			sandboxapi.CodePolicyRejected, "set sandbox_uid = 501 and sandbox_gid = 20 under [openshell.drivers.vm]"},
		{"capabilities", false, func(a *workloadAnswer) { a.capEff = "0000003fffffffff" }, nil, sandboxapi.CodePolicyRejected, "holds capabilities"},
		{"a changed hook", false, func(a *workloadAnswer) { a.files[0].sha256 = strings.Repeat("0", 64) }, nil,
			sandboxapi.CodePolicyRejected, "is not the file DefenseClaw delivered"},
		{"a writable hook", false, func(a *workloadAnswer) { a.files[0].mode = 0o777 }, nil, sandboxapi.CodePolicyRejected, "writable by its group or others"},
		{"a writable VM root", false, func(a *workloadAnswer) { a.rootdir = "writable" }, nil, sandboxapi.CodePolicyRejected, "can add or rename entries of its root folder"},
		{"a VM root owned by another account", false, func(a *workloadAnswer) { a.rootdir = "owner 1234" }, nil, sandboxapi.CodePolicyRejected, "root folder is owned by uid 1234"},
		{"no answer", false, nil, &types.StatusError{Code: types.ErrorInternal, Message: "exec relay closed"}, sandboxapi.CodeUpstream, "exec relay closed"},
		{"a changed hook on docker", true, func(a *workloadAnswer) { a.files[0].sha256 = strings.Repeat("0", 64) }, nil,
			sandboxapi.CodePolicyRejected, "is not the file DefenseClaw delivered"},
		{"another identity on docker", true, func(a *workloadAnswer) { a.uid, a.gid = 0, 0 }, nil,
			sandboxapi.CodePolicyRejected, "runs as uid 0:0, not 501:20, the identity its image was built for and its policy's process.run_as_user names"},
		{"capabilities on docker", true, func(a *workloadAnswer) { a.capEff = "00000000a80425fb" }, nil, sandboxapi.CodePolicyRejected, "holds capabilities"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			if tc.docker {
				e = newEnv(t, nil)
			}
			e.m.host = HostUser{UID: 501, GID: 20, Name: "dev"}
			e.images.rec.UID, e.images.rec.GID = 501, 20
			useOpenCode(t, e)
			e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) {
				if tc.edit != nil {
					tc.edit(a)
				}
			}, nil))
			if tc.fail != nil {
				e.fake.FailNext(openshelltest.MethodExec, tc.fail)
			}
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "badbox", Harness: "opencode", Copy: true})
			apiErr := wantCode(t, err, tc.code)
			if !strings.Contains(apiErr.Error(), tc.want) {
				t.Fatalf("refusal = %v, want %q", apiErr, tc.want)
			}
			if tc.code == sandboxapi.CodePolicyRejected && !strings.HasSuffix(apiErr.Message, "does not run as DefenseClaw prepared it; DefenseClaw deleted it") {
				t.Fatalf("refusal message = %q, want it to say the sandbox was deleted", apiErr.Message)
			}
			if n := e.fake.Calls(openshelltest.MethodCreateSandbox); n != 1 {
				t.Fatalf("create calls = %d", n)
			}
			assertNothingLeft(t, e)
		})
	}
}

// A create refused because its check was cut short names the shell setting
// passed with --env that did it and says what to do (SHELLOPTS=noexec makes
// the check's shell run none of its script). The refusal and what it
// refuses are unchanged; a cut-short answer without such a setting, and a
// refusal for another reason, keep their plain text.
func TestCreateRefusalNamesTheShellSettingThatCutTheCheckShort(t *testing.T) {
	const plain = "the check's answer was cut short"
	for _, tc := range []struct {
		name string
		env  map[string]string
		edit func(a *workloadAnswer)
		want string
	}{
		{"SHELLOPTS", map[string]string{"SHELLOPTS": "noexec"}, func(a *workloadAnswer) { a.cut = true },
			plain + ", most likely by the shell setting SHELLOPTS passed with --env; run the sandbox again without it"},
		{"two settings, in order", map[string]string{"SHELLOPTS": "noexec", "BASHOPTS": "nullglob", "FOO": "1"}, func(a *workloadAnswer) { a.cut = true },
			plain + ", most likely by the shell setting BASHOPTS, SHELLOPTS passed with --env; run the sandbox again without it"},
		{"no shell setting", map[string]string{"FOO": "1"}, func(a *workloadAnswer) { a.cut = true }, plain},
		{"no env", nil, func(a *workloadAnswer) { a.cut = true }, plain},
		{"another reason keeps its text", map[string]string{"SHELLOPTS": "noexec"}, func(a *workloadAnswer) { a.capEff = "0000003fffffffff" }, "holds capabilities"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			e.m.host = HostUser{UID: 501, GID: 20, Name: "dev"}
			e.images.rec.UID, e.images.rec.GID = 501, 20
			useOpenCode(t, e)
			e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { tc.edit(a) }, nil))
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "envbox", Harness: "opencode", Copy: true, Env: tc.env})
			apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected)
			if !strings.Contains(apiErr.Detail, tc.want) {
				t.Fatalf("detail = %q, want it to contain %q", apiErr.Detail, tc.want)
			}
			if tc.want == plain && apiErr.Detail != plain {
				t.Fatalf("detail = %q, want the plain text", apiErr.Detail)
			}
			if !strings.HasSuffix(apiErr.Message, "does not run as DefenseClaw prepared it; DefenseClaw deleted it") {
				t.Fatalf("message = %q", apiErr.Message)
			}
			assertNothingLeft(t, e)
		})
	}
}

// A start checks the workload against what the create recorded, not a
// fresh render: a start after the hook render changed passes. A sandbox
// that fails the check is stopped again.
func TestStartChecksTheWorkloadAgainstTheRecord(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	e.create(sandboxapi.CreateRequest{Name: "restart", Harness: "opencode", Copy: true})
	e.stopBox("restart")
	recorded := *e.boxOf("restart").rec.Verify
	// The sandbox answers with the files create left in it, whatever the
	// start expects.
	created := answerFor(recorded, "restart")
	created.rootdir = "fixed"
	resolverCalls := 0
	e.fake.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isResolverCall(call) {
			resolverCalls++
			return openshelltest.ExecResponse{Stdout: []byte(goodResolverOutput)}
		}
		if isWorkloadCheck(call) {
			return openshelltest.ExecResponse{Stdout: created.stdout()}
		}
		return openshelltest.DefaultExec(call)
	})
	// An upgrade that renders the hooks otherwise (here: another ingress
	// port), which a check against a fresh render would refuse.
	e.m.opts.IngressPort++
	spec, _ := harness.Get("opencode")
	arts, err := spec.Provider.SandboxArtifacts(connector.SandboxRenderTarget{
		IngressPort: e.m.opts.IngressPort, AgentVersion: e.images.rec.HarnessVersion, HookContractID: e.images.rec.HookContract})
	if err != nil {
		t.Fatal(err)
	}
	if fresh := verifyExpectation(e.images.rec, spec, arts); reflect.DeepEqual(fresh.Files, recorded.Files) {
		t.Fatalf("another ingress port renders the same hooks: %+v", fresh.Files)
	}
	e.startBox("restart", sandboxapi.StartRequest{})
	if calls := e.workloadCheckCalls("restart"); len(calls) != 2 || !slices.Equal(calls[1].Command, verifyArgv(recorded, true)) || resolverCalls != 1 {
		t.Fatalf("workload checks = %+v, direct resolver calls %d", calls, resolverCalls)
	}
	if after := e.boxOf("restart").rec.Verify; after == nil || !reflect.DeepEqual(*after, recorded) {
		t.Fatalf("the start changed what the check expects: %+v, want %+v", after, recorded)
	}
	e.stopBox("restart")

	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.files[0].sha256 = strings.Repeat("0", 64) }, nil))
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err = e.m.Start(t.Context(), "restart", sandboxapi.StartRequest{})
	apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected)
	if !strings.Contains(apiErr.Message, "last successful disk sync") || strings.Contains(apiErr.Message, "(its work is kept)") {
		t.Fatalf("failed MicroVM verification promises unsynced work: %q", apiErr.Message)
	}
	if got, _ := e.client.GetSandbox(t.Context(), "restart"); got.Status.Phase != openshell.PhaseStopped ||
		e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 {
		t.Fatalf("after the failed check: phase %s, stops %d", got.Status.Phase, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
	if phases := e.tel.phases("restart"); phases[len(phases)-1] != audit.SandboxPhaseStopped {
		t.Fatalf("lifecycle = %v", phases)
	}
	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.rootdir = "writable" }, nil))
	stops = e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err = e.m.Start(t.Context(), "restart", sandboxapi.StartRequest{})
	apiErr = wantCode(t, err, sandboxapi.CodePolicyRejected)
	if !strings.Contains(apiErr.Detail, "can add or rename entries of its root folder") || e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 {
		t.Fatalf("writable root at restart: %+v, stops %d", apiErr, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
}

// A MicroVM recorded before the guest resolver check (DefenseClaw 1.0.7 and
// earlier) has no caller in its image: its create passed the hook-fire
// MicroVM verdict, and its start keeps the check it was created under
// instead of refusing the upgraded sandbox. A MicroVM created now records
// the check, and a start keeps that mark.
func TestStartKeepsTheCheckOfAMicroVMRecordedBeforeTheResolverCheck(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	e.create(sandboxapi.CreateRequest{Name: "upgraded", Harness: "opencode", Copy: true})
	e.stopBox("upgraded")
	b := e.boxOf("upgraded")
	if b.rec.Verify == nil || !b.rec.Verify.LocalhostResolver {
		t.Fatalf("a MicroVM create did not record the resolver check: %+v", b.rec.Verify)
	}
	legacy := *b.rec.Verify
	legacy.LocalhostResolver = false
	e.m.mu.Lock()
	b.rec.Verify = &legacy
	e.m.mu.Unlock()
	resolverCalls := 0
	checks := e.workloadChecks(nil, nil)
	e.fake.HandleExec(func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isResolverCall(call) {
			resolverCalls++
			return openshelltest.ExecResponse{Stderr: []byte("exec: no such file or directory"), ExitCode: 127}
		}
		return checks(ctx, call)
	})
	e.startBox("upgraded", sandboxapi.StartRequest{})
	calls := e.workloadCheckCalls("upgraded")
	if resolverCalls != 0 || len(calls) != 2 || calls[1].Command[7] != "defenseclaw-verify" {
		t.Fatalf("legacy MicroVM start ran resolver calls %d, workload checks %+v", resolverCalls, calls)
	}
	if after := e.boxOf("upgraded").rec.Verify; after == nil || after.LocalhostResolver {
		t.Fatalf("the start changed the legacy record: %+v", after)
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dkmark"})
	if rec := d.boxOf("dkmark").rec; rec.Verify == nil || rec.Verify.LocalhostResolver {
		t.Fatalf("a docker create recorded the MicroVM resolver check: %+v", rec.Verify)
	}
}

// On docker too a start that finds the sandbox not as prepared (here the
// run files it rewrote are on a writable mount) stops it again and says so.
func TestStartOnDockerStopsASandboxNotAsPrepared(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "dkstart"})
	e.stopBox("dkstart")
	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) {
		for i := range a.files {
			if a.files[i].mount != "" {
				a.files[i].mount = "rw,relatime"
			}
		}
	}, nil))
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err := e.m.Start(t.Context(), "dkstart", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected); !strings.HasSuffix(apiErr.Message, "DefenseClaw stopped it again (its work is kept)") ||
		!strings.Contains(apiErr.Detail, "is not on a read-only mount") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	if got, _ := e.client.GetSandbox(t.Context(), "dkstart"); got.Status.Phase != openshell.PhaseStopped ||
		e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 {
		t.Fatalf("after the failed check: phase %s, stops %d", got.Status.Phase, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
	if calls := e.workloadCheckCalls("dkstart"); len(calls) != 2 {
		t.Fatalf("workload checks = %d, want one at create and one at start", len(calls))
	}
}

// When the stop after a failed check fails too, the sandbox still runs:
// the refusal says so, not that it was stopped, and names the stop that
// ends it (rel-1-0-2:GAP-0014 fix-up).
func TestStartSaysASandboxNotAsPreparedStillRunsWhenItCannotBeStopped(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "dkkeep"})
	e.stopBox("dkkeep")
	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.files[0].sha256 = strings.Repeat("0", 64) }, nil))
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	_, err := e.m.Start(t.Context(), "dkkeep", sandboxapi.StartRequest{})
	apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected)
	if strings.Contains(apiErr.Message, "stopped it again") || strings.Contains(err.Error(), "driver busy") ||
		!strings.HasPrefix(apiErr.Message, "sandbox dkkeep does not run as DefenseClaw prepared it; ") ||
		!strings.HasSuffix(apiErr.Message, "so it is still running: stop it with `defenseclaw sandbox stop dkkeep`") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	if got, _ := e.client.GetSandbox(t.Context(), "dkkeep"); got.Status.Phase == openshell.PhaseStopped {
		t.Fatal("the fake gateway stopped the sandbox although its stop failed")
	}
	e.stopBox("dkkeep")
}

// A record that does not say what its create delivered (every create
// records it) cannot be checked: its start is refused the same way, and
// the sandbox stopped again.
func TestStartRefusesARecordWithoutItsCheck(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "nocheck"})
	e.stopBox("nocheck")
	b := e.boxOf("nocheck")
	e.m.mu.Lock()
	b.rec.Verify = nil
	e.m.mu.Unlock()
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err := e.m.Start(t.Context(), "nocheck", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodePolicyRejected); !strings.HasSuffix(apiErr.Message, "DefenseClaw stopped it again (its work is kept)") ||
		!strings.Contains(apiErr.Detail, "cannot be checked") ||
		!strings.Contains(apiErr.Detail, "pull nocheck --apply") ||
		!strings.Contains(apiErr.Detail, "may be refused because it must start again") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	if got, _ := e.client.GetSandbox(t.Context(), "nocheck"); got.Status.Phase != openshell.PhaseStopped ||
		e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 {
		t.Fatalf("after the refusal: phase %s, stops %d", got.Status.Phase, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
	if calls := e.workloadCheckCalls("nocheck"); len(calls) != 1 {
		t.Fatalf("workload checks = %d, want only the create's", len(calls))
	}
}

// A start keeps the hostname the check finds.
func TestStartRecordsTheHostname(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	e.create(sandboxapi.CreateRequest{Name: "hostbox", Harness: "opencode", Copy: true})
	e.stopBox("hostbox")
	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.hostname = "renamed" }, nil))
	e.startBox("hostbox", sandboxapi.StartRequest{})
	recs, errs := newRecordStore(e.dataDir).loadAll()
	if len(errs) != 0 || len(recs) != 1 || recs[0].Hostname != "renamed" {
		t.Fatalf("records = %+v, %v", recs, errs)
	}
}

// The hostname the check found is the sandbox's own: a lookup of it (git
// making up an e-mail address) is no blocked site. A name with a dot is.
func TestOwnHostNameIsTheRecordedOne(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	e.create(sandboxapi.CreateRequest{Name: "vmhost", Harness: "opencode", Copy: true})
	e.ocsf("vmhost", "NET:OPEN [MED] DENIED /usr/bin/git(0) -> vmhost:80 [reason:transparent_tcp_policy_denied]", time.Now())
	if got := e.get("vmhost"); got.Egress.Blocked != 0 || len(e.events("vmhost", sandboxapi.ActivityEgressBlocked, "")) != 0 {
		t.Fatalf("the sandbox's own name counted as a blocked site: %+v", got.Egress)
	}
	if !ownHostName("abf22769329d", "") || !ownHostName("VMHost", "vmhost") || ownHostName("vmhost.example.com", "vmhost.example.com") ||
		ownHostName("other", "vmhost") {
		t.Fatal("ownHostName")
	}
}
