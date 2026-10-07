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
	return len(call.Command) >= 8 && call.Command[0] == "/usr/bin/env" && call.Command[7] == "defenseclaw-verify"
}

// workloadAnswer is what a sandbox answers the workload check.
type workloadAnswer struct {
	uid, gid int
	hostname string
	home     string
	capEff   string
	// cpus and memKB are the processors and the MemTotal (kB) it sees.
	cpus  int
	memKB int64
	files []answerFile
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
	if !a.cut {
		b.WriteString("end\n")
	}
	return []byte(b.String())
}

// answerFor is the answer of a sandbox named hostname (a MicroVM's
// hostname is its name) that runs as want expects.
func answerFor(want verifyRecord, hostname string) workloadAnswer {
	a := workloadAnswer{uid: want.UID, gid: want.GID, hostname: hostname, home: "writable", capEff: "0000000000000000", cpus: 2, memKB: 2000000}
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
// (exit 0 without output when nil).
func (e *harnessEnv) workloadChecks(edit func(sandbox string, a *workloadAnswer), other openshelltest.ExecHandler) openshelltest.ExecHandler {
	return func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if !isWorkloadCheck(call) {
			if other != nil {
				return other(ctx, call)
			}
			return openshelltest.ExecResponse{}
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
}

// The check runs in an empty environment with every tool by absolute path:
// nothing planted on the image PATH (under /sandbox) answers for itself.
func TestWorkloadCheckRunsNothingFromThePath(t *testing.T) {
	argv := verifyArgv(testVerify())
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
	argv = verifyArgv(want)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + planted + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	must(t, err)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a tool planted on the PATH ran")
	}
	facts, err := parseWorkloadFacts(out)
	must(t, err)
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
	if !slices.Contains(paths, "/usr/local/lib/defenseclaw/opencode/defenseclaw.js") || !slices.Contains(paths, "/etc/opencode/opencode.json") ||
		!slices.Contains(paths, "/usr/local/lib/defenseclaw/bin/opencode-launch") || !slices.Equal(calls[0].Command[8:], paths) {
		t.Fatalf("checked %q, recorded %q", calls[0].Command[8:], paths)
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dkcheck"})
	dcalls := d.workloadCheckCalls("dkcheck")
	rec = d.boxOf("dkcheck").rec
	if len(dcalls) != 1 || rec.Verify == nil || !slices.Equal(dcalls[0].Command, verifyArgv(*rec.Verify)) || rec.Hostname != "dkcheck" {
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
	e.fake.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isWorkloadCheck(call) {
			return openshelltest.ExecResponse{Stdout: created.stdout()}
		}
		return openshelltest.ExecResponse{}
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
	if calls := e.workloadCheckCalls("restart"); len(calls) != 2 || !slices.Equal(calls[1].Command, verifyArgv(recorded)) {
		t.Fatalf("workload checks = %+v", calls)
	}
	if after := e.boxOf("restart").rec.Verify; after == nil || !reflect.DeepEqual(*after, recorded) {
		t.Fatalf("the start changed what the check expects: %+v, want %+v", after, recorded)
	}
	e.stopBox("restart")

	e.fake.HandleExec(e.workloadChecks(func(_ string, a *workloadAnswer) { a.files[0].sha256 = strings.Repeat("0", 64) }, nil))
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	_, err = e.m.Start(t.Context(), "restart", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodePolicyRejected)
	if got, _ := e.client.GetSandbox(t.Context(), "restart"); got.Status.Phase != openshell.PhaseStopped ||
		e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 {
		t.Fatalf("after the failed check: phase %s, stops %d", got.Status.Phase, e.fake.Calls(openshelltest.MethodStopSandbox)-stops)
	}
	if phases := e.tel.phases("restart"); phases[len(phases)-1] != audit.SandboxPhaseStopped {
		t.Fatalf("lifecycle = %v", phases)
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
		!strings.Contains(apiErr.Detail, "cannot be checked") {
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
