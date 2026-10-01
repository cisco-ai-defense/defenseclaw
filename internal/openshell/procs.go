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

package openshell

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// process is one of the user's processes as ps(1) lists it.
type process struct {
	pid, ppid int
	// path is the executable: macOS's ps prints its full path.
	path string
}

// processes are this user's processes, listed once, when a Mac's checks
// need them: what runs a gateway Homebrew's service does not run, and
// which MicroVM driver it runs. They are empty when ps cannot list them.
func (r *doctorRun) processes(ctx context.Context) []process {
	if r.procsDone {
		return r.procs
	}
	r.procsDone = true
	out, err := r.Runner.Output(ctx, Command{Name: "ps", Args: []string{"-axww", "-o", "pid=,ppid=,uid=,comm="}, Timeout: 10 * time.Second})
	if err != nil {
		return nil
	}
	uid := r.Geteuid()
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		owner, err3 := strconv.Atoi(f[2])
		// An executable path may hold spaces.
		path := strings.Join(f[3:], " ")
		if err1 != nil || err2 != nil || err3 != nil || owner != uid || !filepath.IsAbs(path) {
			continue
		}
		r.procs = append(r.procs, process{pid: pid, ppid: ppid, path: path})
	}
	return r.procs
}

// findProcess is the first of procs running the executable named name
// whose parent is parent (any parent when parent is 0), or nil.
func findProcess(procs []process, name string, parent int) *process {
	for i, p := range procs {
		if filepath.Base(p.path) == name && (parent == 0 || p.ppid == parent) {
			return &procs[i]
		}
	}
	return nil
}

// gatewayProcess is this user's running openshell-gateway, or nil.
func (r *doctorRun) gatewayProcess(ctx context.Context) *process {
	return findProcess(r.processes(ctx), GatewayBinary, 0)
}

// launchdLabel is the label of the launchd job, in this user's domain,
// whose process is pid ("" when none is: a process started from a shell,
// even one launchd adopted after the shell went).
func (r *doctorRun) launchdLabel(ctx context.Context, pid int) string {
	out, err := r.Runner.Output(ctx, Command{Name: "launchctl", Args: []string{"list"}, Timeout: 10 * time.Second})
	if err != nil {
		return ""
	}
	want := strconv.Itoa(pid)
	for _, line := range strings.Split(string(out), "\n") {
		// PID, last exit status, label.
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == want {
			return strings.Join(f[2:], " ")
		}
	}
	return ""
}

// unmanagedService judges a gateway that DefenseClaw's gateway service does
// not run: on a Mac OpenShell's release binaries (the ones the formula
// downloads) started by a LaunchAgent of the user's own, or by hand; on
// Linux an OpenShell that came without the openshell-gateway user unit.
// DefenseClaw starts and restarts the gateway through that service only.
// A healthy gateway warns (its sandboxes run and setup uses it, but
// DefenseClaw cannot start or restart it) and, on a Mac, says how it runs
// instead of "not installed"; with none answering the check fails, as
// setup stops there. Either way the fix is unmanagedFix, the user's.
func (r *doctorRun) unmanagedService(ctx context.Context) {
	c := r.report.Get(CheckIDGatewayService)
	if c == nil || r.service == nil || r.service.Installed {
		return
	}
	healthy := r.gateway != nil && r.gateway.Healthy
	if r.report.GatewayUnmanaged() {
		first := startYourself
		if healthy {
			first = restartYourself
		}
		c.Fix = r.unmanagedFix(first)
	}
	switch {
	case !healthy:
		return
	case r.GOOS != "darwin" && !r.report.GatewayUnmanaged():
		// No OpenShell CLI to use its gateway with: the install sets the
		// unit up.
		return
	case r.GOOS != "darwin":
		c.Status = StatusWarn
		c.Detail = r.service.Unit + " is not installed; the gateway that answers runs another way, so DefenseClaw cannot start or restart it"
		return
	}
	c.Status = StatusWarn
	notBrew := "not Homebrew's " + GatewayFormula + " service"
	gw := r.gatewayProcess(ctx)
	if gw == nil {
		c.Detail = "the gateway answers, but " + notBrew + " runs it (DefenseClaw could not tell what does), so DefenseClaw cannot restart it"
		return
	}
	if label := r.launchdLabel(ctx, gw.pid); label != "" {
		c.Detail = fmt.Sprintf("%s runs under launchd (%s), %s, so DefenseClaw cannot restart it", gw.path, label, notBrew)
		return
	}
	c.Detail = fmt.Sprintf("%s (process %d) was started by hand, %s: it does not start again at login, and DefenseClaw cannot restart it",
		gw.path, gw.pid, notBrew)
}
