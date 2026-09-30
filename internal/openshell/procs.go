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

// unmanagedService judges, on a Mac, a gateway that Homebrew's service does
// not run: OpenShell's release binaries (the ones the formula downloads)
// started by a LaunchAgent of the user's own, or by hand. DefenseClaw
// starts and restarts the gateway through Homebrew's service only, and
// setup refuses an OpenShell installed another way (DefenseClaw's install
// step would find its CLI and not run NVIDIA's installer), so the fix is
// setup's: stop that gateway, remove that OpenShell, then install the
// formula. A healthy gateway warns (its sandboxes run, but DefenseClaw
// cannot restart it) and says how it runs instead of "not installed".
func (r *doctorRun) unmanagedService(ctx context.Context) {
	c := r.report.Get(CheckIDGatewayService)
	if r.GOOS != "darwin" || c == nil || r.service == nil || r.service.Installed {
		return
	}
	if r.report.OpenShellOutsideFormula() {
		c.Fix = &Fix{Summary: OpenShellOutsideFormulaFix, Command: installOpenShellCommand}
	}
	if r.gateway == nil || !r.gateway.Healthy {
		return
	}
	notBrew := "not Homebrew's " + GatewayFormula + " service"
	c.Status = StatusWarn
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
