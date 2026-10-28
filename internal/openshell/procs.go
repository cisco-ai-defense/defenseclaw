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
	"net"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// process is one of the user's processes as ps(1) lists it.
type process struct {
	pid, ppid int
	// path is the executable's full path.
	path string
}

// processes are this user's processes, listed once, when the checks need
// them: what runs a gateway Homebrew's service does not run (a Mac), and
// which MicroVM driver it runs. They are empty when ps cannot list them.
func (r *doctorRun) processes(ctx context.Context) []process {
	if r.procsDone {
		return r.procs
	}
	r.procsDone = true
	// macOS's ps prints an executable's full path as comm; procps prints
	// only a name there, so on Linux the path is the first word of the
	// command line.
	column, linux := "comm=", r.GOOS == "linux"
	if linux {
		column = "args="
	}
	out, err := r.Runner.Output(ctx, Command{Name: "ps", Args: []string{"-axww", "-o", "pid=,ppid=,uid=," + column}, Timeout: 10 * time.Second})
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
		if linux {
			path = f[3]
			// argv[0] is process-controlled and procps does not escape its
			// spaces. Use the kernel's executable for this account's PID when
			// available, so another gateway's argv cannot supply its driver.
			if err1 == nil && err3 == nil && owner == uid {
				if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil && filepath.IsAbs(exe) {
					// Linux marks an unlinked running binary this way. Its
					// directory can still hold the driver the process uses.
					path = strings.TrimSuffix(exe, " (deleted)")
				}
			}
		}
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

// registeredGatewayPID identifies the owner of the selected local gateway's
// listening socket. A process merely named openshell-gateway under this uid
// may belong to another registration and must not supply its driver.
func registeredGatewayPID(reg *Registration, uid int, holder func(string, int) (daemon.PortHolder, error)) int {
	if !reg.Local() || holder == nil {
		return 0
	}
	host, portText, err := net.SplitHostPort(reg.Target())
	if err != nil {
		return 0
	}
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	owner, err := holder(host, port)
	if err != nil || owner.UID != uid || owner.PID <= 0 {
		return 0
	}
	return owner.PID
}

// GatewayExecutableOnPort is the kernel's executable of this account's
// gateway listening on its managed loopback port. It returns no path when
// the port is unowned, another account owns it, or the listener is not an
// openshell-gateway. The managed daemon uses this only on Linux.
func GatewayExecutableOnPort(port int) string {
	if port < 1 || port > 65535 {
		return ""
	}
	owner, err := daemon.FindPortHolder("127.0.0.1", port)
	if err != nil || owner.UID != os.Geteuid() || owner.PID <= 0 {
		return ""
	}
	path, err := os.Readlink("/proc/" + strconv.Itoa(owner.PID) + "/exe")
	if err != nil || !filepath.IsAbs(path) || filepath.Base(path) != GatewayBinary {
		return ""
	}
	return path
}

// gatewayProcess is the gateway doctor contacted when it answers, or nil
// when the listener cannot be tied to this account's process. When no
// gateway answers, the first process is only a best-effort service hint.
func (r *doctorRun) gatewayProcess(ctx context.Context) *process {
	if r.gateway != nil && r.gateway.Healthy {
		pid := registeredGatewayPID(r.reg, r.Geteuid(), r.PortHolder)
		if pid == 0 {
			return nil
		}
		procs := r.processes(ctx)
		for i := range procs {
			if procs[i].pid == pid && filepath.Base(procs[i].path) == GatewayBinary {
				return &procs[i]
			}
		}
		return nil
	}
	return findProcess(r.processes(ctx), GatewayBinary, 0)
}

// homebrewKegPrefix is the Homebrew prefix whose openshell formula keg
// holds path (<prefix>/opt/openshell/... or
// <prefix>/Cellar/openshell/<version>/...), "" when path is in none.
func homebrewKegPrefix(path string) string {
	name := pathpkg.Base(GatewayFormula)
	for d := filepath.Dir(filepath.Clean(path)); d != filepath.Dir(d); d = filepath.Dir(d) {
		if parent := filepath.Dir(d); filepath.Base(d) == name && (filepath.Base(parent) == "opt" || filepath.Base(parent) == "Cellar") {
			return filepath.Dir(parent)
		}
	}
	return ""
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
	// Another account's gateway on the port (checkService) is not one this
	// account runs another way: the check keeps that refusal (GAP-0390).
	if c == nil || r.service == nil || r.service.Installed || r.portOther {
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
	if keg := homebrewKegPrefix(gw.path); keg != "" && keg != filepath.Clean(r.brewPrefix()) {
		// The formula of another Homebrew runs it, one of your own that
		// HOMEBREW_PREFIX and PATH do not name (an ssh session without
		// its shellenv): its service is not "by hand" (GAP-0391).
		brew := filepath.Join(keg, "bin", "brew")
		c.Detail = fmt.Sprintf("%s (process %d) is the %s formula of the Homebrew at %s, but DefenseClaw uses the Homebrew at %s "+
			"(HOMEBREW_PREFIX, else the brew first on PATH), so it cannot see or restart that service", gw.path, gw.pid, GatewayFormula, keg, r.brewPrefix())
		c.Fix = &Fix{Summary: "put the Homebrew at " + keg + " first on PATH (or HOMEBREW_PREFIX), then run the command again", Command: "eval \"$(" + brew + " shellenv)\""}
		return
	}
	if label := r.launchdLabel(ctx, gw.pid); label != "" {
		c.Detail = fmt.Sprintf("%s runs under launchd (%s), %s, so DefenseClaw cannot restart it", gw.path, label, notBrew)
		return
	}
	c.Detail = fmt.Sprintf("%s (process %d) was started by hand, %s: it does not start again at login, and DefenseClaw cannot restart it",
		gw.path, gw.pid, notBrew)
}
