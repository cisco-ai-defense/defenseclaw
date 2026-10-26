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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A stop or restart of the gateway ends every MicroVM on it, and a VM's
// disk keeps only what its guest synced. DefenseClaw's own restarts check
// right before that OpenShell reports every sandbox stopped
// (CheckStopped), but a raw `openshell sandbox start` takes no DefenseClaw
// lock: one that lands after the final check, while the restart command
// runs, was ended with what its guest had written since its last sync
// (GAP-0380). The stop sync closes that interval where it can be closed,
// inside the service manager's stop: the systemd gateway service's
// ExecStop syncs the disk of every MicroVM OpenShell lists ready, whoever
// started it and whoever stops the gateway, before the gateway goes down.
// Every DefenseClaw restart makes sure the service has it first
// (GAP-1927); a service that cannot have it, the Homebrew launchd one, has
// each running MicroVM synced right before the restart command instead
// (GAP-1928).

// stopSyncDropIn is the systemd drop-in that gives the gateway's user unit
// that ExecStop. It sits next to the umask drop-in (vmUnitDropIn).
const stopSyncDropIn = "zz-defenseclaw-stop-sync.conf"

// StopSyncArgs are the arguments of DefenseClaw's gateway binary that the
// ExecStop runs (SyncGatewaySandboxes).
var StopSyncArgs = []string{"sandbox-daemon", "sync-sandboxes"}

// StopSyncTimeout bounds the ExecStop's work, under systemd's default
// TimeoutStopSec (90 s), and the sync before a restart; stopSyncWait
// bounds the sync of one MicroVM.
const (
	StopSyncTimeout = 75 * time.Second
	stopSyncWait    = 45 * time.Second
)

// StopSync is the ExecStop DefenseClaw gives a gateway service that runs
// MicroVMs (GatewayConfigurator.StopSync).
type StopSync struct {
	// Binary is the absolute path of DefenseClaw's gateway binary.
	Binary string
	// Gateway names the registration the ExecStop dials (empty: the
	// openshell CLI's active one).
	Gateway string
}

// stopSyncUnsafe are the characters a path or name in the ExecStop line
// may not hold: systemd splits on white space, expands % specifiers and $
// variables and reads quotes and backslashes.
const stopSyncUnsafe = " \t\r\n\"'\\%$;"

func (s StopSync) execStop() (string, error) {
	if !filepath.IsAbs(s.Binary) || strings.ContainsAny(s.Binary, stopSyncUnsafe) {
		return "", fmt.Errorf("openshell: %q cannot be a systemd ExecStop command path", s.Binary)
	}
	if strings.ContainsAny(s.Gateway, stopSyncUnsafe) || strings.HasPrefix(s.Gateway, "-") {
		return "", fmt.Errorf("openshell: %q cannot be named in a systemd ExecStop line", s.Gateway)
	}
	// The leading "-" keeps a command that cannot run (DefenseClaw
	// uninstalled, say) from holding the stop up.
	cmd := "-" + s.Binary + " " + strings.Join(StopSyncArgs, " ")
	if s.Gateway != "" {
		cmd += " --gateway " + s.Gateway
	}
	return cmd, nil
}

func (g *GatewayConfigurator) stopSyncDropInPath() string {
	return filepath.Join(filepath.Dir(g.unitDropInPath()), stopSyncDropIn)
}

// isStopSyncDropIn reports whether path is the stop sync drop-in.
func isStopSyncDropIn(path string) bool {
	return filepath.Base(path) == stopSyncDropIn && strings.HasSuffix(filepath.Base(filepath.Dir(path)), unitDropInSuffix)
}

// StopSyncSummary is what a stop sync drop-in DefenseClaw wrote does.
const StopSyncSummary = "the " + GatewayService + " service now syncs each running MicroVM's disk before it stops (a systemd drop-in; no restart)"

// EnsureStopSync gives the gateway's systemd user unit the stop sync
// (StopSync) when it lacks it, and has the user manager read it: no
// restart, no sandbox stops. It returns the files it wrote; nothing when
// StopSync is unset, off Linux (launchd gives a Homebrew service no stop
// hook), on a managed host, with no gateway service, or when the unit
// already has it. A failure puts the previous files back.
func (g *GatewayConfigurator) EnsureStopSync(ctx context.Context) (*GatewayApplyResult, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	if g.StopSync == nil || g.GOOS != "linux" || g.managedHost() || g.NoService(ctx) {
		return nil, nil
	}
	cmd, err := g.StopSync.execStop()
	if err != nil {
		return nil, err
	}
	path := g.stopSyncDropInPath()
	before, info, err := readGatewayFile(path)
	if err != nil {
		return nil, err
	}
	after := []byte("# Written by DefenseClaw. A stop or restart of the gateway ends every MicroVM on it, and a VM's disk\n" +
		"# keeps only what its guest synced: sync each running MicroVM first, whoever started it or stops the gateway.\n" +
		"[Service]\nExecStop=" + cmd + "\n")
	if info != nil && string(before) == string(after) {
		return nil, nil
	}
	if info == nil {
		before = nil
	}
	plan := &GatewayPlan{Files: []*FileChange{{Path: path, Before: before, After: after,
		Summary: []string{"ExecStop=" + strings.TrimPrefix(cmd, "-") + " for the " + GatewayService + " service"}}}}
	res := &GatewayApplyResult{}
	err = g.writeFiles(res, plan)
	if err == nil {
		err = g.reloadUnits(ctx, res.Files)
	}
	if err != nil {
		if rerr := g.restore(ctx, res); rerr != nil {
			return nil, fmt.Errorf("%w; restoring the previous unit files also failed: %v", err, rerr)
		}
		return nil, fmt.Errorf("%w (the previous unit files were restored)", err)
	}
	return res, nil
}

// syncBeforeRestart readies a restart, which ends every MicroVM on the
// gateway, for one a raw client started after the restart's final check:
// a systemd service on the MicroVM driver gets the stop sync first
// (EnsureStopSync), whose ExecStop syncs it inside the stop; a service
// without it has each running MicroVM synced now (SyncSandboxes). Neither
// refuses the restart (the check before it already passed): a sync that
// fails is named on Out.
func (g *GatewayConfigurator) syncBeforeRestart(ctx context.Context) {
	g.restartStopSync = nil
	if g.StopSync != nil && g.GOOS == "linux" && g.runsMicroVMs(ctx) {
		res, err := g.EnsureStopSync(ctx)
		switch {
		case err != nil:
			fmt.Fprintf(g.out(), "the %s service could not get the stop sync of its MicroVMs (%v): syncing them before the restart instead\n", GatewayService, err)
		case res != nil:
			g.restartStopSync = res
			if g.StopSyncWritten != nil {
				g.StopSyncWritten(res)
			}
		}
	}
	if g.hasStopSync() {
		return
	}
	syncAll := g.SyncSandboxes
	if syncAll == nil {
		syncAll = func(ctx context.Context, out io.Writer) error { return SyncGatewaySandboxes(ctx, g.Discover, out) }
	}
	ctx, cancel := context.WithTimeout(ctx, StopSyncTimeout)
	defer cancel()
	// SyncRunningSandboxes names each sandbox it could not sync; a gateway
	// that cannot be reached or listed has nothing it could sync.
	_ = syncAll(ctx, g.out())
}

// runsMicroVMs reports whether the gateway runs, or is configured to run,
// a compute driver whose stop keeps only what a workload synced.
func (g *GatewayConfigurator) runsMicroVMs(ctx context.Context) bool {
	if d, err := g.RunningDriver(ctx); err == nil {
		return !d.StopFlushes
	}
	st, err := g.Read()
	return err == nil && st.ComputeDriver == DriverVM
}

// hasStopSync reports whether the systemd gateway service has the stop
// sync drop-in.
func (g *GatewayConfigurator) hasStopSync() bool {
	if g.GOOS != "linux" {
		return false
	}
	info, err := os.Lstat(g.stopSyncDropInPath())
	return err == nil && info.Mode().IsRegular()
}

func (g *GatewayConfigurator) out() io.Writer {
	if g.Out != nil {
		return g.Out
	}
	return io.Discard
}

// splitStopSync splits applied files into the stop sync drop-in and the
// rest.
func splitStopSync(res *GatewayApplyResult) (rest, stopSync *GatewayApplyResult) {
	rest, stopSync = &GatewayApplyResult{}, &GatewayApplyResult{}
	for _, f := range res.Files {
		if isStopSyncDropIn(f.Path) {
			stopSync.Files = append(stopSync.Files, f)
		} else {
			rest.Files = append(rest.Files, f)
		}
	}
	return rest, stopSync
}

// SyncGatewaySandboxes is the stop sync of the gateway opts discovers
// (SyncRunningSandboxes), for the gateway service's ExecStop.
func SyncGatewaySandboxes(ctx context.Context, opts DiscoverOptions, out io.Writer) error {
	reg, err := Discover(opts)
	if err != nil {
		return fmt.Errorf("find the OpenShell gateway to sync its MicroVMs before it stops: %w", err)
	}
	c, err := Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second})
	if err != nil {
		return fmt.Errorf("connect to the OpenShell gateway to sync its MicroVMs before it stops: %w", err)
	}
	defer c.Close()
	return SyncRunningSandboxes(ctx, c, out)
}

// SyncRunningSandboxes runs sync(1) in every sandbox OpenShell lists ready
// on the gateway c talks to, all at once, unless the gateway's driver keeps
// what a stop ends (Driver.StopFlushes). It says on out which it synced and
// which it could not, and fails when one could not be synced or the
// sandboxes could not be listed; it stops and starts nothing.
func SyncRunningSandboxes(ctx context.Context, c Client, out io.Writer) error {
	if info, err := c.GatewayInfo(ctx); err == nil {
		if d, err := GatewayDriver(info); err == nil && d.StopFlushes {
			return nil
		}
	}
	list, err := c.ListSandboxes(ctx, nil)
	if err != nil {
		return fmt.Errorf("list the sandboxes to sync before the OpenShell gateway stops: %w", err)
	}
	var ready []string
	for _, sb := range list {
		if sb != nil && sb.Status.Phase == PhaseReady {
			ready = append(ready, sb.Name)
		}
	}
	errs := make([]error, len(ready))
	var wg sync.WaitGroup
	for i, name := range ready {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.Exec(ctx, name, []string{"/bin/sync"}, ExecOptions{Timeout: stopSyncWait, Attempts: 1, MaxOutputBytes: 256})
			if err == nil && res.ExitCode != 0 {
				err = fmt.Errorf("sync(1) exited with status %d", res.ExitCode)
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	var failed []error
	for i, name := range ready {
		if errs[i] != nil {
			fmt.Fprintf(out, "could not sync the disk of sandbox %s before the OpenShell gateway stops (%v): files written since its last sync may come back empty\n", name, errs[i])
			failed = append(failed, fmt.Errorf("%s: %w", name, errs[i]))
			continue
		}
		fmt.Fprintf(out, "synced the disk of sandbox %s before the OpenShell gateway stops\n", name)
	}
	return errors.Join(failed...)
}
