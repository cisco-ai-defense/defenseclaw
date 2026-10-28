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
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// VMGone reports OpenShell's account of a sandbox in its error state whose
// MicroVM no longer runs (said is FailureReason's, or a record's
// PhaseReason): the vm driver's ProcessExited, which it sets once the VM
// process or its host supervisor exited, and then ends the other, and for
// a sandbox whose main process had exited before the driver restarted,
// which it restores without launching its VM (0.1.3 and 0.1.5). Nothing of
// such a sandbox runs, so a stop of its gateway ends nothing.
func VMGone(said string) bool {
	return saysReason(said, "ProcessExited")
}

// MainProcessFailed reports OpenShell's error reason for a workload whose
// main process exited. OpenShell returns its stop as it is in this state.
func MainProcessFailed(said string) bool {
	return saysReason(said, "MainProcessFailed")
}

// saysReason reports whether said (FailureReason's "Reason: message; ..."
// or a bare reason) gives the condition reason reason.
func saysReason(said, reason string) bool {
	for _, part := range strings.Split(said, "; ") {
		if part == reason || strings.HasPrefix(part, reason+":") {
			return true
		}
	}
	return false
}

// HoldsGateway reports whether a sandbox that OpenShell lists in phase p
// (said: as for VMGone) keeps DefenseClaw from stopping, restarting or
// upgrading its gateway, or from moving its account to another OpenShell
// setup. Any of those stops every sandbox on the gateway, and where the
// compute driver's stop does not keep what a workload has not synced
// (stopFlushes false: the MicroVM driver, whose VMs end with the gateway,
// and a driver DefenseClaw does not know) a VM that still runs loses what
// it wrote last.
//
// Only OpenShell's own state releases a sandbox: it is stopped, it is
// being deleted, or it is in the error state because its VM process
// exited (VMGone). Nothing else does: not the time since its workload
// ended, nor a stop DefenseClaw asked for that OpenShell did not make.
// Ready, provisioning, starting, stopping, unknown and unnamed phases
// hold, and so do completed and every other error state (a main process
// that failed, a VM process OpenShell could not poll, a provisioning that
// timed out, an image that failed, no reason given): the VM keeps running
// after its main process ends (GAP-0012), with whatever that process left
// running, and nothing in OpenShell flushes it. On a driver whose stop
// keeps the workload's writes (docker: an exited container), the ended
// phases hold nothing.
func HoldsGateway(p SandboxPhase, said string, stopFlushes bool) bool {
	switch p {
	case PhaseStopped, PhaseDeleting:
		return false
	case PhaseCompleted:
		return !stopFlushes
	case PhaseError:
		return !stopFlushes && !VMGone(said)
	}
	return true
}

// StopWayOn is what the user runs to bring the sandbox name, which holds
// its gateway in phase p (HoldsGateway; said: as for VMGone), to a phase in
// which OpenShell reports it stopped, on a gateway that runs DefenseClaw
// sandboxes (release: SupportedMin or later), an older gateway, or one whose
// release could not be read. An older gateway's stop of a
// sandbox in its error state OpenShell refuses and on which DefenseClaw
// starts none. OpenShell refuses the stop of a sandbox whose provisioning
// timed out, which never ran its workload: a start after OpenShell's
// cleanup, then the stop of the ready sandbox, brings it to stopped. It
// returns its stop of a completed sandbox, or of one whose main process
// failed, as it is. A lingering failed MicroVM may still run, and nothing
// in OpenShell writes its disk back (exec needs a ready sandbox, and
// 0.1.5's flushing stop covers only a running workload): its start ends
// the VM with no flush first, so what the VM has not written to its disk
// is lost. Its way on says so, and needs the start's --end-vm
// (sandboxapi.StartRequest.EndVM), as does its delete, which loses all of
// its work. Neither keeps all of it. The gateway also lists raw OpenShell
// sandboxes, which DefenseClaw's commands refuse, so each stop and delete
// also names OpenShell's own.
func StopWayOn(name string, p SandboxPhase, said, release string) string {
	runs := RunsSandboxes(release)
	_, parseErr := ParseVersion(release)
	knownOld := !runs && parseErr == nil
	dcStop := "`defenseclaw sandbox stop " + name + "`"
	rawStopCommand := "`openshell sandbox stop " + name + "` (raw OpenShell sandbox)"
	rawStop := rawStopCommand
	if !runs {
		rawStop = "on an older or unknown gateway release, raw stop may not flush the guest: save its work outside the guest first, then " + rawStop
	}
	stop := "save or sync any accessible guest work first, then " + dcStop + " (DefenseClaw sandbox), or " + rawStop
	del := "`defenseclaw sandbox delete " + name + "` (DefenseClaw sandbox) or `openshell sandbox delete " + name +
		"` (raw OpenShell sandbox), which deletes it and its work"
	switch {
	case p == PhaseReady:
		return stop
	case p != PhaseCompleted && p != PhaseError:
		return "wait until `openshell sandbox list` shows it ready or stopped, then " + stop + " if it is ready"
	case knownOld:
		return "save or sync any accessible guest work outside the guest first; OpenShell " + release + " cannot stop or start a completed or error-state MicroVM: " + del
	case !runs:
		return "save or sync any accessible guest work first; the gateway release is unknown and raw stop may not flush the guest, so save its work outside the guest before trying " + rawStopCommand + "; only if OpenShell refuses stop or still reports the VM running, " + del
	case p == PhaseError && ProvisioningTimedOut(said):
		return "wait a minute for OpenShell's cleanup of the provisioning that timed out, then `defenseclaw sandbox start " + name + "`; save or sync any accessible guest work first, then " + dcStop +
			" once it is ready (OpenShell refuses to stop a sandbox whose provisioning timed out); for a raw OpenShell sandbox, `openshell sandbox start " + name + "`, then save or sync its work before " + rawStop + " once it is ready"
	case p == PhaseCompleted || p == PhaseError && LingeringVM(p, said, false) && MainProcessFailed(said):
		return EndedVMWayOn(name)
	}
	return stop
}

// EndedVMWayOn is how the user ends name, a MicroVM whose workload
// completed or whose main process failed while its VM still runs
// (LingeringVM), on OpenShell SupportedMin: its stop returns it as it is,
// and its start, `start --end-vm` too, fails with Conflict ("VM sandbox is
// already running generation") and leaves it starting, where its stop is
// refused as well, so no command named here may advise either (GAP-0570).
// Its delete ends it, with its work; until then it keeps the gateway.
func EndedVMWayOn(name string) string {
	return "save or sync any accessible guest work first; nothing in OpenShell writes this MicroVM's disk back or stops it: on OpenShell " + SupportedMin +
		" its start (`defenseclaw sandbox start " + name + " --end-vm` or `openshell sandbox start " + name + "` too) fails with Conflict and leaves it starting, " +
		"so keep it while you need what it holds (it keeps the OpenShell gateway); only then `defenseclaw sandbox delete " + name + "` (DefenseClaw sandbox) or `openshell sandbox delete " +
		name + "` (raw OpenShell sandbox), which deletes it and its work"
}

// LingeringVMLoss is what keeping or ending a MicroVM whose main process
// ended (completed, or failed) costs: StopWayOn's way on and the start's
// refusal say it.
const LingeringVMLoss = "nothing in OpenShell writes this MicroVM's disk back or stops it: its VM still runs what its workload left running, " +
	"and its start ends that VM with no flush first, so what the VM has not written to its disk is lost"

// LingeringVM reports a MicroVM that OpenShell reports in phase p (said:
// as for VMGone) whose VM may still run what its workload left running,
// which its start ends with no flush (StopWayOn): completed, or in the
// error state but for a VM that is gone and a provisioning that timed out,
// which never ran the workload. On a driver whose stop keeps the writes
// (stopFlushes: docker) none is.
func LingeringVM(p SandboxPhase, said string, stopFlushes bool) bool {
	return (p == PhaseCompleted || p == PhaseError) && HoldsGateway(p, said, stopFlushes) && !ProvisioningTimedOut(said)
}

// phaseWord is p as OpenShell's lower-case name ("unknown" for none).
func phaseWord(p SandboxPhase) string {
	if p == "" {
		return "unknown"
	}
	return strings.ToLower(string(p))
}

// stoppedRefusal is base for the sandboxes of list that hold their gateway
// on a driver whose stop does not flush (HoldsGateway), each named with
// its phase and its way on (StopWayOn, on a gateway that runs sandboxes
// when release says so; asked only when one holds), and then is the step to
// retry after; nil when none holds.
func stoppedRefusal(base error, list []*Sandbox, release func() string, then string) error {
	var held []*Sandbox
	for _, sb := range list {
		if sb != nil && HoldsGateway(sb.Status.Phase, FailureReason(sb), false) {
			held = append(held, sb)
		}
	}
	if len(held) == 0 {
		return nil
	}
	currentRelease := release()
	lines := make([]string, 0, len(held))
	for _, sb := range held {
		lines = append(lines, fmt.Sprintf("%s (%s): %s", sb.Name, phaseWord(sb.Status.Phase), StopWayOn(sb.Name, sb.Status.Phase, FailureReason(sb), currentRelease)))
	}
	slices.Sort(lines)
	return fmt.Errorf("%w; OpenShell has not reported these stopped: %s; then %s", base, strings.Join(lines, "; "), then)
}

// VMCount counts the MicroVMs that run as this account (CountMicroVMs):
// the evidence a check before a gateway stop, restart or upgrade falls back
// on when it cannot read the gateway's own account of its sandboxes. An
// error means it cannot tell.
type VMCount func(context.Context) (int, error)

// microVMLauncherFlag is the flag OpenShell's vm driver starts the launcher
// of every MicroVM with (openshell-driver-vm --internal-run-vm, 0.1.1 to
// 0.1.5). That process runs the VM for as long as the VM lives, as the
// gateway's account, and dies with the gateway (procguard), so a gateway
// whose account runs none has no MicroVM a stop could end.
const microVMLauncherFlag = "--internal-run-vm"

// CountMicroVMs counts the processes of this account that run a MicroVM
// (microVMLauncherFlag), listed with ps through r. A ps that fails is an
// error: nothing then shows that none runs.
func CountMicroVMs(ctx context.Context, r Runner) (int, error) {
	out, err := r.Output(ctx, Command{Name: "ps", Args: []string{"-ww", "-u", strconv.Itoa(os.Getuid()), "-o", "args="}, Timeout: 15 * time.Second})
	if err != nil {
		return 0, fmt.Errorf("list this account's processes: %v: %s", err, strings.TrimSpace(string(out)))
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if slices.Contains(strings.Fields(line), microVMLauncherFlag) {
			n++
		}
	}
	return n, nil
}

// unreachableRefusal is the outcome of a check (base: ErrUnflushed,
// ErrSandboxesRunning) before a gateway stop, restart or upgrade that could
// not read the gateway's sandboxes, why in cause: no registration, no
// connection, or a gateway that refused both calls. That does not show that
// nothing runs on it: a gateway whose registration or certificates broke
// still runs its MicroVMs. So it refuses unless vms shows that no MicroVM
// runs as this account, the only processes the stop would end with no
// flush; then is the step to retry after.
func unreachableRefusal(ctx context.Context, base, cause error, vms VMCount, then string) error {
	way := "make the gateway answer DefenseClaw again (its service, its registration, its certificates), so it can see which sandbox runs, then " + then
	if vms == nil {
		return fmt.Errorf("%w (the sandboxes on it could not be read: %v, and nothing counted the MicroVMs of this account); %s", base, cause, way)
	}
	n, err := vms(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("%w (the sandboxes on it could not be read: %v, and the MicroVMs of this account could not be counted: %v); %s", base, cause, err, way)
	case n > 0:
		return fmt.Errorf("%w (the sandboxes on it could not be read: %v, and %s run as this account, which the gateway's stop would end with no flush); %s",
			base, cause, plural(n, "MicroVM", "MicroVMs"), way)
	}
	return nil
}

// restartGatewayRelease reports the gateway's health release, or an empty string
// when it cannot be read.
func restartGatewayRelease(ctx context.Context, c Client) string {
	h, err := c.Health(ctx)
	if err != nil || h == nil {
		return ""
	}
	return h.RawVersion
}
