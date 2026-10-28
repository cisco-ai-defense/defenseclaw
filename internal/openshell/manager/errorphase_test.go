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
	"errors"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

func TestTimeoutConditionOutranksConfigurationPending(t *testing.T) {
	pending := stream.Condition{Type: "ConfigurationReady", Status: "False", Reason: "ConfigurationPending"}
	timedOut := stream.Condition{Type: "Ready", Status: "False", Reason: "ImagePreparationTimedOut",
		Message: "Image preparation exceeded its absolute deadline"}
	for _, conditions := range [][]stream.Condition{{pending, timedOut}, {timedOut, pending}} {
		e := newVMEnv(t, nil)
		e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
		b := e.boxOf("box")
		e.m.statusEvent(t.Context(), b, &stream.Status{Phase: openshell.PhaseError, Conditions: conditions})
		e.m.mu.Lock()
		reason := b.rec.PhaseReason
		e.m.mu.Unlock()
		if !strings.Contains(reason, "ImagePreparationTimedOut") || strings.Contains(reason, "ConfigurationPending") {
			t.Fatalf("conditions %+v recorded %q, want timeout recovery", conditions, reason)
		}
		way := errorPhaseWayOn("box", reason, "", true)
		if !strings.Contains(way, "then `defenseclaw sandbox start box` (no stop)") || strings.Contains(way, "`defenseclaw sandbox stop box`") {
			t.Fatalf("timeout recovery = %q", way)
		}
	}
}

// Both the live stream and a failed operation's GetSandbox recovery choose
// the first failing condition unless a failing Ready gives the phase's cause.
func TestErrorPhaseConditionPriorityOnWatchAndRestore(t *testing.T) {
	for _, tc := range []struct {
		name       string
		conditions []types.SandboxCondition
		want       string
		reject     string
	}{
		{"first non-Ready", []types.SandboxCondition{
			{Type: "ConfigurationReady", Status: "False", Reason: "SpecificConfigurationFailure"},
			{Type: "ImagePreparation", Status: "False", Reason: "GenericImageFailure"},
		}, "SpecificConfigurationFailure", "GenericImageFailure"},
		{"later Ready", []types.SandboxCondition{
			{Type: "ConfigurationReady", Status: "False", Reason: "ConfigurationPending"},
			{Type: "Ready", Status: "False", Reason: "ImagePreparationTimedOut"},
		}, "ImagePreparationTimedOut", "ConfigurationPending"},
		{"earlier Ready", []types.SandboxCondition{
			{Type: "Ready", Status: "False", Reason: "ImagePreparationTimedOut"},
			{Type: "ConfigurationReady", Status: "False", Reason: "ConfigurationPending"},
		}, "ImagePreparationTimedOut", "ConfigurationPending"},
	} {
		for _, path := range []string{"watch", "restore"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				e := newVMEnv(t, nil)
				e.create(sandboxapi.CreateRequest{Name: "box", Copy: true})
				b := e.boxOf("box")
				if path == "watch" {
					conditions := make([]stream.Condition, 0, len(tc.conditions))
					for _, c := range tc.conditions {
						conditions = append(conditions, stream.Condition{Type: c.Type, Status: c.Status, Reason: c.Reason})
					}
					e.m.statusEvent(t.Context(), b, &stream.Status{Phase: openshell.PhaseError, Conditions: conditions})
				} else {
					sb, err := e.client.GetSandbox(t.Context(), "box")
					if err != nil {
						t.Fatal(err)
					}
					sb.Status.Phase = openshell.PhaseError
					sb.Status.Conditions = tc.conditions
					e.fake.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
					e.m.restorePhase(t.Context(), e.gw, b, audit.SandboxTriggerStart, audit.SandboxPhaseStarting)
				}
				e.m.mu.Lock()
				reason := b.rec.PhaseReason
				e.m.mu.Unlock()
				if !strings.Contains(reason, tc.want) || strings.Contains(reason, tc.reject) {
					t.Fatalf("%s: recorded %q, want %s before %s", path, reason, tc.want, tc.reject)
				}
			})
		}
	}
}

// A gateway that runs sandboxes (openshell.SupportedMin, which includes
// NVIDIA/OpenShell#4231) stops a sandbox in its error state and starts it
// again after, so the way on keeps the sandbox; an older one can do
// neither, and the way on upgrades OpenShell first.
func TestErrorPhaseWayOnFollowsTheGatewayRelease(t *testing.T) {
	now := errorPhaseWayOn("box", "", "", false)
	if strings.Contains(now, "delete") || !strings.Contains(now, "`defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
		t.Errorf("from %s: %q", openshell.SupportedMin, now)
	}
	old := errorPhaseWayOn("box", "", "upgrade OpenShell", false)
	if !strings.Contains(old, "neither stop nor start") || !strings.Contains(old, "upgrade OpenShell, then `defenseclaw sandbox stop box`") {
		t.Errorf("before %s: %q", openshell.SupportedMin, old)
	}
	oldVM := errorPhaseWayOn("box", "MainProcessFailed: exited 1", "upgrade OpenShell", true)
	if save, del := strings.Index(oldVM, "save or sync any accessible work outside the guest first"), strings.Index(oldVM, "`defenseclaw sandbox delete box`"); save < 0 || del < save {
		t.Errorf("old MicroVM deletion lacks save-first advice: %q", oldVM)
	}
	if got := errorPhaseWayOn("box", overlayDiskFullText, "", false); got != overlayDiskWayOn("box") {
		t.Errorf("a full disk: %q", got)
	}
}

func TestStoppedUnverifiedAdviceQualifiesMicroVMWork(t *testing.T) {
	err := sessionRulesLeft("box", errors.New("policy store busy"), nil, false)
	if !strings.Contains(err.Error(), "last successful disk sync") || strings.Contains(err.Error(), "(its work is kept)") {
		t.Fatalf("failed start promises unsynced MicroVM work: %v", err)
	}
	if msg := unflushedStopMessage("box"); !strings.Contains(msg, "last successful disk sync") || strings.Contains(msg, "flushes first") {
		t.Fatalf("unflushed stop advice promises a successful sync: %q", msg)
	}
}

func TestFailedMicroVMRecoveryDoesNotPromiseUnsyncedWork(t *testing.T) {
	for _, upgrade := range []string{"", "upgrade OpenShell"} {
		for _, reason := range []string{"ProcessExited: VM process exited with status 1", "ProcessPollFailed: Bad file descriptor"} {
			got := errorPhaseWayOn("box", reason, upgrade, true)
			if upgrade != "" && !openshell.VMGone(reason) {
				continue // an older gateway must wait for the user's delete
			}
			if !strings.Contains(got, "last successful disk sync") {
				t.Errorf("failed VM reason %q, upgrade %q has no sync limit: %s", reason, upgrade, got)
			}
			if strings.Contains(got, "which keep the sandbox and its work") || strings.Contains(got, "start Docker again") {
				t.Errorf("failed VM reason %q, upgrade %q: %s", reason, upgrade, got)
			}
		}
	}
}

// NVIDIA/OpenShell#4231 refuses the stop of a sandbox whose provisioning
// timed out ("sandbox provisioning timed out; retry start after timeout
// cleanup completes"): the way on waits for OpenShell's cleanup and starts
// it, with no stop, in the feed's line and in the refusals of a stop and of
// a start made before the cleanup ended.
func TestProvisioningTimeoutWayOnStartsWithoutAStop(t *testing.T) {
	for _, reason := range []string{
		errorPhaseReason(&audit.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}),
		errorPhaseReason(&audit.SandboxCondition{Type: "Ready", Status: "False", Reason: "ImagePreparationTimedOut",
			Message: "Image preparation or initial supervisor startup exceeded its absolute deadline"}),
	} {
		got := errorPhaseWayOn("box", reason, "", false)
		if !strings.Contains(got, "refuses to stop it") || !strings.Contains(got, "then `defenseclaw sandbox start box` (no stop)") ||
			strings.Contains(got, "`defenseclaw sandbox stop box`") {
			t.Errorf("%q: %q", reason, got)
		}
	}
	e := newEnv(t, nil)
	for _, refusal := range []string{
		"FailedPrecondition: sandbox provisioning timed out; retry start after timeout cleanup completes",
		"FailedPrecondition: provisioning timeout cleanup is still pending; retry start after compute is reclaimed",
	} {
		err := e.m.errorPhaseRefusal("box", "", "", errors.New(refusal))
		var apiErr *sandboxapi.Error
		if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeConflict || !strings.Contains(apiErr.Message, "provisioning timed out") ||
			!strings.Contains(apiErr.Detail, "(no stop)") {
			t.Errorf("%q: %v", refusal, err)
		}
	}
	if err := e.m.errorPhaseRefusal("box", "", "", errors.New("Unavailable: connection refused")); err != nil {
		t.Errorf("another error: %v", err)
	}
}
