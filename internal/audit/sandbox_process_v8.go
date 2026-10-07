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

package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Events and sources of a sandbox process (defenseclaw.sandbox.process.event
// and .source), shared by log.sandbox.process and log.sandbox.process_tree.
const (
	SandboxProcessStart = "start"
	SandboxProcessExit  = "exit"

	SandboxProcessSourceSample = "sample"
	SandboxProcessSourceOCSF   = "ocsf"
)

// Bounds of a process record, as the registry declares them.
const (
	maxSandboxProcessName      = 64
	maxSandboxProcessLineage   = 32
	maxSandboxProcessLineageID = 64
)

// SandboxProcessEvent is one process that joined or left a sandbox's opt-in
// process tree, emitted as log.sandbox.process_tree. Every text field is the
// workload's to choose: display text. The executable, command line, working
// folder and lineage are content, which each destination's redaction
// profile governs.
type SandboxProcessEvent struct {
	Sandbox SandboxIdentity
	// Event is SandboxProcessStart or SandboxProcessExit, and Source what
	// saw the process first (SandboxProcessSource*).
	Event  string
	Source string
	// PID and ParentPID are the sandbox's own process ids; ParentPID is 0
	// while only OpenShell reported the process.
	PID, ParentPID   int
	Executable, Name string
	CommandLine      string
	WorkingDirectory string
	// ExitCode is the exit status an OpenShell PROC terminate record
	// reported, nil when unknown.
	ExitCode *int
	// Lineage names the process's ancestors, its parent first.
	Lineage []string
	// UserID and UserName are the host account that launched the sandbox,
	// ConversationID the harness session its hooks last named (the
	// manager's telemetry stamps both).
	UserID, UserName string
	ConversationID   string
	Timestamp        time.Time
}

// RecordSandboxProcess emits log.sandbox.process_tree for one process of a
// sandbox's process tree.
func (recorder *SandboxRecorder) RecordSandboxProcess(ctx context.Context, input SandboxProcessEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validate(true); err != nil {
		return err
	}
	if input.Event != SandboxProcessStart && input.Event != SandboxProcessExit {
		return fmt.Errorf("audit: sandbox process event %q is not registered", input.Event)
	}
	if input.Source != "" && input.Source != SandboxProcessSourceSample && input.Source != SandboxProcessSourceOCSF {
		return fmt.Errorf("audit: sandbox process source %q is not registered", input.Source)
	}
	if input.PID <= 0 || input.PID > maxSandboxPID {
		return fmt.Errorf("audit: sandbox process id %d is out of range", input.PID)
	}
	parent := optionalSandboxPID(input.ParentPID)
	exitCode := observability.Absent[int64]()
	if input.ExitCode != nil {
		exitCode = observability.Present(int64(*input.ExitCode))
	}
	lineage := observability.Absent[[]string]()
	if len(input.Lineage) > 0 {
		names := make([]string, 0, min(len(input.Lineage), maxSandboxProcessLineage))
		for _, name := range input.Lineage[:min(len(input.Lineage), maxSandboxProcessLineage)] {
			if text, ok := optionalSandboxText(name, maxSandboxProcessLineageID).Get(); ok {
				names = append(names, text)
			}
		}
		if len(names) > 0 {
			lineage = observability.Present(names)
		}
	}
	fields := sandboxV8FieldsFor(identity)
	event := recorder.newEvent(ctx, ActionSandboxProcess, identity, identity.Name, "INFO", input.Timestamp)
	conversationID, _ := sandboxAgentCorrelation(event, input.ConversationID)
	log := sandboxV8Log{
		action: ActionSandboxProcess, event: event, bucket: observability.BucketAgentLifecycle,
		eventName: observability.TelemetryEventSandboxProcessTree, phase: "process",
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxProcessTree(observability.LogSandboxProcessTreeInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: identity.Name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:               fields.bindingID,
				DefenseClawSandboxProcessEvent:            input.Event,
				DefenseClawSandboxProcessPid:              int64(input.PID),
				DefenseClawSandboxProcessSource:           optionalSandboxEnum(input.Source),
				DefenseClawSandboxProcessParentPid:        parent,
				DefenseClawSandboxProcessName:             optionalSandboxText(input.Name, maxSandboxProcessName),
				DefenseClawSandboxProcessExecutable:       optionalSandboxText(input.Executable, maxSandboxPathBytes),
				DefenseClawSandboxProcessCommandLine:      optionalSandboxText(input.CommandLine, maxSandboxCommandLineBytes),
				DefenseClawSandboxProcessWorkingDirectory: optionalSandboxText(input.WorkingDirectory, maxSandboxPathBytes),
				DefenseClawSandboxProcessExitCode:         exitCode,
				DefenseClawSandboxProcessLineage:          lineage,
				UserID:                                    optionalNetworkIdentifier(input.UserID),
				DefenseClawUserIDKind:                     optionalNetworkUserIDKind(useridentity.KindForID(input.UserID)),
				DefenseClawUserName:                       optionalNetworkIdentifier(input.UserName),
				GenAIConversationID:                       conversationID,
			})
		},
	}
	return recorder.emit(ctx, log, nil)
}
