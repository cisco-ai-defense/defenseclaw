// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

type setupLaunchRejection string

const (
	setupLaunchAllowed        setupLaunchRejection = ""
	setupLaunchProbeFailed    setupLaunchRejection = "probe_failed"
	setupLaunchService        setupLaunchRejection = "service_identity"
	setupLaunchSessionZero    setupLaunchRejection = "session_zero"
	setupLaunchElevated       setupLaunchRejection = "elevated"
	setupLaunchNonInteractive setupLaunchRejection = "non_interactive"
)

// setupLaunchFacts contains only read-only facts about the process token and
// desktop. Keeping policy evaluation independent of Win32 calls makes every
// rejected launch mode deterministic and exhaustively testable.
type setupLaunchFacts struct {
	Elevated                 bool
	ServiceIdentity          bool
	SessionID                uint32
	InteractiveToken         bool
	InteractiveWindowStation bool
	DialogSafe               bool
}

type setupLaunchDecision struct {
	Reason      setupLaunchRejection
	AllowDialog bool
}

func decideSetupLaunchContext(facts setupLaunchFacts) setupLaunchDecision {
	dialog := facts.DialogSafe && !facts.ServiceIdentity && facts.SessionID != 0 &&
		facts.InteractiveToken && facts.InteractiveWindowStation
	switch {
	case facts.ServiceIdentity:
		return setupLaunchDecision{Reason: setupLaunchService, AllowDialog: dialog}
	case facts.SessionID == 0:
		return setupLaunchDecision{Reason: setupLaunchSessionZero}
	case facts.Elevated:
		return setupLaunchDecision{Reason: setupLaunchElevated, AllowDialog: dialog}
	case !facts.InteractiveToken || !facts.InteractiveWindowStation:
		return setupLaunchDecision{Reason: setupLaunchNonInteractive}
	default:
		return setupLaunchDecision{Reason: setupLaunchAllowed}
	}
}

type setupLaunchContextError struct {
	Decision setupLaunchDecision
	Cause    error
}

func (err *setupLaunchContextError) Error() string {
	var guidance string
	switch err.Decision.Reason {
	case setupLaunchProbeFailed:
		guidance = "could not verify the current-user interactive launch context"
	case setupLaunchService:
		guidance = "cannot run as LocalSystem, LocalService, NetworkService, or from a Windows service"
	case setupLaunchSessionZero:
		guidance = "cannot run in Windows session zero"
	case setupLaunchElevated:
		guidance = "must run without administrator elevation; close this copy and start Setup normally (do not use Run as administrator)"
	case setupLaunchNonInteractive:
		guidance = "requires the signed-in user's interactive Windows desktop and cannot run from a background or batch context"
	default:
		guidance = "was rejected because its launch context is unsupported"
	}
	message := "DefenseClaw Setup " + guidance + ". No system or user settings were changed."
	if err.Cause != nil {
		return fmt.Sprintf("%s Context check: %v", message, err.Cause)
	}
	return message
}

func (err *setupLaunchContextError) Unwrap() error { return err.Cause }

var inspectCurrentSetupLaunchContext = probeSetupLaunchContext

func requireCurrentUserInteractiveSetup() error {
	facts, err := inspectCurrentSetupLaunchContext()
	if err != nil {
		return &setupLaunchContextError{
			Decision: setupLaunchDecision{Reason: setupLaunchProbeFailed, AllowDialog: facts.DialogSafe},
			Cause:    err,
		}
	}
	decision := decideSetupLaunchContext(facts)
	if decision.Reason == setupLaunchAllowed {
		return nil
	}
	return &setupLaunchContextError{Decision: decision}
}
