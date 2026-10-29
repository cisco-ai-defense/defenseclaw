// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"strings"
)

// hermesBlocksFailures reports a Hermes pre_tool_call whose native hook
// blocks when DefenseClaw cannot check it (hermesFailsClosed). Hermes has no
// fail-closed hook contract of its own (failOpenOnly: a timeout, a spawn
// error or an empty answer lets the call run), but it blocks a tool call
// whose hook prints its block directive, so the native hook prints that
// directive whenever it cannot get a verdict, as the Linux and macOS shell
// hook does in fail mode closed. The installed Windows command binds no
// event: it comes from the payload, so an invocation whose event is unknown
// (input too large or unreadable before the event was read, a payload that
// names none) may be a tool call and blocks too. Every other named Hermes
// event keeps the neutral result.
func hermesBlocksFailures(opts Options, sp spec) bool {
	return sp.connector == "hermes" && hermesFailsClosed(opts) && hermesToolCallEvent(opts.Event)
}

// hermesToolCallEvent reports a Hermes pre_tool_call, or an invocation whose
// event is unknown and so may be one.
func hermesToolCallEvent(event string) bool {
	event = strings.TrimSpace(event)
	return event == "" || strings.EqualFold(event, "pre_tool_call")
}

// hermesFailsClosed reports a Hermes hook that fails closed. A Secure Client
// hook keeps Hermes' upstream fail-open. Every other hook, managed standalone
// (rel-1-0-2 GAP-0423) and per-user alike, fails closed unless its fail mode
// is explicitly open (a standalone hook's is the administrator's, owner
// decision 2026-10-20), so a fail mode that is closed or not set blocks a
// tool call during a gateway outage on Windows as on Linux and macOS
// (rel-1-0-3 GAP-0269, GAP-0150). Strict availability closes it too.
func hermesFailsClosed(opts Options) bool {
	if opts.ManagedEnterprise && !managedNativeDecision(opts) {
		return false
	}
	return opts.StrictAvailability || !strings.EqualFold(strings.TrimSpace(opts.FailMode), "open")
}

// managedHermesPrefixEvent names the event of a Hermes invocation whose input
// was refused before its event was resolved, from the top-level fields of the
// bounded prefix the hook read (payloadPrefixFields), with resolveHookEvent's
// rule: two fields that disagree name no event. An empty result keeps the
// invocation a possible tool call (hermesBlocksFailures).
func managedHermesPrefixEvent(opts Options, sp spec, prefix []byte) string {
	if sp.connector != "hermes" || strings.TrimSpace(opts.Event) != "" {
		return opts.Event
	}
	fields := payloadPrefixFields(prefix)
	event, _ := pickHookEvent(fields["hook_event_name"], fields["event"])
	return event
}

// managedHermesEventConflictReason is the logged reason of a Hermes
// invocation whose input names two different events (rel-1-0-3 GAP-0202).
const managedHermesEventConflictReason = "hook input names two different events"

// failHermesEventConflict blocks a Hermes invocation that fails closed
// (hermesBlocksFailures) whose installed command binds no event and whose
// input names two different events: it may be a tool call, and which event
// it is cannot be told, so the hook prints the Hermes block directive and
// logs fail_mode closed (rel-1-0-3 GAP-0202). The gateway is not asked: its
// verdict would be for an event Hermes may not be running.
func failHermesEventConflict(opts Options, sp spec) int {
	logHookFailure(opts, sp, managedHermesEventConflictReason, "response", "closed", true)
	code, _ := hermesFailClosed(opts, sp, "input", managedHermesEventConflictReason)
	return code
}

// managedHermesAnswerUsable reports whether a gateway answer without a
// hook_output directive is a verdict a Hermes tool call that fails closed
// (hermesBlocksFailures) may run on:
// an allow, an advisory alert, or a confirm (Hermes has no ask; the gateway
// records the downgraded finding). A block needs its directive, and a
// missing or unknown action is no verdict.
func managedHermesAnswerUsable(action string) bool {
	switch action {
	case "allow", "alert", "confirm":
		return true
	}
	return false
}

// hermesFailClosed blocks a Hermes tool call DefenseClaw could not check
// (hermesBlocksFailures) with Hermes' native block directive and a plain
// text for layer, so Hermes says why: for example that the DefenseClaw
// gateway service is not running (a managed hook,
// managedStandaloneFailClosedText) or that this account's gateway is not
// running and how to start it (a per-user hook, perUserFailClosedText).
// handled is false for every other invocation.
func hermesFailClosed(opts Options, sp spec, layer, reason string) (int, bool) {
	if !hermesBlocksFailures(opts, sp) {
		return 0, false
	}
	if strings.TrimSpace(opts.Event) == "" {
		// An unknown event blocks as a possible tool call; say so.
		opts.Event = "pre_tool_call"
	}
	if !opts.ManagedEnterprise {
		fmt.Fprintf(opts.Stderr, "defenseclaw: blocking %s (fail mode closed): %s\n", sp.subject, reason)
		fmt.Fprintln(opts.Stdout, `{"action":"block","message":`+mustJSONString(perUserFailClosedText(opts, layer, reason))+`}`)
		return 0, true
	}
	text := managedFailClosedText(opts, layer, reason)
	switch reason {
	case managedSIDUnregisteredReason, managedEnrollmentPendingReason:
		text = "DefenseClaw blocked this tool call: " + unenrolledAccountExplanation + "."
	case managedUIDUnregisteredReason:
		text = "DefenseClaw blocked this tool call: " + unixUnenrolledAccountExplanation + "."
	case managedRootDeniedReason:
		text = "DefenseClaw blocked this tool call: " + rootDeniedExplanation + "."
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking managed %s (fail mode closed): %s\n", sp.subject, reason)
	fmt.Fprintln(opts.Stdout, `{"action":"block","message":`+mustJSONString(text)+`}`)
	return 0, true
}

// perUserFailClosedText is what a per-user Hermes or Copilot hook that fails
// closed shows as the reason the tool call did not run: why, in plain words,
// and the next step, as hermes-hook.sh does on Linux and macOS
// (hermes_block_message).
func perUserFailClosedText(opts Options, layer, reason string) string {
	const lead = "DefenseClaw blocked this tool call: "
	switch layer {
	case "oversized":
		return lead + "it is too large for DefenseClaw to inspect. Make it smaller and try again."
	case "input":
		return lead + "its hook input names two different events, so DefenseClaw cannot tell what to check. " +
			"Run `defenseclaw doctor` to see why."
	case "response":
		if opts.gatewayRefusal != "" {
			return opts.gatewayRefusal
		}
		return lead + "the DefenseClaw gateway returned an answer DefenseClaw could not use. " +
			"Run `defenseclaw doctor` to see why."
	}
	if text := perUserGatewayDownText(opts, reason); text != "" {
		return text
	}
	return lead + "the DefenseClaw gateway is not available (fail mode closed). " +
		"Run `defenseclaw doctor` to see why, then try again."
}

// failOpenOnlyCloses reports whether a connector without a fail-closed hook
// contract (failOpenOnly) still blocks this failed invocation: a Copilot tool
// call or permission request of a managed hook or of a per-user hook that
// fails closed (copilotFailClosed), or a Hermes tool call that fails closed
// (hermesBlocksFailures). The hook-failure log
// records that outcome, not the configured fail mode, so a call that ran
// fail-open is reported as one (rel-1-0-2 GAP-0446).
func failOpenOnlyCloses(opts Options, sp spec) bool {
	switch sp.connector {
	case "copilot":
		if !opts.ManagedEnterprise {
			return perUserCopilotFailsClosed(opts, sp) && (opts.Event == "preToolUse" || opts.Event == "permissionRequest")
		}
		if sp.dialect == copilotVSCodeLocalSurface {
			return copilotVSCodeLocalOutput(opts.Event, "block", failedClosed) != ""
		}
		return opts.Event == "preToolUse" || opts.Event == "permissionRequest"
	case "hermes":
		return hermesBlocksFailures(opts, sp)
	}
	return false
}

// loggedFailMode is the fail mode a hook-failure line records: the outcome
// for a failOpenOnly connector (failOpenOnlyCloses, except an open Secure
// Client Copilot hook, managedCopilotOpen), the given one otherwise.
func loggedFailMode(opts Options, sp spec, failMode string) string {
	if !sp.failOpenOnly {
		return failMode
	}
	if failOpenOnlyCloses(opts, sp) && !managedCopilotOpen(opts, sp, failMode) {
		return "closed"
	}
	return "open"
}
