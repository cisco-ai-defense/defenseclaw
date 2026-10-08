// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// The words of every enterprise.tetragon warning and problem: one table, so
// status, verify, the lifecycle and the troubleshooting page say the same
// thing. Every message is "<what happened> (<impact>); <next step>", the
// lifecycle's message shape, and its next step is copy-paste ready:
//
//   - root commands carry sudo and the package path: the binaries are not on
//     PATH, and sudo resets PATH (adminCommand, helperCommand);
//   - config changes name the YAML path and say "in the admin config and
//     apply it": managed local writers refuse a `config set`;
//   - Tetragon changes are the exact tetragon.conf.d write plus the restart,
//     which drops policies added with tetra.
//
// TestTetragonHintsAreRunnable checks every command in every message;
// TestEveryTetragonCodeHasText that every code has an entry here, and
// TestEveryTetragonCodeIsDocumented that each is on the troubleshooting page.

// adminBinDir is where the Linux enterprise packages install the binaries.
var adminBinDir = func() string {
	if layout, err := managed.StandaloneLayoutFor("linux"); err == nil && layout.BinDir != "" {
		return layout.BinDir
	}
	return "/opt/defenseclaw/bin"
}()

// adminCommand is a defenseclaw-gateway command as root pastes it:
// sudo /opt/defenseclaw/bin/defenseclaw-gateway <args>.
func adminCommand(args ...string) string {
	return strings.Join(append([]string{"sudo", path.Join(adminBinDir, binGateway)}, args...), " ")
}

// helperCommand is a defenseclaw-sensor-helper command as root pastes it.
func helperCommand(args ...string) string {
	return strings.Join(append([]string{"sudo", path.Join(adminBinDir, binSensorHelper)}, args...), " ")
}

// tetragonConfDir is Tetragon's drop-in directory: one file per flag, named
// for the flag. DefenseClaw never writes there; the administrator does.
const tetragonConfDir = "/etc/tetragon/tetragon.conf.d"

// tetragonSetting is the command that sets one Tetragon flag.
func tetragonSetting(flag, value string) string {
	return "echo " + value + " | sudo tee " + tetragonConfDir + "/" + flag
}

// tetragonRestartNote is what every restart of Tetragon must say.
const tetragonRestartNote = "this drops policies added with tetra; tetragon.tp.d policies reload"

// tetragonRestart is the restart step in prose.
func tetragonRestart() string {
	return literal("sudo systemctl restart tetragon") + " (" + tetragonRestartNote + ")"
}

// literal quotes a command or a YAML assignment.
func literal(text string) string { return "`" + text + "`" }

// adminConfig is a config change as an administrator makes it on a managed
// host: in the admin config, applied by config management.
func adminConfig(assignments ...string) string {
	quoted := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		quoted = append(quoted, literal(assignment))
	}
	return "set " + strings.Join(quoted, " and ") + " in the admin config and apply it"
}

// Codes the lifecycle itself raises (the helper's are in kernelpolicy).
const (
	// codeKernelPolicyOrphaned names DefenseClaw policies that may still be
	// loaded in Tetragon with nothing reconciling them. verify fails on it;
	// an uninstall or rollback that could not remove them warns with it.
	codeKernelPolicyOrphaned = "kernel_policy_orphaned"
	// codeKernelStateUnreadable says the helper's state files could not be
	// read.
	codeKernelStateUnreadable = "kernel_state_unreadable"
	// codeKernelPolicyNotApplied says the sensor helper runs another control
	// set or intent than this deployment renders: it did not restart into it.
	codeKernelPolicyNotApplied = "kernel_policy_not_applied"
	// codeTetragonTCPAPI is the helper's reason for never dialling a Tetragon
	// that serves its API on TCP.
	codeTetragonTCPAPI = "tetragon_tcp_api"
	// codeTetragonUntrusted is the helper's reason for refusing an endpoint
	// that is not root-owned or is writable by others.
	codeTetragonUntrusted = "tetragon_untrusted_endpoint"
	// codeEnrollmentUnreadable is the helper's warning when it cannot read
	// or trust targets.yaml and keeps its last enrollment.
	codeEnrollmentUnreadable = "enrollment_unreadable"
	// codeCustomerEventsCapped is the helper's warning when a customer
	// policy's events from AI agents went over the per-policy budget in the
	// last hour (item 1).
	codeCustomerEventsCapped = "tetragon_customer_events_capped"
)

// Variants of the codes that have more than one message.
const (
	variantNoAnchors   = "no_anchors"
	variantNoReadyUser = "no_ready_user"
	variantDigest      = "digest"
	variantMode        = "mode"
	variantNotInSync   = "not_in_sync"
	variantGeneration  = "generation"
	variantNotRunning  = "not_running"
	variantRetired     = "retired"
	variantLeft        = "left"
	variantUnreadable  = "unreadable"
	variantState       = "state"
	variantFallback    = "fallback"
	variantInfo        = "info"
)

// tetragonFacts are the values a message names. Each code reads the ones it
// needs; the zero value of each reads as "not known".
type tetragonFacts struct {
	// Variant picks one of a code's messages.
	Variant string
	// Detail is the part of a helper warning after "code:" (a connector, a
	// family, a policy, a variable), or the helper's reason text.
	Detail string
	// Mode is the mode the deployment renders; Applied what the helper runs
	// or applies (a mode or a digest).
	Mode, Applied string
	// Digest is this build's kernel_policy; Ack the approval as rendered.
	Digest, Ack string
	// Address, Path, Owner and Perm describe Tetragon's endpoint.
	Address, Path, Owner, Perm string
	Version                    string
	// Pause and PauseInvalid describe a pause; SetBy names who set it.
	Pause        *kernelpolicy.Pause
	PauseInvalid string
	SetBy        string
	// At is when an operator changed a family; Verb what they did.
	At   time.Time
	Verb string
	// Names are policy names; Users and Connectors those a message lists.
	Names, Users, Connectors []string
	Count                    int
	// State and Error describe a policy.
	State, Error string
	// ETA is when the next user is ready, in words.
	ETA string
	// Why says what the lifecycle was doing.
	Why string
}

// tetragonCodeText is one code: its doctor spelling (when doctor reports it
// too) and its message.
type tetragonCodeText struct {
	// Doctor is the hyphenated reason code doctor uses for the same
	// condition, if any.
	Doctor string
	// Problem marks a code verify fails on (DefenseClaw-owned state only).
	Problem bool
	// Variants lists the Variant values the message reads ("" is the
	// default), for the tests.
	Variants []string
	Message  func(f tetragonFacts) string
}

var (
	gwVerifyEnforce = literal(adminCommand("enterprise", "linux", "tetragon", "verify", "--ready-for", "enforce"))
	gwResume        = literal(adminCommand("enterprise", "linux", "tetragon", "resume"))
	gwStatus        = literal(adminCommand("enterprise", "linux", "tetragon", "status"))
	gwEnsure        = literal(adminCommand("enterprise", "linux", "ensure"))
	gwRepair        = literal(adminCommand("enterprise", "linux", "repair"))
	gwVerify        = literal(adminCommand("enterprise", "linux", "verify"))
	helperCleanup   = literal(helperCommand("--tetragon-cleanup"))
	helperStart     = literal("sudo systemctl start defenseclaw-sensor-helper")
	helperRestart   = literal("sudo systemctl restart defenseclaw-sensor-helper")
	helperJournal   = literal("sudo journalctl -u defenseclaw-sensor-helper -n 50")
	tetragonJournal = literal("sudo journalctl -u tetragon -n 50")
	nativePlaneC    = "Plane C uses cn_proc and fanotify"
)

// tetragonCodes is the code table (SPEC-TETRAGON-UX 5.7).
var tetragonCodes = map[string]tetragonCodeText{
	kernelpolicy.WarnTetragonUnavailable: {Doctor: "tetragon-unavailable", Message: func(f tetragonFacts) string {
		return "Tetragon is not reachable from the sensor helper" + parenthesized(f.Detail) +
			" (" + nativePlaneC + "; no kernel control is enforced); check it with " + literal("systemctl status tetragon") +
			" and start it with " + literal("sudo systemctl start tetragon")
	}},
	codeTetragonTCPAPI: {Doctor: "tetragon-tcp-api", Message: func(f tetragonFacts) string {
		return "Tetragon serves its API on " + defaultStr(f.Address, "a TCP address") + ", which any local account can use to load kernel policies" +
			" (the sensor helper never dials it: " + nativePlaneC + ", and observe and enforce are refused); run " +
			literal(tetragonSetting("server-address", "unix:///var/run/tetragon/tetragon.sock")) + ", then " + tetragonRestart()
	}},
	codeTetragonUntrusted: {Variants: []string{"", variantInfo}, Message: func(f tetragonFacts) string {
		next := "; restore its owner and mode, or run " + tetragonRestart() + " so Tetragon recreates the socket"
		if f.Path == "" {
			return "the sensor helper does not trust Tetragon's endpoint" + parenthesized(f.Detail) +
				" (it does not connect: " + nativePlaneC + ")" + next
		}
		found := ""
		if f.Owner != "" && f.Perm != "" {
			found = " (found owner " + f.Owner + ", mode " + f.Perm + ")"
		}
		return f.Path + " must be owned by root and not writable by others" + found +
			" (the sensor helper does not connect: " + nativePlaneC + ")" + next
	}},
	kernelpolicy.WarnUnsupportedVersion: {Variants: []string{"", variantFallback}, Message: func(f tetragonFacts) string {
		impact := "no DefenseClaw policy is loaded; the sensor helper reads Tetragon's events"
		if f.Variant == variantFallback {
			impact = nativePlaneC
		}
		version := strings.TrimSpace("Tetragon " + f.Version)
		return version + " is not supported for " + defaultStr(f.Mode, "this mode") +
			" (consume: 1.6 and 1.7; observe and enforce: 1.7) (" + impact +
			"); install Tetragon 1.7.x, or keep mode consume on 1.6. A later DefenseClaw release adds newer Tetragon versions"
	}},
	kernelpolicy.WarnPersistentSensors: {Message: func(tetragonFacts) string {
		return "Tetragon runs with keep-sensors-on-exit on, or its config cannot be read" +
			" (enforce stays in monitor mode: stopping Tetragon would leave programs enforcing with nobody updating them); run " +
			literal(tetragonSetting("keep-sensors-on-exit", "false")) + ", then " + tetragonRestart() +
			", then remove leftover pins under /sys/fs/bpf/tetragon"
	}},
	config.TetragonReasonPlaneCOff: {Doctor: "tetragon-plane-c-off", Message: func(f tetragonFacts) string {
		return "enterprise.tetragon.mode is " + defaultStr(f.Mode, "set") + ", but AI Discovery Plane C is off" +
			" (the sensor helper runs with Tetragon off); " +
			adminConfig("ai_discovery.runtime.enabled: true", "ai_discovery.runtime.enable_host_plane: true")
	}},
	config.TetragonReasonNotApplicable: {Message: func(tetragonFacts) string {
		return "enterprise.tetragon is set, but Tetragon runs only on Linux (this host ignores the block);" +
			" remove enterprise.tetragon from this OS's config to silence it"
	}},
	kernelpolicy.WarnForeignName: {Message: func(f tetragonFacts) string {
		return "Tetragon has a policy named " + defaultStr(f.Detail, "defenseclaw-...") +
			" in DefenseClaw's name pattern that the sensor helper did not load" +
			" (DefenseClaw treats it as yours and never changes it); rename it if the name is confusing"
	}},
	kernelpolicy.WarnConfigInvalid: {Message: func(f tetragonFacts) string {
		return "the sensor helper ignored a malformed " + defaultStr(f.Detail, "value") +
			" in its drop-in (it used the safe default); run " + gwRepair
	}},
	kernelpolicy.ReasonIdentityUnknown: {Message: func(tetragonFacts) string {
		return "Tetragon's pid is not known from " + tetragonInfoPath + " (nothing is loaded); run " + tetragonRestart() +
			" so it rewrites the file"
	}},
	codeCustomerEventsCapped: {Message: func(f tetragonFacts) string {
		what := "Events"
		if f.Count > 0 {
			what = fmt.Sprintf("%d events", f.Count)
		}
		return what + " of your Tetragon policy " + defaultStr(f.Detail, "") + " were not forwarded in the last hour" +
			" (over the per-policy limit of 20/s; the counts stay exact); nothing to do, or " +
			adminConfig("enterprise.tetragon.customer_events: off")
	}},
	kernelpolicy.WarnEnforceAckMissing: {Message: func(f tetragonFacts) string {
		return "enterprise.tetragon.mode is enforce, but enforce_ack is empty (the kernel controls stay in monitor mode); review " +
			gwVerifyEnforce + ", then " + adminConfig("enterprise.tetragon.enforce_ack: "+f.Digest)
	}},
	kernelpolicy.WarnEnforceAckStale: {Message: func(f tetragonFacts) string {
		ring := "[" + strings.ReplaceAll(f.Ack, ",", ", ") + ", " + f.Digest + "]"
		return "enforce_ack " + defaultStr(f.Ack, "(empty)") + " does not include this build's " + f.Digest +
			" (the controls changed in this release; every user is in monitor mode); review the release notes and " +
			gwVerifyEnforce + ", then " + adminConfig("enterprise.tetragon.enforce_ack: "+f.Digest) +
			", or to " + literal("enterprise.tetragon.enforce_ack: "+ring) + " while the ring upgrades"
	}},
	kernelpolicy.WarnGuardrailObserve: {Message: func(f tetragonFacts) string {
		connector := defaultStr(f.Detail, "<connector>")
		return "the " + connector + " guardrail is not in action mode (its agents are observed, not enforced, by the kernel controls);" +
			" to deny for it, " + adminConfig("guardrail.connectors."+connector+".mode: action") + ", or leave it monitor-only"
	}},
	kernelpolicy.WarnEnforcePaused: {Doctor: "kernel-enforce-paused", Message: func(f tetragonFacts) string {
		until, by := "until the next reboot", ""
		if p := f.Pause; p != nil {
			if !p.UntilReboot {
				until = "until " + p.Until.UTC().Format(time.RFC3339)
			}
			by = " (set by " + defaultStr(f.SetBy, fmt.Sprintf("uid %d", p.SetByUID)) + " at " + p.SetAt.UTC().Format(time.RFC3339) + pauseReason(p) + ")"
		}
		return "kernel enforcement on this host is paused " + until + by + " (every user on this host is in monitor mode); resume with " + gwResume
	}},
	kernelpolicy.WarnPauseInvalid: {Message: func(f tetragonFacts) string {
		return "a pause file is present but not trusted or not readable" + parenthesized(f.PauseInvalid) +
			" (kernel enforcement stays paused for every user on this host); remove it with " + gwResume
	}},
	kernelpolicy.WarnEnforceInactive: {Variants: []string{"", variantNoAnchors, variantNoReadyUser}, Message: func(f tetragonFacts) string {
		if f.Variant == variantNoReadyUser {
			eta := "burn-in accrues while their agents run"
			if f.ETA != "" {
				eta = "the next user is ready in " + f.ETA + " at the current rate"
			}
			return "no user has finished burn-in yet (nothing is denied yet); nothing to do: " + eta
		}
		var who []string
		if len(f.Users) > 0 {
			who = append(who, "no agent installed for "+strings.Join(f.Users, ", "))
		}
		if len(f.Connectors) > 0 {
			who = append(who, "no enrolled user has a row for "+strings.Join(f.Connectors, ", "))
		}
		detail := ""
		if len(who) > 0 {
			detail = ": " + strings.Join(who, "; ")
		}
		return "no enrolled user has an anchored command-line agent (nothing can be denied" + detail +
			"); install a command-line agent for an enrolled user, or enroll a user who runs one"
	}},
	kernelpolicy.WarnBurnInSkipped: {Message: func(tetragonFacts) string {
		return "enterprise.tetragon.burn_in is 0 (users are enforced without a measured burn-in); " +
			adminConfig("enterprise.tetragon.burn_in: 24h") + " (or more) to measure first"
	}},
	kernelpolicy.WarnOperatorOverride: {Message: func(f tetragonFacts) string {
		at := ""
		if !f.At.IsZero() {
			at = " at " + f.At.UTC().Format(time.RFC3339)
		}
		return "an operator " + defaultStr(f.Verb, "changed") + " the " + defaultStr(f.Detail, "") + " policy in Tetragon" + at +
			" (the sensor helper does not undo it); to hand it back to DefenseClaw, change enterprise.tetragon.enforce_ack or" +
			" enterprise.tetragon.mode in the admin config and apply it"
	}},
	codeKernelPolicyNotApplied: {Doctor: "kernel-policy-not-applied", Variants: []string{variantDigest, variantMode, variantNotInSync, variantGeneration}, Message: func(f tetragonFacts) string {
		next := "; run " + gwEnsure + " so the helper restarts with this build's controls"
		switch f.Variant {
		case variantMode:
			return "the sensor helper runs Tetragon mode " + f.Applied + ", but the deployment renders " + f.Mode +
				" (it did not restart into the current drop-in)" + next
		case variantNotInSync:
			return "the sensor helper's last pass did not leave Tetragon with the policies enterprise.tetragon calls for" +
				" (they stay in or move to monitor mode until a pass succeeds); see " + gwStatus + ", then run " + gwEnsure +
				" so the helper restarts with this build's controls"
		case variantGeneration:
			return "the sensor helper applies kernel policy " + f.Applied + ", but the gateway's policy generation has " + f.Digest +
				" (the helper did not restart into this build)" + next
		}
		return "the sensor helper applies control set " + f.Applied + ", but this build ships " + f.Digest +
			" (it did not restart into this build)" + next
	}},
	kernelpolicy.WarnRootsOverLimit: {Message: func(f tetragonFacts) string {
		return defaultStr(f.Detail, "some") + fmt.Sprintf(" live agent processes are over the %d-pid anchor limit", kernelpolicy.MaxPIDs) +
			" (they are observed, not enforced); nothing to do, the count is reported"
	}},
	kernelpolicy.WarnPIDMonitorOnly: {Message: func(tetragonFacts) string {
		return "agent sessions matched only by their process id, such as a script-hosted agent run by node, are monitored in enforce mode" +
			" (a process id can be reused between two passes, so it never denies; only a native agent binary is a deny anchor);" +
			" nothing to do: their would-block hits are still counted, and the Tetragon guide lists this limit"
	}},
	kernelpolicy.WarnSessionsPredateControls: {Message: func(f tetragonFacts) string {
		return defaultStr(f.Detail, "some") + " agent session(s) of enforced users started before the kernel controls loaded" +
			" (Tetragon marks an agent's processes when the agent starts, so these are monitored, not denied);" +
			" restart them to be denied: after enforce starts, and after a Tetragon restart. " + gwStatus + " lists them" +
			" under Observed, not enforced"
	}},
	kernelpolicy.WarnBinaryScopeLimited: {Message: func(tetragonFacts) string {
		return "more than one user of a controls policy has a native agent install" +
			" (in enforce it denies for one of them, the lowest uid; the others stay in monitor mode);" +
			" nothing to do: their would-block hits are still counted, and the Tetragon guide lists this limit"
	}},
	kernelpolicy.WarnReconcileFailed: {Message: func(tetragonFacts) string {
		return "the sensor helper's last pass failed (policies stay in or move to monitor mode); see the ERROR column of " + gwStatus +
			" and " + helperJournal
	}},
	kernelpolicy.WarnLSMUnavailable: {Message: func(tetragonFacts) string {
		return "BPF LSM is off on this kernel (the controls cannot deny); add bpf to the kernel's lsm= boot parameter and reboot" +
			" (see the Tetragon guide)"
	}},
	codeKernelStateUnreadable: {Message: func(f tetragonFacts) string {
		return "could not read the sensor helper's Tetragon state" + prefixed(": ", f.Error) + " (status shows the defaults); run " +
			helperRestart + "; if it persists, check that " + kernelpolicy.DefaultStateDir + " is root-owned with mode 0700"
	}},
	codeEnrollmentUnreadable: {Message: func(tetragonFacts) string {
		return "the sensor helper cannot read targets.yaml, or does not trust it (it keeps its last enrollment); run " + gwRepair
	}},
	codeKernelPolicyOrphaned: {Doctor: "kernel-policy-orphaned", Problem: true, Variants: []string{variantNotRunning, variantRetired, variantLeft, variantUnreadable}, Message: func(f tetragonFacts) string {
		names := strings.Join(f.Names, ", ")
		switch f.Variant {
		case variantRetired:
			return "enterprise.tetragon.mode is " + f.Mode + ", but DefenseClaw's Tetragon policies " + names +
				" are still recorded as loaded after the sensor helper's retire step (nothing reconciles them); remove them with " +
				helperCleanup + ", then run " + gwVerify
		case variantLeft:
			return f.Why + "; DefenseClaw's Tetragon policies " + names + " may still be loaded with no sensor helper to manage them" +
				" (their names stay in " + path.Join(kernelpolicy.DefaultStateDir, "tetragon-loaded") + ", so a sensor helper installed later removes them);" +
				" delete each with " + literal("sudo tetra tracingpolicy delete <name>") + ", or run " + tetragonRestart()
		case variantUnreadable:
			return "could not read the sensor helper's record of the Tetragon policies it loaded" + prefixed(": ", f.Error) +
				" (DefenseClaw's policies may still be loaded); check that " + kernelpolicy.DefaultStateDir +
				" is root-owned with mode 0700, then run " + gwVerify
		}
		return "the sensor helper is not running (DefenseClaw's Tetragon policies " + names +
			" may be loaded with frozen anchors and nothing reconciling them); start it with " + helperStart +
			", or remove them with " + helperCleanup + ", then run " + gwVerify
	}},
	kernelpolicy.WarnPolicyLoadError: {Problem: true, Variants: []string{"", variantState}, Message: func(f tetragonFacts) string {
		what := "DefenseClaw's Tetragon policy " + f.Detail + " did not load"
		if f.Variant == variantState {
			what = "DefenseClaw's Tetragon policy " + f.Detail + " is in state " + f.State + ": " + defaultStr(f.Error, "no error reported")
		}
		return what + " (its controls stay in monitor mode or do not run); check Tetragon's journal (" + tetragonJournal +
			"), then run " + helperRestart
	}},
}

// tetragonMessage is the text of code (with or without a ":detail" suffix).
// A code without an entry, which only a newer helper can report, prints as
// the helper wrote it.
func tetragonMessage(fullCode string, f tetragonFacts) string {
	base, detail, _ := strings.Cut(fullCode, ":")
	if f.Detail == "" {
		f.Detail = strings.TrimSpace(detail)
	}
	if entry, ok := tetragonCodes[base]; ok {
		return entry.Message(f)
	}
	return fullCode + " (reported by the sensor helper); see " + gwStatus
}

// observedReasonWords say why an agent session is observed, not enforced.
var observedReasonWords = map[string]string{
	kernelpolicy.ReasonIDEHosted:        "an IDE terminal",
	kernelpolicy.ReasonHeuristicRoot:    "looks like an agent by name only",
	kernelpolicy.ReasonNotEnrolled:      "user not enrolled",
	kernelpolicy.ReasonGuardrailObserve: "connector in observe mode",
	kernelpolicy.ReasonPredatesControls: "started before the kernel controls loaded; restart it to be denied",
}

// observedReason is the reason in words with the code in parentheses.
func observedReason(reason string) string {
	if words, ok := observedReasonWords[reason]; ok {
		return words + " (" + reason + ")"
	}
	return reason
}

// monitorReasonWords say why a user stays in monitor mode.
var monitorReasonWords = map[string]string{
	"observe mode":                      "mode observe",
	kernelpolicy.WarnEnforceAckMissing:  "enforce_ack is empty",
	kernelpolicy.WarnEnforceAckStale:    "enforce_ack is for another build",
	kernelpolicy.WarnPersistentSensors:  "Tetragon keeps sensors on exit",
	kernelpolicy.WarnEnforcePaused:      "paused",
	kernelpolicy.ReasonGuardrailObserve: "connector in observe mode",
	kernelpolicy.WarnPIDMonitorOnly:     "no native agent binary (a process id never denies)",
	kernelpolicy.WarnBinaryScopeLimited: "another user's native agent holds the one deny anchor",
	kernelpolicy.WarnPolicyLoadError:    "the controls policy did not load in Tetragon",
	kernelpolicy.WarnPolicyNotApplied:   "the controls policy is not in enforce mode yet",
}
