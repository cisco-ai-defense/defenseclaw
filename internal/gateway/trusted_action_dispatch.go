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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	osuser "os/user"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/pattern"
	"mvdan.cc/sh/v3/syntax"
)

// trustedActionDispatchMaxCost bounds the semantic rules' total CEL cost per
// action (each program also has its own cost limit), for one profile and for
// a strictest combination of profiles alike (trustedActionBudget). The bound
// is on cost, not wall-clock time: a 50 ms deadline here skipped every
// semantic rule left when a loaded host stalled the gateway, so a CRITICAL
// command rule only alerted and the call ran (GAP-2140). The caller's
// context still cancels the evaluation. A variable only so tests can lower it.
var trustedActionDispatchMaxCost = uint64(24_000_000)

// trustedActionBudget is the semantic CEL cost one action has used. The
// members of a strictest combination of profiles share one
// (newTrustedActionBudget(true)): together they cost no more than one
// profile, and an expression several members have is judged once on each
// view of the action (evals), so overlapping packs do not spend the budget
// twice. A judged expression stays usable once the budget is spent: it costs
// nothing more, so a member whose rule another member already judged keeps
// its finding however much the members before it spent. A rule the budget
// does not reach keeps its fallback lane, as in one profile, and a
// combination that reaches it says so once (noteMeetBudget).
type trustedActionBudget struct {
	consumed uint64
	reached  bool
	evals    map[trustedActionEvalKey]trustedActionEval
}

// trustedActionEvalKey is one expression on one projection of the action:
// view 0 is the judged view, 1 its enforcement projection, 2 and 3 the same
// for the PowerShell body view.
type trustedActionEvalKey struct {
	expression string
	view       int
}

type trustedActionEval struct {
	result semantic.Result
	code   semantic.EvalCode
}

// newTrustedActionBudget is an empty budget; shared is set for the members of
// a strictest combination, which judge a shared expression once.
func newTrustedActionBudget(shared bool) *trustedActionBudget {
	budget := &trustedActionBudget{}
	if shared {
		budget.evals = make(map[trustedActionEvalKey]trustedActionEval)
	}
	return budget
}

// spent reports whether the budget leaves no cost for another evaluation.
func (b *trustedActionBudget) spent() bool {
	done := b.consumed >= trustedActionDispatchMaxCost
	b.reached = b.reached || done
	return done
}

// judged reports whether candidate's expression has a result on the view
// numbered view that costs nothing more (a shared budget's evals).
func (b *trustedActionBudget) judged(candidate compiledSemanticRule, view int) bool {
	_, ok := b.evals[trustedActionEvalKey{expression: candidate.rule.Expression, view: view}]
	return ok
}

// eval judges candidate on projection, the view numbered view
// (trustedActionEvalKey), and charges its cost; for a shared budget once per
// expression and view, also after the budget is spent. ok is false when the
// budget had no cost left for a new evaluation or the new evaluation went
// past it: then the rule was not judged within the budget. A shared budget
// keeps that last result too, already paid for, for the members after.
func (b *trustedActionBudget) eval(ctx context.Context, candidate compiledSemanticRule, view int, projection *semanticpb.Facts) (result semantic.Result, code semantic.EvalCode, ok bool) {
	key := trustedActionEvalKey{expression: candidate.rule.Expression, view: view}
	if hit, cached := b.evals[key]; cached {
		return hit.result, hit.code, true
	}
	if b.spent() {
		return semantic.Result{}, code, false
	}
	result, code = candidate.program.EvalBool(ctx, projection)
	b.consumed += result.Cost
	if b.evals != nil && code == semantic.EvalOK {
		b.evals[key] = trustedActionEval{result: result, code: code}
	}
	if b.consumed > trustedActionDispatchMaxCost {
		b.reached = true
		return semantic.Result{}, code, false
	}
	return result, code, true
}

// noteMeetBudget says once per combination that its members' semantic rules
// of one action reached the budget, so rules past it were judged by their
// fallback lanes only.
func noteMeetBudget(generation *compiledRulePackCategories, budget *trustedActionBudget) {
	if generation == nil || generation.budgetNote == nil || budget == nil || !budget.reached {
		return
	}
	generation.budgetNote.Do(func() {
		fmt.Fprintf(os.Stderr, "[guardrail] strictest combination of profiles: the semantic rules of one action reached their cost budget (%d); the rules past it were judged by their fallback patterns\n",
			trustedActionDispatchMaxCost)
	})
}

// trustedActionRequest is private so a remote payload cannot assert that an
// arbitrary body is a trusted or enforcement-capable action. Only adapters
// that have already established a typed server-side boundary construct it.
type trustedActionRequest struct {
	Input              actionfacts.Input
	LegacyText         string
	Connector          string
	EnforcementCapable bool
	// StrictPolicy grades an unverifiable extra argument as a block.
	StrictPolicy bool
	// sessionID is the connector's session of the call, for the checks that
	// follow a session across calls (the page a browser tool has open).
	sessionID string
	// ManagedInstall is set for a call judged by a managed enterprise install:
	// content the rules could not prove is judged as the strict tier judges it,
	// because a managed device fails closed.
	ManagedInstall             bool
	UnknownKeyPossibleOverflow bool
	// hostTwinDepth is the number of wrapper layers the call's parents used
	// reading it as a script (actionfacts.HostScriptReadings): one budget for a
	// call however its twins nest.
	hostTwinDepth int
	// hostTwinListed: the call is a statement, or a run of statements, of a
	// list already read one by one.
	hostTwinListed bool
	// hostScriptTwinOff turns the script reading off, so a test can compare a
	// call's findings with and without it (TestHostScriptTwinOnlyAddsFindings).
	// Production requests never set it.
	hostScriptTwinOff bool
	// windowsTwinHosts, on a Windows reading twin (windowsReadingTwinRequests),
	// holds the script readings its call judges itself, which the twin leaves
	// out (judgedHostReadings, rel-1-0-10:GAP-1316).
	windowsTwinHosts *windowsTwinHostReadings
	// ArtifactBody is set when LegacyText and Input.Command are the whole
	// body of a script the call runs (the artifact lane): its comments and
	// data are not tool-call text, so a migrated literal rule must match a
	// word the parse took from an executed command (GAP-1513).
	ArtifactBody bool
	// conflictSource is the tool call's argument object before a connector
	// projection took arguments out of Input.Args, for the conflicting-keys
	// check (conflictingToolArgumentKeys); nil when Input.Args is the object
	// the call carried.
	conflictSource *conflictingToolArgumentSource
	// capFloor is the cap floor of the hook call (withCapFloor), shared by
	// the call and its piece twins; capFloorSeen marks a request whose
	// floor is already registered (every other twin of it inherits that),
	// and capFloorDepth counts the piece twins above it.
	capFloor      *capFloorState
	capFloorSeen  bool
	capFloorDepth int
	// DowngradeReadOnlyDataArgs is advisory-only. Bare executable names and
	// PowerShell cmdlets are not runtime-attested, so Action-mode adapters must
	// leave this false even when the argv shape is a static reader.
	DowngradeReadOnlyDataArgs bool
	// operandBounded marks the bounded reading of a call over the operand
	// bound (operandBoundDispatch): it is judged once, not bounded again.
	operandBounded bool
	// statementBounded marks the statement-bounded reading of a call
	// (operandBoundDispatch). It only adds findings to the reading judged
	// before it, which has no path facts for the long statement, so an
	// operand the client map leaves out does not fail it closed.
	statementBounded bool
	// A sandbox action may execute in a filesystem the gateway cannot see.
	SkipLocalFilesystemResolution bool
	// CopilotSharedLocalFile marks an exact file call decoded from a Local
	// body in the per-user CLI document. Its direct protected read has the same
	// file-action authority as its lexical path.
	CopilotSharedLocalFile bool
	// ProtectedHomeHook is set only from a kernel-verified managed hook peer.
	// Its gateway cannot inspect the caller's home when ProtectHome is active.
	ProtectedHomeHook bool
	// ManagedHookOverflowHold retains a bounded state reading on an
	// authenticated managed Windows hook without changing path resolution.
	ManagedHookOverflowHold bool
	// gitBashDrive marks a gitBashDriveView request (GAP-2577).
	gitBashDrive bool
	// staticOperandReading marks a DynamicOperandTwins reading judged behind
	// ProtectHome: for an operand the call as written left unknown in the
	// hook client map, the answer of the reading
	// (hookpaths.ReadingTargetPrefix) decides (GAP-2477).
	staticOperandReading bool
	// localLinkTwin marks the reading of a shell call with the words a link
	// moves spelled as their places (localCommandLinkTwinRequest).
	localLinkTwin bool
	// hereStringPipeReading marks the printf WORD | CMD reading of a bash
	// here-string (hereStringStateMutation). The call it reads got its own
	// any-program wrapper twin, which is read the same way; inside this
	// reading a read that the walk left as a pipe binds in a subshell, so
	// unwrapping a call next to it (command echo IFS=x) would prove a write
	// through the value the read replaces (rel-1-0-10:GAP-1083, GAP-1246).
	hereStringPipeReading bool
	// hereStringTwinsJudged leaves out the here-string readings
	// (hereStringReadingTwinRequest, hereStringStateMutation) of a wrapper
	// twin whose parent has a here-string reading twin: the parent's twin
	// printf WORD | sudo tee F has the wrapper twin printf WORD | tee F,
	// which is this twin's here-string reading, so each was judged twice,
	// and sudo tee F <<< WORD cost about 10 times ls (rel-1-0-10:GAP-1472).
	hereStringTwinsJudged bool
	// ResolvedWriteTargets comes from the hook running as the real user.
	// A present empty map means the client inspected the action and found no
	// static write target; nil denotes missing or invalid client evidence.
	ResolvedWriteTargets map[string]string
	// ShellStartup is the shell startup of the agent's process, from the
	// hook client's header (nil: an older client; the gateway's own).
	ShellStartup *hookpaths.ShellStartup
	// ActiveAgentFileIdentities maps the hook client's file identity of each
	// instruction file the session loaded to that file, for a gateway that
	// cannot read it (hookpaths.LoadedIdentityPrefix).
	ActiveAgentFileIdentities map[string]string // loaded file -> identity
	// Hermes' native patch parser can reinterpret a symlink target containing
	// a line break as another file directive. Its write views require the
	// narrower patch-target proof, including in guest-directory views.
	patchTarget bool
	// strictPatchLinks is set for a patch target judged in the strict policy
	// tier: a target the managed hook resolved through a link is not trusted
	// there (hermesClientPatchTarget).
	strictPatchLinks bool
	// Sandbox absolute targets are guest names; their host-directory views
	// carry the filesystem proof.
	patchHostView   bool
	record          func(actionfacts.Facts, []RuleFinding)
	recordTelemetry func(trustedActionTelemetry)
	// recordEffectShadow receives the answer of the live shadow run of the
	// effect lane (guardrail.cascade.lanes.effects=shadow). Only the hook route sets it;
	// the dispatch takes it once, at the outermost call, and clears it so a
	// twin or child request never runs the lane again.
	recordEffectShadow func(EffectShadowResult)
	// Prevent recursive standalone evaluation of an already flattened command.
	simpleCommandPass bool
	// stateProofOnly limits the judgment to the rule that proves a write to
	// DefenseClaw state: a LoginGuess reading of a simple command keeps only
	// that proof (loginGuessProvedFinding), so no other rule needs to run.
	stateProofOnly bool
	// unplacedStatement marks a simple command of a sandbox call that the
	// walk placed in no folder (SimpleCommand.UnresolvedFolder): it is judged
	// unplaced, as on the laptop, so the guest placement of the call alone
	// reads it in the guest's directories (sandboxGuestPlacedInput).
	unplacedStatement bool
	// sendDestination marks the routing values of a message call, where its
	// text is sent (ToolInspectRequest.sendDestination): the call is a send
	// whatever the tool is named (trustedActionSendsMessage).
	sendDestination bool
	// overBudgetOmission, when set, is told that the authorized-keys proof
	// found only an operand that the client's bounded map left out because
	// it was full (hookpaths.BudgetKey, GAP-0146).
	overBudgetOmission *bool
	// unresolvedTarget, when set, is told that the authorized-keys proof
	// failed closed on an operand the managed hook client could not
	// resolve (an empty map value: an unreadable folder, a link loop) and
	// this gateway cannot resolve either (rel-1-0-2:GAP-0690).
	unresolvedTarget *bool
	// resolvedTarget, when set, is told that the code-owned target walk
	// confirmed a protected file rather than conservatively holding an
	// unresolved write.
	resolvedTarget *bool
	// unprovenTarget, when set, is told the class (hookpaths.UnprovenWriteTitle)
	// and the operand of an authorized-keys proof that held a write whose
	// target it could not resolve, rather than a protected file it found
	// (rel-1-0-10:GAP-0013). The operand is empty when no one operand was
	// at fault (a directory walk or a pattern the shell expands).
	unprovenTarget *unprovenWrite
	// nonWriteMention, when set, is told that the target scan held the call
	// only on words of statements that read a protected file, in a per-user
	// default or permissive install (ActionMentionsNoWriteRole): the finding
	// alerts, it does not block (rel-1-0-10:GAP-0018).
	nonWriteMention *bool
	// unknownMention, when set, is told that the target scan held the call
	// only on words of reader statements beside a program, pipe stage or
	// named sink it has no write model of (ActionMentionsNoKnownWrite): the
	// key finding alerts and the shared unknown-tier finding decides
	// (rel-1-0-10:GAP-0843).
	unknownMention *bool
	// evidenceCWD places a simple command whose cwd the gateway cannot see
	// (ProtectHome) where the managed hook client keyed its evidence: the
	// client's cwd followed through the command's static cd.
	evidenceCWD string
	// cwdPlacedRoot is the folder the hook ran a simple command of the call
	// from, when the walk read the command in another folder (after a cd):
	// the owners that place a path by the working folder itself
	// (cwdPlacedRule: the active .git/hooks of the project) place it by this
	// folder, as they do when the whole call is read (rel-1-0-10:GAP-1083).
	cwdPlacedRoot string
	// parentPatch is the whole shell call of a simple-command child. A stage
	// such as the apply_patch of @'...'@ | apply_patch reads an envelope that
	// only the whole text shows: when every apply_patch of that text reads a
	// literal envelope (hookpaths.ApplyPatchWriteTargets known), the child is
	// judged on those directive targets, not as a file-fed patch.
	parentPatch *actionfacts.Input
	// SandboxGuestCWD is a sandbox call's working directory in the guest's
	// namespace (sandboxHookGuestCWD); Input.CWD is its host mount. Only
	// the authorized-keys proofs and the guest reading
	// (sandboxGuestPlacedInput) read it, and only to add findings.
	SandboxGuestCWD string
	// guestToolCWDUnresolved marks a supplied workdir that the guest path
	// resolver cannot place. It must not fall back to the guest home.
	guestToolCWDUnresolved bool
	// sandboxGuest marks a call of an authenticated sandbox request
	// (isSandboxHookRequest), set once by dispatchTrustedActionOnce: it runs
	// in a Linux guest, so a walk this gateway cannot make on the guest's
	// files places its folders by the Linux guest layout, whatever OS the
	// gateway runs on (rel-1-0-10:GAP-2203).
	sandboxGuest bool
	// guestKeyReadCommand is the shell command a Substrate actor's kit
	// proved reads the actor's SSH private key in the actor's file system
	// (substrateGuestClaims): the private-key read proof of a request that
	// judges exactly that command holds (substrate-1 GAP-0471).
	guestKeyReadCommand string
	// guestProtectedWriteCommand is the shell command the kit's run of the
	// laptop's protected-target decision (hookpaths.ActionCommandDecision)
	// found writes a protected file in the actor's file system
	// (trustedExistingAuthorizedKeysSymlinkWrite, substrate-1 GAP-0471).
	guestProtectedWriteCommand string
	// guestLinkTwin marks the twin of a file-tool call whose path arguments
	// the kit resolved through a link (substrateGuestLinkTwinRequest).
	guestLinkTwin bool
	// guestCommandTwin marks the twin of a shell call whose path words the
	// kit placed through a link (substrateGuestCommandTwinRequests).
	guestCommandTwin bool
	// guestClaimHomePlaces reads, from a Substrate actor's kit facts, which
	// places of the actor's home only their owner can reach; nil without
	// such facts. guestHomePlaces is the view the home copy checks read:
	// nil (this host's file system) except on the command twin and where
	// only a kit claim holds a finding (homePlaceView, substrate-1
	// GAP-0549). guestWriteClaimOnly receives whether the kit's protected
	// write claim alone holds a key write.
	guestClaimHomePlaces homePlaceView
	guestHomePlaces      homePlaceView
	guestWriteClaimOnly  *bool
	// guestByNameOnly receives whether only the by-name reading of a
	// copy-mode actor's call in its guest folder (copyModeWholeCallByName)
	// found the protected target (substrate-1 GAP-0922).
	guestByNameOnly *bool
	// byNameGuestCWD is the guest folder of a copy-mode actor's call, for
	// the by-name reading (copyModeByNameGuestCWD); "" for every other call.
	// The outermost dispatch sets it, so every hook path (Claude Code,
	// Codex and the shared agent hook) gets it (substrate-1 GAP-0993).
	byNameGuestCWD string
	// windowsShellDialect is set when Input.DialectHint is inferred from
	// the call's command (agentHookWindowsShellDialect, Windows host hooks):
	// a command judged on its own (inspectSandboxShellToolPolicyCtx) then
	// has its hint inferred again from that command (GAP-0686).
	windowsShellDialect bool
	// windowsDialectReadings is set by the Windows hooks, which choose one shell
	// dialect per call: a call whose PowerShell reading is partial is also judged
	// as its readable statements (windowsReadingTwinRequests), never as another
	// shell.
	windowsDialectReadings bool
	// windowsPowerShellReading is the PowerShell reading the hook's dialect
	// selection made of a call it placed in no dialect; the readings above
	// reuse it instead of parsing the call again. nil: none.
	windowsPowerShellReading *windowsHintedReading
	// readingTwin marks a request that is itself one of those readings.
	readingTwin bool
	// posixReadingTwin is a Windows-dialect call of a shell tool that does
	// not name its shell (agy run_command): it is also judged in the POSIX
	// reading it had before the Windows dialect, and what that reading
	// proves is kept (posixReadingTwinRequest, rel-1-0-10:GAP-0850).
	posixReadingTwin bool
	// launcherDepth is the number of shell launchers whose body this request
	// reads (launcherBodyTwinRequest), bounded by maxLauncherBodyDepth.
	launcherDepth int
	// generation is the rule generation the call is judged with; nil: the
	// request profile's (snapshotRulePackGenerationFor). A caller that
	// combines several dispatches of one request judges each with each
	// member's generation of a strictest combination of profiles
	// (promotedArtifactFindings).
	generation *compiledRulePackCategories
	// budget is the semantic cost budget the call is judged within; nil: a
	// new one. The dispatches of the members of a strictest combination of
	// profiles for one action share one (trustedActionBudget).
	budget *trustedActionBudget
	// targetMemo keeps the hook path readers' file system answers for the
	// whole evaluation: the call, its twins and its simple-command passes
	// (hookpaths.TargetMemo, rel-1-0-2:GAP-0568). dispatchTrustedAction
	// makes it; a copy of the request shares it.
	targetMemo *hookpaths.TargetMemo
	// simpleMemo keeps the simple commands of the call, read once for the
	// statement budget and again for the pass of every profile member over the
	// same input and facts. dispatchTrustedAction makes it; a copy of the
	// request shares it, and a child command with another input reads its own.
	simpleMemo *trustedSimpleMemo
	// guestMemo keeps the guest placement of the call (guestReadingMemo):
	// the placed children, the split-gap reading and the sandbox hook-config
	// guard read the same guest input. A copy of the request shares it.
	guestMemo *guestReadingMemo
	// inlineTierNested marks a request derived from one already dispatched:
	// only the outermost call applies the inline hand-off tier
	// (withInlineHandoffTier).
	inlineTierNested bool
	// skipRunTimeShellTwin leaves out the run-time shell reading
	// (runTimeShellTwinRequest) of this request and the requests derived from
	// it. The here-string probe of the state mutation proof sets it: the
	// reading of the call itself judges the shell script of the here-string
	// once, the probe asks only whether the script reaches state, and the
	// reading of its pipe twin was the same script judged a second time
	// (rel-1-0-10:GAP-1088). The here-string reading twin sets it when the
	// call has a run-time shell reading of its own: printf WORD | bash -c
	// TEXT judged the script that bash -c TEXT judges already, and
	// bash <<< 'defenseclaw-gateway stop' cost about 12 times ls
	// (rel-1-0-10:GAP-1472).
	skipRunTimeShellTwin bool
}

// trustedSimpleMemo holds the first simple-command split asked of it.
type trustedSimpleMemo struct {
	mu      sync.Mutex
	set     bool
	input   actionfacts.Input
	facts   actionfacts.Facts
	simples []actionfacts.SimpleCommand
}

// commands returns actionfacts.SimpleCommands(input, facts): the split the memo
// holds when input and facts are the ones it was made for, a fresh one
// otherwise. The first split asked of an empty memo is kept.
func (memo *trustedSimpleMemo) commands(input actionfacts.Input, facts actionfacts.Facts) (simples []actionfacts.SimpleCommand) {
	if trustedSimpleCommandsFaultHook != nil {
		// Test-only seam (like hookEvaluatorPanicHook): a reader failure on
		// the hook route is judged as SimpleCommands answers it.
		defer func() {
			if recover() != nil {
				simples = []actionfacts.SimpleCommand{{EvaluationFailure: actionfacts.EvaluationFailureInternal}}
			}
		}()
		trustedSimpleCommandsFaultHook()
	}
	if memo == nil {
		return actionfacts.SimpleCommands(input, facts)
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if memo.set {
		if reflect.DeepEqual(memo.input, input) && reflect.DeepEqual(memo.facts, facts) {
			return slices.Clone(memo.simples)
		}
		return actionfacts.SimpleCommands(input, facts)
	}
	memo.set, memo.input, memo.facts = true, input, facts
	memo.simples = actionfacts.SimpleCommands(input, facts)
	return slices.Clone(memo.simples)
}

// trustedSimpleCommandsFaultHook is a test-only seam: when non-nil it runs
// before the per-command split, so a route test can make the reader fail.
// Production never sets it.
var trustedSimpleCommandsFaultHook func()

// trustedActionTelemetry is value-free dispatch telemetry. It deliberately
// carries counts only: raw shell text, argv, matched rule IDs, paths, and
// network destinations must never leave the trusted action boundary through
// this channel.
type trustedActionTelemetry struct {
	ParserUncertaintyCount              int64
	ParserUncertaintyCatalogMatchCount  int64
	ParserUncertaintyShadowFindingCount int64
}

func (t *trustedActionTelemetry) merge(other trustedActionTelemetry) {
	t.ParserUncertaintyCount += other.ParserUncertaintyCount
	t.ParserUncertaintyCatalogMatchCount += other.ParserUncertaintyCatalogMatchCount
	t.ParserUncertaintyShadowFindingCount += other.ParserUncertaintyShadowFindingCount
}

// widen raises each count of t to other's where that is larger: a call
// judged with the rules of several generations counts its parse once.
func (t *trustedActionTelemetry) widen(other trustedActionTelemetry) {
	t.ParserUncertaintyCount = max(t.ParserUncertaintyCount, other.ParserUncertaintyCount)
	t.ParserUncertaintyCatalogMatchCount = max(t.ParserUncertaintyCatalogMatchCount, other.ParserUncertaintyCatalogMatchCount)
	t.ParserUncertaintyShadowFindingCount = max(t.ParserUncertaintyShadowFindingCount, other.ParserUncertaintyShadowFindingCount)
}

func (t trustedActionTelemetry) empty() bool {
	return t.ParserUncertaintyCount == 0 &&
		t.ParserUncertaintyCatalogMatchCount == 0 &&
		t.ParserUncertaintyShadowFindingCount == 0
}

// dispatchTrustedActionOnce judges request; dispatchTrustedAction is it
// through the hook call's memo (trustedDispatchMemo).
func dispatchTrustedActionOnce(
	parent context.Context,
	request trustedActionRequest,
) (findings []RuleFinding) {
	// One wait for walk slots per hook request: the hook route puts it on
	// ctx (withHookWalkBudget), so the calls of a Copilot envelope, the
	// members of an artifact and the readings of a shell command, each its
	// own top-level dispatch, draw on one wait. A dispatch that comes with
	// none makes its own for the call; the twins and simple-command passes
	// below copy the request, so they share it (substrate-1:GAP-1083).
	if request.Input.CredentialWalkBudget == nil {
		request.Input.CredentialWalkBudget = hookWalkBudgetFrom(parent)
	}
	if request.Input.CredentialWalkBudget == nil {
		request.Input.CredentialWalkBudget = actionfacts.NewCredentialWalkBudget(parent)
	}
	request = windowsStatementsOnePerLine(request)
	request.sandboxGuest = request.sandboxGuest || isSandboxHookRequest(parent)
	// A call judged as the twin of its data word leaves a detection-only
	// record of the word (rel-1-0-10:GAP-0382). It is added last, after every
	// other defer, so a limit finding any of them raises is kept as it is and
	// the record never stands in for it.
	var unreadDataWord bool
	defer func() {
		if unreadDataWord {
			findings = withPosixDataWordRecord(findings)
		}
	}()
	// A DefenseClaw state write that only a partial reading proves is at
	// least the unknown tier, never a clean allow: judged after every other
	// reading and twin, so a proven block keeps its verdict
	// (rel-1-0-10:GAP-0892).
	defer func() { findings = withPartialStateWriteFloor(request, findings) }()
	// One dispatch is one hook call whichever surface carries the action (the
	// hook request, an ACP frame, a direct evaluation): the file system reads
	// of its reach scans are remembered for the decision (hookpaths.HookCall;
	// nested in the handler's own call, or in a twin of this dispatch, it
	// begins nothing more, rel-1-0-10:GAP-0766).
	defer hookpaths.HookCall()()
	defer func() { findings = markShellProtectedFileFindings(request, findings) }()
	defer recoverTrustedActionFault(request, &findings)
	// A call whose shell the tool does not name is judged in the POSIX
	// reading too, before any bound below decides the call: a credential
	// operand the POSIX reading proves past the argv bound kept its block
	// there, and the PowerShell reading left it at the unknown tier
	// (rel-1-0-10:GAP-0850). The twins made below never repeat it.
	if twin, ok := posixReadingTwinRequest(request); ok {
		defer func() {
			findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	request.posixReadingTwin = false
	if request.byNameGuestCWD == "" {
		request.byNameGuestCWD = copyModeByNameGuestCWD(parent, request)
	}
	if claims := substrateGuestClaimsFrom(parent); claims != nil {
		// A Substrate actor's kit proved, in the actor's file system, what the
		// laptop's gateway proves in its own (substrate-1 GAP-0471): a
		// private-key read of the call's command, the link targets of its
		// path arguments, and which places of the home are private
		// (GAP-0549). All only add findings; the command twin is judged in
		// trustedToolCallFindings (GAP-0546).
		request.guestKeyReadCommand = claims.keyReadCommand
		request.guestProtectedWriteCommand = claims.protectedWriteCommand
		request.guestClaimHomePlaces = claims.homePlaceView()
		if twin, ok := substrateGuestLinkTwinRequest(parent, request); ok {
			defer func() {
				findings = withOverLimitTwinFindings(findings, dispatchTrustedAction(parent, twin))
			}()
		}
	}
	if trustedActionFaultHook != nil {
		trustedActionFaultHook(request)
	}
	// The hand-off tier is for the call's final findings only: a twin or a
	// simple-command pass inside it is a proof the outer call reads as proven.
	if !request.inlineTierNested {
		request.inlineTierNested = true // every twin and pass below is a copy of this request
		defer func() { findings = withInlineHandoffTier(parent, request, findings) }()
	}
	parent, endOpenedPaths := withOpenedPathScope(parent)
	defer endOpenedPaths()
	// Effect-model rule lane (S7). Compute once at the outermost dispatch.
	// In ON the verdict participates; in shadow/off nothing is appended, so
	// the live answer is unchanged. The benchmark measures shadow through
	// EvaluateDeterministicAction, not here.
	if octx, outermost := markOutermostEffectDispatch(parent); outermost {
		parent = octx
		switch mode := effectsRulesModeFor(); mode {
		case effectRulesOn:
			effectRequest := request
			defer func() {
				findings = append(findings, effectShadowFindings(computeEffectShadow(effectRequest, mode, effectsRulesTierFor()), mode)...)
			}()
		case effectRulesShadow:
			// Shadow: compute and record beside today's rules, off the hook's
			// path and verdict-neutral (effect_shadow_live.go, GAP-0256).
			scheduleEffectShadow(request, mode, effectsRulesTierFor(), request.recordEffectShadow)
		}
		request.recordEffectShadow = nil
		// Secret flow tracking (S7). It keeps a bounded per-session state and
		// alerts (default) or blocks (strict/managed) when a labeled secret
		// reaches an external sink. Shadow records the hit and never changes the
		// answer; the lane runs at most once per call.
		fctx := parent
		freq := request
		defer func() {
			findings = append(findings, runSecretFlowShadow(fctx, freq)...)
		}()
	}
	if _, ok := managedHookPeerFromContext(parent); ok {
		request.ProtectedHomeHook = true
	}
	// A call the shell parser failed on (the hook client's evidence, or the
	// same reading here) blocks in every pack, with its own reason, before
	// any bound or reader decides (rel-1-0-10:GAP-0486). The readers still
	// run: a finding of theirs stays on the verdict.
	shellReason := trustedCallShellParseReason(request)
	if shellReason == hookpaths.UnprovenParserFault {
		defer func() { findings = withParserFaultFinding(findings, request.EnforcementCapable) }()
	}
	if ManagedEnterpriseActive() && !isSubstrateActorRequest(parent) {
		return nil
	}
	// A script body the hook call kept unread because its network share
	// budget was spent is not a body that writes nothing: the strict tier
	// judges the call as one past the evaluation limit, the others alert
	// (shareBodyUnreadFindings, rel-1-0-6:GAP-0482). A managed gateway does
	// not open the user home: the hook client reads the bodies and reports
	// one it left unread in its evidence, which is judged the same way
	// (hookpaths.ShareBodyUnreadKey, rel-1-0-9:GAP-0950).
	defer func() {
		budget, linkBound := hookpaths.ShareBodyUnreadCauses()
		clientBudget, clientLinkBound := hookpaths.ClientShareBodyUnread(request.ResolvedWriteTargets)
		budget, linkBound = budget || clientBudget, linkBound || clientLinkBound
		if budget || linkBound {
			findings = shareBodyUnreadFindings(parent, findings, request.EnforcementCapable, budget, linkBound)
		}
	}()
	if request.targetMemo == nil {
		request.targetMemo = hookpaths.NewTargetMemo()
	}
	if request.ShellStartup != nil {
		request.targetMemo.WithShellStartup(request.ShellStartup)
	}
	// A backup file of sed -i or perl -i the readers cannot resolve is a
	// path target past what they judge: at least the unknown tier
	// (rel-1-0-10:GAP-0540).
	defer func() { findings = sedBackupUnresolvedFindings(request, findings) }()
	if request.simpleMemo == nil {
		request.simpleMemo = &trustedSimpleMemo{}
	}
	if request.guestMemo == nil {
		request.guestMemo = &guestReadingMemo{}
	}
	request.Input.ActiveStateTreeNames = clientStateTreeNames(request.ResolvedWriteTargets)
	// Only the strict tier judges the body of a function the text never
	// calls; the other tiers follow the functions a call runs.
	request.Input.StraightLineFunctions = !request.StrictPolicy
	request.Input.ClientResolvedTargets = withLocalWriteAnswers(
		request, clientResolvedPathTargets(request.ResolvedWriteTargets),
		actionfacts.NativeFileWriteTargets(request.Input),
	)
	request.Input.ClientWorkingDirectories = clientWorkingDirectories(request.ResolvedWriteTargets, request.Input.CWD)
	// Only the strict tier follows code the shell may never run into a loop
	// binding; the other tiers follow the top-level statements before it.
	request.Input.LoopBindsStraightLine = !request.StrictPolicy
	request.Input.ClientNativeFileContents = withNativeEditFileContents(request)
	// analyzedCaps: the caps the action analysis below stopped at.
	var analyzedCaps bounded.CapSet
	// nestedBodies: the call is past the nested-body bound, which the owner
	// ruled is decided at once (GAP-0677): the cap floor judges only its
	// statements of at most capFloorPieceBytes, never its bodies.
	var nestedBodies bool
	if !request.capFloorSeen {
		// After every path below, the budget and limit paths included: a
		// block proven on a statement the cap did not take still decides
		// (withCapFloor, rel-1-0-10:GAP-0312, GAP-0360, GAP-0435, GAP-0381,
		// GAP-0532).
		request.capFloorSeen = true
		if request.capFloor == nil {
			request.capFloor = &capFloorState{}
		}
		floorRequest := request
		defer func() { findings = withCapFloor(parent, floorRequest, findings, analyzedCaps, nestedBodies) }()
	}
	bound := trustedActionCommandBound(request.Input)
	nestedBodies = bound == shellReadingNestedBodies
	if bound == shellReadingBudget {
		// Past the reading budget (shellparse.BudgetExceeded): no reader
		// below parses it, and the call is opaque to them. It takes the
		// over-limit path the profile decides, with the reason
		// parse_budget_exceeded, and keeps the one check that needs no
		// parse: a call whose text may name the active DefenseClaw state
		// is a possible write to it, which blocks in every mode and
		// profile, as the readers' proof of a state write did before the
		// budget refused to read the call (GAP-0254, GAP-0255, GAP-0281).
		return withPowerShellCapPieces(parent, request,
			withBudgetStateBlock(request, trustedActionBudgetFindings(request.EnforcementCapable)))
	}
	if bound == shellReadingTooDeep || bound == shellReadingNestedBodies {
		// Past the reading bounds: no reader below parses it, and the call
		// takes the over-limit path, which the profile decides (GAP-2537,
		// GAP-0677). It is decided before the recovered-parse reading
		// below, which would read the same bodies again for the same
		// finding.
		return withPowerShellCapPieces(parent, request, trustedActionLimitFindings(request.EnforcementCapable))
	}
	if request.EnforcementCapable && shellReason == "shell-parse-bound" {
		if !trustedCallReadsSyntaxTail(request) {
			return withPowerShellCapPieces(parent, request, trustedActionLimitFindings(true))
		}
		// A plain syntax error stops the recovering parse at its proof
		// bound too, but the statements that parse are read: they are
		// judged in full below, and the bound still decides the call at
		// least as the evaluation limit does (rel-1-0-10:GAP-0526).
		defer func() { findings = withTrustedActionLimitFinding(findings, true) }()
	}
	// A write operand the resolver read past its path bound is truncated
	// (bounded.Paths): what was read is judged below, and the bound rule
	// floors the call to the unknown tier of the pack (rel-1-0-10 GAP-0438).
	if caps := trustedResolverCaps(request); caps.Any() {
		defer func() { findings = withBoundedTruncation(findings, caps, request) }()
	}
	if bound == shellReadingNestedProof {
		// The readers below read it, but past this weight they do not prove
		// its protected targets: a call whose text may name one also gets
		// the evaluation-limit finding the profile decides.
		if trustedReadingBoundMayNameProtected(request) {
			defer func() { findings = withTrustedActionLimitFinding(findings, request.EnforcementCapable) }()
		}
	}
	if boundedFindings, handled := operandBoundDispatch(parent, request); handled {
		// A call past actionfacts.MaxOperandsPerCall operands is unresolved
		// (GAP-0943), and a statement of more argv words than the analysis
		// reads has no path facts (GAP-1069): operandBoundDispatch judges
		// the bounded readings. They are judged under this call's cap
		// floor, so the depth cap of the call's own analysis is this
		// call's: a wrapper chain past the analysis bound in a statement of
		// many words is TRUNCATED as in a short one, never a clean allow
		// (rel-1-0-10:GAP-0973). Its item and node caps are what the
		// bounded readings stand in for, so they are not taken.
		if !request.simpleCommandPass && capFloorAnalysisCaps(request.Input, actionfacts.Analyze(request.Input)).Has(bounded.Depth) {
			analyzedCaps = analyzedCaps.Union(bounded.Of(bounded.Depth))
		}
		return boundedFindings
	}
	var (
		facts     actionfacts.Facts
		analyzed  bool
		telemetry trustedActionTelemetry
	)
	if request.recordTelemetry != nil {
		defer func() {
			if !telemetry.empty() {
				request.recordTelemetry(telemetry)
			}
		}()
	}
	if request.record != nil {
		defer func() {
			if !analyzed {
				facts = actionfacts.Analyze(request.Input)
			}
			request.record(toolChainPlacedFacts(facts, request), findings)
		}()
	}
	if parent == nil {
		parent = context.Background()
	}
	if !request.simpleCommandPass {
		facts = analyzeWithPatchHeaderAnswers(&request)
		analyzed = true
		analyzedCaps = capFloorAnalysisCaps(request.Input, facts)
		// A write operand with a .. component whose walk cannot be resolved
		// has an unknown target: at least the unknown tier of the pack, what
		// the readers proved still deciding (the one bound rule, cap paths;
		// rel-1-0-10:GAP-1007).
		if trustedDotDotWalkUnresolved(request, facts) {
			defer func() { findings = withBoundedTruncation(findings, bounded.Of(bounded.Paths), request) }()
		}
		if trustedCallOverStatementBudgetWith(request.Input, facts, request.simpleMemo.commands(request.Input, facts)) {
			// Over the statement budget the call blocks with
			// ACTION-COMPOUND-LIMIT whatever its statements are, so it is
			// refused here, before the twins, the readers and the
			// per-statement passes run. Those cost about 4 ms per
			// statement on a Windows host and kept a 3000-statement call in
			// the gateway for 36 s, past the hook answer window
			// (rel-1-0-2:GAP-0568). The whole-call state check still runs:
			// observe mode allows the budget finding but hard-blocks a
			// proven write to the active state, and that proof is formed
			// only there (withOverBudgetStateMutation).
			// A call whose analysis also stopped at a byte bound names that cap
			// (GAP-0382); the finding is the same one. The statements at the start
			// and the end of a PowerShell call are also judged alone: a protected
			// write beside the padding that put the call past the budget keeps its
			// block (GAP-0693).
			return withPowerShellCapPieces(parent, request,
				withOverBudgetStateMutation(parent, request, facts,
					withBoundedTruncation(trustedActionLimitFindings(request.EnforcementCapable),
						posixParseTruncation(request, facts), request)))
		}
		if awkCommandDynamic(facts) && !awkDynamicBoundBySimpleCommands(request, facts) {
			// An awk command built at run time has no text to judge
			// (GAP-0499): the call is unknown, never an allow. A word built
			// only from a literal the call assigns before it is not: the
			// simple-command pass judges the awk call on its bound text.
			defer func() {
				findings = withAwkDynamicCommand(findings, request.EnforcementCapable)
			}()
		}
		defer func() {
			findings = withStaticFunctionStateMutation(parent, request, findings)
		}()
		if facts.Parse.Status == actionfacts.StatusLimitExceeded {
			// A PowerShell call the reading stopped at a cap of its own (a
			// nesting, word, statement or command cap, or the input bound)
			// keeps the blocks its first and last statements prove alone
			// (GAP-0693).
			defer func() { findings = withPowerShellCapPieces(parent, request, findings) }()
		}
		launcher := launcherBodyTwinRequest(request, facts)
		for _, twin := range launcher.twins {
			// The script of an argv shell launcher (powershell.exe -Command,
			// cmd /c) is judged as the string command the same script is
			// (rel-1-0-10:GAP-0711, GAP-0712): its findings count, the
			// TRUNCATED floor of its own cap among them. Each launcher the
			// call may run is judged (rel-1-0-10:GAP-0857).
			defer func() {
				findings = withOverLimitTwinFindings(findings, dispatchTrustedAction(parent, twin))
			}()
		}
		if launcher.depthCut {
			// A launcher nested past maxLauncherBodyDepth is not read: TRUNCATED
			// at the depth cap (the one bound rule, rel-1-0-10:GAP-0806).
			defer func() { findings = withBoundedTruncation(findings, bounded.Of(bounded.Depth), request) }()
		}
		if launcher.readingCut {
			// A wrapper chain with more launcher readings than the reader
			// judges, or one still open past the words it reads, has a
			// launcher reading no request judged: TRUNCATED (the one bound
			// rule, rel-1-0-10:GAP-0971). The readings judged, the last
			// launcher of the chain among them, still decide.
			defer func() { findings = withBoundedTruncation(findings, bounded.Of(bounded.Items), request) }()
		}
		if cut := trustedUndecodedCommandCut(request.Input, facts); cut.Any() {
			// A command array past the decode bound is read by nothing: the
			// call is TRUNCATED (the one bound rule, rel-1-0-10:GAP-0858).
			defer func() { findings = withUndecodedCommandTruncation(findings, cut, request) }()
		}
		// A script past the input bound is not read in full, so the bound of the argv
		// call still cuts it (rel-1-0-10:GAP-0712), and so do the words a POSIX -c
		// script runs as its arguments and long wrapper words (rel-1-0-10:GAP-0803).
		// An argv call the POSIX reading judges past its byte bound as the text of
		// its words (posixParseTruncation: a word in code position truncated, a data
		// word judged as its twin) keeps that reading, which is the finer floor: a
		// plain operand past 4 KiB of echo or dcx stays data, as in the text form
		// (rel-1-0-10:GAP-0689). The argv cut covers every other argv call.
		argvRead := launcher.read && launcher.fully ||
			posixByteBoundCommand(request, facts) != ""
		if cut := trustedReadingCut(request.Input, facts, argvRead); cut.Any() {
			// The reading of the call stopped at a cap of its own under the
			// statement budget: the call is TRUNCATED (the one bound rule),
			// never judged below the unknown tier of its pack, and what was
			// read still decides (trustedReadingCut).
			defer func() { findings = withBoundedTruncation(findings, cut, request) }()
			if facts.Parse.Dialect == actionfacts.DialectPowerShell && !request.readingTwin {
				// The statements of the call are also read in runs that fit
				// under the cap, so a block proven on a run keeps its own
				// verdict (actionfacts.PowerShellCappedRuns).
				for _, run := range actionfacts.PowerShellCappedRuns(request.Input, facts) {
					twin := windowsReadingTwin(request)
					twin.Input = run
					twin.LegacyText = run.Command
					defer func() {
						findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
					}()
				}
			}
		}
	}
	// A ~<active user> tilde-prefix names the active home from the password
	// database (GAP-2378), and under a Windows home an MSYS drive mount
	// (/c/...) names the drive path (GAP-2375): the twin with that spelling
	// is judged too, and a block proven there counts, as for the plain one.
	if twin, ok := homeSpellingTwinRequest(request, trustedActiveLogins(parent, request.Input.ActiveHome)...); ok {
		defer func() {
			findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	// A cp, mv, install, ln, dd or tee call with a runtime-expanded operand word has
	// a partial argv that ties no path to the call, so a literal destination
	// went unjudged (cp a.txt ~/.defenseclaw/config.yaml $(true), GAP-2477).
	// Each reading with static operands is one way the call can run, and a
	// block proven on one counts.
	for _, twin := range dynamicOperandTwinRequests(request) {
		defer func() {
			findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	// A pathname pattern under ~/.defenseclaw names the state files it
	// matches when the shell runs the call (cp a.txt ~/.defenseclaw/conf*.yaml,
	// GAP-2496); the reading with the matches is judged, and only its block
	// counts.
	if twin, ok := stateGlobTwinRequest(request); ok {
		defer func() {
			twinFindings := dispatchTrustedAction(parent, twin)
			if request.ProtectedHomeHook {
				// The named reading lists state names that may not exist,
				// and its other operands are not in the client map, which
				// was walked for the call as written: only its state-write
				// block counts there.
				twinFindings = slices.DeleteFunc(twinFindings, func(f RuleFinding) bool {
					return f.RuleID != "tamper.detector_state_write"
				})
			}
			findings = withTwinProvenBlocks(findings, twinFindings)
		}()
	}
	// A managed hook peer call that reaches the gateway without a cwd is also read
	// in the directory the hook client ran it in, as a per-user gateway
	// reads it; only a private-key read block of that reading counts
	// (GAP-0179).
	if twin, ok := protectedHomePrivateKeyTwinRequest(request); ok {
		defer func() {
			twinFindings := slices.DeleteFunc(dispatchTrustedAction(parent, twin), func(f RuleFinding) bool {
				return trustedActionFindingKey(f.RuleID) != "PATH-SSH-KEY"
			})
			findings = withTwinProvenBlocks(findings, twinFindings)
		}()
	}
	// The same reading judges a write of a shell startup profile spelled
	// relative to that directory (echo x >> .bashrc in the home, a function
	// that may return before its cd): only its shell-profile finding counts
	// (substrate-1:GAP-1090).
	if twin, ok := protectedHomeShellProfileTwinRequest(request); ok {
		defer func() {
			twinFindings := slices.DeleteFunc(dispatchTrustedAction(parent, twin), func(f RuleFinding) bool {
				return trustedActionFindingKey(f.RuleID) != trustedActionFindingKey(shellProfileWriteRule)
			})
			findings = withTwinProvenBlocks(findings, twinFindings)
		}()
	}
	// A file writer or a shell run through any static prefix wrapper
	// (nohup, nice, setsid, stdbuf, ionice, sudo, ...; or after a word that
	// may expand to nothing) writes what the plain call does (GAP-2512,
	// GAP-2519); the plain reading is judged, and only its block counts.
	// The here-string reading twin is asked here, before the wrapper twin is
	// made; request and facts do not change before it is judged below.
	hereStringTwin, hereStringTwinOK := hereStringReadingTwinRequest(request, facts)
	writerTwin, writerTwinOK := wrapperUnwrapTwinRequest(request, false)
	if writerTwinOK {
		writerTwin.hereStringTwinsJudged = writerTwin.hereStringTwinsJudged || hereStringTwinOK
		defer func() {
			findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, writerTwin))
		}()
	}
	// Any other program run that way writes or removes what the plain call
	// does too (find -delete, truncate, rm of the state behind setsid or
	// "$(echo nice)", rel-1-0-10:GAP-1186, GAP-1246), but the wrapped form
	// keeps its own verdict for every other rule: sudo curl stays outside the
	// exact curl sink grammar, command printf skips a function named printf,
	// and a leading "$X" or time would turn every rule of the call into a
	// second reading of it. Only a state-mutation block of that reading
	// counts.
	if twin, ok := wrapperUnwrapTwinRequest(request, true); ok &&
		(!writerTwinOK || twin.Input.Command != writerTwin.Input.Command) {
		defer func() {
			findings = withTwinProvenBlocks(findings, slices.DeleteFunc(dispatchTrustedAction(parent, twin), func(f RuleFinding) bool {
				return !wrappedStateMutationRule(f.RuleID)
			}))
		}()
	}
	// A shell named at run time ("$SHELL" -c TEXT, $BASH -ec TEXT, env
	// "$SHELL" -c TEXT, "$SHELL" <<< TEXT) runs TEXT as the literal shell
	// call does: that reading is judged too, and the stricter of the two
	// readings counts (rel-1-0-10:GAP-0980).
	var shellTwin trustedActionRequest
	var shellTwinOK, shellUnread bool
	var shellCaps bounded.CapSet
	if !request.skipRunTimeShellTwin {
		shellTwin, shellTwinOK, shellCaps, shellUnread = runTimeShellTwinRequest(request)
	}
	if shellTwinOK {
		defer func() {
			findings = withOverLimitTwinFindings(findings, dispatchTrustedAction(parent, shellTwin))
		}()
	}
	if shellUnread {
		// A shell runs here-document or here-string text the reading cannot
		// know (a body with a command substitution, a document handed on
		// through a command or a descriptor the reading does not follow):
		// what it runs is unknown, so the call is at least the unknown tier
		// (rel-1-0-10:GAP-1147).
		defer func() {
			findings = withUnknownFinding(findings, unknownReasonFinding(unreadShellTextTitle, unreadShellTextReason, request.EnforcementCapable))
		}()
	}
	if shellCaps.Any() {
		// A program word past the bounds of that reading (command
		// substitutions nested past its depth, more words than its budget)
		// is not read: the call is truncated (bound rule, rel-1-0-10:GAP-1041).
		defer func() {
			findings = withBoundedTruncation(findings, shellCaps, request)
		}()
	}
	// The commands an awk program starts through system(), print | and
	// | getline, written as string literals, are run by the shell as the
	// hook would run them directly (GAP-0499): that reading is judged too,
	// and only its block counts.
	twin, awkReading, awkTwin := awkCommandTwinRequest(request)
	awkCaps := awkReading.Truncated
	if awkTwin {
		defer func() {
			findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	if awkProgramFilesUnknown(request, awkReading) {
		// A program file the call runs could not be read, or starts a command
		// built at run time: the call is unknown (GAP-0499, GAP-0652).
		defer func() {
			findings = withAwkDynamicCommand(findings, request.EnforcementCapable)
		}()
	}
	if awkCaps.Any() {
		// An awk program in shell STRINGs nested past the bound is not read:
		// the call is truncated (bound rule, cap depth).
		defer func() {
			findings = withBoundedTruncation(findings, awkCaps, request)
		}()
	}

	if !analyzed {
		facts = analyzeWithPatchHeaderAnswers(&request)
		analyzed = true
	}
	facts = fileToolLinkTargetFacts(facts, request)
	// An apply_patch call whose envelope names a file by a spelling no reader
	// places (a home form the tool does not expand, a drive-relative path, a
	// device path) writes a file no path rule can name: it is judged at the
	// unknown tier of the pack at least, never a clean allow
	// (rel-1-0-10:GAP-1052, GAP-0947). Whatever the parse status: the placed
	// headers of the same envelope are facts the rules judge, and a block they
	// prove stays a block (rel-1-0-10:GAP-1055). The same envelope fed to
	// apply_patch by a shell here-document is judged as the tool's is
	// (rel-1-0-10:GAP-1077).
	if actionfacts.PatchNamesUnplacedTarget(request.Input.Tool, request.Input.Args) ||
		actionfacts.CommandPatchNamesUnplacedTarget(facts) {
		defer func() {
			findings = withUnknownFinding(findings, unknownReasonFinding(unplacedPatchTargetTitle,
				actionfacts.UnplacedPatchTargetReason, request.EnforcementCapable))
		}()
	}
	// A Windows call the tokenizer stopped reading at its input bound (one word
	// over the word limit) is truncated: judged as unknown at the pack's
	// unknown tier at least, never a clean allow (rel-1-0-10:GAP-0345). So is
	// a Windows host call past the command size (no dialect read) or under a
	// POSIX tool label, and a shell command too large to read at all
	// (actionfacts.TruncatedHostCall).
	if facts.Parse.Status == actionfacts.StatusLimitExceeded &&
		slices.Contains(facts.Parse.Issues, actionfacts.IssueInputLimit) &&
		(facts.Parse.Dialect == actionfacts.DialectPowerShell || facts.Parse.Dialect == actionfacts.DialectCMD ||
			actionfacts.TruncatedHostCall(request.Input)) {
		defer func() {
			findings = withBoundedTruncation(findings, bounded.Of(bounded.Bytes), request)
		}()
	}
	// The POSIX analysis reads a call as invalid syntax when it holds a Bash
	// spelling it has no grammar for (an ANSI-C quote with an escaped quote
	// before the launcher, rel-1-0-10:GAP-0740 lead-dollarsq), so it never
	// stops at the input bound the Bash reading of the same text hits: a
	// word past the string bound in a call that names a host launcher is
	// truncated all the same, never a clean allow.
	if facts.Parse.Status == actionfacts.StatusInvalid && slices.Contains(facts.Parse.Issues, actionfacts.IssueInvalidSyntax) {
		if command, known := trustedBashCommandInput(request.Input); known &&
			actionfacts.ShellInputPastByteBound(command, len(request.Input.Args)) &&
			actionfacts.TruncatedHostCall(request.Input) {
			defer func() {
				findings = withBoundedTruncation(findings, bounded.Of(bounded.Bytes), request)
			}()
		}
	}
	// A download cradle psparse proves on the tree, in a call the tokenizer
	// cannot prove it in, is judged at the unknown tier of the pack at least
	// (rel-1-0-10:GAP-0160): an alert outside the strict tier, a block in it.
	defer func() {
		findings = withCradleUnknownTier(findings, request)
	}()
	analyzedCaps = capFloorAnalysisCaps(request.Input, facts)
	// Credential material that reaches a sender whose destination is not read
	// in full (interpreter code that names a credentials file and a network
	// capability, a credential-named environment variable piped into an
	// upload) is the unknown tier of the one bound rule: the profile decides,
	// an alert in the default and permissive packs, a block in strict
	// (GAP-0595).
	// A cap the sender reader hit (its nesting depth, its reading bounds) is
	// TRUNCATED, whatever it read before the cap still judged: at least the
	// unknown tier of the pack (the one bound rule, GAP-0721).
	var senderCaps bounded.Truncated
	actionfacts.ReadSenders(facts).Bound(&senderCaps)
	if set := senderCaps.Set(); set.Any() {
		defer func() {
			findings = withBoundedTruncation(findings, set, request)
		}()
	}
	// A cap the secret-read chain's credentials-file resolve hit (its
	// candidates, work or lookups) is TRUNCATED too: at least the unknown
	// tier of the pack, and what it resolved before the cap still joins the
	// chain (rel-1-0-10:GAP-1029).
	if set := facts.CredentialPathReadCaps(parent); set.Any() {
		defer func() {
			findings = withBoundedTruncation(findings, set, request)
		}()
	}
	// The record is whole only up to here: every later reader of it (the
	// chain projection, the placement) sees the reads it can tell apart
	// (substrate-1:GAP-0674).
	thinCredentialPathReads(facts)
	if reason := actionfacts.CredentialSenderUnreadDestination(facts); reason != actionfacts.CredentialSenderNone {
		defer func() {
			findings = withCredentialSenderFinding(findings, reason, request.EnforcementCapable)
		}()
	}
	defer func() {
		findings = withUnreadPowerShellFloor(findings, request, facts)
	}()
	// A bash here-string (CMD <<< WORD) is a syntax error to the POSIX
	// analysis, so the call has no facts: it is judged as its twin
	// printf '%s\n' WORD | CMD as well, by every rule, and the twin's
	// findings are kept (rel-1-0-10:GAP-1083: cd X, then a here-string,
	// then a write in X).
	if twin, ok := hereStringTwin, hereStringTwinOK; ok {
		// The run-time shell reading of the call judges the script of a
		// shell that reads the here-string (bash <<< TEXT is bash -c TEXT):
		// the twin's own run-time shell reading (printf WORD | bash -c TEXT)
		// judged it a second time (rel-1-0-10:GAP-1472).
		twin.skipRunTimeShellTwin = twin.skipRunTimeShellTwin || shellTwinOK
		defer func() {
			// The twin is the call as typed without the bashism: every
			// finding of it is one of the call, an alert as well as a block.
			findings = withSimpleCommandFindings(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	windowsTwins, windowsTwinCut := windowsReadingTwinRequests(request, facts)
	var ownHostReadings *judgedHostReadings
	if len(windowsTwins) != 0 && !windowsTwinsKeepHostReadings {
		ownHostReadings = &judgedHostReadings{}
	}
	for _, twin := range windowsTwins {
		if ownHostReadings != nil {
			twin.windowsTwinHosts = &windowsTwinHostReadings{call: ownHostReadings, input: twin.Input}
		}
		defer func() {
			findings = withTwinProvenBlocks(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	if windowsTwinCut.Any() {
		defer func() { findings = withBoundedTruncation(findings, windowsTwinCut, request) }()
	}
	// A POSIX list on a Windows hook is also read cut before each later
	// statement, so a run of benign trailers cannot hide what the rest proves
	// (windowsListPrefixTwinRequests, rel-1-0-10:GAP-0348, GAP-1569).
	listPrefixTwins, listPrefixCut := windowsListPrefixTwinRequests(request, facts)
	for _, twin := range listPrefixTwins {
		defer func() {
			findings = withHostTwinFindings(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	if listPrefixCut.Any() {
		defer func() { findings = withBoundedTruncation(findings, listPrefixCut, request) }()
	}
	// A POSIX shell call the analysis stopped reading at a byte bound (one word
	// past the string bound ends it with no command) is truncated: judged at
	// the unknown tier of the pack, never a clean allow (rel-1-0-10:GAP-0382).
	if set := posixParseTruncation(request, facts); set.Any() {
		defer func() {
			findings = withBoundedTruncation(findings, set, request)
		}()
	}
	// A word past the bound that the local shell only passes on (a big script
	// handed to dcx or ssh) is data: the call is judged as its twin with the
	// word shortened, and the word leaves a detection-only record
	// (rel-1-0-10:GAP-0382).
	if twin, ok := posixDataWordTwinRequest(request, facts); ok {
		defer func() {
			findings = withOverLimitTwinFindings(findings, dispatchTrustedAction(parent, twin))
			unreadDataWord = true
		}()
	}
	// The call is read once more where the agent's working directory is
	// known but the request's is not, and that reading can only add
	// semantic findings: a sandbox call in the guest's own directory, by
	// every semantic owner (sandboxGuestPlacedInput, GAP-0264, GAP-0282); a
	// managed peer's call in the hook client's bounded directory, by the
	// rules whose owner places a path by the working directory itself
	// (protectedHomeCWDPlacedInput, cwdPlacedRule). The managed view is
	// parsed only when the action already names a possible active mutation
	// of what those rules own; a text mention or an inactive .sample path
	// needs no second reading.
	placed := placedReading{}
	if input, ok := sandboxGuestPlacedInput(request, facts); ok {
		analyzed := request.guestMemo.analyze(input)
		children, candidates, evals, cut := sandboxGuestPlacedViews(request.guestMemo, input, analyzed)
		placed = placedReading{facts: &analyzed, everyOwner: true, children: children, candidates: candidates, evals: evals}
		if cut.Any() {
			// More placed commands than the reading takes: the call is
			// truncated, judged at the unknown tier of the pack, never a
			// clean allow of what was not read (substrate-1 GAP-0304).
			defer func() { findings = withBoundedTruncation(findings, cut, request) }()
		}
	} else if hasGitHookMutationCandidate(facts) || hasGitReadOutputWrite(facts) {
		if input, ok := protectedHomeCWDPlacedInput(request); ok {
			analyzed := actionfacts.Analyze(input)
			placed = placedReading{facts: &analyzed}
		} else if request.cwdPlacedRoot != "" {
			// A simple command the walk read in the folder a cd moved it
			// to: its paths stay where they resolve there, and the
			// cwdPlacedRule owners read the project from the hook folder.
			rooted := facts
			rooted.CWD = request.cwdPlacedRoot
			placed = placedReading{facts: &rooted}
		}
	}
	if twin, ok := overLimitWriteBoundedTwinRequest(request, facts); ok {
		defer func() {
			findings = withOverLimitTwinFindings(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	// An operand in a folder the call does not give: the unknown tier when
	// it may be a protected file there (rel-1-0-10:GAP-0871).
	defer func() {
		findings = withUnresolvedFolderTier(findings, request, facts, false)
		findings = withSandboxGuestFolderTier(findings, request, facts)
	}()
	if twin, ok := overLimitCommandBoundedTwinRequest(request, facts); ok {
		defer func() {
			findings = withOverLimitTwinFindings(findings, dispatchTrustedAction(parent, twin))
		}()
	}
	// A file-tool call with an argument key outside its reviewed schema is
	// judged as each reading the harness may run (gas-ux-r1 GAP-0076).
	// A static powershell, pwsh or cmd launcher, call block or Invoke-Expression
	// literal also runs the script it names. psparse reads that script (the
	// launcher itself stays as the tokenizer saw it); the script reading only
	// ever adds findings (host_script_twin.go).
	if twins, caps := hostScriptTwinRequests(request, facts); len(twins) != 0 || caps.Any() {
		// The Windows reading twins registered above are judged after this
		// call's script readings are made: they leave out the ones it
		// judges itself (judgedHostReadings).
		ownHostReadings.note(twins)
		defer func() {
			for _, twin := range twins {
				twinFindings := dispatchTrustedAction(parent, twin)
				if twin.hostTwinListed {
					// A statement of a list read alone is a fragment: that it
					// is too large to judge says nothing the whole call's own
					// limit does not. A bound the statement's own reading hit
					// (a launcher nested past the depth, a body past the size)
					// is a truncation of the call all the same, alone, in a
					// list or in a call block: its caps reach the call
					// (rel-1-0-10:GAP-0477).
					caps = caps.Union(boundedCapsOf(twinFindings))
					twinFindings = withoutLimitFindings(twinFindings)
				}
				findings = withHostTwinFindings(findings, twinFindings)
			}
			findings = withBoundedTruncation(findings, caps, request)
		}()
	}
	twins, overflow := unknownKeyTwinRequests(request, facts)
	request.UnknownKeyPossibleOverflow = request.UnknownKeyPossibleOverflow || overflow
	for _, twin := range twins {
		defer func() {
			findings = withOverLimitTwinFindings(findings, twin.findings(parent))
		}()
	}
	if conflict, ok := conflictingToolArgumentKeys(request, facts); ok {
		// Two argument keys name one field: judge each candidate (GAP-0678).
		return dispatchConflictingToolArguments(parent, request, conflict)
	}
	generation := request.generation
	if generation == nil {
		generation = snapshotRulePackGenerationFor(parent, request.Connector)
	}
	budget := request.budget
	if generation == nil || len(generation.members) == 0 {
		if budget == nil {
			budget = newTrustedActionBudget(false)
		}
		return dispatchTrustedActionWith(parent, request, facts, placed, generation, budget, &telemetry)
	}
	// A strictest combination of profiles judges the call with each
	// member's own rules within one budget. Each finding keeps its member for
	// the later verdict and audit, even when two members share a rule ID.
	if budget == nil {
		budget = newTrustedActionBudget(true)
	}
	for i, member := range generation.members {
		var memberTelemetry trustedActionTelemetry
		found := dispatchTrustedActionWith(parent, request, facts, placed, member, budget, &memberTelemetry)
		if i < len(generation.memberNames) {
			for j := range found {
				found[j].profile = generation.memberNames[i]
			}
		}
		findings = append(findings, found...)
		telemetry.widen(memberTelemetry)
	}
	noteMeetBudget(generation, budget)
	return findings
}

// dispatchTrustedActionWith is dispatchTrustedAction's judgment of the
// call's facts with the rules of one generation, within budget.
func dispatchTrustedActionWith(
	ctx context.Context,
	request trustedActionRequest,
	facts actionfacts.Facts,
	placed placedReading,
	generation *compiledRulePackCategories,
	budget *trustedActionBudget,
	telemetry *trustedActionTelemetry,
) (findings []RuleFinding) {
	// Registered first, so it runs after every other lane: a write of an SSH
	// control file is named for the file (rel-1-0-6 GAP-0305).
	// A compound call's own facts hold no paths (each simple command is
	// judged on its own pass), so it keeps the keys title unless every
	// target is proven; that is the conservative reading.
	if !request.simpleCommandPass {
		defer func() {
			findings = withSSHControlFileTitle(facts, findings)
		}()
		// Registered with it, so it runs after every lane that adds a
		// finding, including the pass of each simple command below.
		defer func() {
			findings = withProvenFindingsBeforeUnprovenKeysBlock(findings)
		}()
	}
	// After every lane below, on what it returns (GAP-1469, GAP-1478).
	defer func() {
		findings = withMigratedLiteralRuleFindings(generation, request, facts, findings)
	}()
	defer func() {
		findings = withActiveStateTargetMention(request, facts, findings)
	}()
	if !request.simpleCommandPass {
		defer func() {
			checkedWholeWrite := false
			wholeWriteSafe := false
			checkedLocalOrdinary := false
			localOrdinary := false
			checkedSplitGapEffects := false
			// The closed WinDefend sequence proof owns a call with several
			// WinDefend sc steps: its stop, read alone, does not prove the
			// disable the sequence does not (rel-1-0-10:GAP-1194). Other
			// commands keep the findings they prove.
			winDefendSequenceUnproved := actionfacts.WinDefendSequenceUnproved(facts)
			wholeCommand, wholeCommandKnown := trustedBashCommandInput(request.Input)
			simples := withCappedWindowsReadings(request, request.simpleMemo.commands(request.Input, facts))
			if len(simples) == 0 && wholeCommandKnown &&
				(facts.Parse.Dialect != actionfacts.DialectPOSIX || facts.Parse.Status == actionfacts.StatusLimitExceeded) &&
				trustedStatementBudgetExceeded(request.Input, facts, wholeCommand) {
				// The analysis stopped at its node or input bound before the
				// per-command split, so no simple command of the call was
				// judged: the call is over the statement budget at every size,
				// as it is between 129 statements and those bounds (GAP-0146,
				// GAP-0568).
				simples = []actionfacts.SimpleCommand{{EvaluationFailure: "limit"}}
			}
			if slices.Contains(facts.Parse.Issues, actionfacts.IssueInternalParserFailure) {
				// Analyze recovered from an internal error: the call was not
				// read, so it is judged unknown, with a rule id.
				simples = append([]actionfacts.SimpleCommand{{EvaluationFailure: actionfacts.EvaluationFailureInternal}}, simples...)
			}
			evidenceCWDs := trustedSimpleCommandEvidenceCWDs(request, simples)
			for index, simple := range simples {
				if simple.UnprovenHome {
					// The command reads ~ or $HOME after HOME got a value
					// known only at run time (HOME=$(pwd)): its reading
					// names the previous home, the file it reaches is not
					// known, so the call is at least the unknown tier
					// (rel-1-0-10:GAP-0996).
					findings = withUnknownFinding(findings, unknownReasonFinding(runtimeHomeTitle, runtimeHomeReason, request.EnforcementCapable))
				}
				if simple.EvaluationFailure != "" {
					if simple.EvaluationFailure == actionfacts.EvaluationFailureInternal {
						findings = withSimpleCommandFindings(findings, trustedActionParseFailureFindings(request.EnforcementCapable))
						continue
					}
					if simple.EvaluationFailure == actionfacts.EvaluationFailureUnresolvedBody {
						// A nested shell body the walk cannot resolve: what it
						// runs is unknown (rel-1-0-10:GAP-0535).
						findings = withSimpleCommandFindings(findings, trustedActionUnresolvedBodyFindings(request.EnforcementCapable))
						continue
					}
					if simple.EvaluationFailure == actionfacts.EvaluationFailureUnknownStdinConsumer ||
						simple.EvaluationFailure == actionfacts.EvaluationFailureUnknownStdinConsumerStrict && request.StrictPolicy {
						// A here-document that may write DefenseClaw state goes
						// to a program whose use of its input is not known: the
						// unknown tier of the pack, a block in strict
						// (rel-1-0-10:GAP-1183, GAP-1240). A data program after
						// a PATH change is judged so in the strict tiers only;
						// the others allow it, as release did (GAP-1481).
						findings = withUnknownFinding(findings, unknownReasonFinding(unknownStdinConsumerTitle, unknownStdinConsumerReason, request.EnforcementCapable))
						continue
					}
					if simple.EvaluationFailure == actionfacts.EvaluationFailureUnknownStdinConsumerStrict {
						continue
					}
					if simple.EvaluationFailure == actionfacts.EvaluationFailureSyntaxCap {
						// The reading of the syntax error stopped at a cap:
						// the unknown tier, and the statements read before it
						// are judged as the other simple commands are.
						findings = withSimpleCommandFindings(findings, trustedActionLimitFindings(request.EnforcementCapable))
						continue
					}
					if simple.EvaluationFailure == actionfacts.EvaluationFailureSyntax {
						// A text with a syntax error: its readable statements
						// are judged as the simple commands around this one,
						// and the part that was not read is unknown
						// (rel-1-0-10:GAP-0526).
						findings = withSimpleCommandFindings(findings, trustedActionSyntaxUnreadFindings(request.EnforcementCapable,
							unreadPartMayWriteProtected(request, generation, syntaxUnreadText(wholeCommand))))
						continue
					}
					if simple.EvaluationFailure != "limit" {
						// A parser gap is left to the whole-action evaluation
						// and is not itself an enforcement finding. That
						// reading does not judge the files a partial call
						// touches, so each path effect of the call is judged
						// by its effect twin (withSplitGapEffects,
						// substrate-1:GAP-0693, GAP-0694, GAP-0695, GAP-0698).
						if splitGapUnreadPart(simple) && wholeCommandKnown && !checkedSplitGapEffects {
							checkedSplitGapEffects = true
							var judged *splitGapJudged
							findings, judged = withSplitGapEffects(ctx, request, generation, budget, facts, wholeCommand, findings, nil)
							findings = withSandboxGuestSplitGapEffects(ctx, request, generation, budget, facts, wholeCommand, findings, judged)
						}
						continue
					}
					findings = withSimpleCommandFindings(findings, trustedActionLimitFindings(request.EnforcementCapable))
					break
				}
				if simple.OpaqueValueAssignment || simple.LiteralOutputOnly {
					continue
				}
				child := request
				child.Input.Command = simple.Text
				child.Input.CWD = simple.CWD
				if simple.AbsoluteOnly {
					// The shell directory is unknown (an eval, a cd the walk
					// cannot read) but no operand of the command depends on
					// it: the directory the action starts in judges it as it
					// judges the same command written out, so a no-op eval
					// before a write does not hide the write.
					child.Input.CWD = request.Input.CWD
				}
				if simple.LoginGuess && !loginGuessReadingMayProveStateWrite(request, simple, child.Input.CWD) {
					continue
				}
				if simple.UnboundUser {
					// A name a read, loop or eval binds is not the login the
					// home spells. The child keeps the spelling of the path
					// as the home path it reads, but a file it reaches only
					// through a link on disk is not a file the command names.
					child.SkipLocalFilesystemResolution = true
				}
				// An earlier cd, pushd or env -C of the action moved a Git
				// Bash shell to another native Windows directory: the
				// child's operands resolve there (GAP-2473). The flag stays
				// off for the action itself and for a child in the hook's
				// own directory, whose readings are unchanged.
				child.Input.MovedWindowsShellCWD = request.Input.MovedWindowsShellCWD ||
					simple.CWD != "" && !strings.HasPrefix(simple.CWD, "/") &&
						filepath.VolumeName(simple.CWD) != "" && !strings.EqualFold(filepath.Clean(simple.CWD), filepath.Clean(request.Input.CWD))
				if evidenceCWDs != nil {
					child.evidenceCWD = evidenceCWDs[index]
				}
				if filepath.IsAbs(child.Input.CWD) && filepath.IsAbs(request.Input.CWD) &&
					filepath.Clean(child.Input.CWD) != filepath.Clean(request.Input.CWD) {
					child.cwdPlacedRoot = request.Input.CWD
				}
				// The managed hook has already walked a static cd. Its write
				// targets are keyed in that physical directory, which may
				// differ from the shell's logical PWD through a symlink.
				// Judge the standalone child in the same directory as the
				// hook's target evidence.
				if request.ProtectedHomeHook {
					if physical := request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+simple.CWD]; filepath.IsAbs(physical) {
						child.Input.CWD = physical
					}
				}
				child.Input.Args, child.Input.Argv = nil, nil
				child.LegacyText = simple.Text
				child.conflictSource = nil
				child.record, child.recordTelemetry = nil, nil
				child.simpleCommandPass = true
				child.stateProofOnly = simple.LoginGuess
				// A statement the walk placed nowhere is judged as the laptop
				// judges it, in no folder: the guest placement of the call
				// already reads it in each directory the guest may be in
				// (guestPlacementPlan). Placed in the guest's directory
				// here, its proof there hid the unknown tier of the folder it
				// may really run in, which the laptop names
				// (withUnresolvedFolderTier, rel-1-0-10:GAP-0871; substrate-1
				// GAP-0377 at FU8: $CMD; cat .ssh/id_ed25519).
				child.unplacedStatement = simple.UnresolvedFolder && child.SandboxGuestCWD != ""
				parent := request.Input
				if wholeCommandKnown {
					parent.Command = wholeCommand
				}
				child.parentPatch = &parent
				// The child is judged by this generation (a meet member) within
				// the call budget, like its parent.
				child.generation, child.budget = generation, budget
				childFindings := dispatchTrustedAction(ctx, child)
				if simple.UnresolvedFolder {
					// The walk does not know the folder this statement runs
					// in (cd "$X", cd "$(...)"): the unknown tier when an
					// operand may be a named protected file there
					// (rel-1-0-10:GAP-0871).
					childFindings = withUnresolvedFolderTier(childFindings, child, actionfacts.Analyze(child.Input), true)
				}
				if simple.LoginGuess {
					childFindings = slices.DeleteFunc(childFindings, func(f RuleFinding) bool {
						return !loginGuessProvedFinding(f)
					})
				}
				if child.Input.MovedWindowsShellCWD && !request.Input.MovedWindowsShellCWD {
					// The moved-directory reading only adds findings: the
					// child's reading without it (a hooks-dir removal or move
					// under a home spelling) keeps every block it proved
					// (GAP-2473 RV-r10-1).
					unmoved := child
					unmoved.Input.MovedWindowsShellCWD = false
					childFindings = withSimpleCommandFindings(childFindings, dispatchTrustedAction(ctx, unmoved))
				}
				if simple.ZshHistoryBuiltin {
					// Zsh's history builtin lists events (fc -l). The Bash-only
					// history -c clear rule does not apply inside that shell.
					childFindings = slices.DeleteFunc(childFindings, func(f RuleFinding) bool {
						return f.RuleID == "integrity.history_tamper"
					})
				}
				if simple.UnresolvedBoundVariable {
					if !checkedWholeWrite {
						checkedWholeWrite = true
						wholeWriteSafe = wholeCommandKnown &&
							request.targetMemo.ActionCommandDecisionWithDialectAndGlobFacts(wholeCommand,
								request.Input.CWD, request.Input.ActiveHome, request.Input.DialectHint, clientGlobFacts(request)) == ""
						if !wholeWriteSafe && wholeCommandKnown && !request.ProtectedHomeHook &&
							(request.Connector == "claudecode" || request.Connector == "codex") &&
							trustedPOSIXShellCall(request.Input, facts) {
							wholeWriteSafe = hookpaths.ProvedOrdinaryVariableTargets(
								wholeCommand, request.Input.CWD, request.Input.ActiveHome)
						}
					}
					if wholeWriteSafe {
						// A child with a missing action-local value cannot prove a
						// protected write by itself. The full action's class resolver
						// has already judged that binding; retain every other rule.
						childFindings = slices.DeleteFunc(childFindings, func(f RuleFinding) bool {
							return f.RuleID == "persistence.ssh_authorized_keys_command"
						})
					}
				}
				if !simple.UnresolvedBoundVariable && wholeCommandKnown && !request.ProtectedHomeHook &&
					(request.Connector == "claudecode" || request.Connector == "codex") &&
					trustedPOSIXShellCall(request.Input, facts) &&
					slices.ContainsFunc(childFindings, func(f RuleFinding) bool {
						return f.RuleID == "persistence.ssh_authorized_keys_command"
					}) {
					if !checkedLocalOrdinary {
						checkedLocalOrdinary = true
						localOrdinary = hookpaths.ProvedOrdinaryVariableTargets(
							wholeCommand, request.Input.CWD, request.Input.ActiveHome)
					}
					if localOrdinary {
						childFindings = slices.DeleteFunc(childFindings, func(f RuleFinding) bool {
							return f.RuleID == "persistence.ssh_authorized_keys_command"
						})
					}
				}
				if winDefendSequenceUnproved && actionfacts.ExactWinDefendSingleStep(actionfacts.Analyze(child.Input)) {
					childFindings = slices.DeleteFunc(childFindings, func(f RuleFinding) bool {
						return f.RuleID == "tamper.endpoint_security_product_disable"
					})
				}
				findings = withSimpleCommandFindings(findings, childFindings)
			}
			// A find hands its starting points to the program it runs, and an
			// xargs its fixed input: that program on each name is judged as
			// the statement alone, for the call and for each of its
			// statements, and the strictest finding is kept
			// (rel-1-0-10:GAP-1048, GAP-0997).
			inputs := []actionfacts.Input{request.Input}
			for _, simple := range simples {
				if simple.EvaluationFailure == "" && !simple.OpaqueValueAssignment && !simple.LiteralOutputOnly &&
					!simple.LoginGuess {
					input := request.Input
					input.Command, input.Args, input.Argv, input.CWD = simple.Text, nil, nil, simple.CWD
					if simple.AbsoluteOnly {
						input.CWD = request.Input.CWD
					}
					inputs = append(inputs, input)
				}
			}
			for index, input := range inputs {
				text, _ := trustedBashCommandInput(input)
				// An xargs fed fixed names (echo|printf WORDS | xargs CMD) runs
				// CMD with them: that call is judged as typed too, so a
				// credential file handed to a copy through xargs gets the
				// finding of the copy (rel-1-0-10:GAP-0997).
				readings := xargsStaticInputReadings(text, request.Input.ActiveHome)
				if strings.Contains(text, "-exec") || strings.Contains(text, "-ok") {
					inputFacts := facts
					if index != 0 {
						inputFacts = actionfacts.Analyze(input)
					}
					found, truncated := actionfacts.FindHandedReadings(inputFacts)
					if truncated {
						findings = withSimpleCommandFindings(findings, trustedActionLimitFindings(request.EnforcementCapable))
					}
					readings = append(readings, found...)
				}
				for _, reading := range readings {
					child := request
					child.Input = input
					child.Input.Command, child.Input.Args, child.Input.Argv = reading, nil, nil
					child.LegacyText = reading
					child.conflictSource = nil
					child.record, child.recordTelemetry = nil, nil
					child.simpleCommandPass = true
					parent := request.Input
					if wholeCommandKnown {
						parent.Command = wholeCommand
					}
					child.parentPatch = &parent
					child.generation, child.budget = generation, budget
					findings = withSimpleCommandFindings(findings, dispatchTrustedAction(ctx, child))
				}
			}
		}()
	}
	options := ruleScanOptions{
		includeToolCallOnly: true,
		excludeTrustExploit: true,
	}
	if request.stateProofOnly {
		options.onlyRule = loginGuessProvesRule
	}
	if generation == nil || len(generation.semanticRules) == 0 {
		var fallbackTelemetry trustedActionTelemetry
		findings, fallbackTelemetry = dispatchTrustedFallback(
			generation,
			request,
			facts,
			options,
		)
		telemetry.merge(fallbackTelemetry)
		return findings
	}

	excluded := make(map[string]struct{})
	semanticFindings := make([]RuleFinding, 0, len(generation.semanticRules))
	matchedSemanticOwnerIDs := make(map[string]struct{})

	// evaluateSemanticRules runs the semantic rules that candidateOK admits
	// on view (projection is its projection) and reports whether the view's
	// enforcement projection failed, in which case no finding was added
	// after the failure and the caller decides what that means.
	// done is ctx.Done(): a closed channel is a non-nil ctx.Err(). The rule
	// loop reads it for every rule of every view, and ctx.Err() walked the
	// hook's context chain each time: 1.1 million times a call of 8,000
	// placed views, 6% of a copy-mode actor's time (rel-1-0-10:GAP-2226).
	done := ctx.Done()
	evaluateSemanticRules := func(
		viewID int,
		view actionfacts.Facts,
		projection *semanticpb.Facts,
		candidateOK func(compiledSemanticRule) bool,
		matchOnly bool,
		staticTargetTwin *actionfacts.Facts,
		kept *guestViewEvalTable,
	) (projectionFailed bool) {
		var enforcementFacts actionfacts.Facts
		var enforcementProjection *semanticpb.Facts
		enforcementProjected := false
		projectionCode := semantic.ProjectionOK
		for rule, candidate := range generation.semanticRules {
			if contextDone(done) {
				break
			}
			if request.stateProofOnly && !loginGuessProvesRule(candidate.rule.ID) {
				continue
			}
			if budget.spent() && !budget.judged(candidate, viewID) {
				// Past the budget, only an expression another member of a
				// strictest combination already judged here still counts:
				// it costs nothing more (trustedActionBudget).
				if budget.evals == nil {
					break
				}
				continue
			}
			if _, alreadyMatched := matchedSemanticOwnerIDs[candidate.rule.ID]; alreadyMatched {
				continue
			}
			if candidateOK != nil && !candidateOK(candidate) {
				continue
			}
			if !kept.eligibleFor(rule, &candidate, &view) {
				if !matchOnly && candidate.owner.suppressFallback != nil &&
					candidate.owner.suppressFallback(view) {
					excludeSemanticOwner(excluded, candidate.owner, false)
				}
				continue
			}
			if staticTargetTwin != nil && !candidate.owner.eligible(*staticTargetTwin) {
				continue
			}
			result, evalCode, judged := budget.evalKept(ctx, candidate, viewID, projection, kept, guestKeptSlot(rule, false))
			if !judged {
				if budget.evals == nil {
					break
				}
				continue
			}
			if evalCode != semantic.EvalOK {
				if ctx.Err() != nil {
					break
				}
				continue
			}
			if !result.Matched {
				if !matchOnly {
					excludeSemanticOwner(excluded, candidate.owner, false)
				}
				continue
			}

			if !enforcementProjected {
				enforcementFacts, enforcementProjection, projectionCode = kept.enforcementOf(&view)
				enforcementProjected = true
			}
			if projectionCode != semantic.ProjectionOK {
				return true
			}
			enforcementResult, enforcementCode, judged := budget.evalKept(ctx, candidate, viewID+1, enforcementProjection, kept, guestKeptSlot(rule, true))
			if !judged {
				if budget.evals == nil {
					break
				}
				continue
			}
			if enforcementCode != semantic.EvalOK {
				if ctx.Err() != nil {
					break
				}
				continue
			}

			excludeSemanticOwner(excluded, candidate.owner, true)
			for _, claimedID := range candidate.owner.claimedIDs(true) {
				matchedSemanticOwnerIDs[claimedID] = struct{}{}
			}
			finding := RuleFinding{
				RuleID:      candidate.rule.ID,
				Title:       candidate.rule.Title,
				Severity:    candidate.rule.Severity,
				Confidence:  candidate.rule.Confidence,
				Tags:        append([]string(nil), candidate.rule.Tags...),
				enforcement: findingEnforcementAllowed,
			}
			if !request.EnforcementCapable ||
				candidate.owner.detectionOnly || candidate.owner.alertOnly ||
				!enforcementFacts.EnforcementEligible() ||
				!enforcementResult.Matched {
				finding.enforcement = findingEnforcementDetectionOnly
			}
			if request.EnforcementCapable && candidate.owner.alertOnly {
				finding.enforcement = findingEnforcementAlertOnly
			}
			if candidate.owner.strictEnforced && !request.StrictPolicy &&
				finding.enforcement == findingEnforcementAllowed {
				finding.enforcement = findingEnforcementAlertOnly
			}
			finding = finding.withTrustedActionProof(
				newActionFactsSemanticFindingProof(
					candidate.rule.ID,
					actionFactsSemanticProofInput{
						FactsAuthoritative:  view.Authoritative(),
						EnforcementEligible: enforcementFacts.EnforcementEligible(),
						ProjectionComplete:  projectionCode == semantic.ProjectionOK,
						EvaluationComplete:  enforcementCode == semantic.EvalOK,
						Matched:             enforcementResult.Matched,
					},
				),
			)
			semanticFindings = append(
				semanticFindings,
				adjustConfidence(request.Input.Tool, finding),
			)
		}
		return false
	}

	// judgePlaced judges the working-directory reading (placedReading). It
	// shares this dispatch and budget, and it can add only positive semantic
	// findings, of every owner for a sandbox and of cwdPlacedRule rules for a
	// managed peer; all other lanes keep the gateway's original facts.
	judgePlaced := func() {
		placedRule := func(candidate compiledSemanticRule) bool {
			return placed.everyOwner || cwdPlacedRule(candidate.rule.ID)
		}
		placed.eachView(func(index int, view *actionfacts.Facts) {
			if !view.Authoritative() {
				return
			}
			// A child's projections and rule results are kept with its
			// reading for the hook's later judgments (guestViewEvals).
			var evals *guestViewEvals
			if index > 0 && index <= len(placed.evals) {
				evals = placed.evals[index-1]
			}
			kept := evals.lock(generation)
			defer evals.unlock()
			if projection, code := kept.project(view); code == semantic.ProjectionOK {
				// Each view has its own pair of budget keys (the view and its
				// enforcement projection), after the fixed views 0 to 5.
				evaluateSemanticRules(placedReadingFirstView+2*index, *view, projection, placedRule, true, nil, kept)
			}
		})
	}
	// fallback judges a call no semantic view of the whole call can judge
	// (dispatchTrustedFallback). A sandbox call's guest placement still
	// judges it: each simple command a static cd moved is a complete view
	// of its own, so what one proves there (its semantic findings and the
	// lexical private-key read proof) counts as it does on the laptop, where
	// the per-command pass reads each command in its directory. Without it a
	// heredoc or here-string into a shell, a $CMD, an eval or a long && list
	// after cd .cache let cat ../.ssh/id_ed25519 or rm
	// ../.defenseclaw/audit.db through where the laptop blocks
	// (substrate-1 GAP-0363). The whole-call view stays unjudged.
	fallback := func() []RuleFinding {
		out, fallbackTelemetry := dispatchTrustedFallback(generation, request, facts, options)
		telemetry.merge(fallbackTelemetry)
		if !placed.everyOwner {
			return out
		}
		judgePlaced()
		if len(semanticFindings) != 0 {
			out = withSimpleCommandFindings(out,
				finalizeTrustedActionFindings(generation, request, facts, append([]RuleFinding(nil), semanticFindings...)))
		}
		if !request.stateProofOnly && placed.provesSSHPrivateKeyContentRead() {
			out = withProvedPrivateKeyRead(out, generation, request)
		}
		return out
	}

	// A partial action whose only uncertainty is a runtime-expanded redirect
	// target ("> ~/out.txt", "> $HOME/out.txt") still has a static, provable
	// argv. Semantic rules run on the complete analysis of a static-target
	// twin without those redirects, but only a match counts there, and only
	// for a rule that match cannot depend on the dropped redirect and path
	// facts (redirectReductionCandidate). A code-owned prerequisite is a Go
	// check written for complete facts, so it must also hold on the twin
	// with its static targets (staticTargetTwin). A non-match or a skipped
	// rule never suppresses its legacy fallback, which, like every recovery
	// lane below, still sees the whole action.
	//
	// A partial action with && or || lists is judged as if every command of
	// each list runs: a block stops the whole call before any of it runs, so
	// a rule that blocks `a; b` also blocks `a && b` and `a || b`. Semantic
	// rules that do not read how complete the analysis is
	// (listReductionCandidate) and the context checks run on the complete
	// analysis of the list read as a sequence, which has every fact of the
	// action, so there a non-match counts as it does for `a; b`. A fallback
	// finding that analysis proves may block too. A list with a
	// runtime-expanded redirect target is read as a sequence inside the
	// redirect-target view.
	semanticFacts := facts
	// viewCandidate is set when semanticFacts is a view, and reports whether
	// a rule's result on that view may stand for the whole action.
	var viewCandidate func(compiledSemanticRule) bool
	// staticTargetTwin is the complete analysis a redirect-target view was
	// cut from, with the placeholder targets' redirect and path facts.
	var staticTargetTwin *actionfacts.Facts
	// subsetView is set when semanticFacts keeps only the action's static,
	// certain commands; as on a redirect-target view, only a match counts.
	subsetView := false
	// overLimitView is set when semanticFacts is the over-limit view of a
	// write tool call, the only facts that name the targets of that call.
	overLimitView := false
	// powerShellView keeps the independently parsed commands of exact
	// pwsh -Command / -EncodedCommand bodies next to the action's static
	// top-level commands. The original action remains partial. The view
	// never replaces a view chosen below, whose rule classes and non-matches
	// keep their meaning: it is an extra pass where only a monotone argv
	// rule's match counts.
	var powerShellView *actionfacts.Facts
	if !facts.Authoritative() {
		if view, ok := actionfacts.PowerShellCommandSubsetReduction(request.Input, facts); ok {
			powerShellView = &view
		}
		if view, _, ok := actionfacts.OverLimitWriteTargetReduction(request.Input, facts); ok {
			// A write tool call whose arguments are limit-exceeded, judged on
			// the same call with its large text left out: it names the same
			// targets, so a match counts (GAP-0674).
			semanticFacts, subsetView, overLimitView = view, true, true
		} else if view, twin, ok := actionfacts.DynamicRedirectTargetReduction(request.Input, facts); ok {
			semanticFacts, staticTargetTwin, viewCandidate = view, &twin, redirectReductionCandidate
		} else if view, ok := actionfacts.ShortCircuitListReduction(request.Input, facts); ok {
			semanticFacts, viewCandidate = view, listReductionCandidate
		} else if view, ok := actionfacts.CompoundCommandReduction(request.Input, facts); ok {
			// A simple command in a subshell, group, if, loop or case body,
			// or a negated or background statement, is judged as if it ran
			// alone: `(rm -rf /)` as `rm -rf /`. The view has every command
			// of the action, as a list read as a sequence does, but not the
			// scope of a subshell or the count of a loop, so only a match
			// counts.
			semanticFacts, viewCandidate, subsetView = view, listReductionCandidate, true
		} else if view, ok := actionfacts.PowerShellProfileWrapperReduction(request.Input, facts); ok {
			// pwsh -Command "<body>" without -NoProfile, alone or first in a
			// list: a profile only runs more commands before the body, so a
			// match on the body counts.
			semanticFacts, viewCandidate, subsetView = view, subsetReductionCandidate, true
		} else if view, ok := actionfacts.OpaqueCMDWrapperArgvReduction(request.Input, facts); ok {
			// cmd.exe /c has a complete outer argv even when AutoRun leaves
			// its child opaque. Only a positive match on that argv counts.
			semanticFacts, viewCandidate, subsetView = view, argvSubsetReductionCandidate, true
		} else if view, partialArgv, ok := actionfacts.StaticCommandSubsetReduction(request.Input, facts); ok {
			semanticFacts, viewCandidate, subsetView = view, subsetReductionCandidate, true
			if partialArgv {
				viewCandidate = argvSubsetReductionCandidate
			}
		} else if view, ok := actionfacts.UnmodeledProgramArgvReduction(request.Input, facts); ok {
			// A program with no modeled operand grammar (hostname) left the
			// action partial, so a custom argv rule about it never ran
			// (GAP-0912). Only a monotone argv rule's match counts.
			semanticFacts, viewCandidate, subsetView = view, argvSubsetReductionCandidate, true
		} else if view, ok := actionfacts.SourcedFileReduction(request.Input, facts); ok {
			// A file sourced by a static name (source .env && aws ...) is
			// opaque, so no rule ran on the commands after it and a custom
			// argv rule was only a detection-only regex finding (GAP-0117).
			// Only a monotone argv rule's match counts.
			semanticFacts, viewCandidate, subsetView = view, argvSubsetReductionCandidate, true
		} else if powerShellView != nil {
			semanticFacts, viewCandidate, subsetView = *powerShellView, argvSubsetReductionCandidate, true
			powerShellView = nil
		} else {
			return fallback()
		}
	}
	// matchOnly is set when only a match on the view counts.
	matchOnly := staticTargetTwin != nil || subsetView
	fullProjection, projectionCode := semantic.Project(semanticFacts)
	if projectionCode != semantic.ProjectionOK {
		return fallback()
	}

	if evaluateSemanticRules(
		0,
		semanticFacts,
		fullProjection,
		viewCandidate,
		matchOnly,
		staticTargetTwin,
		nil,
	) {
		clear(excluded)
		semanticFindings = semanticFindings[:0]
	}
	judgePlaced()
	// The PowerShell body view adds positive argv matches only. A failed
	// projection there adds nothing and leaves the result above unchanged.
	if powerShellView != nil {
		if projection, code := semantic.Project(*powerShellView); code == semantic.ProjectionOK {
			evaluateSemanticRules(
				2,
				*powerShellView,
				projection,
				argvSubsetReductionCandidate,
				true,
				nil,
				nil,
			)
		}
	}
	restoreTrustedUnresolvedReadFallbacks(
		excluded,
		generation,
		request.Input,
		request.Input.Tool,
		facts,
	)
	restoreTrustedEmbeddedCommandFallbacks(
		excluded,
		generation,
		request.Input.Tool,
		facts,
	)

	options.excludedRuleIDs = excluded
	scanned := scanRuleGeneration(
		generation,
		trustedRuleScanText(request, facts),
		request.Input.Tool,
		options,
	)
	scanned = append(scanned, fileToolLinkTargetFindings(generation, request, facts, options)...)
	fallbackLanes := func(
		legacyFindings []RuleFinding,
		facts actionfacts.Facts,
	) ([]RuleFinding, trustedActionTelemetry) {
		return trustedFallbackLanes(generation, request, options, legacyFindings, facts)
	}
	legacyFindings, fallbackTelemetry := fallbackLanes(
		append([]RuleFinding(nil), scanned...),
		facts,
	)
	telemetry.merge(fallbackTelemetry)
	// A list read as a sequence has every fact of the action, so the checks
	// that decide whether a fallback, content or path finding may block judge
	// it as that sequence too. A redirect-target view lacks the target's facts.
	contextFacts := facts
	if viewCandidate != nil && !matchOnly {
		contextFacts = semanticFacts
		sequenceFindings, _ := fallbackLanes(scanned, semanticFacts)
		legacyFindings = withSequenceProvenFindings(legacyFindings, sequenceFindings)
	}
	// A write tool call over the argument limit names its targets only on
	// its over-limit view, so a path finding of the recovery lanes is proven
	// and judged there; only a finding proven on the view is added (GAP-0674).
	if overLimitView {
		contextFacts = semanticFacts
		viewFindings, _ := fallbackLanes(scanned, semanticFacts)
		legacyFindings = withSequenceProvenFindings(legacyFindings, viewFindings)
	}
	findings = append(semanticFindings, legacyFindings...)
	finalized := finalizeTrustedActionFindings(
		generation, request, contextFacts, findings,
	)
	if !request.stateProofOnly {
		// These two add only SSH-key, private-key and unverified-write
		// findings, never the state-write proof a stateProofOnly reading keeps.
		finalized = appendTrustedWriteTargetFindings(finalized, generation, request, facts)
		finalized = appendTrustedPrivateKeyReaderFinding(finalized, generation, request, facts)
		if placed.everyOwner && placed.provesSSHPrivateKeyContentRead() {
			finalized = withProvedPrivateKeyRead(finalized, generation, request)
		}
		finalized = appendWindowsPathUnverifiedFinding(finalized, request, facts)
	}
	if staticTargetTwin == nil {
		return finalized
	}
	// The recovery lanes and the context checks also judge the static-target
	// twin of a redirect-target view, and, as for semantic rules, only a block
	// proven there counts. The twin's stand-in target is no sensitive path,
	// so such a block rests on the rest of the action, which the runtime
	// target does not change; any other result keeps the whole-action one.
	twinLegacy, _ := fallbackLanes(append([]RuleFinding(nil), scanned...), *staticTargetTwin)
	twinFindings := finalizeTrustedActionFindings(
		generation,
		request,
		*staticTargetTwin,
		append(append([]RuleFinding(nil), semanticFindings...), twinLegacy...),
	)
	return withTwinProvenBlocks(finalized, twinFindings)
}

// withoutUnprovenStateWrite drops the state-write findings that do not
// take part in enforcement from the findings of a bash here-string call
// whose POSIX twins were judged and write no state (hereStringStateMutation).
// The POSIX parse rejects `<<<`, so the pack's text match of a state name
// (python3 - <<< 'print(open("~/.defenseclaw/config.yaml").read())') stayed
// in the verdict as a CRITICAL tamper.detector_state_write row although the
// twin proved the call changes no state: an allowed read named a rule the
// call did not trigger (rel-1-0-10:GAP-0376). A finding that enforces is
// kept as it is.
func withoutUnprovenStateWrite(findings []RuleFinding) []RuleFinding {
	return slices.DeleteFunc(findings, func(f RuleFinding) bool {
		return f.RuleID == "tamper.detector_state_write" && !f.contributesToEnforcement()
	})
}

// The action target check uses a resolved active security-state mention to
// find candidates, then requires the executing operand's mutation role and
// physical target before adding a finding. Keep it separate from SSH keys.
func withActiveStateTargetMention(
	request trustedActionRequest,
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	// The bounded view of a large structured write keeps its complete target
	// facts. Use that same view for the gateway-owned state proof as the pack
	// rules use for their path decisions.
	if view, _, ok := actionfacts.OverLimitWriteTargetReduction(request.Input, facts); ok {
		facts = view
	}
	// A pattern, brace list, rsync or git clean that expands onto the
	// state names no path fact, so it is proved from the shell words
	// (GAP-2047); so is an archive extraction into it (GAP-2415).
	// A bash here-string, which the POSIX parse rejects, is judged by its
	// POSIX twin alone (GAP-2047 row a): a read through one names state but
	// changes none.
	// A find with an unquoted -name/-path pattern is judged by its quoted
	// twin (GAP-2498); xargs fed by a static printf or echo by the call it
	// makes (GAP-0052).
	// `cat <<< WORD | xargs rm -rf` is a here-string too: its xargs twin
	// is judged before the here-string verdict ends the check (pod check31).
	// A Git Bash call on Windows names its home as a drive path (C:/Users/x)
	// that the POSIX link, pattern and xargs checks do not read as absolute:
	// they also judge its drive view (GAP-2577).
	driveFacts, driveRequest, driven := gitBashDriveView(facts, request)
	// A for loop whose body writes a path that some value of its variable (or
	// of a variable the walk cannot read) makes active state is judged by that
	// target, whatever the list holds and whatever runs before the loop
	// (rel-1-0-6:GAP-0880). The match is on the spelling, so a gateway that
	// cannot open the user home reads it as a per-user one does.
	// A gateway behind ProtectHome receives no cwd of its own; the loop scan
	// reads the spelling only, so it is placed where the hook client ran the
	// call (GAP-1052).
	loopCWD := request.Input.CWD
	if client, placed := protectedHomeReportedDirectory(request); placed {
		loopCWD = client
	}
	if command, known := trustedBashCommandInput(request.Input); known && trustedPOSIXShellCall(request.Input, facts) &&
		hookpaths.LoopWriterReachesState(command, loopCWD, request.Input.ActiveHome, request.StrictPolicy) {
		return withProvenActiveStateMutation(request, findings)
	}
	hereStringMutates, hereStringJudged := hereStringStateMutation(facts, request)
	xargsMutates := xargsStaticInputStateMutation(facts, request) ||
		driven && xargsStaticInputStateMutation(driveFacts, driveRequest)
	if hereStringJudged && !hereStringMutates && !xargsMutates {
		if strings.HasPrefix(facts.ActiveHome, "/") {
			return withoutUnprovenStateWrite(findings)
		}
		// Under a Windows drive home the twin only clears the pack's text
		// match; every later proof (the cmd and PowerShell readings among
		// them) still runs and adds the gateway's own finding for a write it
		// proves (rel-1-0-10:GAP-0376).
		findings = withoutUnprovenStateWrite(findings)
	}
	// A managed call whose cwd the gateway cannot see is also judged for
	// links in the directory the hook client walked its words from
	// (GAP-2569), and its relative patterns are walked from there through
	// the cd, pushd and popd of the call (GAP-2485, T11 managed RHEL: the
	// nested-cd rows Y5 and Y6 started nowhere and proved nothing).
	linkFacts, linkRequest, placed := managedLinkWalkView(request)
	throughLink := func(check func(actionfacts.Facts, trustedActionRequest) bool) bool {
		return check(facts, request) || placed && check(linkFacts, linkRequest) ||
			driven && check(driveFacts, driveRequest)
	}
	// Structured write tools have no shell command to scan. Their complete
	// path facts still prove the same mutation, independently of pack rules.
	if actionfacts.StructuredWriteTool(request.Input.Tool) && throughLink(provenStateMutationPath) {
		return withProvenActiveStateMutation(request, findings)
	}
	// A write through a link the command makes to active state is proven by
	// the link reading: the mention scan and the whole-action proof do not
	// follow the new link (GAP-2522), nor read sed -i --follow-symlinks
	// (GAP-2529).
	if !hereStringMutates && !xargsMutates && !globbedStateMutation(facts) &&
		(!placed || !globbedStateMutation(linkFacts)) && !throughLink(globbedStateMutationThroughLink) &&
		!findGlobTwinStateMutation(facts, request) &&
		!archiveExtractsIntoState(facts, request) && !inlineHandoffStateWrite(facts, request) &&
		!provenLinkedStateWrite(facts, request) &&
		!provenFollowedInPlaceStateWrite(facts, request) && !fileToolWriteThroughLinkToState(facts, request) {
		command, known := trustedBashCommandInput(request.Input)
		if !known {
			return findings
		}
		if !request.targetMemo.ActionStateTargetMention(command, request.Input.CWD, request.Input.ActiveHome) &&
			!factsHaveFindHandOff(facts) && !throughLink(stateOperandThroughLink) &&
			(!driven || !globbedStateMutation(driveFacts)) {
			// Behind ProtectHome the gateway cannot open the user's home, so the
			// mention scan cannot place a home target. A redirect target the
			// shell opens is still proven against the hook client's resolved
			// target map (GAP-2328: $CMD; echo $X > ~/.defenseclaw/config.yaml).
			// So is a proven writer or delete whose operand the client
			// followed into the state tree through a link the gateway cannot
			// read (GAP-2549: rm /dev/shm/x/y/config.yaml, y -> ~/.defenseclaw).
			// A managed peer's call is placed where the hook client ran it
			// (managedLinkWalkView): the gateway behind ProtectHome receives no
			// cwd of its own, so a bare name in the state folder (echo x >>
			// config.yaml in ~/.defenseclaw) or a link in the project the
			// client followed into the state tree was placed nowhere and
			// allowed (rel-1-0-10:GAP-1135).
			if !request.ProtectedHomeHook ||
				!provenShellRedirectStateWrite(request) && !throughLink(provenStateMutationPath) &&
					!provenStaticRedirectStateMutation(facts, request) {
				// The mention scan places files below the state directory; a
				// cmd /c body that removes or moves the directory itself (cmd
				// /c rd /s /q %USERPROFILE%\.defenseclaw) names none, while the
				// cmd twin (or the PowerShell reading, GAP-2414) proves the mutation of
				// the state root (classifier-ps checker it9 RV9-2 X02, X07).
				// A managed PowerShell call that reaches the state through a
				// link names no state: its reading follows the paths the hook
				// client placed there (GAP-1023). Nor does the quoted script of
				// a pwsh launcher on Linux or macOS that names the state through
				// a link: the mention scan reads the launcher's words, not the
				// script, which the PowerShell reading walks (rel-1-0-10:GAP-1134).
				// A .NET open that may write the state by a mode or path known
				// only at run time is the unknown tier (rel-1-0-10:GAP-1138).
				spelled := strings.Contains(strings.ToLower(command), ".defenseclaw")
				proven, unknown := spelled && provenCMDSlashCStateWrite(request), false
				if !proven && (spelled || request.ProtectedHomeHook || strings.HasPrefix(request.Input.ActiveHome, "/")) {
					proven, unknown = provenPowerShellStateWrite(request)
				}
				// A proven GNU target-directory write (rel-1-0-10:GAP-1250) keeps its
				// own verdict over the unknown tier of a .NET open; one that moves or
				// copies a source of unknown name into the state root is the unknown
				// tier (rel-1-0-10:GAP-1260).
				if !proven && spelled {
					written, unknownSource := provenTargetDirectoryStateWrite(request)
					proven, unknown = written, unknown || unknownSource
				}
				if !proven && unknown {
					return withTrustedActionLimitFinding(findings, request.EnforcementCapable)
				}
				if !proven {
					return findings
				}
			}
		} else if !throughLink(provenStateMutationPath) && !provenStaticRedirectStateMutation(facts, request) &&
			!provenBashAggregateStateWrite(request) &&
			!provenShellRedirectStateWrite(request) && !provenCMDSlashCStateWrite(request) {
			// A proven target-directory write keeps its verdict (GAP-1250); a
			// source of unknown name in one (GAP-1260) or a .NET open known
			// only at run time (GAP-1138) is the unknown tier.
			if written, unknownSource := provenTargetDirectoryStateWrite(request); !written {
				if proven, unknown := provenPowerShellStateWrite(request); unknown || !proven && unknownSource {
					return withTrustedActionLimitFinding(findings, request.EnforcementCapable)
				} else if !proven {
					return findings
				}
			}
		}
	}
	return withProvenActiveStateMutation(request, findings)
}

// provenStaticRedirectStateMutation keeps an independently proved state
// operand when an unrelated redirect target is expanded by the shell. Both
// complete readings of the redirect reduction must prove that operand.
func provenStaticRedirectStateMutation(facts actionfacts.Facts, request trustedActionRequest) bool {
	if facts.Authoritative() {
		return false
	}
	view, twin, ok := actionfacts.DynamicRedirectTargetReduction(request.Input, facts)
	return ok && provenStateMutationPath(view, request) && provenStateMutationPath(twin, request)
}

// withProvenActiveStateMutation adds (or upgrades) the
// tamper.detector_state_write finding of a proven mutation of the active
// state: the one finding observe mode still blocks on where the pack blocks
// it (provenActiveStateMutation).
// stateCheckUnansweredTitle and stateCheckUnansweredTag name a state-write
// refusal whose only cause is a local read that did not answer in time
// (hookpaths.StateCheckUnanswered).
const (
	stateCheckUnansweredTitle = "DefenseClaw could not check this write target in time (a local folder read did not answer); retry the command"
	stateCheckUnansweredTag   = "state-check-unanswered"
)

func withProvenActiveStateMutation(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	const ruleID = "tamper.detector_state_write"
	// This protection belongs to the gateway. A selected pack may omit or
	// relabel the rule, but a proved mutation of active state is always
	// reported at the severity of the request's tier (stateWriteSeverityFor):
	// HIGH, a high alert, in the default and permissive tiers (a managed
	// install's default pack included); CRITICAL, a block in every route,
	// in strict and managed-strict (owner, 2026-11-15T15:20Z,
	// rel-1-0-10:GAP-0747). profileClassFloor keeps it at least an alert in
	// every pack and a block where it is CRITICAL.
	severity := stateWriteSeverityFor(request)
	index := slices.IndexFunc(findings, func(f RuleFinding) bool { return f.RuleID == ruleID })
	canonical := RuleFinding{
		RuleID: ruleID, Title: "DefenseClaw security state mutation", Severity: severity,
		Confidence: 0.98, Tags: []string{"cognitive-tampering", "tampering", "security-state"},
		Evidence: trustedActionInputText(request.Input, ""), LineNumber: 1,
	}
	finding := canonical
	if index >= 0 && findings[index].contributesToEnforcement() && findings[index].proof.authorizes(ruleID) &&
		(findings[index].proof.kind == findingProofActionFactsSemantic ||
			findings[index].proof.kind == findingProofActionFactsSubgraph) {
		// Keep the stronger ActionFacts proof of an actual state mutation.
		findings[index].Severity = severity
		findings[index].Title = canonical.Title
		findings[index].Tags = canonical.Tags
		return findings
	}
	if index >= 0 && findings[index].disposition == findingDispositionUnspecified &&
		!slices.Contains(findings[index].Tags, trustedParserUncertaintyTag) {
		finding = findings[index]
	} else {
		// A parser-uncertainty or audit-only finding of the rule is replaced
		// by the rule itself: the mutation is proven ($CMD > ~/f, GAP-2225).
		finding = adjustConfidence(request.Input.Tool, finding)
	}
	// The selected pack's severity may differ, but a proved mutation of
	// DefenseClaw state has one severity per tier.
	finding.Severity = severity
	finding.Title = canonical.Title
	finding.Tags = canonical.Tags
	if hookpaths.StateCheckUnanswered() {
		// The target was refused because a local read it needed did not
		// answer in time, not because it is known to be state: say so, so
		// the user retries, and tag the row so these refusals can be
		// counted apart (rel-1-0-10:GAP-1805).
		finding.Title = stateCheckUnansweredTitle
		finding.Tags = append(slices.Clone(canonical.Tags), stateCheckUnansweredTag)
	}
	finding.enforcement = findingEnforcementDetectionOnly
	if request.EnforcementCapable {
		finding.enforcement = findingEnforcementAllowed
	}
	finding = finding.withTrustedActionProof(newFindingProof(findingProofActiveStateMutation, ruleID, true))
	if index >= 0 {
		findings[index] = finding
		return findings
	}
	return append(findings, finding)
}

// provenBashAggregateStateWrite judges the Bash reading of an all-output
// redirect (true &> ~/.defenseclaw/config.yaml, echo x &>> f, : >& f):
// bash and zsh write f, while the POSIX facts read "cmd &" and "> f" and
// tie no write of f to a command (GAP-2143). The command is analyzed again
// with the redirects spelled > f 2> f, which proves the write as it does
// for the ordinary redirect.
func provenBashAggregateStateWrite(request trustedActionRequest) bool {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	spelled, ok := actionfacts.BashAggregateRedirectsAsPOSIX(command)
	if !ok {
		return false
	}
	input := request.Input
	input.Command, input.Args, input.Argv = spelled, nil, nil
	twin := request
	twin.Input = input
	return provenStateMutationPath(actionfacts.Analyze(input), twin)
}

// cmdProgramWord finds a word that starts cmd.exe in an agent's shell
// command: cmd or cmd.exe, bare or with a (single- or double-quoted) path,
// %ComSpec% and PowerShell's $env:ComSpec / ${env:ComSpec}, at the start of
// the command or of a statement, after the PowerShell call operator & or a
// pipe.
var cmdProgramWord = lazyregexp.New(`(?i)(?:^|[\s;|&(){}])(?:"[^"\r\n]*?[\\/]|'[^'\r\n]*?[\\/]|"|'|[^\s"';|&(){}]*[\\/])?(?:cmd(?:\.exe)?|\$\{?env:comspec\}?|%comspec%)["']?`)

// cmdOuterReading is a grammar the outer shell may read a command with. A
// Windows tool call does not say which shell runs it (Codex names its
// PowerShell tool Bash, shell_command may be Git Bash), so a cmd program word
// counts when any reading runs it: a text span hides it only when every
// reading hides it (over-block, never under-block; checker it10 RV10-1).
type cmdOuterReading int

const (
	cmdReadingPowerShell cmdOuterReading = iota
	cmdReadingGitBash
	cmdReadingCMD
)

// cmdTextSpan is a part of a shell command the outer shell reads as text,
// not as a statement: a terminated quoted word, a # comment, a PowerShell
// <# #> block comment or here-string. runs marks a quoted word that is itself
// run as a command line (any string of a powershell/pwsh/Invoke-Expression
// statement, a string after a bash/sh -c flag); args marks a Start-Process
// -ArgumentList string, which is the command line of the program it starts.
//
// expands marks a span whose $(...) (and Git Bash `...`) bodies run: a
// double-quoted word or an unquoted Git Bash here-document body. heredoc
// marks a Git Bash here-document body, whose runs (fed to a shell) and
// cmdFeed (fed to cmd.exe) are set from its command line (checker it11
// RV11-1). argvRuns marks a Git Bash double-quoted word whose command
// substitution holds a here-document and whose output is the argv or input
// of a launcher, an unknown program, a shell or cmd (env "$(cat <<EOF)"):
// the bodies of those here-documents are read as run by a shell and cmd
// (GAP-2539).
type cmdTextSpan struct {
	start, end       int
	inner            string
	runs, args       bool
	expands, heredoc bool
	cmdFeed          bool
	argvRuns         bool
}

func cmdSingleQuote(r rune, reading cmdOuterReading) bool {
	switch reading {
	case cmdReadingCMD:
		return false
	case cmdReadingPowerShell:
		// PowerShell also reads the typographic single quotes as quotes.
		return r == '\'' || r == '‘' || r == '’' || r == '‚' || r == '‛'
	}
	return r == '\''
}

func cmdDoubleQuote(r rune, reading cmdOuterReading) bool {
	if reading == cmdReadingPowerShell {
		return r == '"' || r == '“' || r == '”' || r == '„'
	}
	return r == '"'
}

// cmdQuotedWord reads the quoted word that starts at i. ok is false when no
// quote starts there or the word is not terminated: an unterminated quote is
// not text, the scan goes on (RV10-1). In the Git Bash reading a $(...)
// inside a double-quoted word is a command substitution that bash parses on
// its own, so a quote inside it (or inside a here-document it opens) does
// not end the word (pod it17: git commit -m "$(cat <<'EOF' ... "cmd //c"
// ... EOF )" was read as two words and the mention blocked). budget bounds
// that nested reading; past it the word ends at the next quote as before.
func cmdQuotedWord(command string, i int, reading cmdOuterReading, budget *int) (end int, inner string, ok bool) {
	open, size := utf8.DecodeRuneInString(command[i:])
	single, double := cmdSingleQuote(open, reading), cmdDoubleQuote(open, reading)
	if !single && !double {
		return 0, "", false
	}
	closes := func(r rune) bool {
		if single {
			return cmdSingleQuote(r, reading)
		}
		return cmdDoubleQuote(r, reading)
	}
	for j := i + size; j < len(command); {
		r, w := utf8.DecodeRuneInString(command[j:])
		if double && j+w < len(command) &&
			((reading == cmdReadingPowerShell && r == '`') || (reading == cmdReadingGitBash && r == '\\')) {
			_, next := utf8.DecodeRuneInString(command[j+w:])
			j += w + next
			continue
		}
		if double && reading != cmdReadingCMD && r == '$' && j+1 < len(command) && command[j+1] == '(' &&
			budget != nil && *budget > 0 {
			end, ok := 0, false
			if reading == cmdReadingGitBash {
				end, ok = cmdGitBashSubstitutionEnd(command, j+2, budget)
			} else {
				end, ok = cmdPowerShellSubexpressionEnd(command, j+2, budget)
			}
			if ok {
				j = end
				continue
			}
		}
		if closes(r) {
			if reading == cmdReadingPowerShell && j+w < len(command) {
				if r2, w2 := utf8.DecodeRuneInString(command[j+w:]); closes(r2) {
					j += w + w2 // PowerShell '' or "" inside the word.
					continue
				}
			}
			inner = command[i+size : j]
			if single && reading == cmdReadingPowerShell {
				inner = strings.ReplaceAll(inner, "''", "'")
			}
			return j + w, inner, true
		}
		j += w
	}
	return 0, "", false
}

// cmdGitBashSubstitutionEnd returns the offset after the ) that closes the
// Git Bash command substitution whose body starts at start: quotes,
// backticks, nested parentheses and here-document bodies inside it are
// skipped as bash parses them. ok is false when it does not close (or the
// budget runs out): the caller keeps its plain reading.
func cmdGitBashSubstitutionEnd(command string, start int, budget *int) (int, bool) {
	depth := 1
	var pending []cmdHeredoc
	for j := start; j < len(command); {
		*budget--
		if *budget <= 0 {
			return 0, false
		}
		c := command[j]
		switch {
		case c == '\\':
			j += 2
			continue
		case c == '\'':
			k := strings.IndexByte(command[j+1:], '\'')
			if k < 0 {
				return 0, false
			}
			*budget -= k
			j += k + 2
			continue
		case c == '"':
			end, _, ok := cmdQuotedWord(command, j, cmdReadingGitBash, budget)
			if !ok {
				return 0, false
			}
			*budget -= end - j
			j = end
			continue
		case c == '`':
			k := strings.IndexByte(command[j+1:], '`')
			if k < 0 {
				return 0, false
			}
			*budget -= k
			j += k + 2
			continue
		case c == '<' && j+1 < len(command) && command[j+1] == '<' && (j+2 >= len(command) || command[j+2] != '<'):
			if doc, end, ok := cmdHeredocDelimiter(command, j+2); ok {
				pending = append(pending, doc)
				j = end
				continue
			}
		case c == '\n' && len(pending) > 0:
			bodies, end := cmdHeredocBodies(command, j+1, pending, nil)
			if len(bodies) < len(pending) {
				// The search read the rest of the command (GAP-2557).
				*budget -= len(command) - j
				return 0, false
			}
			*budget -= end - j
			pending = nil
			j = end
			continue
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return j + 1, true
			}
		}
		j++
	}
	return 0, false
}

// cmdPowerShellSubexpressionEnd returns the offset after the ) that closes
// the PowerShell $(...) of a double-quoted string whose body starts at
// start: strings, backtick escapes, comments and nested parentheses inside
// it are skipped as PowerShell parses them. ok is false when it does not
// close (or the budget runs out).
func cmdPowerShellSubexpressionEnd(command string, start int, budget *int) (int, bool) {
	depth := 1
	for j := start; j < len(command); {
		*budget--
		if *budget <= 0 {
			return 0, false
		}
		c := command[j]
		tokenStart := j == 0 || strings.IndexByte(" \t\r\n;|&(){}", command[j-1]) >= 0
		switch {
		case c == '`':
			j += 2
			continue
		case c == '#' && tokenStart:
			k := strings.IndexByte(command[j:], '\n')
			if k < 0 {
				return 0, false
			}
			*budget -= k
			j += k
			continue
		case c == '<' && j+1 < len(command) && command[j+1] == '#':
			k := strings.Index(command[j+2:], "#>")
			if k < 0 {
				return 0, false
			}
			*budget -= k
			j += k + 4
			continue
		case c == '\'' || c == '"':
			end, _, ok := cmdQuotedWord(command, j, cmdReadingPowerShell, budget)
			if !ok {
				return 0, false
			}
			*budget -= end - j
			j = end
			continue
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return j + 1, true
			}
		}
		j++
	}
	return 0, false
}

// cmdHeredoc is a pending Git Bash here-document of cmdTextSpans.
type cmdHeredoc struct {
	delim             string
	stripTabs, quoted bool
	level             int
	runs, cmdFeed     bool
	// op is the offset of the << operator and lineStart the start of its
	// logical command line (cmdTextSpansRead).
	op, lineStart int
}

// cmdHeredocDelimiter reads the delimiter word after a Git Bash << at start
// (quote removal as bash does it, $'EOF' and $"EOF" included). ok is false
// for a here-string (<<<) or no word.
func cmdHeredocDelimiter(command string, start int) (doc cmdHeredoc, end int, ok bool) {
	j := start
	if j < len(command) && command[j] == '<' {
		return doc, 0, false
	}
	if j < len(command) && command[j] == '-' {
		doc.stripTabs = true
		j++
	}
	for j < len(command) && (command[j] == ' ' || command[j] == '\t') {
		j++
	}
	var word strings.Builder
	for j < len(command) && strings.IndexByte(" \t\r\n;|&<>()", command[j]) < 0 {
		switch c := command[j]; c {
		case '$':
			if j+1 < len(command) && (command[j+1] == '\'' || command[j+1] == '"') {
				j++
				continue
			}
			word.WriteByte(c)
			j++
		case '\'', '"':
			q := strings.IndexByte(command[j+1:], c)
			if q < 0 {
				return doc, 0, false
			}
			word.WriteString(command[j+1 : j+1+q])
			doc.quoted = true
			j += q + 2
		case '\\':
			doc.quoted = true
			if j+1 < len(command) {
				word.WriteByte(command[j+1])
			}
			j += 2
		default:
			word.WriteByte(c)
			j++
		}
	}
	doc.delim = word.String()
	return doc, min(j, len(command)), doc.delim != ""
}

// cmdHeredocFeeds reports whether the logical command line around a
// here-document operator at offset op of line hands its body to a shell
// (bash <<EOF, cat <<EOF | sh) or to cmd.exe (cmd <<EOF): then the body runs
// (over-block, never under-block). Every word of the line counts except,
// with trust on, the arguments of a known text consumer (grep cmd <<EOF,
// cat <<EOF | rg bash): they name text the consumer reads, not a receiver
// (GAP-2530). The line is the whole command line as bash reads it: lines
// joined by a backslash-newline, quoted words and substitutions that span
// lines included (bash \<newline><<EOF, cat <<EOF \<newline>| bash;
// GAP-2538).
func cmdHeredocFeeds(line string, op int, trust bool) (runs, cmdFeed bool) {
	for _, word := range cmdLineReceiverWords(line, op, trust) {
		if word == cmdUnknownReceiver {
			// "$BASH" -s <<EOF, $0 <<EOF, env "$BASH" -s <<EOF: the program
			// is not known, so the body is read as a shell's and as cmd's
			// (GAP-2536).
			return true, true
		}
		if cmdShellWord(word) != "" {
			runs = true
		}
		w := strings.NewReplacer("{", "", "}", "").Replace(strings.ToLower(strings.Trim(word, `"'`)))
		if k := strings.LastIndexAny(w, `\/`); k >= 0 {
			w = w[k+1:]
		}
		switch strings.TrimSuffix(w, ".exe") {
		case "cmd", "%comspec%", "$env:comspec":
			runs, cmdFeed = true, true
		}
	}
	return runs, cmdFeed
}

var cmdAssignmentWord = lazyregexp.New(`^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=`)

// cmdRedefinesCommand matches a function definition, name() or "name"()
// (the quoted name is blanked by cmdCodeOutsideText), on the code outside
// here-document bodies, quoted words and comments: prose in a body or a
// title is no definition (GAP-2530 checker it2). An empty ( ) after =, $,
// <, > or an extglob operator is an array or a substitution.
var cmdRedefinesCommand = lazyregexp.New(`(^|[^=$<>@!*+?])\s*\(\s*\)`)

// cmdRedefiningCommands are the command words that can make a text
// consumer's name run something else (alias, function, hash -p, enable) or
// run a string or file in the current shell (eval, source, ., trap). They
// are matched as command words after quote removal with backslashes
// dropped (\alias, al""ias, "eval"; GAP-2536), so a keyword that is only an
// argument (grep -n alias) or prose stays text.
var cmdRedefiningCommands = map[string]bool{
	"function": true, "alias": true, "unalias": true, "hash": true, "enable": true,
	"eval": true, "source": true, "trap": true, ".": true,
}

// cmdUnknownReceiver marks a statement that can run a program named by an
// expansion ($BASH, "$0", ${SHELL:-sh}, $(...)) as its command word or
// through a launcher (env "$BASH" -s): the program it runs is not known
// (GAP-2536). Among cmdRedefines command words it marks an expansion.
const cmdUnknownReceiver = "\x00unknown-receiver"

// cmdPathAssignment marks a statement that assigns PATH (PATH=.:$PATH,
// export PATH=...): a consumer name may then run another program
// (GAP-2536 checker it4).
const cmdPathAssignment = "\x00path-assignment"

// cmdReservedMark prefixes a reserved word that opens or closes a compound
// command (cmdCompoundReserved) among the cmdRedefines command words.
const cmdReservedMark = "\x00reserved:"

// cmdCompoundReserved are the reserved words, read before a statement's
// command word, that open (+1) or close (-1) a compound command whose
// output can still go on to a pipe (done | bash, } | bash; GAP-2547).
var cmdCompoundReserved = map[string]int{
	"{": 1, "if": 1, "while": 1, "until": 1,
	"}": -1, "fi": -1, "done": -1, "esac": -1,
}

// cmdCompoundShape returns how many compound commands the Git Bash text
// opens less the ones it closes (for, case and select count as command
// words), and whether a statement of it starts with a closer (or the text
// with a ) ), so the output of what it closes goes on to the rest of the
// line (GAP-2547).
func cmdCompoundShape(text string) (delta int, closes bool) {
	var words []string
	cmdScanReceiverWords(text, 0, 0, false, -1, &words, nil)
	for _, w := range words {
		switch w {
		case "for", "case", "select":
			delta++
		}
		if r, ok := strings.CutPrefix(w, cmdReservedMark); ok {
			delta += cmdCompoundReserved[r]
			closes = closes || cmdCompoundReserved[r] < 0
		}
	}
	return delta, closes || strings.HasPrefix(strings.TrimLeft(text, " \t"), ")")
}

// cmdLineContinues reports a Git Bash line that ends in a pipe or list
// operator (|, |&, ||, &&), before any comment: the command goes on on the
// next line that holds a word, after any here-document bodies (GAP-2547).
func cmdLineContinues(line string) bool {
	t := strings.TrimRight(cmdLineCode(line), " \t\r")
	return strings.HasSuffix(t, "|") || strings.HasSuffix(t, "|&") || strings.HasSuffix(t, "&&")
}

// cmdLineHasWord reports a Git Bash line with a word outside its comment.
// Bash reads a pipe or list left open across blank and comment-only lines
// (GAP-2547 checker it7 X03, X04), so such a line neither continues nor
// ends the command.
func cmdLineHasWord(line string) bool {
	return strings.Trim(cmdLineCode(line), " \t\r") != ""
}

// cmdLineCode returns Git Bash text with its comments removed: a # that
// starts a word outside quotes, up to the end of its physical line. The
// logical line of a here-document inside ( ) or $( ) spans several physical
// lines, so a comment on an earlier one hides nothing after its newline
// (GAP-2547 checker it8 Y01, Y05, Y06).
func cmdLineCode(line string) string {
	var b strings.Builder
	var quote byte
	from := 0
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\\' && quote != '\'':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || strings.IndexByte(" \t\r\n;|&()<>", line[i-1]) >= 0):
			b.WriteString(line[from:i])
			j := strings.IndexByte(line[i:], '\n')
			if j < 0 {
				return b.String()
			}
			i += j
			from = i
		}
	}
	if from == 0 {
		return line
	}
	b.WriteString(line[from:])
	return b.String()
}

// cmdExpansionInertCommands never run an argument or hand standard input to
// one, so an expansion among their arguments (cd "$REPO", echo "$X") names
// no receiver. A path to one of them may be any program.
var cmdExpansionInertCommands = map[string]bool{
	"cd": true, "pushd": true, "echo": true, "printf": true, "test": true, "[": true, "[[": true,
	"mkdir": true, "ls": true, "rm": true, "cp": true, "mv": true, "touch": true, "export": true,
	"true": true, "false": true, ":": true,
}

// cmdRedefines reports whether the Git Bash command, with the text spans of
// its untrusted reading, redefines a command (cmdRedefinesCommand,
// cmdRedefiningCommands). The command words are read from the command with
// only here-document bodies and comments blanked.
func cmdRedefines(command string, spans []cmdTextSpan) bool {
	if cmdRedefinesCommand.MatchString(cmdCodeOutsideText(command, spans)) {
		return true
	}
	var prose []cmdTextSpan
	for _, span := range spans {
		if span.heredoc || (span.start >= 0 && span.start < len(command) && command[span.start] == '#') {
			prose = append(prose, span)
		}
	}
	var words []string
	cmdScanReceiverWords(cmdCodeOutsideText(command, prose), 0, 0, false, -1, &words, nil)
	for _, w := range words {
		// An expansion command word can be any of them ($E 'grep() { bash; }'
		// after E=eval, $'alias' grep=bash), and a PATH assignment changes
		// which program a consumer name runs (GAP-2536 checker it4).
		if cmdRedefiningCommands[w] || w == cmdUnknownReceiver || w == cmdPathAssignment {
			return true
		}
	}
	return false
}

// cmdCodeOutsideText returns command with the text spans of one reading
// (here-document bodies, quoted words, comments) blanked. A quoted word
// that runs in the current shell needs eval, source, . or trap outside it;
// a command substitution runs in a subshell.
func cmdCodeOutsideText(command string, spans []cmdTextSpan) string {
	b := []byte(command)
	for _, span := range spans {
		for k := max(0, span.start); k < min(span.end, len(b)); k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	return string(b)
}

// cmdHeredocTextConsumers read standard input as text and never run it, so a
// shell or cmd word among their arguments is a pattern or a title, not a
// receiver (GAP-2530). Programs with a way to run their input (sed e, awk
// system, sort --compress-program, git aliases, a pager) are not listed.
var cmdHeredocTextConsumers = map[string]bool{
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "wc": true, "head": true, "tail": true,
	"cut": true, "tr": true, "cat": true, "tac": true, "tee": true, "diff": true, "nl": true,
	"fold": true, "fmt": true, "rev": true, "base64": true, "od": true, "xxd": true, "jq": true,
	"md5sum": true, "sha1sum": true, "sha256sum": true, "gh": true,
}

// cmdLineReceiverWords returns the words of one Git Bash line that can name
// the program that receives a here-document body: every word of every
// statement (split at ; | & ( ) and read inside $( ), backticks and process
// substitutions, quoted or not), less redirect targets, except the
// arguments of a statement whose command word (past reserved words and time
// options) is a bare known text consumer (grep cmd <<EOF). It over-reads,
// never under-reads: with trust false every word counts. op is the offset of
// the here-document operator in line (-1 for none): a substitution that
// holds it (git commit -m "$(cat <<EOF) is where the body goes, not an
// expansion naming the outer program.
func cmdLineReceiverWords(line string, op int, trust bool) []string {
	words, _ := cmdScanReceiverWords(line, 0, 0, trust, op, nil, nil)
	return words
}

// cmdScanReceiverWords scans line from i to the unquoted closer () or a
// backtick, 0 for the end of the line) and returns the receiver words and
// the offset of the closer. An unquoted newline ends a statement. A non-nil
// commandWords gets the command word of every statement with backslashes
// dropped, and the word after builtin or command, followed by
// cmdUnknownReceiver when it is an expansion, and cmdPathAssignment for a
// statement that assigns PATH (cmdRedefines).
func cmdScanReceiverWords(line string, i int, closer byte, trust bool, op int, commandWords *[]string, lines *hookpaths.HeredocLines) (words []string, end int) {
	if lines == nil {
		// One finder for line and every substitution read in it (GAP-2557).
		lines = &hookpaths.HeredocLines{}
	}
	end = cmdScanReceiverWordsInto(line, i, closer, trust, op, commandWords, lines, &words)
	return words, end
}

// cmdScanReceiverWordsInto is cmdScanReceiverWords appending to words, which
// the substitutions read in it share: copying the words of each nested
// $( up a level was quadratic in the nesting (GAP-2557).
func cmdScanReceiverWordsInto(line string, i int, closer byte, trust bool, op int, commandWords *[]string, lines *hookpaths.HeredocLines, words *[]string) int {
	var stmt []string
	var stmtExp []bool // stmtExp[k]: stmt[k] holds an expansion
	var stmtOp []bool  // stmtOp[k]: stmt[k] is a substitution that holds op
	// docs are the here-documents opened on the current line: their bodies
	// are text read by their own receiver, skipped as bash skips them.
	var docs []cmdHeredoc
	var word strings.Builder
	inWord, wordExp, wordOp, redirect, depth := false, false, false, false, 0
	flush := func() {
		if !inWord {
			return
		}
		w, exp, holds := word.String(), wordExp, wordOp
		word.Reset()
		inWord, wordExp, wordOp = false, false, false
		if redirect {
			redirect = false
			return
		}
		stmt = append(stmt, w)
		stmtExp = append(stmtExp, exp)
		stmtOp = append(stmtOp, holds)
	}
	finish := func() {
		flush()
		redirect = false
		if commandWords != nil {
			k, _ := cmdStatementCommand(stmt)
			if cmdAssignsPath(stmt, k) {
				*commandWords = append(*commandWords, cmdPathAssignment)
			}
			for _, w := range stmt[:k] {
				if cmdCompoundReserved[w] != 0 {
					*commandWords = append(*commandWords, cmdReservedMark+w)
				}
			}
			for ; k < len(stmt); k++ {
				w := strings.ReplaceAll(stmt[k], `\`, "")
				*commandWords = append(*commandWords, w)
				if stmtExp[k] || strings.HasPrefix(stmt[k], "$") {
					*commandWords = append(*commandWords, cmdUnknownReceiver)
				}
				if w != "builtin" && w != "command" && !strings.HasPrefix(w, "-") {
					break
				}
			}
		}
		*words = append(*words, cmdStatementReceiverWords(stmt, stmtExp, stmtOp, trust)...)
		stmt, stmtExp, stmtOp = stmt[:0], stmtExp[:0], stmtOp[:0]
	}
	// nested reads a command substitution: its statements are commands of
	// their own, and no consumer in them is trusted: a consumer printing
	// its argument is how a substitution yields a program name
	// ("$(grep -m1 bash /etc/shells)" <<EOF, checker it2). The outer word
	// only gets a marker, so it never reads as a consumer name.
	nested := func(j int, cl byte) int {
		e := cmdScanReceiverWordsInto(line, j, cl, false, op, commandWords, lines, words)
		word.WriteString("$()")
		inWord = true
		// Its output is an expansion, unless it holds the here-document
		// operator: git commit -m "$(cat <<EOF hands the body to cat, whose
		// output is the word (cmdArgvHeredocReceiver, GAP-2539).
		if op < j || op > e {
			wordExp = true
		} else {
			wordOp = true
		}
		return e
	}
	var quote byte
	for ; i < len(line); i++ {
		c := line[i]
		switch quote {
		case '\'':
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		case '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(line) && line[i+1] == '\n':
				i++ // a backslash-newline is removed (GAP-2538).
			case c == '\\' && i+1 < len(line):
				word.WriteByte(c)
				word.WriteByte(line[i+1])
				i++
			case c == '$' && i+1 < len(line) && line[i+1] == '(':
				i = nested(i+2, ')')
			case c == '`':
				i = nested(i+1, '`')
			default:
				word.WriteByte(c)
				wordExp = wordExp || c == '$'
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			inWord = true
		case '\\':
			if i+1 < len(line) && line[i+1] == '\n' {
				// A backslash-newline joins the lines: bash removes it
				// (bash \<newline><<EOF; GAP-2538).
				i++
				continue
			}
			word.WriteByte(c)
			if i+1 < len(line) {
				word.WriteByte(line[i+1])
				i++
			}
			inWord = true
		case ' ', '\t', '\r':
			flush()
		case '<', '>':
			// An fd number before the operator (2>file) is part of it.
			if w := word.String(); inWord && w != "" && strings.Trim(w, "0123456789") == "" {
				word.Reset()
				inWord = false
			}
			flush()
			redirect = true
			// One operator: > >> >| >& < << <<- <<< <& <>. A | or & after
			// it that is not part of it separates statements.
			if i+1 < len(line) {
				switch n := line[i+1]; {
				case c == '>' && (n == '>' || n == '|' || n == '&'), c == '<' && (n == '&' || n == '>'):
					i++
				case c == '<' && n == '<':
					i++
					if doc, _, ok := cmdHeredocDelimiter(line, i+1); ok {
						docs = append(docs, doc)
					}
					if i+1 < len(line) && (line[i+1] == '<' || line[i+1] == '-') {
						i++
					}
				}
			}
			if line[i] == '&' && i+1 < len(line) && line[i+1] == '-' {
				// >&- and <&- close a descriptor: no target word.
				i++
				redirect = false
			}
		case '&':
			if i+1 < len(line) && line[i+1] == '>' {
				flush()
				i++
				if i+1 < len(line) && line[i+1] == '>' {
					i++
				}
				redirect = true
				continue
			}
			finish()
		case ';', '|', '\n':
			finish()
			if c == '\n' && len(docs) > 0 {
				// The bodies start after this line; a body that does not
				// end stays scanned (over-read).
				if bodies, bodyEnd := cmdHeredocBodies(line, i+1, docs, lines); len(bodies) == len(docs) {
					i = bodyEnd
				}
				docs = nil
			}
		case '(':
			if w := word.String(); inWord && strings.HasSuffix(w, "$") {
				i = nested(i+1, ')')
				continue
			}
			finish()
			depth++
		case ')':
			if closer == ')' && depth == 0 {
				finish()
				return i
			}
			depth--
			finish()
		case '`':
			if closer == '`' {
				finish()
				return i
			}
			i = nested(i+1, '`')
		default:
			word.WriteByte(c)
			inWord = true
			// $( is read by the ( case.
			wordExp = wordExp || c == '$' && (i+1 >= len(line) || line[i+1] != '(')
		}
	}
	finish()
	return len(line)
}

// cmdStatementCommand returns the index of the command word of stmt, past
// assignments, reserved words and time with its options, and whether an
// assignment comes before it.
func cmdStatementCommand(stmt []string) (k int, assigned bool) {
	for k < len(stmt) {
		switch w := stmt[k]; {
		case cmdAssignmentWord.MatchString(w):
			assigned = true
			k++
		case w == "{" || w == "}" || w == "!" || w == "if" || w == "then" || w == "else" || w == "elif" ||
			w == "fi" || w == "do" || w == "done" || w == "while" || w == "until" || w == "esac":
			k++
		case w == "time":
			k++
			for k < len(stmt) && strings.HasPrefix(stmt[k], "-") {
				k++
			}
		default:
			return k, assigned
		}
	}
	return k, assigned
}

// cmdStatementReceiverWords returns the words of one statement that can
// name a receiver: none when its command word is a bare known text consumer
// (no assignment before it, trust on), every word otherwise, plus
// cmdUnknownReceiver when it can run a program named by an expansion
// (cmdExpansionReceiver).
func cmdStatementReceiverWords(stmt []string, exp, ops []bool, trust bool) []string {
	k, assigned := cmdStatementCommand(stmt)
	if k < len(stmt) && trust && !assigned && cmdTextConsumerStatement(stmt[k:]) {
		// PATH=... grep runs another program: never a trusted consumer.
		return nil
	}
	words := cmdSplitQuotedWords(stmt)
	if k < len(stmt) && (cmdExpansionReceiver(stmt, exp, k) || cmdArgvHeredocReceiver(stmt, ops, k)) {
		words = append(words[:len(words):len(words)], cmdUnknownReceiver)
	}
	return words
}

// cmdExpansionReceiver reports whether the statement with command word k
// can run a program named by an expansion: the command word itself
// ("$BASH" -s, $0) or, unless the command word runs no argument
// (cmdExpansionInertCommands), any later word: env "$BASH" -s, nice $0 -s,
// timeout 5 "$BASH", xargs -0 "$BASH" -c (GAP-2536 checker it4). Launchers
// are not listed, so an unknown one over-reads, never under-reads.
func cmdExpansionReceiver(stmt []string, exp []bool, k int) bool {
	if exp[k] || strings.HasPrefix(stmt[k], "$") {
		return true
	}
	if cmdExpansionInertCommands[stmt[k]] {
		return false
	}
	for _, e := range exp[k+1:] {
		if e {
			return true
		}
	}
	return false
}

// cmdArgvHeredocReceiver reports whether a word of the statement with
// command word k is a substitution that holds the here-document operator
// (ops) and hands the body over as the argv of a program that may run it:
// the command word itself ($(cat <<EOF)), or an argument of any command but
// a known text consumer, a command that runs no argument
// (cmdExpansionInertCommands) and git commit, tag or notes, whose argument
// is a message: env $(cat <<EOF), exec, timeout `cat <<EOF`, xargs
// (GAP-2539). Unknown programs over-read, never under-read.
func cmdArgvHeredocReceiver(stmt []string, ops []bool, k int) bool {
	if !slices.Contains(ops[k:], true) {
		return false
	}
	if ops[k] {
		return true
	}
	return !cmdExpansionInertCommands[stmt[k]] && !cmdTextConsumerStatement(stmt[k:]) && !cmdGitMessageStatement(stmt[k:])
}

// cmdGitMessageStatement reports git commit, tag or notes (past -C and -c
// with their values and other options): a git alias cannot shadow a git
// command, and their arguments are a message or names, never a program.
func cmdGitMessageStatement(args []string) bool {
	if strings.TrimSuffix(strings.ToLower(args[0]), ".exe") != "git" {
		return false
	}
	for i := 1; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-C" || a == "-c":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return a == "commit" || a == "tag" || a == "notes"
		}
	}
	return false
}

// cmdAssignsPath reports whether the statement with command word k assigns
// PATH: before the command word (PATH=.:$PATH; or PATH=... grep) or as an
// argument of export, declare, typeset, local or readonly.
func cmdAssignsPath(stmt []string, k int) bool {
	path := func(w string) bool { return strings.HasPrefix(w, "PATH=") || strings.HasPrefix(w, "PATH+=") }
	for _, w := range stmt[:k] {
		if path(w) {
			return true
		}
	}
	if k < len(stmt) {
		switch stmt[k] {
		case "export", "declare", "typeset", "local", "readonly":
			for _, w := range stmt[k+1:] {
				if path(w) {
					return true
				}
			}
		}
	}
	return false
}

// cmdSplitQuotedWords returns words plus the pieces of every word that
// holds a blank or an operator (a quoted word): eval 'bash -s' <<EOF hands
// the body to bash as the whole-line split read it (over-read, never
// under-read; GAP-2530 checker it2).
func cmdSplitQuotedWords(words []string) []string {
	out := words
	for _, w := range words {
		if strings.ContainsAny(w, " \t\r;|&()<>{}") {
			if len(out) == len(words) {
				out = append([]string(nil), words...)
			}
			out = append(out, strings.FieldsFunc(w, func(r rune) bool {
				return strings.ContainsRune(" \t\r;|&()<>{}", r)
			})...)
		}
	}
	return out
}

// cmdTextConsumerStatement reports whether args (command word first) runs
// a known text consumer that cannot run its input: a bare name (a path may
// be any program), gh only for pr, issue, release, api and gist (an alias
// may run a shell), and no --pre or --pager option.
func cmdTextConsumerStatement(args []string) bool {
	name := strings.TrimSuffix(strings.ToLower(args[0]), ".exe")
	if !cmdHeredocTextConsumers[name] {
		return false
	}
	if name == "gh" {
		if len(args) < 2 {
			return false
		}
		switch args[1] {
		case "pr", "issue", "release", "api", "gist":
		default:
			return false
		}
	}
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "--pre") || strings.HasPrefix(a, "--pager") {
			return false
		}
	}
	return true
}

// cmdHeredocBodies reads the bodies of the pending here-documents from start
// (the line after the one that ends the command) and returns their spans and
// the offset after the last one read. A delimiter line that is never found
// ends the reading there: the rest stays scanned (over-block, never
// under-block).
//
// lines finds the delimiter lines; nil scans line by line, which costs the
// text up to the delimiter (or the rest of the command when none comes).
func cmdHeredocBodies(command string, start int, docs []cmdHeredoc, lines *hookpaths.HeredocLines) (spans []cmdTextSpan, end int) {
	pos := start
	end = start
	for _, doc := range docs {
		bodyStart := pos
		lineStart, lineEnd, found := lines.Next(command, doc.delim, doc.stripTabs, pos)
		if !found {
			break
		}
		spans = append(spans, cmdTextSpan{start: bodyStart, end: lineEnd, inner: command[bodyStart:lineStart],
			expands: !doc.quoted, heredoc: true, runs: doc.runs, cmdFeed: doc.cmdFeed})
		end = lineEnd
		pos = lineEnd + 1
	}
	return spans, end
}

// cmdTextSpans scans command for the parts the outer shell reads as text in
// one reading. Spans are in order and do not overlap. A Git Bash
// here-document body at command level is a span (checker it11 RV11-1).
// stops is true when the PowerShell reading meets a << that starts a token:
// PowerShell cannot parse the command, so it runs none of it (as in
// hookpaths actionWindowsExpressionBodies, RV5-1, RV6-1).
func cmdTextSpans(command string, reading cmdOuterReading) (spans []cmdTextSpan, stops bool) {
	// A here-document receiver trusts a text consumer only when the code
	// outside the text spans redefines no command (GAP-2530 checker it2):
	// span offsets do not depend on trust, so the untrusted reading finds
	// the spans first.
	spans, stops = cmdTextSpansRead(command, reading, false)
	if reading != cmdReadingGitBash || stops || !strings.Contains(command, "<<") {
		return spans, stops
	}
	if cmdRedefines(command, spans) {
		// A redefinition can make any consumer name a shell or cmd (alias
		// grep=bash on an earlier line): every here-document body is read
		// as run by both (over-read, never under-read; GAP-2536).
		for k := range spans {
			if spans[k].heredoc {
				spans[k].runs, spans[k].cmdFeed = true, true
			}
		}
		return spans, stops
	}
	return cmdTextSpansRead(command, reading, true)
}

// cmdTextSpansRead is cmdTextSpans with the here-document consumer trust
// of cmdHeredocFeeds.
func cmdTextSpansRead(command string, reading cmdOuterReading, trust bool) (spans []cmdTextSpan, stops bool) {
	// Git Bash: open ${...}, arithmetic (( )), name[...] and ( ) frames; a
	// << inside the first three is no here-document operator (RV5-2).
	braces, arith, subscript, parens := 0, 0, 0, 0
	var pending []cmdHeredoc
	// nestBudget bounds the nested $(...) reading of double-quoted words
	// (linear in the command, RV10-3).
	nestBudget := 8*len(command) + 1<<16
	// lines finds the delimiter lines of the bodies in linear time (GAP-2557).
	lines := &hookpaths.HeredocLines{}
	// stopParsing is the end of a PowerShell --% tail: verbatim text.
	stopParsing := -1
	commentSeparators := " \t\r\n;|&()<>"
	if reading == cmdReadingPowerShell {
		commentSeparators = " \t\r\n;|&(){}"
	}
	commentStart := func(i int) bool {
		return i == 0 || strings.IndexByte(commentSeparators, command[i-1]) >= 0
	}
	n := len(command)
	// lineStart is the start of the Git Bash logical command line: after
	// the last newline outside ( ) frames, quoted words, here-document
	// bodies and backslash-newlines (GAP-2538). lineQuoted are the double-
	// quoted spans of that line with a << inside (GAP-2539).
	lineStart := 0
	var lineQuoted []int
	// feedBudget bounds the receiver reads (cmdHeredocFeeds, cmdCompoundShape)
	// of one command: each costs its text, and a command needing more is
	// read as feeding every body to a shell and cmd (over-read, never
	// under-read; linear in the command, GAP-2539 checker it6).
	feedBudget := 8*len(command) + 1<<16
	feeds := func(text string, op int) (runs, cmdFeed bool) {
		if feedBudget -= len(text) + 1; feedBudget < 0 {
			return true, true
		}
		return cmdHeredocFeeds(text, op, trust)
	}
	shape := func(text string) (int, bool) {
		if feedBudget -= len(text) + 1; feedBudget < 0 {
			return 1, true
		}
		return cmdCompoundShape(text)
	}
	// awaiting are the here-document bodies whose command goes on after
	// them (GAP-2547): the line of << ended in a pipe or list operator
	// (cat <<EOF |, reading), or the body is inside a ( ), $( ) or compound
	// command that a later line closes and pipes on (( cat <<EOF .. ) | bash,
	// } | bash, done | bash). The lines that continue the command, and the
	// lines that close a construct, are read as the bodies' receivers too.
	// compound counts the compound commands open at lineStart; physStart is
	// the start of the current physical line and skipNL the newline that
	// ends the last body read.
	//
	// The bodies still reading a pipe or list (open) all read every line
	// with a word and stop together; the others (closing) read only the
	// lines that close a construct. Each group logs its reads once and a
	// body takes the reads logged after it joined when the group lets it
	// go, so a line costs the same for one body or many (GAP-2557: a
	// { } of many bodies read every line once per body).
	type awaitRead struct{ runs, cmdFeed bool }
	type awaitGroup struct {
		span, join []int
		log        []awaitRead
	}
	var open, closing awaitGroup
	release := func(g *awaitGroup) {
		if len(g.span) == 0 {
			g.log = g.log[:0]
			return
		}
		runs, cmdFeed := make([]bool, len(g.log)+1), make([]bool, len(g.log)+1)
		for e := len(g.log) - 1; e >= 0; e-- {
			runs[e], cmdFeed[e] = runs[e+1] || g.log[e].runs, cmdFeed[e+1] || g.log[e].cmdFeed
		}
		for k, at := range g.span {
			spans[at].runs = spans[at].runs || runs[g.join[k]]
			spans[at].cmdFeed = spans[at].cmdFeed || cmdFeed[g.join[k]]
		}
		g.span, g.join, g.log = g.span[:0], g.join[:0], g.log[:0]
	}
	await := func(g *awaitGroup, span int) {
		g.span = append(g.span, span)
		g.join = append(g.join, len(g.log))
	}
	compound, physStart, skipNL := 0, 0, -1
	awaitLine := func(text string) {
		if len(open.span) == 0 && len(closing.span) == 0 || !cmdLineHasWord(text) {
			return
		}
		_, closes := shape(text)
		if len(open.span) == 0 && (!closes || len(closing.span) == 0) {
			return
		}
		runs, cmdFeed := feeds(text, -1)
		if closes && len(closing.span) > 0 {
			closing.log = append(closing.log, awaitRead{runs, cmdFeed})
		}
		if len(open.span) > 0 {
			open.log = append(open.log, awaitRead{runs, cmdFeed})
		}
		// Every body that read the line reads on when it continues a pipe
		// or list (} |, done |), and waits for a closing line otherwise.
		from, to := &open, &closing
		if cmdLineContinues(text) {
			if !closes {
				return
			}
			from, to = &closing, &open
		}
		moved := slices.Clone(from.span)
		release(from)
		for _, at := range moved {
			await(to, at)
		}
	}
	argvQuoted := func(end int) {
		for _, k := range lineQuoted {
			span := spans[k]
			for from := 0; ; {
				at := strings.Index(span.inner[from:], "<<")
				if at < 0 {
					break
				}
				op := span.start + 1 + from + at
				if runs, cmdFeed := feeds(command[lineStart:end], op-lineStart); runs || cmdFeed {
					spans[k].argvRuns = true
					break
				}
				from += at + 2
			}
		}
		lineQuoted = lineQuoted[:0]
	}
	for i := 0; i < n; {
		c := command[i]
		switch {
		case (reading == cmdReadingPowerShell && c == '`' ||
			reading == cmdReadingGitBash && c == '\\' ||
			reading == cmdReadingCMD && c == '^') && i+1 < n:
			i += 2
			continue
		case reading == cmdReadingPowerShell && c == '$' && i+1 < n && command[i+1] == '$':
			i += 2 // $$ is one variable: a { after it opens a script block (RV7-1).
			continue
		case reading == cmdReadingPowerShell && c == '$' && i+1 < n && command[i+1] == '{':
			// A braced variable name (${a<<b}, ${a'b}) is one token up to
			// its first unescaped } (RV6-1); unterminated: scanned on.
			j := i + 2
			for j < n && command[j] != '}' {
				if command[j] == '`' {
					j++
				}
				j++
			}
			if j < n {
				i = j + 1
				continue
			}
		case reading == cmdReadingPowerShell && c == '-' && strings.HasPrefix(command[i:], "--%") &&
			(i == 0 || command[i-1] == ' ' || command[i-1] == '\t') &&
			(i+3 == n || strings.IndexByte(" \t\r\n", command[i+3]) >= 0):
			stopParsing = n
			if k := strings.IndexAny(command[i:], "\r\n|"); k >= 0 {
				stopParsing = i + k
			}
		case reading == cmdReadingPowerShell && c == '<' && i+1 < n && command[i+1] == '<' && i >= stopParsing &&
			(i == 0 || strings.IndexByte(" \t\r\n;|&(){}", command[i-1]) >= 0):
			return spans, true
		case reading == cmdReadingGitBash && c == '$' && i+1 < n && command[i+1] == '{':
			braces++
			i += 2
			continue
		case reading == cmdReadingGitBash && c == '{' && braces > 0:
			braces++
		case reading == cmdReadingGitBash && c == '}' && braces > 0:
			braces--
		case reading == cmdReadingGitBash && c == '(' && i+1 < n && command[i+1] == '(':
			arith++
			i += 2
			continue
		case reading == cmdReadingGitBash && c == ')' && arith > 0 && i+1 < n && command[i+1] == ')':
			arith--
			i += 2
			continue
		case reading == cmdReadingGitBash && c == '(':
			parens++
		case reading == cmdReadingGitBash && c == ')':
			parens = max(0, parens-1)
		case reading == cmdReadingGitBash && c == '[' && i > 0 && cmdNameByte(command[i-1]):
			subscript++
		case reading == cmdReadingGitBash && c == ']' && subscript > 0:
			subscript--
		case reading == cmdReadingGitBash && c == '<' && i+1 < n && command[i+1] == '<' &&
			(i == 0 || command[i-1] != '<') && braces == 0 && arith == 0 && subscript == 0:
			doc, end, ok := cmdHeredocDelimiter(command, i+2)
			if !ok {
				i += 2
				for i < n && command[i] == '<' {
					i++ // a here-string (<<<) word is scanned on.
				}
				continue
			}
			doc.level = parens
			doc.op, doc.lineStart = i, lineStart
			pending = append(pending, doc)
			i = end
			continue
		case reading == cmdReadingGitBash && c == '\n':
			subscript = 0
			if i != skipNL {
				awaitLine(command[physStart:i])
			}
			physStart = i + 1
			if parens == 0 {
				argvQuoted(i)
			}
			if len(pending) > 0 && parens <= pending[0].level {
				// The receivers are read on the logical line that ends here;
				// the bodies start after it.
				for k := range pending {
					doc := &pending[k]
					doc.runs, doc.cmdFeed = feeds(command[doc.lineStart:i], doc.op-doc.lineStart)
				}
				bodies, end := cmdHeredocBodies(command, i+1, pending, lines)
				// The pending docs share one logical line: read it once
				// (cmdLineContinues is linear in the line).
				readFrom, continues := -1, false
				for k := range bodies {
					if pending[k].lineStart != readFrom {
						readFrom, continues = pending[k].lineStart, cmdLineContinues(command[pending[k].lineStart:i])
					}
					if continues {
						await(&open, len(spans)+k)
					} else {
						await(&closing, len(spans)+k)
					}
				}
				pending = nil
				if len(bodies) > 0 {
					spans = append(spans, bodies...)
					i, skipNL, physStart = end, end, end+1
					continue
				}
			}
			if parens == 0 {
				delta, _ := shape(command[lineStart:i])
				if compound = max(0, compound+delta); compound == 0 {
					// The command is complete: a body waits only for the
					// next line of a pipe or list it continues.
					release(&closing)
				}
				lineStart = i + 1
			}
		case reading == cmdReadingPowerShell && c == '<' && i+1 < n && command[i+1] == '#':
			if end := strings.Index(command[i+2:], "#>"); end >= 0 {
				stop := i + 2 + end + 2
				spans = append(spans, cmdTextSpan{start: i, end: stop, inner: command[i+2 : stop-2]})
				i = stop
				continue
			}
		case reading == cmdReadingPowerShell && c == '@' && i+2 < n && (command[i+1] == '\'' || command[i+1] == '"') &&
			(command[i+2] == '\n' || command[i+2] == '\r'):
			closing := "\n" + string(command[i+1]) + "@"
			if end := strings.Index(command[i+2:], closing); end >= 0 {
				stop := i + 2 + end + len(closing)
				spans = append(spans, cmdTextSpan{start: i, end: stop, inner: command[i+2 : i+2+end]})
				i = stop
				continue
			}
		case reading != cmdReadingCMD && c == '#' && commentStart(i):
			end := strings.IndexAny(command[i:], "\r\n")
			if end < 0 {
				end = n - i
			}
			spans = append(spans, cmdTextSpan{start: i, end: i + end, inner: command[i : i+end]})
			i += end
			continue
		case reading == cmdReadingGitBash && c == '$' && i+1 < n && command[i+1] == '\'':
			// Bash ANSI-C quoting: a backslash escapes the next byte.
			j := i + 2
			for j < n && command[j] != '\'' {
				if command[j] == '\\' {
					j++
				}
				j++
			}
			if j < n {
				spans = append(spans, cmdTextSpan{start: i, end: j + 1, inner: command[i+2 : j]})
				i = j + 1
			} else {
				i += 2
			}
			continue
		case c == '"' || c == '\'' || c >= utf8.RuneSelf:
			if end, inner, ok := cmdQuotedWord(command, i, reading, &nestBudget); ok {
				if reading == cmdReadingPowerShell && c == '"' && cmdPowerShellSubexpressionStops(inner) {
					// PowerShell parses a $(...) of a string as code: a
					// token-start << there is a parse error too, so it
					// runs none of the command (pod it17: a Git Bash
					// git commit -m "$(cat <<'EOF' ... EOF)" message).
					return spans, true
				}
				if reading == cmdReadingGitBash && c == '"' && strings.Contains(inner, "<<") {
					lineQuoted = append(lineQuoted, len(spans))
				}
				spans = append(spans, cmdTextSpan{start: i, end: end, inner: inner, expands: c == '"'})
				i = end
				continue
			}
		}
		i++
	}
	if reading == cmdReadingGitBash && physStart < n {
		awaitLine(command[physStart:n])
	}
	release(&open)
	release(&closing)
	argvQuoted(n)
	cmdMarkRunStrings(command, spans)
	return spans, false
}

// cmdPowerShellSubexpressionStops reports a $(...) of the double-quoted
// PowerShell string inner with a << that starts a token outside its quotes,
// which PowerShell cannot parse. One level is read (linear).
func cmdPowerShellSubexpressionStops(inner string) bool {
	if !strings.Contains(inner, "<<") {
		return false
	}
	for _, sub := range cmdSubexpressions(inner, cmdReadingPowerShell) {
		for i := 0; i < len(sub); i++ {
			c := sub[i]
			tokenStart := i == 0 || strings.IndexByte(" \t\r\n;|&(){}", sub[i-1]) >= 0
			switch {
			case c == '`':
				i++
			case c == '#' && tokenStart:
				// A comment: a << in it is text.
				if k := strings.IndexByte(sub[i:], '\n'); k >= 0 {
					i += k
				} else {
					i = len(sub)
				}
			case c == '<' && i+1 < len(sub) && sub[i+1] == '#':
				if k := strings.Index(sub[i+2:], "#>"); k >= 0 {
					i += k + 3
				} else {
					i = len(sub)
				}
			case c == '\'' || c == '"':
				if end, _, ok := cmdQuotedWord(sub, i, cmdReadingPowerShell, nil); ok {
					i = end - 1
				}
			case c == '<' && i+1 < len(sub) && sub[i+1] == '<' && tokenStart:
				return true
			}
		}
	}
	return false
}

func cmdNameByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// cmdBodyEnds lists, in order, where the outer shell of reading ends the
// statement a cmd call is in, so a cmd /c body stops there and is not read
// again as the rest of the command (checker it11 RV11-2): ; | and newlines
// outside text spans and escapes, also && in PowerShell and a & that is not
// part of a redirection in Git Bash. The cmd reading lists none: cmd's own
// & | stay in the body.
func cmdBodyEnds(command string, spans []cmdTextSpan, reading cmdOuterReading) []int {
	if reading == cmdReadingCMD {
		return nil
	}
	escape := byte('`')
	if reading == cmdReadingGitBash {
		escape = '\\'
	}
	var ends []int
	k := 0
	for i := 0; i < len(command); i++ {
		if k < len(spans) && i == spans[k].start {
			i = spans[k].end - 1
			k++
			continue
		}
		switch c := command[i]; {
		case c == escape:
			i++
		case reading == cmdReadingPowerShell && c == '-' && strings.HasPrefix(command[i:], "--%") &&
			(i == 0 || command[i-1] == ' ' || command[i-1] == '\t'):
			// The stop-parsing tail goes verbatim to the program up to
			// the line end or a pipe: its ; is cmd's text.
			if k := strings.IndexAny(command[i:], "\r\n|"); k >= 0 {
				i += k - 1
			} else {
				i = len(command)
			}
		case c == ';' || c == '|' || c == '\r' || c == '\n':
			ends = append(ends, i)
		case c == '&' && reading == cmdReadingPowerShell:
			if i+1 < len(command) && command[i+1] == '&' {
				ends = append(ends, i)
			}
		case c == '&':
			redirect := i > 0 && (command[i-1] == '>' || command[i-1] == '<') ||
				i+1 < len(command) && command[i+1] == '>'
			if !redirect {
				ends = append(ends, i)
			}
		}
	}
	return ends
}

// cmdShellWord names the shell a word starts: "ps" for PowerShell and
// Invoke-Expression, whose strings run as command lines, "sh" for a POSIX
// shell, whose -c (also -lc, -ic, ...) string runs.
func cmdShellWord(word string) string {
	w := strings.ToLower(strings.Trim(word, `"'`))
	if k := strings.LastIndexAny(w, `\/`); k >= 0 {
		w = w[k+1:]
	}
	switch strings.TrimSuffix(w, ".exe") {
	case "powershell", "pwsh", "iex", "invoke-expression":
		return "ps"
	case "bash", "sh", "zsh", "dash", "ksh":
		return "sh"
	}
	return ""
}

var cmdShellRunFlag = lazyregexp.New(`^-[a-zA-Z]*c[a-zA-Z]*$`)

func cmdArgumentListWord(word string) bool {
	word = strings.TrimSuffix(word, ":")
	name, dashed := strings.CutPrefix(word, "-")
	return dashed && name != "" && (strings.HasPrefix("argumentlist", name) || name == "args")
}

// cmdMarkRunStrings sets runs and args on spans in one pass over command: a
// span runs when its statement (up to ; | or a newline) has a PowerShell or
// Invoke-Expression word before it, or a POSIX shell word and a -c flag
// cluster (RV10-1); a -c of another program (grep -c, rg -c) is no runner
// (RV10-2). args: the word before it is -ArgumentList (or a prefix, -Args),
// or a comma after an args span.
func cmdMarkRunStrings(command string, spans []cmdTextSpan) {
	ps, sh, shRun := false, false, false
	lastWord, wordStart := "", -1
	finish := func(end int) {
		if wordStart < 0 {
			return
		}
		word := command[wordStart:end]
		wordStart = -1
		switch cmdShellWord(word) {
		case "ps":
			ps = true
		case "sh":
			sh = true
		default:
			if sh && cmdShellRunFlag.MatchString(word) {
				shRun = true
			}
		}
		lastWord = strings.ToLower(word)
	}
	k := 0
	for i := 0; i < len(command); {
		if k < len(spans) && i == spans[k].start {
			finish(i)
			if !spans[k].heredoc {
				spans[k].runs = ps || shRun
				spans[k].args = cmdArgumentListWord(lastWord) || (lastWord == "," && k > 0 && spans[k-1].args)
			}
			lastWord = "\x00"
			i = spans[k].end
			k++
			continue
		}
		switch c := command[i]; {
		case c == ';' || c == '|' || c == '\n' || c == '\r':
			finish(i)
			ps, sh, shRun, lastWord = false, false, false, ""
		case c == ',':
			finish(i)
			lastWord = ","
		case strings.IndexByte(" \t(){}&=@", c) >= 0:
			finish(i)
		default:
			if wordStart < 0 {
				wordStart = i
			}
		}
		i++
	}
}

// cmdSpanAt returns the span that holds pos (binary search: spans are in
// order and do not overlap).
func cmdSpanAt(spans []cmdTextSpan, pos int) (cmdTextSpan, bool) {
	k, _ := slices.BinarySearchFunc(spans, pos, func(span cmdTextSpan, pos int) int {
		if span.end <= pos {
			return -1
		}
		return 1
	})
	if k < len(spans) && spans[k].start <= pos {
		return spans[k], true
	}
	return cmdTextSpan{}, false
}

// cmdFirstSpanFrom returns the index of the first span that starts at or
// after pos.
func cmdFirstSpanFrom(spans []cmdTextSpan, pos int) int {
	k, _ := slices.BinarySearchFunc(spans, pos, func(span cmdTextSpan, pos int) int {
		if span.start < pos {
			return -1
		}
		return 1
	})
	return k
}

// cmdStatementBreaks lists, in order, the ; | and newline bytes outside the
// text spans: the statement ends of the outer shell.
func cmdStatementBreaks(command string, spans []cmdTextSpan) []int {
	var breaks []int
	k := 0
	for i := 0; i < len(command); i++ {
		if k < len(spans) && i == spans[k].start {
			i = spans[k].end - 1
			k++
			continue
		}
		switch command[i] {
		case ';', '|', '\r', '\n':
			breaks = append(breaks, i)
		}
	}
	return breaks
}

// cmdSubexpressions returns the bodies a double-quoted word runs: each
// $(...) (one pass with a stack; an unclosed one runs to the end), and in
// the Git Bash reading each `...`.
func cmdSubexpressions(inner string, reading cmdOuterReading) []string {
	var subs []string
	var open []int // body start of each open (, -1 for a plain one
	for i := 0; i < len(inner); i++ {
		if len(open) > 0 && (inner[i] == '\'' || inner[i] == '"') {
			// A quoted word inside a $(...) is text of it: a ) there does
			// not close it (pod it17); an unterminated one is scanned on.
			if end, _, ok := cmdQuotedWord(inner, i, reading, nil); ok {
				i = end - 1
				continue
			}
		}
		switch inner[i] {
		case '(':
			if i > 0 && inner[i-1] == '$' {
				open = append(open, i+1)
			} else {
				open = append(open, -1)
			}
		case ')':
			if len(open) > 0 {
				start := open[len(open)-1]
				open = open[:len(open)-1]
				if start >= 0 {
					subs = append(subs, inner[start:i])
				}
			}
		}
	}
	for _, start := range open {
		if start >= 0 {
			subs = append(subs, inner[start:])
		}
	}
	if reading == cmdReadingGitBash {
		parts := strings.Split(inner, "`")
		for k := 1; k < len(parts); k += 2 {
			subs = append(subs, parts[k])
		}
	}
	return subs
}

var (
	cmdSwitchWord = lazyregexp.New(`(?i)^/{1,2}[a-z](?::\S*)?$`)
	cmdRunWord    = lazyregexp.New(`(?i)^/{1,2}[ck]`)
	// cmdStartProcessWord: Start-Process (or its aliases) right before the
	// program word cmd.
	cmdStartProcessWord = lazyregexp.New(`(?i)(?:^|[\s;|&(){}])(?:start-process|saps|start)\s+(?:-filepath\s+)?["']?$`)
)

// cmdSwitchRunBody reads the switch run of a cmd.exe command line (after the
// program word, or the start of a Start-Process argument string) and returns
// the text after its /c or /k (also //c, //k from Git Bash), or false when
// another word comes first: then cmd runs no body.
func cmdSwitchRunBody(rest string) (string, bool) {
	for {
		trimmed := strings.TrimLeft(rest, " \t")
		if trimmed == "" {
			return "", false
		}
		end := strings.IndexAny(trimmed, " \t\r\n")
		if end < 0 {
			end = len(trimmed)
		}
		word := trimmed[:end]
		if word == "--%" {
			// PowerShell's stop-parsing token: the rest goes verbatim to
			// cmd (checker it11 note K01).
			rest = trimmed[end:]
			continue
		}
		if loc := cmdRunWord.FindStringIndex(word); loc != nil {
			after := word[loc[1]:]
			if after == "" || after[0] == '"' || after[0] == '\'' {
				return trimmed[loc[1]:], true
			}
		}
		if !cmdSwitchWord.MatchString(word) {
			return "", false
		}
		rest = trimmed[end:]
	}
}

// Bounds of one cmd body reading. A command that needs more is judged as a
// state write when it names DefenseClaw state (over-block, never
// under-block), so a crafted command cannot outlast the hook budget
// (checker it10 RV10-3).
const (
	cmdMaxBodies    = 64
	cmdMaxArgSpans  = 64
	cmdMaxNestDepth = 6
)

type cmdBodyReader struct {
	readings []cmdOuterReading
	bodies   []string
	seen     map[string]bool
	budget   int
	overflow bool
}

func (r *cmdBodyReader) add(body string) {
	body = strings.TrimSpace(body)
	if body == "" || r.seen[body] {
		return
	}
	if len(r.bodies) >= cmdMaxBodies {
		r.overflow = true
		return
	}
	r.seen[body] = true
	r.bodies = append(r.bodies, body)
}

func (r *cmdBodyReader) read(command string, depth int) {
	cost := len(command) * len(r.readings)
	if r.overflow || depth > cmdMaxNestDepth || cost > r.budget {
		r.overflow = true
		return
	}
	r.budget -= cost
	for _, reading := range r.readings {
		r.readWith(command, reading, depth)
	}
}

// readArgvHeredocs reads the here-document bodies of the Git Bash
// substitution body sub, whose output a launcher or a shell runs
// (cmdTextSpan.argvRuns): as a shell's and as cmd's (GAP-2539).
func (r *cmdBodyReader) readArgvHeredocs(sub string, depth int) {
	spans, _ := cmdTextSpans(sub, cmdReadingGitBash)
	for _, span := range spans {
		if span.heredoc && !r.overflow {
			r.add(span.inner)
			r.read(span.inner, depth+1)
		}
	}
}

func (r *cmdBodyReader) readWith(command string, reading cmdOuterReading, depth int) {
	spans, stops := cmdTextSpans(command, reading)
	if stops {
		return // PowerShell runs nothing of a command it cannot parse.
	}
	for _, span := range spans {
		if r.overflow {
			return
		}
		if span.cmdFeed {
			r.add(span.inner) // cmd <<EOF: cmd.exe runs the body lines.
		}
		if span.runs {
			if span.args {
				// Start-Process powershell -ArgumentList '-c "..."': the
				// string is the argument list of a PowerShell.
				r.read("powershell "+span.inner, depth+1)
			} else {
				r.read(span.inner, depth+1)
			}
		}
		if reading != cmdReadingCMD && span.expands {
			for _, sub := range cmdSubexpressions(span.inner, reading) {
				r.read(sub, depth+1)
				if span.argvRuns {
					r.readArgvHeredocs(sub, depth+1)
				}
			}
		}
	}
	var argSpans []int
	for k, span := range spans {
		if span.args {
			argSpans = append(argSpans, k)
		}
	}
	breaks := cmdStatementBreaks(command, spans)
	ends := cmdBodyEnds(command, spans, reading)
	for _, loc := range cmdProgramWord.FindAllStringIndex(command, -1) {
		if r.overflow {
			return
		}
		start := loc[0]
		if strings.ContainsRune(" \t\r\n;|&(){}", rune(command[start])) {
			start++
		}
		if span, in := cmdSpanAt(spans, start); in && (span.start != start || span.end != loc[1]) {
			continue // Text the outer shell does not run (a quoted program path is run).
		}
		rest := command[loc[1]:]
		if rest != "" && !strings.ContainsRune(" \t\r\n/'\"", rune(rest[0])) {
			continue // cmdlet, cmdkey, ...: another program.
		}
		body, ok := cmdSwitchRunBody(rest)
		if !ok {
			r.addArgumentList(command, spans, argSpans, breaks, start, loc[1], rest)
			continue
		}
		bodyStart := len(command) - len(body)
		if k, _ := slices.BinarySearch(ends, bodyStart); k < len(ends) {
			body = command[bodyStart:ends[k]]
		}
		r.add(body)
		trimmed := strings.TrimSpace(body)
		if trimmed == "" {
			continue
		}
		quote := trimmed[0]
		if quote != '\'' && quote != '"' {
			continue
		}
		if end := strings.IndexByte(trimmed[1:], quote); end >= 0 {
			// The outer shell's quoted word.
			r.add(trimmed[1 : end+1])
		}
		if last := strings.LastIndexByte(trimmed, quote); last > 0 {
			// cmd /c strips the first and the last quote of the line.
			r.add(trimmed[1:last] + trimmed[last+1:])
		}
	}
}

// addArgumentList reads Start-Process cmd -ArgumentList '/c ...': the
// argument string (an array is joined with spaces, as PowerShell does) of the
// same statement, after or before the program word, or the positional
// argument right after Start-Process cmd, is the cmd command line.
func (r *cmdBodyReader) addArgumentList(command string, spans []cmdTextSpan, argSpans, breaks []int, start, wordEnd int, rest string) {
	statementEnd := len(command)
	if k, _ := slices.BinarySearch(breaks, wordEnd); k < len(breaks) {
		statementEnd = breaks[k]
	}
	statementStart := 0
	if k, _ := slices.BinarySearch(breaks, start); k > 0 {
		statementStart = breaks[k-1] + 1
	}
	collect := func(from, to int) []string {
		var args []string
		k, _ := slices.BinarySearchFunc(argSpans, from, func(index, pos int) int {
			if spans[index].start < pos {
				return -1
			}
			return 1
		})
		for ; k < len(argSpans) && spans[argSpans[k]].start < to; k++ {
			if len(args) >= cmdMaxArgSpans {
				r.overflow = true
				return nil
			}
			args = append(args, spans[argSpans[k]].inner)
		}
		return args
	}
	args := collect(wordEnd, statementEnd)
	if len(args) == 0 {
		// -ArgumentList before the program word (-FilePath last).
		args = collect(statementStart, start)
	}
	if len(args) == 0 && cmdStartProcessWord.MatchString(command[max(0, start-64):start]) {
		// Start-Process cmd '/c ...': the positional argument list.
		after := wordEnd + len(rest) - len(strings.TrimLeft(rest, " \t"))
		if k := cmdFirstSpanFrom(spans, after); k < len(spans) && spans[k].start == after {
			args = append(args, spans[k].inner)
		}
	}
	if len(args) == 0 || r.overflow {
		return
	}
	if argBody, ok := cmdSwitchRunBody(strings.Join(args, " ")); ok {
		r.add(argBody)
	}
}

// cmdInvocationReadings returns the command lines a shell command hands to
// cmd.exe through cmd /c or cmd /k, read after the outer shell's own quote
// removal: a single-quoted (PowerShell, Git Bash) body is its text, a
// double-quoted one loses its first and last quote as cmd /c does, and a
// Start-Process -ArgumentList string is the cmd command line. The program
// word counts only where some reading of the outer shell (PowerShell, Git
// Bash, and cmd itself for a CMD tool call) runs it: in command position, not
// inside a quoted word, a comment or a here-string that every reading reads
// as text (RV9-1), except a string that is itself run (powershell, pwsh,
// Invoke-Expression, bash -c, $(...) or a Git Bash `...` inside double
// quotes), which is read again. complete is false when the command needs
// more reading than the bounds allow.
func cmdInvocationReadings(command string, includeCMD bool) (bodies []string, complete bool) {
	if !cmdSpellingPossible(command) {
		// No reading can run cmd.exe: the bounds below must not turn a
		// large or deeply nested command into a write (rows17 B08).
		return nil, true
	}
	r := &cmdBodyReader{
		readings: []cmdOuterReading{cmdReadingPowerShell, cmdReadingGitBash},
		seen:     map[string]bool{},
		budget:   8*len(command) + 1<<16,
	}
	if includeCMD {
		r.readings = append(r.readings, cmdReadingCMD)
	}
	r.read(command, 0)
	return r.bodies, !r.overflow
}

// cmdSpellingPossible reports whether some reading of command may name
// cmd.exe: "cmd" or "comspec" in the text with every quote, escape and
// continuation character (quotes, backtick, caret, backslash, CR, LF) and
// every non-ASCII rune taken out. It only ever over-reports, so a command it
// rejects has no cmd program word in any reading.
func cmdSpellingPossible(command string) bool {
	var b strings.Builder
	b.Grow(len(command))
	for _, r := range command {
		switch {
		case r >= utf8.RuneSelf, r == 0x22, r == 0x27, r == 0x60, r == 0x5e, r == 0x5c, r == 0x0d, r == 0x0a:
			continue
		case r >= 0x41 && r <= 0x5a:
			b.WriteRune(r + 0x20)
		default:
			b.WriteRune(r)
		}
	}
	folded := b.String()
	return strings.Contains(folded, "cmd") || strings.Contains(folded, "comspec")
}

// provenCMDSlashCStateWrite judges the body of a cmd /c or cmd /k call as
// the cmd command it is (GAP-2408). Without /d the parser keeps cmd /c opaque,
// because a Command Processor AutoRun entry may run first; AutoRun cannot stop
// the body from running, so a body that writes, empties, moves or deletes
// DefenseClaw state (cmd /c "type nul > %USERPROFILE%\.defenseclaw\config.yaml",
// & cmd /c, cmd //c from Git Bash, cmd /v:on /c, cmd /k, $env:ComSpec /c,
// Start-Process cmd -ArgumentList '/c ...') still does. Only the state-write
// proof reads the twin. The caller has already seen a DefenseClaw state
// mention, so a command too large to read within the bounds counts as the
// write (RV10-3).
func provenCMDSlashCStateWrite(request trustedActionRequest) bool {
	home := request.Input.ActiveHome
	windowsHome := len(home) >= 2 && home[1] == ':'
	switch request.Input.DialectHint {
	case actionfacts.DialectCMD, actionfacts.DialectPowerShell:
	case "", actionfacts.DialectPOSIX:
		// No grammar or the Git Bash one: only a Windows home has cmd.
		if !windowsHome {
			return false
		}
	default:
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	includeCMD := request.Input.DialectHint == actionfacts.DialectCMD
	// The bounds count distinct bodies: a body two readings or two depths
	// yield is judged once (RV11-2).
	const maxReadings, maxReadBytes = 128, 1 << 20
	pending, readings, readBytes := []string{command}, 0, 0
	seen := map[string]bool{}
	for depth := 0; depth < 3 && len(pending) > 0; depth++ {
		var next []string
		for _, outer := range pending {
			bodies, complete := cmdInvocationReadings(outer, includeCMD)
			if !complete {
				return true
			}
			for _, body := range bodies {
				if seen[body] {
					continue
				}
				seen[body] = true
				readings++
				readBytes += len(body)
				if readings > maxReadings || readBytes > maxReadBytes {
					return true
				}
				input := request.Input
				input.Command, input.Args, input.Argv = body, nil, nil
				input.DialectHint = actionfacts.DialectCMD
				twin := request
				twin.Input = input
				if provenStateMutationPath(actionfacts.Analyze(input), twin) {
					return true
				}
				next = append(next, body)
			}
		}
		pending = next
	}
	return false
}

// provenShellRedirectStateWrite judges each output redirect target the
// shell opens (actionfacts.ShellRedirectTargets: a literal absolute path or
// a home spelling written as the active home) as the command-less redirect
// ": > target": the shell opens the target before it runs the command,
// whatever the program word is, whatever its other words expand to, for
// every operator that opens the file for writing and in Bash-only syntax,
// so the target is the write its absolute spelling is (GAP-2225, GAP-2268,
// GAP-2298).
func provenShellRedirectStateWrite(request trustedActionRequest) bool {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false
	}
	targets, ok := actionfacts.ShellRedirectTargets(command, request.Input.ActiveHome)
	if !ok {
		return false
	}
	for _, target := range targets {
		if strings.ContainsAny(target, "'\n") {
			continue
		}
		input := request.Input
		input.Command, input.Args, input.Argv = ": > '"+target+"'", nil, nil
		input.DialectHint = actionfacts.DialectPOSIX
		twin := request
		twin.Input = input
		if !strings.HasPrefix(target, "/") {
			// A drive path below a Windows home (Git Bash): the POSIX reading
			// places it as a relative word, so the twin carries the physical
			// target the gateway resolves for it, as a hook target map does.
			if request.SkipLocalFilesystemResolution || request.ProtectedHomeHook {
				continue
			}
			physical, ok := hookpaths.ResolveWriteTarget(target)
			if !ok {
				continue
			}
			twin.ResolvedWriteTargets = make(map[string]string, len(request.ResolvedWriteTargets)+1)
			for spelling, value := range request.ResolvedWriteTargets {
				twin.ResolvedWriteTargets[spelling] = value
			}
			twin.ResolvedWriteTargets[target] = physical
		}
		if provenStateMutationPath(actionfacts.Analyze(input), twin) {
			return true
		}
	}
	return false
}

// ActionFacts' executing mutation role plus the physical active target
// authorize the observe-mode exception. A static shell redirect is independently
// proven even when unrelated command analysis leaves the action partial. The
// hook's resolved target map is preferred; a managed call can use only an
// OS-proved active-state hard link when that map has no entry.
func provenStateMutationPath(facts actionfacts.Facts, request trustedActionRequest) bool {
	projected := facts.EnforcementProjection()
	if projected.ActiveHome == "" {
		return false
	}
	wholeActionProven := projected.Authoritative() && projected.EnforcementEligible()
	lineStaysOff := findStripLineStaysOffOf(request, path.Join(path.Clean(projected.ActiveHome), ".defenseclaw"))
	for _, candidate := range projected.Paths {
		command, ok := integrityCommandByID(projected, candidate.CommandID)
		if !ok {
			continue
		}
		provenMutation := wholeActionProven && stateCommandMutatesPath(command, candidate)
		if !provenMutation {
			provenMutation = provenPartialStateRedirect(facts, command, candidate)
		}
		if !provenMutation {
			provenMutation = provenPartialFindHandOff(facts, command, candidate)
		}
		if !provenMutation {
			continue
		}
		// The spelling the kernel walks first (GAP-2047 L5), then the
		// walk spelling the hook client keys on every system, a Windows
		// junction or drive path included (GAP-1007), then the lexical one
		// the path fact keeps.
		walked, isWalked := stateWalkSpelling(candidate, request.Input.CWD, projected.ActiveHome)
		if isWalked {
			physicalCandidate := candidate
			physicalCandidate.Resolved = walked
			if provenStateCandidateMatches(projected, command, physicalCandidate, request, lineStaysOff) {
				return true
			}
		}
		if raw, ok := dotDotWalkSpelling(candidate, request); ok && (!isWalked || raw != walked) {
			physicalCandidate := candidate
			physicalCandidate.Resolved = raw
			if provenStateCandidateMatches(projected, command, physicalCandidate, request, lineStaysOff) {
				return true
			}
		}
		if provenStateCandidateMatches(projected, command, candidate, request, lineStaysOff) {
			return true
		}
	}
	return !wholeActionProven && placedStatementStateWrite(facts, request)
}

// placedStatementStateWrite reads each top-level statement of a ; / && / ||
// list alone, in every directory the shell may run it in, when the whole
// list is not proven: a pushd leaves the analysis partial, so pushd
// /missing; cp a.txt ../.defenseclaw/config.yaml had no proof, although the
// failed pushd leaves the shell where it was and the cp writes the state
// file (GAP-2574). A statement proven alone that mutates active state is
// the state write; it only adds this block. The reading needs a cd, pushd or
// popd program word in the call (hookpaths.ChangesDirectory), not those
// letters anywhere in its text: a home under a folder named 1cd7970ba0a3
// turned it on and raised the severity of a call with no directory change
// (rel-1-0-10:GAP-1014).
func placedStatementStateWrite(facts actionfacts.Facts, request trustedActionRequest) bool {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return false
	}
	text, known := trustedBashCommandInput(request.Input)
	if !known || !hookpaths.ChangesDirectory(text) {
		return false
	}
	facts, request = protectedHomePlacedReading(facts, request)
	home := facts.EnforcementProjection().ActiveHome
	if home == "" || !filepath.IsAbs(request.Input.CWD) {
		return false
	}
	statements, placed := hookpaths.TopLevelStatements(text, request.Input.CWD, home)
	if !placed || len(statements) < 2 {
		return false
	}
	for _, statement := range statements {
		input := request.Input
		input.Args, input.Argv, input.Command, input.CWD = nil, nil, statement.Command, statement.Dir
		projected := actionfacts.Analyze(input).EnforcementProjection()
		if projected.ActiveHome == "" || !projected.Authoritative() || !projected.EnforcementEligible() {
			continue
		}
		for _, candidate := range projected.Paths {
			command, ok := integrityCommandByID(projected, candidate.CommandID)
			if !ok || !stateCommandMutatesPath(command, candidate) {
				continue
			}
			// A target the state index could not rule out is not proved free of the
			// state: refused, as an unfinished walk refuses a patch target (GAP-1789).
			switch active, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(candidate.Resolved, projected.ActiveHome); {
			case !complete:
				return true
			case same:
				candidate.Resolved = active
			}
			if matchesActiveDefenseClawState(projected, candidate) {
				return true
			}
		}
	}
	return false
}

// provenStateCandidateMatches places one proven mutating operand (a
// directory entry, the hook's resolved target or the local link walk) and
// reports it in the active state.
func provenStateCandidateMatches(
	projected actionfacts.Facts,
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
	request trustedActionRequest,
	lineStaysOff func() bool,
) bool {
	if entry, ok := stateDirectoryEntryTarget(command, candidate, request); ok {
		spellings, written := []string{candidate.Resolved, candidate.Value, candidate.Normalized}, candidate.Value
		candidate.Resolved = entry
		if matchesActiveDefenseClawStateInLine(projected, candidate, lineStaysOff, request.ResolvedWriteTargets) {
			return true
		}
		if request.ProtectedHomeHook && candidate.Access == actionfacts.PathAccessDelete {
			// The gateway cannot follow the directory through a link
			// the user can make; the hook placed the entry as the user
			// and lists it only when it is in the state tree (GAP-2549).
			for _, placed := range clientWriteTargets(request.ResolvedWriteTargets, written, spellings...) {
				if filepath.IsAbs(placed) {
					candidate.Resolved = placed
					if matchesActiveDefenseClawStateInLine(projected, candidate, lineStaysOff, request.ResolvedWriteTargets) {
						return true
					}
				}
			}
		}
		return false
	}
	physical := ""
	if found := clientWriteTargets(request.ResolvedWriteTargets, candidate.Value,
		candidate.Resolved, candidate.Value, candidate.Normalized); len(found) > 0 {
		physical = found[0]
	}
	if physical == "" && !request.SkipLocalFilesystemResolution {
		if request.ProtectedHomeHook {
			// Only an OS-proved alias is safe to resolve here when the
			// authenticated hook supplied no target-map entry. The home
			// itself is the peer's home from the account database: a
			// find that starts there (`yes | find ~ ...`, which the
			// client lists no target for) is judged from it (GAP-2404
			// pod ip21, managed RHEL).
			active, _, complete := hookpaths.ResolveActiveStateHardlinkTarget(candidate.Resolved, projected.ActiveHome)
			if !complete {
				return true // not proved free of the state (GAP-1789)
			}
			physical = active
			if physical == "" && path.IsAbs(candidate.Resolved) &&
				path.Clean(candidate.Resolved) == path.Clean(projected.ActiveHome) {
				physical = path.Clean(candidate.Resolved)
			}
			if physical == "" {
				// A link-walk spelling the client walked (GAP-2569).
				physical, _ = hookpaths.WalkFactTarget(request.ResolvedWriteTargets, candidate.Resolved)
			}
		} else {
			spelled := driveFSPath(request, gitBashOperandSpelling(candidate))
			physical, _ = hookpaths.ResolveWriteTarget(spelled)
			if physical == "" {
				// A target whose own local read did not answer is not
				// proved free of the state (rel-1-0-10:GAP-1804).
				if _, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(spelled, projected.ActiveHome); same || !complete {
					return true
				}
			}
			physical = driveViewPath(request, physical)
		}
	}
	if physical == "" {
		return false
	}
	// A target the state index could not rule out is not proved free of the
	// state: refused, as an unfinished walk refuses a patch target (GAP-1789).
	switch active, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(physical, projected.ActiveHome); {
	case !complete:
		return true
	case same:
		physical = active
	}
	if candidate.Flavor == actionfacts.PathFlavorPOSIX {
		physical = filepath.ToSlash(physical)
	}
	candidate.Resolved = physical
	return matchesActiveDefenseClawStateInLine(projected, candidate, lineStaysOff, request.ResolvedWriteTargets)
}

// stateWalkSpelling is the spelling of an operand with a `..` component
// as the kernel walks it: a `..` after a link ascends from the link's
// target, so with dclink -> ~/.defenseclaw `rm -rf dclink/../.defenseclaw/hooks`
// removes ~/.defenseclaw/hooks while its lexical spelling (the path fact)
// is ./.defenseclaw/hooks (GAP-2047 L5, T10). It is the operand joined to
// the call cwd, uncleaned, when that join cleans to the fact's resolved
// path (an operand placed after a cd keeps its lexical spelling only); ok
// is false for any other operand, which keeps its lexical spelling.
func stateWalkSpelling(candidate actionfacts.PathFact, cwd, home string) (string, bool) {
	if candidate.Flavor == actionfacts.PathFlavorWindows || !hasDotDotComponent(candidate.Value) {
		return "", false
	}
	trimmed := strings.TrimRight(candidate.Value, "/")
	if strings.HasSuffix(trimmed, "/..") || strings.HasSuffix(trimmed, "/.") || trimmed == ".." {
		return "", false
	}
	full, ok := stateHomePath(candidate.Value, strings.TrimRight(home, "/"), cwd)
	if !ok || !path.IsAbs(full) || path.Clean(full) != path.Clean(filepath.ToSlash(candidate.Resolved)) {
		return "", false
	}
	return full, true
}

// hasDotDotComponent reports a slash path with a `..` component.
func hasDotDotComponent(word string) bool {
	return slices.Contains(strings.Split(word, "/"), "..")
}

// walkParent is the parent of a slash path without removing its `..`
// components (filepath.Dir cleans them lexically).
func walkParent(value string) string {
	value = strings.TrimRight(value, "/")
	index := strings.LastIndex(value, "/")
	if index <= 0 {
		return "/"
	}
	return value[:index]
}

// managedLinkWalkView is a managed hook call placed in the directory the
// hook client keyed its link-walk facts in (hookpaths.WalkFactPrefix): the
// client's cwd, or the directory a static cd placed a simple command in
// (evidenceCWD). A gateway behind ProtectHome receives no cwd of its own, so
// a relative link spelling (`git -C dclink clean -fdx`) could not be placed
// (GAP-2569). ok is false when the gateway knows the cwd or the client's is
// not a plain directory in the caller's home.
func managedLinkWalkView(request trustedActionRequest) (actionfacts.Facts, trustedActionRequest, bool) {
	cwd, ok := protectedHomeClientDirectory(request)
	if !ok {
		return actionfacts.Facts{}, request, false
	}
	placed := request
	placed.Input.CWD = cwd
	// The link-walk facts are keyed by the client walk (the hook folder
	// reading of each path, Facts.AtHookFolder).
	return actionfacts.Analyze(placed.Input).AtHookFolder(), placed, true
}

// protectedHomeClientDirectory is the directory a managed hook call runs in
// when the gateway behind ProtectHome receives no cwd of its own, as the
// hook client keyed its evidence: the directory a static cd placed a simple
// command in (evidenceCWD), else the client cwd (hookpaths.CWDKey). ok is
// false when the call is not a managed hook peer call, the gateway knows the
// cwd, or the directory is not an absolute path without ".." in the caller
// home or its project root.
func protectedHomeClientDirectory(request trustedActionRequest) (string, bool) {
	if !request.ProtectedHomeHook || filepath.IsAbs(request.Input.CWD) {
		return "", false
	}
	cwd, home := request.evidenceCWD, request.Input.ActiveHome
	if !filepath.IsAbs(cwd) {
		cwd = request.ResolvedWriteTargets[hookpaths.CWDKey]
	}
	if !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || hasParentElement(cwd) || strings.ContainsRune(cwd, 0) ||
		projectRootKey(cwd) != projectRootKey(home) && !insideHome(home, cwd) {
		return "", false
	}
	return filepath.Clean(cwd), true
}

// protectedHomeReportedDirectory is the directory a managed hook peer
// reported for its call, as protectedHomeClientDirectory reads it, without
// the bound of the caller home and its project root: a project may live
// anywhere the user can reach. It places a path only to look up the evidence
// the client keyed by that spelling, which can add a block and never walks
// the gateway into the directory. ok is false when the call is not a managed
// hook peer call, the gateway knows the cwd, or the directory is not an
// absolute path without ".." and NUL.
func protectedHomeReportedDirectory(request trustedActionRequest) (string, bool) {
	if !request.ProtectedHomeHook || filepath.IsAbs(request.Input.CWD) {
		return "", false
	}
	cwd := request.evidenceCWD
	if !filepath.IsAbs(cwd) {
		cwd = request.ResolvedWriteTargets[hookpaths.CWDKey]
	}
	if !filepath.IsAbs(cwd) || hasParentElement(cwd) || strings.ContainsRune(cwd, 0) {
		return "", false
	}
	return filepath.Clean(cwd), true
}

// protectedHomePrivateKeyTwinRequest returns the call of a managed hook
// peer placed in the directory the hook client ran it in
// (protectedHomeClientDirectory), when its text names an SSH private key
// file. Without a cwd of its own the gateway left a key read spelled
// relative to that directory (cat .ssh/id_ed25519 in the home, cat
// ../.ssh/id_rsa in a project) outside ~/.ssh, so a managed peer was
// allowed what a per-user gateway blocks (GAP-0179). The placed reading is
// the per-user one; the caller keeps only its private-key read block.
func protectedHomePrivateKeyTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	cwd, ok := protectedHomeClientDirectory(request)
	if !ok || request.SkipLocalFilesystemResolution {
		return trustedActionRequest{}, false
	}
	text := strings.ToLower(trustedActionInputText(request.Input, request.LegacyText))
	if !strings.Contains(text, "id_rsa") && !strings.Contains(text, "id_ed25519") &&
		!strings.Contains(text, "id_ecdsa") && !strings.Contains(text, "id_dsa") {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.record, twin.recordTelemetry = nil, nil
	twin.conflictSource = nil
	twin.Input.CWD = cwd
	return twin, true
}

// shellProfileWriteRule is the rule of a write of a shell startup profile.
const shellProfileWriteRule = "persistence.shell_profile_write"

// shellProfileNames are the file names matchesShellProfileCandidate reads
// as a shell startup profile, in lower case.
var shellProfileNames = []string{".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc", "config.fish", "profile.ps1"}

// protectedHomeShellProfileTwinRequest returns the call of a managed hook
// peer placed in the directory the hook client ran it in
// (protectedHomeClientDirectory), when its text names a shell startup
// profile. Without a cwd of its own the gateway read `echo x >> .bashrc`
// and `echo x >> ./.bashrc` from the home as writes of no known file, and
// the function rows of GAP-0690, 0693, 0694 and 0711 the same, so a managed
// peer was allowed what a per-user gateway alerts (default) or blocks
// (strict) as persistence.shell_profile_write (substrate-1:GAP-1090, live
// on dc-ent-rhel). The placed reading is the per-user one; the caller keeps
// only its shell-profile finding.
//
// The per-user reading includes the cap floor (withCapFloor): a function
// whose body runs a command the split cannot read (`f(){ $y; }`, `"$@"`,
// `$r ~`, `eval "$c"`) puts the call at the unknown tier, and the floor
// judges the piece `echo x >> .bashrc` alone in the folder, where it is the
// profile write. The twin is built after the call registered its own floor,
// in no folder, so a twin of the hook call itself gets a floor of its own in
// the client directory (substrate-1:GAP-1091). A piece twin's profile twin
// keeps the call's floor: its pieces are already the call's.
func protectedHomeShellProfileTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	cwd, ok := protectedHomeClientDirectory(request)
	if !ok || request.SkipLocalFilesystemResolution {
		return trustedActionRequest{}, false
	}
	text := strings.ToLower(trustedActionInputText(request.Input, request.LegacyText))
	if !slices.ContainsFunc(shellProfileNames, func(name string) bool { return strings.Contains(text, name) }) {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.record, twin.recordTelemetry = nil, nil
	twin.conflictSource = nil
	twin.Input.CWD = cwd
	if request.capFloorDepth == 0 {
		twin.capFloor, twin.capFloorSeen = nil, false
	}
	return twin, true
}

// hasGitHookMutationCandidate avoids a second parse for text mentions and
// inactive hook names. A CWD changes path placement, not the parsed access
// or the command's mutation role.
func hasGitHookMutationCandidate(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		if !matchesGitHookCandidate(semanticPathValue(candidate)) ||
			matchesSafeGitHookCandidate(facts, candidate) {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if ok && integrityCommandMutatesPath(command, candidate) {
			return true
		}
	}
	return false
}

// hasGitReadOutputWrite avoids a second parse for every call but a git
// show, log, diff or whatchanged that writes its output to a file: the
// reading gitReadOutputConfigPrerequisite places by the working directory.
func hasGitReadOutputWrite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		invocation, ok := parseIntegrityGitInvocation(command)
		if ok && oneOfFold(invocation.subcommand, "show", "log", "diff", "whatchanged") &&
			hasOperation(command, actionfacts.OperationWrite) {
			return true
		}
	}
	return false
}

// cwdPlacedRule names the rules whose semantic owner decides that a path is
// active by the call's working directory itself, not only by where a relative
// operand resolves: persistence.git_hook_write (matchesActiveGitHook:
// <cwd>/.git/hooks/<name>, or the git directory of a git show/log --output)
// and source.git_config_exec (its --output into the active <git dir>/config,
// integrityGitDirectory). A managed peer's reading in the hook client's
// directory keeps only these (protectedHomeCWDPlacedInput). Every other owner
// still resolves a relative operand against the working directory; a sandbox
// call therefore gets the guest reading of every owner (sandboxGuestPlacedInput).
func cwdPlacedRule(ruleID string) bool {
	switch ruleID {
	case "persistence.git_hook_write", "source.git_config_exec":
		return true
	}
	return false
}

// protectedHomeCWDPlacedInput is a managed hook peer's call placed in the
// hook client's project directory (protectedHomeClientDirectory, which the
// verified peer's home bounds), when the call names a .git path and may
// resolve local paths. The reading is lexical (actionfacts.Analyze reads no
// files) and the caller keeps only the positive findings of cwdPlacedRule
// rules from it.
func protectedHomeCWDPlacedInput(request trustedActionRequest) (actionfacts.Input, bool) {
	cwd, ok := protectedHomeClientDirectory(request)
	if !ok || request.SkipLocalFilesystemResolution ||
		!strings.Contains(strings.ToLower(trustedActionInputText(request.Input, request.LegacyText)), ".git") {
		return actionfacts.Input{}, false
	}
	input := request.Input
	input.CWD = cwd
	return input, true
}

// placedReading is the call read in the working directory the agent ran it
// in (dispatchTrustedAction): facts nil when there is none, everyOwner when
// every semantic owner may add a finding from it, not only cwdPlacedRule.
// children are the simple commands of a sandbox call that a static cd moved
// to another directory, each read there (sandboxGuestPlacedChildren).
type placedReading struct {
	facts      *actionfacts.Facts
	everyOwner bool
	children   []actionfacts.Facts
	// evals holds, for each child, what the semantic rules made of it
	// (guestViewEvals); nil, or a nil entry, keeps nothing.
	evals []*guestViewEvals
	// candidates are read for the private-key read proof only
	// (sandboxGuestPlacedChildren).
	candidates []actionfacts.Facts
}

// placedReadingFirstView is the budget view number of the first placed view;
// the dispatch's own views are 0 to 5 (evaluateSemanticRules).
const placedReadingFirstView = 6

// maxSandboxGuestPlacedChildren is the call's own statement budget (128, the
// bound of trustedCallOverStatementBudget) in the guest placement: the
// distinct simple-command readings of a call the analysis read in full, and
// the statements of a pass over a call it did not read in full when the call
// is over that budget (guestPlacementPlan); the readings share the call's
// semantic budget. A cap of 16 gave ACTION-COMPOUND-LIMIT to a cd followed by
// 17 or more distinct commands, a setup script the laptop allows
// (substrate-1 GAP-0359).
const maxSandboxGuestPlacedChildren = 128

// eachView calls visit with each placed view in order, its index first: the
// placed facts, then each child's. A call places up to 8,192 children, and
// copying them into one list for each reading copied megabytes a hook
// (rel-1-0-10:GAP-2226).
func (placed placedReading) eachView(visit func(index int, view *actionfacts.Facts)) {
	if placed.facts == nil {
		return
	}
	visit(0, placed.facts)
	for at := range placed.children {
		visit(at+1, &placed.children[at])
	}
}

// contextDone reports a closed done channel (context.Context.Done); a nil
// channel is never closed.
func contextDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// provesSSHPrivateKeyContentRead reports a placed view that reads an active
// SSH private key's content by its lexical facts alone, the proof
// appendTrustedPrivateKeyReaderFinding makes on the call's own facts: a
// relative read of the guest home's key (cat .ssh/id_ed25519 from the home,
// cat ../sandbox/.ssh/id_ed25519 from /work) is then the laptop's block.
func (placed placedReading) provesSSHPrivateKeyContentRead() bool {
	proves := func(view *actionfacts.Facts) bool {
		return view.Authoritative() && view.EnforcementEligible() &&
			trustedActionActiveSSHPrivateKeyContentRead(view.EnforcementProjection())
	}
	found := false
	placed.eachView(func(_ int, view *actionfacts.Facts) { found = found || proves(view) })
	for at := 0; !found && at < len(placed.candidates); at++ {
		found = proves(&placed.candidates[at])
	}
	return found
}

// sandboxGuestPlacedChildren reads, lexically, each command of a sandbox
// call that may run outside the guest working directory in the directory it
// runs in: cd ../sandbox && echo x >> .profile writes the guest home's
// .profile. The dispatch's own simple-command pass places the command in the
// request's working directory, which a copy-mode actor does not have, so the
// cd led nowhere there. The commands and their directories are
// guestPlacementPlan; a call whose readings stop short reports cut
// (bounded.Items): the caller adds the evaluation-limit finding, so a padded
// chain is never a silent allow (substrate-1 GAP-0304).
//
// candidates are the readings in a directory the call reaches only as a cd
// target no command runs in (guestPlacement.candidate): they count only for
// the private-key read proof, as the laptop's readers judge a candidate
// directory (substrate-1 GAP-0379). After a command the split cannot read
// ($CMD, eval, source), which may change the folder, the laptop keeps such a
// folder as one the later commands run in when the call's own shell stands
// there when that command runs (guestOwnShellFolders, keyed by the
// statement and the folder): the readings there are children, judged by
// every owner. A folder only a later cd reaches stays a candidate for the
// statements before it: (cd ~/.defenseclaw || cd /tmp); $CMD; echo m >
// config.yaml; cd ~/.defenseclaw && ls blocked in strict where the laptop
// allows (substrate-1 GAP-0883). cd .cache; bash <<< true; $CMD; cd s0; ...; cd ../.ssh; echo
// k >> authorized_keys alerted where the laptop blocks (substrate-1
// GAP-0628). A folder a subshell, an uncalled function or an || alternative
// cds to stays a candidate: promoting every candidate after $CMD blocked
// (cd ~/.defenseclaw || cd /tmp); $CMD; echo m > config.yaml where the
// laptop allows.
func sandboxGuestPlacedChildren(memo *guestReadingMemo, input actionfacts.Input, facts actionfacts.Facts) (children, candidates []actionfacts.Facts, cut bounded.CapSet) {
	children, candidates, _, cut = sandboxGuestPlacedViews(memo, input, facts)
	return children, candidates, cut
}

// sandboxGuestPlacedViews is sandboxGuestPlacedChildren with, for each
// child, what the semantic rules made of it (guestViewEvals), kept for the
// hook with the reading.
func sandboxGuestPlacedViews(memo *guestReadingMemo, input actionfacts.Input, facts actionfacts.Facts) (children, candidates []actionfacts.Facts, evals []*guestViewEvals, cut bounded.CapSet) {
	if children, candidates, evals, cut, ok := memo.placedChildren(input, facts); ok {
		return children, candidates, evals, cut
	}
	children, candidates, evals, cut = sandboxGuestPlacedChildrenWalk(memo, input, facts)
	memo.keepPlacedChildren(input, facts, children, candidates, evals, cut)
	return children, candidates, evals, cut
}

// sandboxGuestPlacedChildrenWalk reads the placed children of a call
// (sandboxGuestPlacedChildren) afresh. A reading in a candidate folder is
// kept only when its text may read a key (guestCandidateMayReadKey), the one
// proof it counts for: a cd in each of 64 folders gave every later command
// 64 candidate readings, each a full analysis that could prove nothing
// (touch f1, cd /tmp/x), and the copy-mode actor took 2.6 to 5 times the
// 1.0.10 actor's time (rel-1-0-10:GAP-2226).
func sandboxGuestPlacedChildrenWalk(memo *guestReadingMemo, input actionfacts.Input, facts actionfacts.Facts) (children, candidates []actionfacts.Facts, evals []*guestViewEvals, cut bounded.CapSet) {
	placements, stopped := memo.plan(input, facts).placements(true)
	var folders *guestShellReadings
	if slices.ContainsFunc(placements, func(placement guestPlacement) bool { return placement.candidate }) {
		command := input.Command
		if command == "" {
			command, _ = trustedBashCommandInput(input)
		}
		folders = guestOwnShellFolders(command, input.CWD, input.ActiveHome)
	}
	// A candidate in a folder the call's own shell may stand in is read as a
	// child, but a plain reading in a plain folder stays a candidate, as
	// before the own-shell folders (guestPlainFolder, rel-1-0-10:GAP-2249).
	// This only takes back own-shell promotions: a placement is a candidate
	// here only where the plan made it one (placement.candidate), the set the
	// 1.0.10 line read as candidates, so the candidate set stays a subset of
	// that line's and no reading it judged as a child becomes a candidate.
	var plain map[string]bool
	isCandidate := func(placement guestPlacement) bool {
		if !placement.candidate {
			return false
		}
		dir := path.Clean(placement.cwd)
		if !folders.has(placement.text, dir) {
			return true
		}
		if guestReadingFirst(placement.text) {
			return false
		}
		ok, seen := plain[dir]
		if !seen {
			if plain == nil {
				plain = make(map[string]bool)
			}
			ok = guestPlainFolder(dir, input.ActiveHome)
			plain[dir] = ok
		}
		return ok
	}
	// Each list is made at its size: a long call places thousands of
	// readings, and growing the lists copied their facts again and again
	// (substrate-1 GAP-0956).
	candidate := make([]bool, len(placements))
	candidateCount := 0
	for at, placement := range placements {
		if candidate[at] = isCandidate(placement); candidate[at] {
			candidateCount++
		}
	}
	if count := len(placements) - candidateCount; count != 0 {
		children = make([]actionfacts.Facts, 0, count)
		if memo != nil {
			evals = make([]*guestViewEvals, 0, count)
		}
	}
	read := memo.placedReader(input)
	for at, placement := range placements {
		if !candidate[at] {
			child, childEvals := read(placement)
			children = append(children, child)
			if memo != nil {
				evals = append(evals, childEvals)
			}
		} else if guestCandidateMayReadKey(placement.text) {
			reading, _ := read(placement)
			candidates = append(candidates, reading)
		}
	}
	if stopped {
		return children, candidates, evals, bounded.Of(bounded.Items)
	}
	return children, candidates, evals, bounded.CapSet{}
}

// sandboxGuestPlacedInput is a sandbox call (every Substrate actor, an
// OpenShell sandbox) placed in the guest's own working directory
// (SandboxGuestCWD), the directory the agent resolves its relative operands
// against. The request's working directory is none in copy mode (the
// payload's has no host counterpart) and the host mount in mount mode, so
// every owner that resolves an operand by it lost the guest's placement:
// echo x >> .bashrc from the guest home, cat ../sandbox/.ssh/id_ed25519 or
// rm .defenseclaw/audit.db from the project, and the active Git hook of the
// guest project even when named absolutely (GAP-0264, GAP-0282). "~" is
// already the guest home there (hookActiveHome).
//
// Only the semantic owners judge this reading, over lexical facts
// (actionfacts.Analyze reads no files), with the lexical private-key read
// proof (placedReading.provesSSHPrivateKeyContentRead): the other lanes read
// files under the request's working directory on this host (a script a shell
// runs, a file a tool edits), and a guest path there names a host file the
// sandbox never reaches (TestSandboxIngressCopyModeNeverTouchesHostFS). The reading only
// adds findings, so it reaches the verdict a laptop reaches in that directory
// and never removes one. It is read only when the guest directory may change
// a judgment: a relative operand, a Git hook or config candidate the git
// owners place by the working directory itself, or a call the analysis did
// not read in full, whose commands are then read one by one in the guest's
// directories (a here-string parses invalid and names no path,
// substrate-1 GAP-0363). A statement of the call the walk placed nowhere
// (unplacedStatement) has no reading of its own here: the call's reading
// places it.
//
// The exact-target lane reads this placement too (provedHighWriteFindings):
// its rules match a resolved target, which a copy-mode call names only here.
func sandboxGuestPlacedInput(request trustedActionRequest, facts actionfacts.Facts) (actionfacts.Input, bool) {
	guestCWD := request.SandboxGuestCWD
	if guestCWD == "" || guestCWD == request.Input.CWD || request.unplacedStatement {
		return actionfacts.Input{}, false
	}
	if !guestFolderMayChangeJudgment(facts) {
		return actionfacts.Input{}, false
	}
	input := request.Input
	input.CWD = guestCWD
	return input, true
}

// guestFolderMayChangeJudgment reports a call whose judgment the guest's
// working directory may change (sandboxGuestPlacedInput): one the analysis
// did not read in full, one with a relative operand, and one with a Git hook
// or config candidate the git owners place by the working directory itself.
func guestFolderMayChangeJudgment(facts actionfacts.Facts) bool {
	return !facts.Authoritative() || hasRelativePathOperand(facts) || hasGitHookMutationCandidate(facts) || hasGitReadOutputWrite(facts)
}

// hasRelativePathOperand reports a path the call names relative to its
// working directory: not absolute and not under "~".
func hasRelativePathOperand(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		value := strings.TrimSpace(candidate.Value)
		if value != "" && !candidate.Absolute && !strings.HasPrefix(value, "~") && !path.IsAbs(value) {
			return true
		}
	}
	return false
}

// stateLinkResolver resolves a path through links: the hook's resolved
// write targets first, then the local filesystem when the hook allows it.
func stateLinkResolver(request trustedActionRequest) func(string) (string, bool) {
	return func(value string) (string, bool) {
		if physical, found := request.ResolvedWriteTargets[value]; found && physical != "" {
			return physical, true
		}
		if request.SkipLocalFilesystemResolution {
			return "", false
		}
		if request.ProtectedHomeHook {
			// A managed gateway may not read the user's home: the hook
			// client's walk of the command's words places a link spelling
			// (GAP-2569).
			return hookpaths.WalkFactTarget(request.ResolvedWriteTargets, value)
		}
		physical, ok := request.targetMemo.ResolveWriteTarget(driveFSPath(request, value))
		return driveViewPath(request, physical), ok
	}
}

// gitBashDriveView is a Git Bash call on Windows with its drive home and
// cwd (C:/Users/x) spelled as rooted POSIX paths (/C:/Users/x), so the link,
// pattern and xargs state checks, which read only a rooted home, judge it
// as they judge the call on Linux and macOS (GAP-2577). The view's
// filesystem reads go through driveFSPath and come back through
// driveViewPath. ok is false off Windows, for a managed or sandbox call and
// for a home that is not a drive path.
func gitBashDriveView(facts actionfacts.Facts, request trustedActionRequest) (actionfacts.Facts, trustedActionRequest, bool) {
	if runtime.GOOS != "windows" || request.gitBashDrive || request.ProtectedHomeHook ||
		request.SkipLocalFilesystemResolution {
		return actionfacts.Facts{}, request, false
	}
	home := filepath.ToSlash(facts.ActiveHome)
	if !actionfacts.DriveSlashPath(home) {
		home = filepath.ToSlash(request.Input.ActiveHome)
	}
	if !actionfacts.DriveSlashPath(home) {
		return actionfacts.Facts{}, request, false
	}
	posix := false
	for _, command := range facts.Commands {
		posix = posix || command.Dialect == actionfacts.DialectPOSIX
	}
	if !posix {
		return actionfacts.Facts{}, request, false
	}
	view := request
	view.gitBashDrive = true
	view.Input.ActiveHome = "/" + strings.TrimRight(home, "/")
	view.Input.CWD = ""
	if cwd := filepath.ToSlash(request.Input.CWD); actionfacts.DriveSlashPath(cwd) {
		view.Input.CWD = "/" + cwd
	}
	view.Input.DialectHint = actionfacts.DialectPOSIX
	// Git Bash expands an unquoted leading ~ to the drive home; the view
	// spells it so (`rm -rf ~/proj/dclink/../.defenseclaw/x`).
	if command, ok := trustedBashCommandInput(request.Input); ok {
		if rewritten, changed := driveViewTildeCommand(command, view.Input.ActiveHome); changed {
			view.Input.Command, view.Input.Args = rewritten, nil
		}
	}
	return actionfacts.Analyze(view.Input), view, true
}

// driveViewTildeCommand respells every unquoted leading ~ or ~/ of a call
// word as home. changed is false when nothing was respelled, the command
// does not parse, or home needs quoting.
func driveViewTildeCommand(command, home string) (string, bool) {
	if strings.ContainsAny(home, " \t\n'\"$`*?[]{}()<>|&;#!\\") {
		return "", false
	}
	file, ok := shellparse.Parse(command)
	if !ok {
		return "", false
	}
	changed := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for _, word := range call.Args {
			if len(word.Parts) == 0 {
				continue
			}
			lit, ok := word.Parts[0].(*syntax.Lit)
			if !ok || lit.Value != "~" && !strings.HasPrefix(lit.Value, "~/") {
				continue
			}
			lit.Value = home + lit.Value[1:]
			changed = true
		}
		return true
	})
	if !changed {
		return "", false
	}
	var out bytes.Buffer
	if err := syntax.NewPrinter().Print(&out, file); err != nil {
		return "", false
	}
	return strings.TrimSpace(out.String()), true
}

// driveFSPath is the Windows spelling of a drive view path (/C:/x -> C:/x).
func driveFSPath(request trustedActionRequest, value string) string {
	if request.gitBashDrive && strings.HasPrefix(value, "/") && actionfacts.DriveSlashPath(value[1:]) {
		return value[1:]
	}
	return value
}

// driveViewPath is the drive view spelling of a Windows path (C:\x -> /C:/x).
func driveViewPath(request trustedActionRequest, value string) string {
	if slashed := filepath.ToSlash(value); request.gitBashDrive && actionfacts.DriveSlashPath(slashed) {
		return "/" + slashed
	}
	return value
}

// gitBashOperandSpelling is the local file system path of a POSIX operand.
// On a native Windows host the POSIX reading of a Git Bash call leaves a
// drive path (C:/x, C:\x) unresolved and keeps an MSYS drive mount (/c/x)
// as written, while Git Bash opens the drive path: a write through a disk
// link or junction outside the home to ~/.defenseclaw was not placed in the
// state, though its ~/.ssh twin was (rel-1-0-6:GAP-0213). Elsewhere, and for
// any other operand, it is the resolved path.
func gitBashOperandSpelling(candidate actionfacts.PathFact) string {
	if runtime.GOOS != "windows" || candidate.Flavor != actionfacts.PathFlavorPOSIX {
		return candidate.Resolved
	}
	if candidate.Resolved == "" {
		if value := filepath.ToSlash(candidate.Value); actionfacts.DriveSlashPath(value) {
			return path.Clean(value)
		}
		return ""
	}
	return actionfacts.MSYSDrivePath(candidate.Resolved)
}

// stateRootOf returns the physical state root and a test for a path in it.
func stateRootOf(home string, resolve func(string) (string, bool)) (string, func(string) bool) {
	spelled, separator := filepath.Join(home, ".defenseclaw"), string(filepath.Separator)
	if strings.HasPrefix(home, "/") {
		// A rooted slash home (a Git Bash drive view on Windows, GAP-2577)
		// keeps its slash spelling.
		spelled, separator = path.Join(home, ".defenseclaw"), "/"
	}
	root, ok := resolve(spelled)
	if !ok {
		root = spelled
	}
	return root, func(value string) bool {
		return value == root || strings.HasPrefix(value, root+separator)
	}
}

// globbedStateMutationThroughLink is globbedStateMutation for operands
// spelled through a link to the state (`rm -rf dclink/*`, `rm -rf
// ./dclink/hooks/*`, `cp -a /tmp/x/. dclink/` with dclink ->
// ~/.defenseclaw; pod check17 GAP-2047): the static directory part of each
// word (up to the first pattern component; the parent of a plain word, the
// word itself when it ends in / or /.) is resolved, and a word whose
// directory is physically in the state is judged by its ~/.defenseclaw
// spelling.
func globbedStateMutationThroughLink(facts actionfacts.Facts, request trustedActionRequest) bool {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !strings.HasPrefix(home, "/") {
		return false
	}
	resolve := stateLinkResolver(request)
	root, inState := stateRootOf(home, resolve)
	dirs := posixCommandDirectories(facts, home)
	for commandIndex, command := range facts.Commands {
		if command.Effect == actionfacts.EffectPreview || command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		words, ok := stateOperandWords(command)
		if !ok {
			continue
		}
		git := path.Base(command.Program) == "git"
		rewritten, changed := slices.Clone(words), false
		for index, word := range words {
			if git {
				// `git -C dclink clean -fdx`: a -C or --work-tree value is
				// a directory git enters, so the whole word is resolved
				// (GAP-2047 L11).
				if spelled, ok := gitDirectoryWordThroughLink(words, index, home, facts.CWD, root, resolve, inState); ok {
					rewritten[index], changed = spelled, true
					continue
				}
			}
			if spelled, ok := stateWordThroughLink(word, home, facts.CWD, root, resolve, inState); ok {
				rewritten[index], changed = spelled, true
			}
		}
		if spelled, moved := copyDestinationThroughLink(command, rewritten, home, facts.CWD, root, resolve, inState); moved {
			rewritten, changed = spelled, true
		}
		if changed && globbedStateCommandMutates(command, rewritten, home, facts.CWD) {
			return true
		}
		if copyThroughLinkedChild(request, command, words, home, facts.CWD, root, resolve, inState) {
			return true
		}
		// `cd dclink && git clean -fdx`: a directory the command runs in
		// after a cd, physically in the state but spelled outside it, is
		// judged by its ~/.defenseclaw spelling (GAP-2047 L11).
		if commandIndex >= len(dirs) {
			continue
		}
		program, programWords := unwrapStateWrapper(command, words)
		for _, dir := range dirs[commandIndex] {
			if !strings.HasPrefix(dir, "/") {
				continue
			}
			spelled, ok := stateWordThroughLink(strings.TrimRight(dir, "/")+"/", home, facts.CWD, root, resolve, inState)
			if ok && globbedStateCommandMutates(program, programWords, home, strings.TrimRight(spelled, "/")) {
				return true
			}
		}
	}
	return false
}

// copyDestinationThroughLink spells the destination of a cp, mv or ln, which
// the call treats as a directory when the target-directory option names it or
// the link it names points at one, under ~/.defenseclaw when it is a link to a
// directory of the state (`cp -t dclink /tmp/x/conf*.yaml`, `cp /tmp/x/conf*.yaml
// dclink`, GAP-1053). Its static directory part is the word itself, not the
// parent stateWordThroughLink reads for a plain word.
func copyDestinationThroughLink(
	command actionfacts.CommandFact, words []string, home, cwd, root string,
	resolve func(string) (string, bool),
	inState func(string) bool,
) ([]string, bool) {
	switch path.Base(command.Program) {
	case "cp", "mv", "ln":
	default:
		return words, false
	}
	index, attached, option := actionfacts.CopyOperandRoles(words)
	prefix := ""
	if index < 0 && attached != "" {
		for position, word := range words {
			if option[position] && strings.HasSuffix(word, attached) {
				index, prefix = position, strings.TrimSuffix(word, attached)
				break
			}
		}
	}
	if index < 0 {
		return words, false
	}
	word := strings.TrimPrefix(words[index], prefix)
	if word == "" || stateWordExpands(word) {
		return words, false
	}
	spelled, ok := stateWordThroughLink(strings.TrimRight(word, "/")+"/", home, cwd, root, resolve, inState)
	if !ok {
		return words, false
	}
	moved := slices.Clone(words)
	moved[index] = prefix + strings.TrimRight(spelled, "/")
	return moved, true
}

// copyThroughLinkedChild reports a cp whose destination directory has a child
// that is a link to protected state and whose source words can name it:
// `cp /tmp/x/conf*.yaml dir/` with dir/config.yaml a link to
// ~/.defenseclaw/config.yaml. cp writes through the link; a move or a link
// replaces it. The children are the destination directory read locally, and,
// for a gateway that may not read it, the links the hook client walked
// (hookpaths.WalkFactChildren). GAP-1053.
func copyThroughLinkedChild(
	request trustedActionRequest, command actionfacts.CommandFact, words []string, home, cwd, root string,
	resolve func(string) (string, bool),
	inState func(string) bool,
) bool {
	if path.Base(command.Program) != "cp" {
		return false
	}
	index, directory, option := actionfacts.CopyOperandRoles(words)
	if index >= 0 {
		directory = words[index]
	}
	if directory == "" || stateWordExpands(directory) {
		return false
	}
	placed, ok := stateHomePath(directory, home, cwd)
	if !ok {
		return false
	}
	placed = path.Clean(placed)
	var patterns []string
	for position, word := range words {
		if position != index && !option[position] && word != "" {
			patterns = append(patterns, expandStateBraces(path.Base(word))...)
		}
	}
	if len(patterns) == 0 {
		return false
	}
	children := hookpaths.WalkFactChildren(request.ResolvedWriteTargets, placed)
	if !request.ProtectedHomeHook && !request.SkipLocalFilesystemResolution {
		if entries, err := hookpaths.ReadDir(placed); err == nil && len(entries) <= 4096 {
			for _, entry := range entries {
				if entry.Type()&fs.ModeSymlink == 0 {
					continue
				}
				if physical, linked := resolve(placed + "/" + entry.Name()); linked {
					if children == nil {
						children = map[string]string{}
					}
					children[entry.Name()] = physical
				}
			}
		}
	}
	for name, physical := range children {
		if !inState(physical) || !statePatternReaches(home+"/.defenseclaw"+strings.TrimPrefix(physical, root), home, cwd) {
			continue
		}
		for _, pattern := range patterns {
			if shellComponentMatches(pattern, name) {
				return true
			}
		}
	}
	return false
}

// gitDirectoryWordThroughLink spells the value of a git -C or --work-tree
// option (its own word or attached with =) under ~/.defenseclaw when the
// directory it names is physically in the state.
func gitDirectoryWordThroughLink(
	words []string, index int, home, cwd, root string,
	resolve func(string) (string, bool),
	inState func(string) bool,
) (string, bool) {
	word, prefix := words[index], ""
	switch {
	case strings.HasPrefix(word, "--work-tree="):
		prefix, word = "--work-tree=", strings.TrimPrefix(word, "--work-tree=")
	case index > 0 && (words[index-1] == "-C" || words[index-1] == "--work-tree"):
	default:
		return "", false
	}
	if word == "" || strings.HasPrefix(word, "-") || stateWordExpands(word) {
		return "", false
	}
	spelled, ok := stateWordThroughLink(strings.TrimRight(word, "/")+"/", home, cwd, root, resolve, inState)
	if !ok {
		return "", false
	}
	return prefix + strings.TrimRight(spelled, "/"), true
}

// stateWordThroughLink returns word spelled under ~/.defenseclaw when its
// static directory part is physically in the state but not spelled there.
func stateWordThroughLink(
	word, home, cwd, root string,
	resolve func(string) (string, bool),
	inState func(string) bool,
) (string, bool) {
	if word == "" || strings.HasPrefix(word, "-") {
		return "", false
	}
	full, ok := stateHomePath(word, home, cwd)
	if !ok {
		return "", false
	}
	components := strings.Split(full, "/")
	split := len(components) - 1
	if strings.HasSuffix(full, "/") || strings.HasSuffix(full, "/.") {
		split = len(components)
	}
	for index, component := range components {
		if stateWordExpands(component) {
			split = min(split, index)
			break
		}
	}
	directory := path.Clean("/" + strings.Join(components[:split], "/"))
	// A `..` after a link ascends from the link's target, so the directory
	// part is resolved as the kernel walks it and its lexical spelling
	// proves nothing (`rm -rf dclink/../.defenseclaw/*`, GAP-2047 L5).
	walked := hasDotDotComponent(strings.Join(components[:split], "/"))
	spelledRoot := home + "/.defenseclaw"
	if !walked && (directory == "/" || directory == home ||
		directory == spelledRoot || strings.HasPrefix(directory, spelledRoot+"/")) {
		return "", false
	}
	walkSpelling := directory
	if walked {
		walkSpelling = "/" + strings.TrimLeft(strings.Join(components[:split], "/"), "/")
	}
	physical, ok := resolve(walkSpelling)
	if !ok || !inState(physical) {
		return "", false
	}
	rest := strings.Join(components[split:], "/")
	spelled := spelledRoot + strings.TrimPrefix(physical, root)
	if rest != "" {
		spelled += "/" + rest
	} else if strings.HasSuffix(word, "/") {
		spelled += "/"
	}
	return spelled, true
}

// stateOperandThroughLink reports a changing operand spelled outside the
// state whose place is in it: a project symlink to the state root as a
// parent (`rm -rf dclink/installer`), or as the operand itself when a
// trailing separator makes the kernel follow it (`rm -rf dclink/`). Such a
// call names no state path, so the mention check alone let it through
// (GAP-2047); provenStateMutationPath then judges it on the physical
// target, as it does every other operand. The managed agent settings
// DefenseClaw publishes are protected like the state, so an operand whose
// place is one of them is reported the same way (GAP-1064).
func stateOperandThroughLink(facts actionfacts.Facts, request trustedActionRequest) bool {
	home := facts.ActiveHome
	if !filepath.IsAbs(home) && (!request.gitBashDrive || !path.IsAbs(home)) {
		return false
	}
	resolve := stateLinkResolver(request)
	_, inState := stateRootOf(home, resolve)
	for _, candidate := range facts.Paths {
		switch candidate.Access {
		case actionfacts.PathAccessDelete, actionfacts.PathAccessWrite,
			actionfacts.PathAccessAppend, actionfacts.PathAccessMetadata:
		default:
			continue
		}
		value := gitBashOperandSpelling(candidate)
		drive := request.gitBashDrive && candidate.Flavor == actionfacts.PathFlavorPOSIX && path.IsAbs(value)
		if !filepath.IsAbs(value) && !drive || inState(value) {
			continue
		}
		target := filepath.Dir(value)
		if drive {
			target = path.Dir(value)
		}
		if strings.HasSuffix(candidate.Value, "/") || strings.HasSuffix(candidate.Value, "/.") {
			target = value
		}
		if physical, ok := resolve(target); ok && inState(physical) {
			return true
		}
		// `rm -rf dclink/../.defenseclaw/hooks`: the parent as the kernel
		// walks it (GAP-2047 L5).
		walked, isWalked := stateWalkSpelling(candidate, request.Input.CWD, home)
		if isWalked {
			if physical, ok := resolve(walkParent(walked)); ok && inState(physical) {
				return true
			}
		}
		if drive {
			continue
		}
		if managedSettingsReachedThroughLink(facts, candidate, value, resolve) ||
			isWalked && managedSettingsReachedThroughLink(facts, candidate, walked, resolve) {
			return true
		}
	}
	return false
}

// managedSettingsReachedThroughLink reports a changing operand that is no
// managed agent settings file by its spelling but is one by the file the
// kernel opens for it: a project link to the vendor folder, to a published
// file or to another link (GAP-1064). The operand is followed whole, so a
// link as its last name counts; a delete removes the final name and never
// the file a link there reaches, so only the directory of its name is
// followed. The spelling is walked, not cleaned, so a `..` after a link
// ascends from the target of the link.
func managedSettingsReachedThroughLink(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
	spelling string,
	resolve func(string) (string, bool),
) bool {
	walk, entry := spelling, ""
	if candidate.Access == actionfacts.PathAccessDelete {
		walk, entry = walkParent(spelling), filepath.Base(spelling)
	}
	physical, ok := resolve(walk)
	if !ok || !filepath.IsAbs(physical) {
		return false
	}
	if entry != "" {
		physical = filepath.Join(physical, entry)
	}
	if filepath.Clean(physical) == filepath.Clean(spelling) {
		return false
	}
	linked := candidate
	linked.Value, linked.Normalized, linked.Resolved = physical, physical, physical
	return managedAgentSettingsCandidate(facts, linked)
}

// fileToolWriteThroughLinkToState reports a file tool write (write_file,
// an edit, a patch target: a call with no shell command) whose target is an
// existing link that leads into the active DefenseClaw state. The tool opens
// the path it names and the kernel follows the link, so it writes the state
// file, while the path names no state: the mention and path checks let a
// Hermes V4A patch of a project link to ~/.defenseclaw/... through
// (GAP-0684). The hook client's resolved target decides when it lists one;
// otherwise the target is resolved here, as for the SSH key files (a home
// the gateway cannot read resolves to nothing and proves nothing). A link
// to an ordinary file is judged by that file.
func fileToolWriteThroughLinkToState(facts actionfacts.Facts, request trustedActionRequest) bool {
	if _, shell := trustedBashCommandInput(request.Input); shell {
		return false
	}
	projected := facts.EnforcementProjection()
	if projected.ActiveHome == "" {
		return false
	}
	for _, candidate := range projected.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		command, ok := integrityCommandByID(projected, candidate.CommandID)
		if !ok || !stateCommandMutatesPath(command, candidate) {
			continue
		}
		physical := ""
		for _, spelling := range []string{candidate.Resolved, candidate.Value, candidate.Normalized} {
			if value, found := request.ResolvedWriteTargets[spelling]; found {
				physical = value
				break
			}
		}
		if physical == "" && filepath.IsAbs(candidate.Resolved) && !request.SkipLocalFilesystemResolution {
			var resolved bool
			physical, resolved = hookpaths.ResolveWriteTarget(candidate.Resolved)
			if !resolved {
				// A target whose own local read did not answer is not
				// proved free of the state, as in linkedActiveStateWrite
				// (rel-1-0-10:GAP-1804, GAP-1805).
				if _, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(candidate.Resolved, projected.ActiveHome); same || !complete {
					return true
				}
			}
		}
		if !filepath.IsAbs(physical) || filepath.Clean(physical) == filepath.Clean(candidate.Resolved) {
			continue
		}
		linked := candidate
		linked.Value, linked.Normalized, linked.Resolved = physical, physical, physical
		if matchesActiveDefenseClawState(projected, linked) {
			return true
		}
	}
	return false
}

// provenLinkedStateWrite reports a command whose writer, proven for its
// own command, writes through a link that an earlier part of the same
// command makes to active DefenseClaw state: ln -s ~/.defenseclaw hc;
// cp a.txt hc/config.yaml, plain or behind a prefix wrapper (GAP-2522).
// The analysis marks such an action partial (a new link makes later
// targets unknown), so the whole-action proof never holds for it; the
// link reading here is the proof. A write that only may run (after &&)
// counts, as the ~/.ssh alias does.
func provenLinkedStateWrite(facts actionfacts.Facts, request trustedActionRequest) bool {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return false
	}
	text, known := trustedBashCommandInput(request.Input)
	if !known || !strings.Contains(text, "ln") && !strings.Contains(text, "link") && !strings.Contains(text, "cp") {
		return false
	}
	facts, request = protectedHomePlacedReading(facts, request)
	projected := facts.EnforcementProjection()
	if projected.ActiveHome == "" {
		return false
	}
	var links *hookpaths.Links
	linkedWrite := func(projected actionfacts.Facts) bool {
		for _, candidate := range projected.Paths {
			command, ok := integrityCommandByID(projected, candidate.CommandID)
			if !ok || !stateCommandMutatesPath(command, candidate) {
				continue
			}
			if links == nil {
				made := hookpaths.CommandLinks(request.Input.Tool, text, request.Input.CWD, projected.ActiveHome)
				links = &made
			}
			if linkedActiveStateWrite(projected, command, candidate, *links, request, request.Input.CWD, false) {
				return true
			}
		}
		return false
	}
	if linkedWrite(projected) {
		return true
	}
	// The analysis leaves ~/ and $HOME/ operands dynamic, so a write under
	// the home through a link the command makes (ln -s ~/.defenseclaw/hooks
	// ~/hk; cp a.txt ~/hk/x.sh, or the link made in a subshell after cd ~)
	// has no writer path here; the home-spelled twin places it as the
	// literal home spelling does (GAP-2555). It only adds this block.
	// CommandLinks reads the original text, which expands ~ itself.
	if twin, ok := actionfacts.HomeSpelledTwin(request.Input); ok && linkedWrite(twin.EnforcementProjection()) {
		return true
	}
	if links == nil {
		made := hookpaths.CommandLinks(request.Input.Tool, text, request.Input.CWD, projected.ActiveHome)
		links = &made
	}
	return links.HasAliases() && placedLinkedStateWrite(request, text, projected.ActiveHome, *links)
}

// protectedHomePlacedReading places a call of a managed hook peer whose
// working directory the gateway could not resolve (ProtectHome keeps it out
// of the user's home, so the hook CWD is empty) in the directory the hook
// client reported, as the client keyed its evidence (managedClientCWD): the
// link readings need absolute operands, so ln -s ~/.defenseclaw hc; cp a.txt
// hc/config.yaml was not read there (GAP-2544). The client's directory only
// adds a block of those readings: it must be absolute, without "..", and
// in the caller's home or its project root.
func protectedHomePlacedReading(facts actionfacts.Facts, request trustedActionRequest) (actionfacts.Facts, trustedActionRequest) {
	client, ok := protectedHomeClientDirectory(request)
	if !ok || request.SkipLocalFilesystemResolution {
		return facts, request
	}
	request.Input.CWD = client
	// The client keyed its link facts by its own walk of the call, which
	// places a command by the hook folder: read the paths there too, or a
	// write the gateway places after a cd misses its keys (GAP-0426).
	return actionfacts.Analyze(request.Input).AtHookFolder(), request
}

// placedLinkedStateWrite reads each top-level statement in the directory
// it runs in, so a write after a cd through a link the command makes is
// placed where the shell places it (cd ~ && ln -s .defenseclaw hc && cp
// project/a.txt hc/config.yaml), and an in-place editor operand (sed -i,
// perl -i) through a linked directory is the write it is on the state file
// itself (ln -s ~/.defenseclaw hc; sed -i s/a/b/ hc/config.yaml, GAP-2522).
// An in-place editor replaces the directory entry, so only a link to one of
// its directories is followed. The statements are the ones the link reading
// placed; a command whose directory changes it cannot place is read whole
// in its own directory.
func placedLinkedStateWrite(request trustedActionRequest, text, home string, links hookpaths.Links) bool {
	for _, statement := range hookpaths.PlacedOrWhole(text, request.Input.CWD, home) {
		input := request.Input
		input.Args, input.Argv, input.Command, input.CWD = nil, nil, statement.Command, statement.Dir
		projected := actionfacts.Analyze(input).EnforcementProjection()
		if projected.ActiveHome == "" {
			continue
		}
		// Each statement is read alone, in its directory, even when that is
		// the starting directory: a lone statement gets the trusted home
		// for its ~ and $HOME words, which the whole list does not, so
		// ln -s ~/.defenseclaw/hooks ~/hk; cp a.txt ~/hk/x.sh names its
		// write here only (GAP-2555).
		for _, candidate := range projected.Paths {
			command, ok := integrityCommandByID(projected, candidate.CommandID)
			if ok && stateCommandMutatesPath(command, candidate) &&
				linkedActiveStateWrite(projected, command, candidate, links, request, statement.Dir, true) {
				return true
			}
		}
		for _, operand := range hookpaths.InPlaceEditOperands(statement.Command, statement.Dir, home, statement.User) {
			targets := links.AliasTargets(operand, true)
			if !request.SkipLocalFilesystemResolution && !request.ProtectedHomeHook {
				// The linked entry's parent can go on through an existing
				// disk link to state (GAP-2534); the entry keeps its name.
				for _, target := range slices.Clone(targets) {
					if parent, ok := hookpaths.ResolveWriteTarget(filepath.Dir(target)); ok {
						targets = append(targets, filepath.Join(parent, filepath.Base(target)))
					}
				}
			}
			for _, target := range targets {
				written := actionfacts.PathFact{
					Access: actionfacts.PathAccessWrite, Flavor: actionfacts.PathFlavorPOSIX,
					Value: target, Normalized: target, Absolute: true, Resolved: target,
				}
				if matchesActiveDefenseClawState(projected, written) {
					return true
				}
			}
		}
	}
	return false
}

// provenFollowedInPlaceStateWrite reports sed -i --follow-symlinks (gsed
// too, the option abbreviated or not) whose operand is active DefenseClaw
// state, directly, through an existing link or through a link the same
// command makes: GNU sed then rewrites the file the link names instead of
// replacing the link (GAP-2529). The facts leave --follow-symlinks and a
// clustered -i (-si, -Ei) partial, so no path proof holds for them. Without
// --follow-symlinks sed -i and perl -i replace the directory entry: the
// entry itself is judged (the operand name, its parent read through links),
// never the file a final link names, so an edit of a link to state stays an
// ordinary write (GAP-2531).
func provenFollowedInPlaceStateWrite(facts actionfacts.Facts, request trustedActionRequest) bool {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return false
	}
	text, known := trustedBashCommandInput(request.Input)
	if !known {
		return false // no text test of the call: the readers below take the program from the parsed word (rel-1-0-10:GAP-0737)
	}
	facts, request = protectedHomePlacedReading(facts, request)
	home := facts.EnforcementProjection().ActiveHome
	// The parsed program words decide, never the raw text (GAP-0737): a call
	// with no word that may be sed or perl skips the link reading, and the
	// placing and analysis of each statement below (GAP-0901).
	if home == "" || !hookpaths.MayEditInPlace(text, home) {
		return false
	}
	links := hookpaths.CommandLinks(request.Input.Tool, text, request.Input.CWD, home)
	for _, statement := range hookpaths.PlacedOrWhole(text, request.Input.CWD, home) {
		entries, operands := hookpaths.InPlaceEdits(statement.Command, statement.Dir, home, statement.User)
		if len(operands) == 0 && len(entries) == 0 {
			continue
		}
		input := request.Input
		input.Args, input.Argv, input.Command, input.CWD = nil, nil, statement.Command, statement.Dir
		projected := actionfacts.Analyze(input).EnforcementProjection()
		if projected.ActiveHome == "" {
			continue
		}
		for _, operand := range operands {
			targets := append([]string{operand}, links.AliasTargets(operand, false)...)
			if physical, found := request.ResolvedWriteTargets[operand]; found {
				targets = append(targets, physical)
			} else if !request.SkipLocalFilesystemResolution && !request.ProtectedHomeHook {
				if physical, ok := hookpaths.ResolveWriteTarget(operand); ok {
					targets = append(targets, physical)
				}
			} else if physical, ok := hookpaths.WalkFactTarget(request.ResolvedWriteTargets, operand); ok {
				// The link walk of the hook client places a managed call
				// the gateway cannot read (GAP-1064).
				targets = append(targets, physical)
			}
			for _, target := range targets {
				// A target the state index could not rule out is not proved free of the
				// state: refused, as an unfinished walk refuses a patch target (GAP-1789).
				switch active, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(target, projected.ActiveHome); {
				case !complete:
					return true
				case same:
					target = active
				}
				written := actionfacts.PathFact{
					Access: actionfacts.PathAccessWrite, Flavor: actionfacts.PathFlavorPOSIX,
					Value: target, Normalized: target, Absolute: true, Resolved: target,
				}
				if matchesActiveDefenseClawState(projected, written) {
					return true
				}
			}
		}
		for _, entry := range entries {
			if slices.Contains(operands, entry) {
				continue
			}
			targets := append([]string{entry}, links.AliasTargets(entry, true)...)
			if !request.SkipLocalFilesystemResolution && !request.ProtectedHomeHook {
				if parent, ok := hookpaths.ResolveWriteTarget(filepath.Dir(entry)); ok {
					targets = append(targets, filepath.Join(parent, filepath.Base(entry)))
				}
			} else if state, found := request.ResolvedWriteTargets[hookpaths.InPlaceEntryFactPrefix+entry]; found {
				// The hook client followed the directory (rel-1-0-6:GAP-0681
				// review 2).
				targets = append(targets, state)
			} else if parent, ok := hookpaths.WalkFactTarget(request.ResolvedWriteTargets, filepath.Dir(entry)); ok {
				// The link walk of the hook client reaches the directory of
				// an entry outside the state (GAP-1064).
				targets = append(targets, filepath.Join(parent, filepath.Base(entry)))
			}
			for _, target := range targets {
				written := actionfacts.PathFact{
					Access: actionfacts.PathAccessWrite, Flavor: actionfacts.PathFlavorPOSIX,
					Value: target, Normalized: target, Absolute: true, Resolved: target,
				}
				if matchesActiveDefenseClawState(projected, written) {
					return true
				}
			}
		}
	}
	return false
}

// linkedActiveStateWrite reports a write operand that reaches active
// state through a link the same command makes: ln -s ~/.defenseclaw hc;
// cp a.txt hc/config.yaml writes ~/.defenseclaw/config.yaml, plain or
// behind a prefix wrapper, as the ~/.ssh alias reaches authorized_keys
// (GAP-1521, GAP-2522). The link does not exist when the hook runs, so
// the name is followed through the links of the same command only. ln,
// a delete or a move acts on the final name: only a link to one of its
// directories is followed.
func linkedActiveStateWrite(
	projected actionfacts.Facts,
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
	links hookpaths.Links,
	request trustedActionRequest,
	cwd string,
	placed bool,
) bool {
	value := candidate.Resolved
	if value == "" {
		value = candidate.Normalized
	}
	if !filepath.IsAbs(value) {
		// A POSIX operand under a Windows working directory (Git Bash) has
		// no resolved form in the facts; the link reading places it in the
		// directory the statement runs in, as the shell does (GAP-2550).
		if value = placedPOSIXOperand(value, cwd); value == "" {
			return false
		}
	}
	// ln, a delete and a move replace or remove the final name itself.
	entry := candidate.Access == actionfacts.PathAccessDelete ||
		slices.Contains([]string{"ln", "link", "gln", "glink"}, filepath.Base(command.Program)) ||
		candidate.Access == actionfacts.PathAccessWrite && hasOperation(command, actionfacts.OperationMove) &&
			!hasAnyOperation(command, actionfacts.OperationWrite, actionfacts.OperationAppend, actionfacts.OperationCopy)
	targets := links.AliasTargets(value, entry)
	for _, target := range targets {
		linked := candidate
		linked.Resolved = target
		if matchesActiveDefenseClawState(projected, linked) {
			return true
		}
	}
	// The linked name can go on through a disk link that already exists:
	// ln -s /opt/ext e; echo z > e/y/config.yaml, with /opt/ext/y ->
	// ~/.defenseclaw, writes the state file. The names the command links
	// reach (and, for a statement placed in a directory the links name, the
	// operand itself) are resolved on disk as the direct spelling is in
	// provenStateMutationPath (GAP-2534). An entry operand keeps its final
	// name: only its parent is resolved.
	if request.ProtectedHomeHook {
		// Behind ProtectHome, PrivateTmp and PrivateDevices the gateway
		// cannot read a directory the user can make, so the hook's map,
		// which follows the operand through the command's links as the
		// user, is the proof. Only an operand whose directory goes
		// through a command link is read from it: a link that is the final
		// name may be replaced, not followed (sed -i on the link).
		if len(links.AliasTargets(filepath.Dir(value), false)) == 0 {
			return false
		}
		physical := request.ResolvedWriteTargets[value]
		if physical == "" || physical == value || !filepath.IsAbs(physical) {
			return false
		}
		// A target the state index could not rule out is not proved free of the
		// state: refused, as an unfinished walk refuses a patch target (GAP-1789).
		switch active, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(physical, projected.ActiveHome); {
		case !complete:
			return true
		case same:
			physical = active
		}
		linked := candidate
		linked.Resolved = physical
		return matchesActiveDefenseClawState(projected, linked)
	}
	if request.SkipLocalFilesystemResolution {
		return false
	}
	if placed {
		targets = append(targets, value)
	}
	for _, target := range targets {
		physical, ok := "", false
		if entry {
			if parent, found := hookpaths.ResolveWriteTarget(filepath.Dir(target)); found {
				physical, ok = filepath.Join(parent, filepath.Base(target)), true
			}
		} else {
			physical, ok = hookpaths.ResolveWriteTarget(target)
			if !ok {
				// A target whose own local read did not answer is not
				// proved free of the state (rel-1-0-10:GAP-1804).
				if _, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(target, projected.ActiveHome); same || !complete {
					return true
				}
			}
		}
		if !ok || physical == target {
			continue
		}
		// A target the state index could not rule out is not proved free of the
		// state: refused, as an unfinished walk refuses a patch target (GAP-1789).
		switch active, same, complete := hookpaths.ResolveActiveStateHardlinkTarget(physical, projected.ActiveHome); {
		case !complete:
			return true
		case same:
			physical = active
		}
		linked := candidate
		linked.Resolved = physical
		if matchesActiveDefenseClawState(projected, linked) {
			return true
		}
	}
	return false
}

// placedPOSIXOperand places a plain relative POSIX operand (no tilde,
// parameter, substitution or pattern) in an absolute working directory, or
// returns "".
func placedPOSIXOperand(value, cwd string) string {
	if value == "" || !filepath.IsAbs(cwd) || strings.HasPrefix(value, "-") ||
		strings.ContainsAny(value, "~$`*?[\x00\r\n") || path.IsAbs(value) {
		return ""
	}
	return hookpaths.OperandPath(filepath.FromSlash(value), cwd)
}

// stateDirectoryEntryTarget places an operand that removes or replaces a
// directory entry: a delete or move source and a move destination. rm,
// unlink and mv act on the final name itself, so removing, moving or
// replacing a project symlink or hard link to active state leaves the state
// untouched. Only the parent directories are followed. ok is false, and the
// operand is resolved as a write, when the command also writes through the
// name (shred -u), a trailing separator makes the kernel follow a link, a
// move lands inside a (linked) directory, a Windows delete may recurse
// through a directory link, or the gateway cannot place the parent.
func stateDirectoryEntryTarget(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
	request trustedActionRequest,
) (string, bool) {
	moveDestination := candidate.Access == actionfacts.PathAccessWrite &&
		hasOperation(command, actionfacts.OperationMove)
	if candidate.Access != actionfacts.PathAccessDelete && !moveDestination ||
		request.SkipLocalFilesystemResolution ||
		hasAnyOperation(command, actionfacts.OperationWrite, actionfacts.OperationAppend,
			actionfacts.OperationCopy) {
		return "", false
	}
	windows := candidate.Flavor == actionfacts.PathFlavorWindows
	value := candidate.Resolved
	// A drive view operand (/C:/x, GAP-2577) is a rooted slash path.
	drive := request.gitBashDrive && !windows && path.IsAbs(value)
	if !filepath.IsAbs(value) && !drive || strings.HasSuffix(candidate.Value, "/") ||
		strings.HasSuffix(candidate.Value, "/.") ||
		windows && (strings.HasSuffix(candidate.Value, `\`) || strings.HasSuffix(candidate.Value, `\.`)) {
		return "", false
	}
	parentSpelling := filepath.Dir(value)
	if drive {
		parentSpelling = path.Dir(value)
	}
	if !windows && hasDotDotComponent(value) {
		// A walked spelling (stateWalkSpelling): the kernel follows a link
		// before the `..` after it.
		parentSpelling = walkParent(value)
	}
	parent, ok := "", false
	if request.ProtectedHomeHook {
		// The client walked the parent as the user (GAP-2569).
		parent, ok = hookpaths.WalkFactTarget(request.ResolvedWriteTargets, filepath.ToSlash(parentSpelling))
	}
	if !ok {
		parent, ok = hookpaths.ResolveWriteTarget(driveFSPath(request, parentSpelling))
	}
	if !ok {
		return "", false
	}
	entry := filepath.Join(parent, path.Base(filepath.ToSlash(value)))
	if info, err := hookpaths.Stat(entry); err == nil && info.IsDir() && (moveDestination || windows) {
		return "", false
	}
	if candidate.Flavor == actionfacts.PathFlavorPOSIX {
		// A Git Bash operand on Windows keeps its slash spelling, so the
		// state checks read the entry the way they read the operand.
		entry = filepath.ToSlash(entry)
	}
	return driveViewPath(request, entry), true
}

func provenPartialStateRedirect(
	facts actionfacts.Facts,
	projected actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if !integrityCommandOwnsStaticRedirect(projected, candidate) {
		return false
	}
	// The shell opens a static redirect target before it runs the program,
	// so the write does not depend on what the program is: a program named
	// by a relative path (./build.sh, scripts/gen.sh) has an uncertain
	// effect, yet its redirect writes the target as `make > f` does
	// (GAP-2268).
	original, ok := integrityCommandByID(facts, projected.ID)
	return ok && (original.Effect == actionfacts.EffectExecute ||
		original.Effect == actionfacts.EffectPreview ||
		original.Effect == actionfacts.EffectUncertain) &&
		(!original.ControlFlowUncertain ||
			// One side of a plain && or || list attempts its redirect
			// (cd sub && make >& ~/f, GAP-2225 RV13-3).
			original.ControlFlowOperator == actionfacts.ControlFlowOperatorAnd ||
			original.ControlFlowOperator == actionfacts.ControlFlowOperatorOr) &&
		integrityCommandOwnsStaticRedirect(original, candidate)
}

func stateCommandMutatesPath(command actionfacts.CommandFact, candidate actionfacts.PathFact) bool {
	if integrityCommandMutatesPath(command, candidate) {
		return true
	}
	if command.Effect != actionfacts.EffectExecute {
		return false
	}
	return candidate.Access == actionfacts.PathAccessDelete && hasOperation(command, actionfacts.OperationMove) ||
		candidate.Access == actionfacts.PathAccessMetadata && hasOperation(command, actionfacts.OperationPermissionChange)
}

// withMigratedLiteralRuleFindings blocks a tool call that a migrated 0.8.x
// literal rule (guardrail.MigratedLiteralRule) matches as 0.8.x did: 0.8.x
// ran the rule pattern over the text of the tool call, so the literal
// anywhere in it blocked. The rule pattern runs, with its own case handling,
// over that text (the raw arguments, their decoded strings, the command and
// argv) and over the words the parse took from it (an argument with its
// quotes or escapes removed, a redirect target, a wrapper argument, a path, a
// network host). That covers a call parsed only in part or in another
// dialect ([System.IO.File]::WriteAllText(path, "LITERAL") read as POSIX,
// GAP-1478), a here-string or variable, and text a tool writes, such as file
// content. The expression of such a rule matches only an argument that
// starts or ends with the literal (a CEL substring test over every argument
// does not fit the cost budget), and stays as it is. The literal is all such
// a rule means, so the match is its proof. A match only adds: an already
// enforcing finding is left alone, and a call the adapter cannot enforce
// keeps the finding detection-only.
func withMigratedLiteralRuleFindings(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	if generation == nil {
		return findings
	}
	var texts []string
	collected := false
	for _, candidate := range generation.semanticRules {
		owner := candidate.owner
		if !candidate.migratedLiteral || owner.prerequisite != nil || owner.detectionOnly || owner.alertOnly {
			continue
		}
		index := slices.IndexFunc(findings, func(finding RuleFinding) bool {
			return finding.RuleID == candidate.rule.ID
		})
		if index >= 0 && findings[index].contributesToEnforcement() {
			continue
		}
		if !collected {
			texts, collected = trustedActionTexts(request, facts), true
		}
		if !slices.ContainsFunc(texts, candidate.rule.Pattern.MatchString) {
			continue
		}
		finding := RuleFinding{
			RuleID:     candidate.rule.ID,
			Title:      candidate.rule.Title,
			Severity:   candidate.rule.Severity,
			Confidence: candidate.rule.Confidence,
			Tags:       append([]string(nil), candidate.rule.Tags...),
		}
		if index >= 0 {
			finding = findings[index]
		} else {
			finding = adjustConfidence(request.Input.Tool, finding)
		}
		finding.enforcement = findingEnforcementDetectionOnly
		if request.EnforcementCapable {
			finding.enforcement = findingEnforcementAllowed
		}
		finding = finding.withTrustedActionProof(newActionFactsSubgraphFindingProof(candidate.rule.ID, true, true))
		if index >= 0 {
			findings[index] = finding
		} else {
			findings = append(findings, finding)
		}
	}
	return findings
}

// trustedActionTexts returns the text of a tool call that 0.8.x scanned, its
// raw arguments with their decoded strings, command and argv, and the words
// the parse of its commands took from it, with its path values and network
// hosts.
func trustedActionTexts(request trustedActionRequest, facts actionfacts.Facts) []string {
	var texts []string
	if !request.ArtifactBody {
		texts = append(texts, request.LegacyText, request.Input.Command, string(request.Input.Args))
		texts = append(texts, request.Input.Argv...)
		texts = appendJSONStrings(texts, request.Input.Args)
	}
	for _, command := range facts.Commands {
		texts = append(texts, command.Argv...)
		// The quoted heredoc fed to a command (cat > file <<'EOF') is data
		// the command may act on, so a migrated literal in it counts in a
		// script body too, whatever the command's name. No name proves that
		// stdin goes unread: the shell that runs the script may bind any
		// name, true, cat or /bin/cat alike, to a function that reads it
		// (exported to the shell, or defined by BASH_ENV or a profile), and
		// the gateway sees none of that shell's state.
		if command.LiteralStdinComplete && !command.LiteralStdinAmbiguous {
			texts = append(texts, command.LiteralStdin)
		}
		for _, argument := range command.Arguments {
			texts = append(texts, argument.Value)
		}
		for _, redirect := range command.Redirects {
			texts = append(texts, redirect.Target)
		}
		for _, wrapper := range command.Wrappers {
			texts = append(texts, wrapper.Argv...)
		}
	}
	for _, path := range facts.Paths {
		texts = append(texts, path.Value)
	}
	for _, network := range facts.Network {
		texts = append(texts, network.Host)
	}
	return texts
}

// appendJSONStrings appends every string of the JSON value raw, object keys
// included, decoded, so a literal a JSON escape spells (\u003c for <) matches
// too. Text that is not JSON adds nothing; the raw text is matched as it is.
func appendJSONStrings(texts []string, raw json.RawMessage) []string {
	if len(raw) == 0 {
		return texts
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if err != nil {
			return texts
		}
		if text, ok := token.(string); ok {
			texts = append(texts, text)
		}
	}
}

// withTwinProvenBlocks returns findings, the finalized findings of a
// redirect-target action, with each finding of twin, the same lanes judged on
// its static-target twin, that may block there in place of the finding of the
// same rule or owner that may not, or that may block on a stronger proof: an
// authorized proof over an unauthorized one, and a proven mutation of
// DefenseClaw's own state (the observe-mode self-protection block,
// provenActiveStateMutation) over any other. A weaker finding the original
// spelling raised (a ~<login> path the gateway cannot place, GAP-2378) must
// not hide the twin's proof.
func withTwinProvenBlocks(findings, twin []RuleFinding) []RuleFinding {
	strength := func(finding RuleFinding) int {
		switch {
		case !finding.contributesToEnforcement():
			return 0
		case !finding.proof.authorizes(finding.RuleID):
			return 1
		case finding.proof.kind == findingProofActionFactsSemantic ||
			finding.proof.kind == findingProofActionFactsSubgraph ||
			finding.proof.kind == findingProofActiveStateMutation:
			return 3
		default:
			return 2
		}
	}
	for _, proven := range twin {
		if !proven.contributesToEnforcement() {
			continue
		}
		key := trustedActionFindingKey(proven.RuleID)
		index := slices.IndexFunc(findings, func(finding RuleFinding) bool {
			return trustedActionFindingKey(finding.RuleID) == key
		})
		switch {
		case index < 0:
			findings = append(findings, proven)
		case strength(proven) > strength(findings[index]):
			findings[index] = proven
		}
	}
	return findings
}

// loginGuessProvedFinding reports a finding a LoginGuess reading of a simple
// command may add: the proof of a write to DefenseClaw state. The reading
// gives USER and LOGNAME the login the home spells, a guess the shell may
// not hold, so it never decides a rule over the words of the command: a word
// expanded at run time stays unproven (detection-only) there, as it is in the
// reading without the guess.
func loginGuessProvedFinding(finding RuleFinding) bool {
	return loginGuessProvesRule(finding.RuleID)
}

// loginGuessProvesRule reports whether ruleID is the rule whose finding a
// LoginGuess reading may add. Only that rule is judged on the reading
// (trustedActionRequest.stateProofOnly): the others are discarded unread.
func loginGuessProvesRule(ruleID string) bool {
	return trustedActionFindingKey(ruleID) == canonicalTrustedRuleID("tamper.detector_state_write")
}

// loginGuessReadingMayProveStateWrite reports whether a LoginGuess reading of
// a simple command is worth its full judgment. The reading only proves a
// write to DefenseClaw state (loginGuessProvedFinding), and every lane that
// proves one starts from a command that may name the state folder however it
// is spelled (hookpaths.MayNameState) or whose operands the mention scan
// resolves into the state, through a link on disk too
// (ActionStateTargetMention, the scan withActiveStateTargetMention opens
// with). A reading that does neither would add only its cost to a command
// that merely names USER or LOGNAME. A managed hook proves the write from
// the client evidence instead, so its readings are all judged, except the
// readings of one loop iteration, whose spelled path no client evidence keys.
func loginGuessReadingMayProveStateWrite(request trustedActionRequest, simple actionfacts.SimpleCommand, cwd string) bool {
	return request.ProtectedHomeHook && !simple.LoopReading || hookpaths.MayNameState(simple.Text) ||
		request.targetMemo.ActionStateTargetMention(simple.Text, cwd, request.Input.ActiveHome)
}

// withProvenFindingsBeforeUnprovenKeysBlock puts the authorized-keys block
// that no proof backs (a write the hook could not resolve, so the managed
// gateway fails closed) after the findings a proof backs. The block names
// the call all the same, but the first rule names its cause: a content rule
// proved on a function body or an if block (an unrestricted sudoers grant)
// led the label at the top level and trailed the keys rule in a compound
// call, because the compound pass lists its own finding before the finding
// of each simple command (GAP-1045). The decision and the set of findings
// do not change.
func withProvenFindingsBeforeUnprovenKeysBlock(findings []RuleFinding) []RuleFinding {
	const keysRule = "persistence.ssh_authorized_keys_command"
	unproven := func(finding RuleFinding) bool {
		return finding.RuleID == keysRule && !finding.proof.authorizes(finding.RuleID)
	}
	first := slices.IndexFunc(findings, unproven)
	if first < 0 {
		return findings
	}
	proven := func(finding RuleFinding) bool {
		return finding.RuleID != keysRule && finding.contributesToEnforcement() &&
			finding.proof.authorizes(finding.RuleID)
	}
	if !slices.ContainsFunc(findings[first+1:], proven) {
		return findings
	}
	ordered := make([]RuleFinding, 0, len(findings))
	ordered = append(ordered, findings[:first]...)
	for _, finding := range findings[first:] {
		if proven(finding) {
			ordered = append(ordered, finding)
		}
	}
	for _, finding := range findings[first:] {
		if !proven(finding) {
			ordered = append(ordered, finding)
		}
	}
	return ordered
}

// withSimpleCommandFindings adds each command's ordinary standalone result
// beside the whole action's result. An enforcing or alert-only proof replaces
// a weaker finding for the same rule; a sibling removes nothing.
func withSimpleCommandFindings(findings, alone []RuleFinding) []RuleFinding {
	rank := func(finding RuleFinding) int {
		switch {
		case finding.contributesToEnforcement() && finding.proof.authorizes(finding.RuleID):
			return 3
		case finding.contributesToAlertOnly():
			return 2
		default:
			return 1
		}
	}
	for _, finding := range alone {
		key := trustedActionFindingKey(finding.RuleID)
		index := slices.IndexFunc(findings, func(existing RuleFinding) bool {
			return trustedActionFindingKey(existing.RuleID) == key
		})
		if index < 0 {
			findings = append(findings, finding)
		} else if rank(finding) > rank(findings[index]) ||
			(rank(finding) == rank(findings[index]) &&
				canonicalTrustedRuleID(finding.RuleID) == key &&
				canonicalTrustedRuleID(findings[index].RuleID) != key) {
			findings[index] = finding
		}
	}
	return findings
}

// withSequenceProvenFindings returns findings, the fallback findings checked
// against the whole action, with each finding of sequence, the same findings
// checked against a list read as a sequence, that may block there in place of
// its rule's finding. A finding only the whole action proves stays as it was.
func withSequenceProvenFindings(findings, sequence []RuleFinding) []RuleFinding {
	for _, proven := range sequence {
		if !proven.contributesToEnforcement() ||
			!proven.proof.authorizes(proven.RuleID) {
			continue
		}
		index := slices.IndexFunc(findings, func(finding RuleFinding) bool {
			return finding.RuleID == proven.RuleID
		})
		if index < 0 {
			findings = append(findings, proven)
		} else {
			findings[index] = proven
		}
	}
	return findings
}

// redirectReductionCandidate reports whether a match of candidate on the view
// from actionfacts.DynamicRedirectTargetReduction may stand for the
// whole action: the expression must be one that more redirects cannot turn
// off (semantic.Program.RedirectReductionSafe). Other rules keep their legacy
// fallback, as for any other partial action.
func redirectReductionCandidate(candidate compiledSemanticRule) bool {
	return candidate.program.RedirectReductionSafe()
}

// subsetReductionCandidate reports whether a match of candidate on the view
// from actionfacts.StaticCommandSubsetReduction may stand for the whole
// action: the expression must be one that more commands and facts cannot turn
// off (semantic.Program.StaticCommandSubsetSafe), and the rule must have no
// code-owned prerequisite, a Go check written for complete facts. Other rules
// keep their legacy fallback.
func subsetReductionCandidate(candidate compiledSemanticRule) bool {
	return candidate.owner.prerequisite == nil &&
		candidate.program.StaticCommandSubsetSafe()
}

// argvSubsetReductionCandidate is subsetReductionCandidate for a view that
// also keeps commands with partial argv (semantic.Program.StaticArgvSubsetSafe).
func argvSubsetReductionCandidate(candidate compiledSemanticRule) bool {
	return candidate.owner.prerequisite == nil &&
		candidate.program.StaticArgvSubsetSafe()
}

// listReductionCandidate reports whether a result of candidate on the view
// from actionfacts.ShortCircuitListReduction may stand for the whole action:
// the expression must not read how complete the analysis is
// (semantic.Program.ListReductionSafe). Other rules keep their legacy
// fallback.
func listReductionCandidate(candidate compiledSemanticRule) bool {
	return candidate.program.ListReductionSafe()
}

func excludeSemanticOwner(
	excluded map[string]struct{},
	owner semanticOwner,
	matched bool,
) {
	for _, ruleID := range owner.claimedIDs(matched) {
		excluded[ruleID] = struct{}{}
	}
	if matched {
		for _, ruleID := range owner.fallbackAliasesOnMatch {
			excluded[ruleID] = struct{}{}
		}
	}
}

type exactFallbackContract struct {
	proves                      func(actionfacts.Input, actionfacts.Facts) bool
	boundedSubgraphProves       func(actionfacts.Input, actionfacts.Facts) bool
	requiresExactDetectionProof bool
	detectionOnly               bool
	codeOwnedDetection          bool
	alertOnly                   bool
	// boundedRequiresActiveExpression makes the bounded lane also require
	// the active pack's expression for the rule (boundedRuleExpressionHolds),
	// so the lane never adds a finding the pack turned off or narrowed away
	// (rel-1-0-6:GAP-0419).
	boundedRequiresActiveExpression bool
}

var exactFallbackContracts = map[string]exactFallbackContract{
	"credential.kubernetes_named_secret_content_read": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactKubernetesSecretContentRead(input, facts)
			return ok
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactKubernetesSecretContentRead(input, facts)
			return ok
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		// A named Secret content read is high-value credential access, but
		// administrators also perform it legitimately. Universal profiles alert;
		// the protected-cluster rule below is the explicit blocking boundary.
		alertOnly: true,
	},
	"credential.protected_kubernetes_named_secret_content_read": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactKubernetesSecretContentRead(input, facts)
			return ok
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactKubernetesSecretContentRead(input, facts)
			return ok
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"impact.unbounded_cpu_fanout": {
		proves:                      exactUnboundedCPUFanoutAction,
		boundedSubgraphProves:       exactUnboundedCPUFanoutAction,
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"tamper.docker_insecure_http_registry": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactDockerInsecureRegistryWrite(input, facts)
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactDockerInsecureRegistryWrite(input, facts)
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"tamper.pam_permit_authentication_bypass": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactPAMAuthenticationBypass(input, facts)
			return ok
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactPAMAuthenticationBypass(input, facts)
			return ok
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"integrity.dpkg_status_direct_mutation": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXDPKGStatusMutation(facts) ||
				actionfacts.ExactSubmittedPOSIXDPKGStatusHeredocMutation(input)
		},
		boundedSubgraphProves: func(input actionfacts.Input, _ actionfacts.Facts) bool {
			return actionfacts.ExactSubmittedPOSIXDPKGStatusHeredocMutation(input)
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"integrity.kernel_control_bind_override": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXKernelControlBindOverride(facts)
		},
		requiresExactDetectionProof: true,
		detectionOnly:               true,
	},
	"impact.protected_kernel_control_bind_override": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXKernelControlBindOverride(facts)
		},
		requiresExactDetectionProof: true,
	},
	"PATH-ETC-SHADOW": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return shadowContentAccessPrerequisite(facts)
		},
	},
	"privilege.posix_non_root_uid_zero_account_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXNonRootUIDZeroAccountWrite(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXNonRootUIDZeroAccountWrite(facts)
		},
	},
	"privilege.sudoers_unrestricted_nopasswd": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXUnrestrictedSudoersGrantWrite(facts) ||
				actionfacts.ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXUnrestrictedSudoersGrantWrite(facts) ||
				actionfacts.ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts)
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"persistence.malicious_download_execute_payload": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactMaliciousPersistencePayload(facts)
		},
		detectionOnly: true,
	},
	"persistence.global_ld_preload_install": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return globalLDPreloadInstallPrerequisite(input, facts)
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return globalLDPreloadInstallPrerequisite(input, facts)
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"persistence.shell_profile_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			owner := semanticIntegrityPersistenceOwners["persistence.shell_profile_write"]
			return owner.prerequisite != nil && owner.prerequisite(facts)
		},
	},
	"credential.windows_registry_hive_dump": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.SensitiveRegistryHiveDumpPair(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.SensitiveRegistryHiveDumpPair(facts)
		},
	},
	"credential.windows_lsass_memory_dump": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsLSASSMemoryDumpDetection(facts)
		},
		detectionOnly: true,
	},
	"credential.windows_ntds_ifm_dump": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsNTDSIFMDump(facts)
		},
	},
	"credential.directory_credential_acquisition": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactDirectoryCredentialCompromise(facts)
		},
	},
	"credential.directory_ticket_request": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return directoryTicketRequestOrServiceUse(facts)
		},
	},
	"credential.pkcs12_private_key_extract": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactOpenSSLPKCS12PrivateKeyExtraction(facts)
		},
		detectionOnly: true,
	},
	"credential.kerberos_ticket_forgery": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return exactKerberosTicketForgeryPrerequisite(facts)
		},
	},
	"impact.windows_delete_all_shadow_copies": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsVSSDeleteAllShadows(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsVSSDeleteAllShadows(facts)
		},
	},
	"tamper.windows_usn_journal_delete": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsUSNJournalDelete(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsUSNJournalDelete(facts)
		},
	},
	"tamper.windows_recursive_everyone_full_control": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsRecursiveEveryoneFullControl(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsRecursiveEveryoneFullControl(facts)
		},
	},
	"impact.windows_recovery_disable_pair": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsRecoveryDisablePair(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsRecoveryDisablePair(facts)
		},
	},
	"tamper.windows_audit_policy_wipe": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsAuditPolicyWipePair(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsAuditPolicyWipePair(facts)
		},
	},
	"impact.windows_recovery_store_destruction": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsRecoveryStoreDestruction(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsRecoveryStoreDestruction(facts)
		},
	},
	"tamper.windows_defender_multi_control_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsDefenderMultiControlDisable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsDefenderMultiControlDisable(facts)
		},
	},
	"tamper.windows_defender_component_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesWindowsDefenderDisablement(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesWindowsDefenderDisablement(facts)
		},
	},
	"tamper.windows_registry_security_control_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return windowsRegistrySecurityControlDisablePrerequisite(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return windowsRegistrySecurityControlDisablePrerequisite(facts)
		},
	},
	"privilege.windows_uac_autoelevation_hijack": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesWindowsUACAutoElevationHijack(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesWindowsUACAutoElevationHijack(facts)
		},
	},
	"persistence.windows_accessibility_feature_hijack": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesWindowsAccessibilityFeatureHijack(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesWindowsAccessibilityFeatureHijack(facts)
		},
	},
	"tamper.windows_telemetry_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsTelemetryDisable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsTelemetryDisable(facts)
		},
	},
	"tamper.windows_credential_protection_weaken": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsCredentialProtectionWeakening(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsCredentialProtectionWeakening(facts)
		},
	},
	"tamper.windows_amsi_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsAMSIDisable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactWindowsAMSIDisable(facts)
		},
	},
	"tamper.endpoint_security_product_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactEndpointSecurityProductDisable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactEndpointSecurityProductDisable(facts)
		},
	},
	"tamper.complete_firewall_relaxation": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCompleteFirewallRelaxation(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCompleteFirewallRelaxation(facts)
		},
	},
	"tamper.complete_firewall_relaxation_attempt": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCompleteFirewallRelaxationAttempt(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCompleteFirewallRelaxationAttempt(facts)
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"tamper.cloud_audit_control_destruction": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCloudAuditControlDestruction(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCloudAuditControlDestruction(facts)
		},
	},
	"privilege.cloud_iam_administrator_attachment": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCloudIAMAdministratorAttachment(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCloudIAMAdministratorAttachment(facts)
		},
		detectionOnly: true,
	},
	"credential.pam_password_capture": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPAMPasswordCapture(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPAMPasswordCapture(facts)
		},
	},
	"tamper.posix_logging_hardening_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXLoggingHardeningDisable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXLoggingHardeningDisable(facts)
		},
	},
	"tamper.linux_security_control_disable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactLinuxSecurityControlDisable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactLinuxSecurityControlDisable(facts)
		},
	},
	"tamper.macos_unified_log_erase": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactMacOSUnifiedLogErase(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactMacOSUnifiedLogErase(facts)
		},
	},
	"credential.macos_fake_update_prompt": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactFakeMacOSUpdateCredentialPrompt(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactFakeMacOSUpdateCredentialPrompt(facts)
		},
	},
	"credential.macos_login_keychain_dump": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactMacOSLoginKeychainDump(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactMacOSLoginKeychainDump(facts)
		},
	},
	"impact.linux_magic_sysrq_destruction": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactLinuxMagicSysRqDestruction(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactLinuxMagicSysRqDestruction(facts)
		},
	},
	"impact.posix_host_halt": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXHostHalt(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXHostHalt(facts)
		},
	},
	"tamper.posix_system_log_destruction": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXSystemLogDestruction(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXSystemLogDestruction(facts)
		},
		detectionOnly: true,
	},
	"privilege.temporary_setuid_executable": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactTemporarySetuidExecutable(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactTemporarySetuidExecutable(facts)
		},
	},
	"privilege.custom_root_suid_implant": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCustomRootSUIDImplant(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactCustomRootSUIDImplant(facts)
		},
		requiresExactDetectionProof: true,
	},
	"privilege.pkroot_setuid_shell": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPKRootSetuidShell(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPKRootSetuidShell(facts)
		},
		requiresExactDetectionProof: true,
	},
	"exec.escaped_binary_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.EscapedBinaryFileWrite(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.EscapedBinaryFileWrite(facts)
		},
		// Code-owned effect proof over the commands the parser could read; the
		// catalog regex is inert. Alert-only: the effect cannot prove intent.
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"account.literal_password_change_via_stdin": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.LiteralStdinPasswordChange(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.LiteralStdinPasswordChange(facts)
		},
		// Code-owned effect proof over the commands the parser could read; the
		// catalog regex is inert. Alert-only: the effect cannot prove intent.
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"exec.download_then_run_fetched_file": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.BareAddressDownloadThenRunFetchedFile(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.BareAddressDownloadThenRunFetchedFile(facts)
		},
		// Code-owned effect proof over the commands the parser could read; the
		// catalog regex is inert. Alert-only: the effect cannot prove intent.
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"source_control.clone_then_run_or_adhoc_push": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.GitCloneThenRunOrAdHocPush(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.GitCloneThenRunOrAdHocPush(facts)
		},
		// Code-owned effect proof over the commands the parser could read; the
		// catalog regex is inert. Alert-only: the effect cannot prove intent.
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"exec.inline_code_network_and_exec": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.InlineCodeNetworkAndExec(facts) || actionfacts.RemoteRunnerURL(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.InlineCodeNetworkAndExec(facts) || actionfacts.RemoteRunnerURL(facts)
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
		alertOnly:                   true,
	},
	"exec.remote_ip_download_execute_same_artifact": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.StaticRemoteIPDownloadExecuteSameArtifact(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.StaticRemoteIPDownloadExecuteSameArtifact(facts)
		},
		// The candidate regex is never authoritative by itself. ActionFacts
		// must prove the exact source/destination path join. The bounded proof
		// may survive unrelated later parser uncertainty, but conditional shell
		// execution remains detection-only at the pre-execution hook.
		detectionOnly: true,
	},
	"exfiltration.recursive_model_artifact_external_multipart": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactRecursiveModelArtifactMultipartEgress(facts)
			return ok
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			_, ok := actionfacts.ExactRecursiveModelArtifactMultipartEgress(facts)
			return ok
		},
		// The Python source grammar, recursive traversal, exact opened-path to
		// multipart-handle join, and static destination are all code-owned. The
		// catalog regex is inert; HIGH severity makes this alert in balanced and
		// permissive while strict may block the complete proof.
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	},
	"CMD-REMOTE-PAYLOAD-EXEC-CLEANUP": {
		proves: func(input actionfacts.Input, _ actionfacts.Facts) bool {
			return trustedRemotePayloadExecuteCleanupPattern.MatchString(
				trustedExecutableShellProjection(input.Command),
			)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ProvesRemotePayloadExecuteCleanup(facts)
		},
		// The bounded ActionFacts subgraph independently requires unconditional,
		// ordered download, chmod, execution, and cleanup nodes joined by one
		// literal artifact. Unrelated directory fallback may keep the outer shell
		// PARTIAL without weakening this rule's exact proof.
	},
	"tamper.detector_state_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			owner := semanticIntegrityPersistenceOwners["tamper.detector_state_write"]
			return owner.prerequisite != nil && owner.prerequisite(facts)
		},
		// Detector-state mutation is an operation claim, not a string claim.
		// If ActionFacts cannot authorize the semantic lane, preserve the
		// regex hit for diagnostics but never let it synchronously deny.
		detectionOnly: true,
	},
	"CMD-ENV-DUMP": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return environmentDumpExternalPrerequisite(facts)
		},
	},
	"CMD-DD-IF": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return ddDiskWritePrerequisite(facts)
		},
	},
	"CMD-MKFS": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return filesystemWipePrerequisite(facts)
		},
		detectionOnly: true,
	},
	"CMD-CRONTAB": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return crontabInstallPrerequisite(facts)
		},
		// A crontab fed a heredoc it installs keeps the action partial (its
		// stdin is code ActionFacts does not read); its argv still proves
		// the install (rel-1-0-6:GAP-0419).
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return crontabInstallPrerequisite(certainControlFlowCommands(facts))
		},
		codeOwnedDetection:              true,
		boundedRequiresActiveExpression: true,
		// The fallback has the same dual-use boundary as the semantic owner:
		// retain the signal, but do not block without scheduled-payload proof.
		detectionOnly: true,
	},
	"C2-DNS-TUNNEL": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return dnsSubstitutionFallbackProof(facts)
		},
	},
	"integrity.history_tamper": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return historyTamperPrerequisite(facts)
		},
		detectionOnly: true,
	},
	"CMD-PIPE-CURL": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return curlDownloadExecPrerequisite(facts) ||
				powerShellDownloadExecPrerequisite(facts)
		},
		alertOnly: true,
	},
	"CMD-WRAPPED-DOWNLOAD-EXEC": {
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return wrappedDownloadExecProof(facts)
		},
		codeOwnedDetection: true,
	},
	"CMD-SUBST-DOWNLOAD-EXEC": {
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXDownloadSubstitution(facts, input)
		},
		codeOwnedDetection: true,
	},
	"CMD-PYTHON-SOCKET-CONNECT": {
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPythonExternalSocketConnect(facts)
		},
		codeOwnedDetection: true,
	},
	"secrets.cloud_secret_manager_read": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return cloudSecretManagerPrerequisite(facts)
		},
		detectionOnly: true,
	},
	"CMD-WIN-REG-PERSIST": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return windowsRegistryPersistencePrerequisite(facts)
		},
	},
	"CMD-WIN-IWR-IEX": {
		// The pipe form (iwr | iex) and every other spelling of a download
		// cradle (actionfacts.PowerShellFetchedContentExecution) are one
		// action. The finding enforces on a complete parse only; a cradle
		// that is spelled with parentheses or a variable leaves the tokenizer's
		// parse partial, and the filter below keeps it in shadow (see
		// powerShellCradleShadowOnly).
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return powerShellDownloadExecPrerequisite(facts) ||
				actionfacts.PowerShellFetchedContentExecution(input)
		},
	},
	"CMD-PIPE-WGET": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return stdinInterpreterPipelineFallbackProof(
				facts,
				actionfacts.OperationFetch,
				"wget",
				"wget.exe",
			)
		},
		alertOnly: true,
	},
	"CMD-PIPE-BASE64": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return stdinInterpreterPipelineFallbackProof(
				facts,
				actionfacts.OperationDecode,
				"base64",
				"base64.exe",
			)
		},
		detectionOnly: true,
	},
	"CMD-REVSHELL-BASH": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts) ||
				devTCPFallbackProof(facts, true)
		},
		boundedSubgraphProves: interactiveDevTCPShellProof,
	},
	"CMD-REVSHELL-NC": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts)
		},
	},
	"CMD-SOCAT-EXEC": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts)
		},
	},
	"CMD-REVSHELL-DEVTCP": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return devTCPFallbackProof(facts, false) ||
				scriptDevTCPReverseShellProof(facts)
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPOSIXDescriptorFeedbackShell(facts) ||
				interactiveDevTCPShellProof(input, facts)
		},
		codeOwnedDetection: true,
	},
	"CMD-REVSHELL-PYTHON": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return pythonSocketFallbackProof(facts)
		},
	},
	"CMD-REVSHELL-POWERSHELL-TCP": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPowerShellTCPCommandLoop(facts)
		},
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return actionfacts.ExactPowerShellTCPCommandLoop(facts)
		},
		// The PowerShell parser intentionally remains partial around dynamic
		// evaluation. Preserve the exact closed-grammar proof as detection-only.
		requiresExactDetectionProof: true,
		detectionOnly:               true,
	},
	"exec.reverse_tunnel": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return reverseTunnelFallbackProof(facts)
		},
	},
	"exec.agent_runtime_bypass_flags": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return agentRuntimeBypassPrerequisite(facts)
		},
	},
	"integrity.git_hooks_bypass": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return gitHooksBypassPrerequisite(facts)
		},
	},
	"source.git_config_exec": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return gitConfigExecPrerequisite(facts)
		},
	},
	"persistence.git_hook_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticIntegrityPersistenceOwners["persistence.git_hook_write"].prerequisite(facts)
		},
	},
	"CMD-SUDO": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticReconImpactOwners["CMD-SUDO"].prerequisite(facts)
		},
		// sudo sh fed a heredoc or a stdin redirect keeps the action partial
		// (its stdin runs as root code ActionFacts does not read); the sudo
		// argv still proves the elevated shell (rel-1-0-6:GAP-0419).
		boundedSubgraphProves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return sudoOrRootPrivilegeDiscoveryPrerequisite(certainControlFlowCommands(facts))
		},
		codeOwnedDetection:              true,
		boundedRequiresActiveExpression: true,
	},
	"privilege.host_namespace_entry": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return hostNamespaceEntryFallbackProof(facts)
		},
		detectionOnly: true,
	},
	"privilege.container_host_escape": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticReconImpactOwners["privilege.container_host_escape"].prerequisite(facts)
		},
	},
	"lateral.workload_exec": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return workloadExecFallbackProof(facts)
		},
		detectionOnly: true,
	},
	"impact.fork_bomb": {
		proves:        forkBombFallbackProof,
		detectionOnly: true,
	},
	"impact.cryptomining_launch": {
		proves: cryptominingFallbackProof,
	},
	"impact.mass_process_termination": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticReconImpactOwners["impact.mass_process_termination"].prerequisite(facts)
		},
	},
	"persistence.ssh_authorized_keys_command": {
		proves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return sshAuthorizedKeysCommandPrerequisite(facts) ||
				homeResolvedTwinProves(input, facts, sshAuthorizedKeysCommandPrerequisite)
		},
		boundedSubgraphProves: func(input actionfacts.Input, facts actionfacts.Facts) bool {
			return homeResolvedTwinProves(input, facts, sshAuthorizedKeysCommandPrerequisite)
		},
	},
}

// homeResolvedTwinProves reports whether check holds on the enforcement
// projection of the home-resolved twin of a partial action: the same command
// with its ~/ and $HOME/ paths (> ~/.ssh/authorized_keys, tee -a
// "$HOME/.ssh/authorized_keys") resolved under the caller's home. The shell
// expands those at run time, so the action's own analysis has no path fact
// for them and a rule about that exact path never matched: the write was
// allowed with no finding while the absolute path blocked. Only a check that
// holds counts; a check that fails on the twin proves nothing.
func homeResolvedTwinProves(
	input actionfacts.Input,
	facts actionfacts.Facts,
	check func(actionfacts.Facts) bool,
) bool {
	if facts.Authoritative() {
		return false
	}
	twin, ok := actionfacts.HomeResolvedTwin(input)
	if !ok {
		return false
	}
	enforcement := twin.EnforcementProjection()
	return enforcement.EnforcementEligible() && check(enforcement)
}

func exactUnboundedCPUFanoutAction(
	input actionfacts.Input,
	_ actionfacts.Facts,
) bool {
	// The dedicated extractor reparses the complete trusted command with its
	// own bounded POSIX grammar. Generic ActionFacts intentionally marks loop
	// syntax partial, so this is an independently complete subgraph proof rather
	// than a promotion of generic partial facts.
	if strings.TrimSpace(input.Command) == "" {
		return false
	}
	_, ok := actionfacts.ExtractExactPOSIXUnboundedCPUFanout(input.Command)
	return ok
}

type trustedLegacyProvenCommandDetectionOnlyContract struct {
	category     string
	pattern      string
	title        string
	severity     string
	confidence   float64
	tags         []string
	prerequisite func(actionfacts.Facts) bool
}

const (
	trustedPerlInlinePattern = `(?i)\bperl\s+-e\s+`
	trustedRubyInlinePattern = `(?i)\bruby\s+-e\s+`
)

var (
	trustedPerlInlineRegexp                   = regexp.MustCompile(trustedPerlInlinePattern)
	trustedRubyInlineRegexp                   = regexp.MustCompile(trustedRubyInlinePattern)
	trustedPythonSocketAssignmentPattern      = lazyregexp.New(`(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*socket\s*\.\s*socket\s*\(\s*([^)]*)\)`)
	trustedPythonStaticShellLaunchPattern     = lazyregexp.New(`(?is)\b(?:pty\s*\.\s*spawn|subprocess\s*\.\s*(?:Popen|call|run)|os\s*\.\s*(?:system|execl|execle|execlp|execv|execve))\s*\(\s*(?:\[\s*)?["'](?:(?:/usr)?/bin/(?:ba|z|k|da)?sh|(?:cmd|powershell)(?:\.exe)?)["']`)
	trustedPythonStaticHostnamePattern        = lazyregexp.New(`(?i)^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	trustedRemotePayloadExecuteCleanupPattern = lazyregexp.New(
		`(?is)\b(?:curl|wget)\b[^;\r\n]*https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/[^\s;]+(?:;|\s{2,})[^\r\n]*?\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\s+\S+(?:;|\s{2,})[^\r\n]*?(?:\./|(?:ba)?sh\s+)\S+(?:[ \t][^;\r\n \t]+)*(?:;|[ \t]{2,})[^\r\n]*?(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:\*|[A-Za-z0-9_.-]+\*)|history\s+-c)`,
	)
)

// trustedLegacyProvenCommandDetectionOnly is deliberately code-owned instead
// of rule-pack metadata: policy data must not be able to opt an arbitrary or
// overridden command owner out of enforcement. Each entry binds the shipped
// immutable rule identity as well as its ActionFacts proof. Literal/raw
// fallback and custom rules with a reused ID retain conservative enforcement.
var trustedLegacyProvenCommandDetectionOnly = map[string]trustedLegacyProvenCommandDetectionOnlyContract{
	"CMD-BASH-C": {
		category:     "command",
		pattern:      `(?i)\b(?:ba)?sh\s+-c\s+`,
		title:        "Shell -c execution",
		severity:     "LOW",
		confidence:   0.55,
		tags:         []string{"execution"},
		prerequisite: trustedBashInlineCommandOwnerProven,
	},
	"CMD-PYTHON-C": {
		category:   "command",
		pattern:    `(?i)\bpython[23]?\s+-c\s+`,
		title:      "Python inline execution",
		severity:   "LOW",
		confidence: 0.55,
		tags:       []string{"execution"},
	},
	"CMD-PERL-E": {
		category:     "command",
		pattern:      trustedPerlInlinePattern,
		title:        "Perl inline execution",
		severity:     "LOW",
		confidence:   0.55,
		tags:         []string{"execution"},
		prerequisite: trustedPerlInlineCommandOwnerProven,
	},
	"CMD-RUBY-E": {
		category:     "command",
		pattern:      trustedRubyInlinePattern,
		title:        "Ruby inline execution",
		severity:     "LOW",
		confidence:   0.55,
		tags:         []string{"execution"},
		prerequisite: trustedRubyInlineCommandOwnerProven,
	},
}

func stdinInterpreterPipelineFallbackProof(
	facts actionfacts.Facts,
	operation actionfacts.OperationKind,
	sourcePrograms ...string,
) bool {
	for _, source := range facts.Commands {
		if source.PipelineID == 0 ||
			!oneOfFold(source.Program, sourcePrograms...) ||
			!hasOperation(source, operation) &&
				(operation != actionfacts.OperationFetch || !(hasOperation(source, actionfacts.OperationUpload))) ||
			!actionfacts.ProvesPOSIXPipelineInterpreterSource(source) {
			continue
		}
		for _, sink := range facts.Commands {
			if sink.PipelineID == source.PipelineID &&
				actionfacts.ProvesPOSIXStdinInterpreter(sink) &&
				hasCommandDataFlow(
					facts,
					source.ID,
					sink.ID,
					actionfacts.DataStdout,
					actionfacts.DataStdin,
				) {
				return true
			}
		}
	}
	return false
}

func exactPipelineSourceStdout(command actionfacts.CommandFact) bool {
	return actionfacts.ProvesPOSIXPipelineInterpreterSource(command)
}

func exactStdinInterpreterSink(command actionfacts.CommandFact) bool {
	return actionfacts.ProvesPOSIXStdinInterpreter(command)
}

func reverseTunnelFallbackProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			!exactReverseTunnelArgv(command) ||
			!hasExternalNetworkAction(
				facts,
				command.ID,
				actionfacts.NetworkTunnel,
				actionfacts.NetworkConnect,
			) {
			continue
		}
		return true
	}
	return false
}

func exactReverseTunnelArgv(command actionfacts.CommandFact) bool {
	argv := command.Argv
	switch strings.ToLower(command.Program) {
	case "ssh", "ssh.exe", "autossh", "autossh.exe":
		for index := 1; index < len(argv); index++ {
			argument := argv[index]
			if argument == "-R" && index+1 < len(argv) &&
				argv[index+1] != "" {
				return true
			}
			if strings.HasPrefix(argument, "-R") && len(argument) > 2 {
				return true
			}
			if strings.EqualFold(argument, "-o") &&
				index+1 < len(argv) &&
				strings.HasPrefix(
					strings.ToLower(argv[index+1]),
					"remoteforward=",
				) {
				return true
			}
			if strings.HasPrefix(
				strings.ToLower(argument),
				"-oremoteforward=",
			) {
				return true
			}
		}
	case "chisel", "chisel.exe":
		if len(argv) < 4 || argv[1] != "client" {
			return false
		}
		for _, argument := range argv[3:] {
			lower := strings.ToLower(argument)
			if lower == "r:socks" ||
				strings.HasPrefix(lower, "r:") && len(lower) > 2 {
				return true
			}
		}
	case "ligolo-agent", "ligolo-ng-agent":
		for index := 1; index < len(argv); index++ {
			lower := strings.ToLower(argv[index])
			if (lower == "-connect" || lower == "--connect") &&
				index+1 < len(argv) && argv[index+1] != "" {
				return true
			}
			if strings.HasPrefix(lower, "-connect=") ||
				strings.HasPrefix(lower, "--connect=") {
				return !strings.HasSuffix(lower, "=")
			}
		}
	}
	return false
}

func dnsSubstitutionFallbackProof(facts actionfacts.Facts) bool {
	for _, destination := range facts.Commands {
		if destination.Effect == actionfacts.EffectPreview ||
			!oneOfFold(destination.Program, "dig", "host", "nslookup", "drill") {
			continue
		}
		for _, source := range facts.Commands {
			if source.ParentCommandID == destination.ID &&
				source.Effect == actionfacts.EffectExecute &&
				dnsSubstitutionSource(source) &&
				hasCommandDataFlow(
					facts,
					source.ID,
					destination.ID,
					actionfacts.DataStdout,
					actionfacts.DataProcess,
				) {
				return true
			}
		}
	}
	return false
}

func dnsSubstitutionSource(command actionfacts.CommandFact) bool {
	if !command.ArgvComplete {
		return false
	}
	switch strings.ToLower(command.Program) {
	case "whoami", "hostname":
		return len(command.Argv) == 1
	case "id":
		return len(command.Argv) == 1 ||
			len(command.Argv) == 2 && command.Argv[1] == "-u"
	case "cat":
		return len(command.Argv) == 2 &&
			oneOfFold(
				command.Argv[1],
				"/etc/hostname",
				"/etc/machine-id",
			)
	default:
		return false
	}
}

func interactiveDevTCPShellProof(input actionfacts.Input, facts actionfacts.Facts) bool {
	if facts.Parse.Dialect != actionfacts.DialectPOSIX ||
		facts.Parse.Status != actionfacts.StatusPartial || len(facts.Commands) != 1 {
		return false
	}
	command, ok := trustedBashCommandInput(input)
	return ok && actionfacts.ExactPOSIXInteractiveDevTCPShell(command, facts)
}

func devTCPFallbackProof(
	facts actionfacts.Facts,
	requireShell bool,
) bool {
	for _, network := range facts.Network {
		if network.Action != actionfacts.NetworkConnect ||
			!strings.EqualFold(network.Scheme, "tcp") {
			continue
		}
		command, ok := commandByID(facts, network.CommandID)
		if !ok ||
			command.Effect != actionfacts.EffectExecute ||
			requireShell && !shellProgram(command.Program) {
			continue
		}
		if !actionfacts.ProvesPOSIXInteractiveShell(command) {
			continue
		}
		if hasCommandDataFlow(
			facts,
			command.ID,
			0,
			actionfacts.DataProcess,
			actionfacts.DataNetwork,
		) && hasCommandDataFlow(
			facts,
			0,
			command.ID,
			actionfacts.DataNetwork,
			actionfacts.DataProcess,
		) {
			return true
		}
		// An interactive shell can bind stdin and stdout directly to a
		// /dev/tcp descriptor without the process-level flow emitted for
		// `exec N<>/dev/tcp/...`. Require both directions on the same typed
		// command so one-way health probes and file transfers do not inherit
		// reverse-shell ownership.
		if hasCommandDataFlow(
			facts,
			0,
			command.ID,
			actionfacts.DataNetwork,
			actionfacts.DataStdin,
		) && hasCommandDataFlow(
			facts,
			command.ID,
			0,
			actionfacts.DataStdout,
			actionfacts.DataNetwork,
		) {
			return true
		}
	}
	if requireShell {
		for _, command := range facts.Commands {
			if command.Effect == actionfacts.EffectExecute &&
				shellProgram(command.Program) &&
				(actionfacts.ProvesPOSIXInteractiveShell(command) ||
					legacyUnmodeledInteractiveShellOption(command)) &&
				len(command.Redirects) != 0 {
				return true
			}
		}
	}
	return false
}

func scriptDevTCPReverseShellProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Dialect != actionfacts.DialectPOSIX ||
			command.ControlFlowUncertain || command.ParentCommandID != 0 ||
			command.PipelineID != 0 || command.Effect != actionfacts.EffectExecute ||
			command.Program != "script" || !command.ArgvComplete ||
			len(command.Wrappers) != 0 || len(command.Redirects) != 0 {
			continue
		}
		var nested string
		switch {
		case len(command.Argv) == 4 && command.Argv[1] == "-qc" && command.Argv[3] == "/dev/null":
			nested = command.Argv[2]
		case len(command.Argv) == 5 && command.Argv[1] == "-q" &&
			command.Argv[2] == "-c" && command.Argv[4] == "/dev/null":
			nested = command.Argv[3]
		default:
			continue
		}
		projected := actionfacts.Analyze(actionfacts.Input{
			Tool: "shell", Command: nested, DialectHint: actionfacts.DialectPOSIX,
		})
		if devTCPFallbackProof(projected, true) {
			return true
		}
	}
	return false
}

func legacyUnmodeledInteractiveShellOption(command actionfacts.CommandFact) bool {
	// Zsh and fish intentionally remain outside ActionFacts' bounded invocation
	// grammar. Preserve only the pre-existing requireShell fallback for those
	// programs; the new bidirectional /dev/tcp owner never calls this lane.
	return oneOfFold(command.Program, "zsh", "fish") &&
		containsFold(command.Argv, "-i")
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func pythonSocketFallbackProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			!oneOfFold(
				command.Program,
				"python",
				"python2",
				"python3",
				"python.exe",
				"python2.exe",
				"python3.exe",
			) {
			continue
		}
		for index := 1; index+1 < len(command.Argv); index++ {
			if command.Argv[index] != "-c" {
				continue
			}
			if pythonInlineReverseShellProof(command.Argv[index+1]) {
				return true
			}
		}
	}
	return false
}

func pythonInlineReverseShellProof(script string) bool {
	if !trustedPythonStaticShellLaunchPattern.MatchString(script) {
		return false
	}
	for _, assignment := range trustedPythonSocketAssignmentPattern.FindAllStringSubmatch(script, -1) {
		if len(assignment) != 3 || !pythonSocketArgumentsProveINET(assignment[2]) {
			continue
		}
		socketVariable := assignment[1]
		if !pythonSocketConnectsToStaticNonlocalHost(script, socketVariable) ||
			!pythonSocketHandsOffStandardStreams(script, socketVariable) {
			continue
		}
		return true
	}
	return false
}

func pythonSocketArgumentsProveINET(arguments string) bool {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" {
		// Python's socket.socket() default family is AF_INET.
		return true
	}
	first := strings.TrimSpace(strings.SplitN(arguments, ",", 2)[0])
	first = strings.TrimSpace(strings.TrimPrefix(first, "family="))
	return first == "socket.AF_INET" || first == "AF_INET" ||
		first == "socket.AF_INET6" || first == "AF_INET6"
}

func pythonSocketConnectsToStaticNonlocalHost(script, socketVariable string) bool {
	connectPattern := regexp.MustCompile(
		`(?is)\b` + regexp.QuoteMeta(socketVariable) +
			`\s*\.\s*connect\s*\(\s*\(\s*(?:"([^"]+)"|'([^']+)')\s*,\s*([0-9]{1,5})\s*\)\s*\)`,
	)
	for _, connection := range connectPattern.FindAllStringSubmatch(script, -1) {
		if len(connection) != 4 {
			continue
		}
		host := connection[1]
		if host == "" {
			host = connection[2]
		}
		port, err := strconv.Atoi(connection[3])
		if err == nil && port > 0 && port <= 65535 && pythonStaticNonlocalHost(host) {
			return true
		}
	}
	return false
}

func pythonStaticNonlocalHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return !address.IsLoopback() && !address.IsUnspecified() &&
			!address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
	}
	// Single-label names may resolve to a local socket peer through search
	// domains. Requiring a literal dotted hostname also excludes unresolved
	// variables and expressions from this exact fallback proof.
	return trustedPythonStaticHostnamePattern.MatchString(host)
}

func pythonSocketHandsOffStandardStreams(script, socketVariable string) bool {
	direct := regexp.MustCompile(
		`(?is)\bos\s*\.\s*dup2\s*\(\s*`+regexp.QuoteMeta(socketVariable)+
			`\s*\.\s*fileno\s*\(\s*\)\s*,\s*([012])\s*\)`,
	).FindAllStringSubmatch(script, -1)
	seen := [3]bool{}
	for _, handoff := range direct {
		if len(handoff) == 2 {
			seen[int(handoff[1][0]-'0')] = true
		}
	}
	if seen[0] && seen[1] && seen[2] {
		return true
	}

	loop := regexp.MustCompile(
		`(?is)\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s*[\(\[]\s*0\s*,\s*1\s*,\s*2\s*[\)\]]`,
	).FindStringSubmatch(script)
	if len(loop) == 2 {
		loopHandoff := regexp.MustCompile(
			`(?is)\bos\s*\.\s*dup2\s*\(\s*` + regexp.QuoteMeta(socketVariable) +
				`\s*\.\s*fileno\s*\(\s*\)\s*,\s*` + regexp.QuoteMeta(loop[1]) + `\s*\)`,
		)
		if loopHandoff.MatchString(script) {
			return true
		}
	}

	makefile := regexp.QuoteMeta(socketVariable) + `\s*\.\s*makefile\s*\(`
	for _, stream := range []string{"stdin", "stdout", "stderr"} {
		streamPattern := regexp.MustCompile(
			`(?is)\bsys\s*\.\s*` + stream + `\s*=.{0,160}?` + makefile,
		)
		if !streamPattern.MatchString(script) {
			return false
		}
	}
	return true
}

func hasCommandDataFlow(
	facts actionfacts.Facts,
	fromCommandID int64,
	toCommandID int64,
	from actionfacts.DataKind,
	to actionfacts.DataKind,
) bool {
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID == fromCommandID &&
			flow.ToCommandID == toCommandID &&
			flow.From == from &&
			flow.To == to {
			return true
		}
	}
	return false
}

func commandByID(
	facts actionfacts.Facts,
	commandID int64,
) (actionfacts.CommandFact, bool) {
	for _, command := range facts.Commands {
		if command.ID == commandID {
			return command, true
		}
	}
	return actionfacts.CommandFact{}, false
}

// powerShellCradleShadowOnly reports a download cradle (psparse's reading of
// the script: Invoke-Expression of fetched content, in a spelling the tokenizer
// cannot prove) in a call whose parse is partial. It adds the download-execute
// finding in shadow: recorded, never enforced. The pipe form keeps the product's
// rule when the tokenizer's parse is partial for a reason of its own (a sibling
// statement it does not model raises nothing, the partial-sibling fixture). A
// statement list alone is no such reason: the tokenizer only does not read a
// list of statements, and a fetch whose output feeds Invoke-Expression is a
// cradle wherever it stands in a list of statements psparse reads in full
// (rel-1-0-10:GAP-0160).
func powerShellCradleShadowOnly(input actionfacts.Input, facts actionfacts.Facts) bool {
	if powerShellDownloadExecPrerequisite(facts) &&
		(!powerShellStatementListOnly(facts) || !actionfacts.PowerShellStatementList(input)) {
		return false
	}
	return actionfacts.PowerShellFetchedContentExecution(input)
}

// powerShellListSiblings are the programs a statement list around a cradle may
// hold without making the tokenizer's partial parse more than "a list of
// statements": the cradle's own words and the statements that only change
// directory or print.
var powerShellListSiblings = map[string]bool{
	"invoke-webrequest": true, "iwr": true, "invoke-restmethod": true, "irm": true, "curl": true, "wget": true,
	"invoke-expression": true, "iex": true, "new-object": true,
	"set-location": true, "sl": true, "cd": true, "chdir": true, "push-location": true, "pushd": true,
	"pop-location": true, "popd": true, "write-output": true, "write-host": true, "echo": true, "get-date": true,
}

// powerShellStatementListOnly reports a partial parse whose only reasons are
// that the tokenizer does not read a list of statements (and, for the
// statements of powerShellListSiblings, the operand grammar of a directory
// change). A sibling the tokenizer does not model at all is another reason.
func powerShellStatementListOnly(facts actionfacts.Facts) bool {
	if facts.Parse.Status != actionfacts.StatusPartial || len(facts.Parse.Issues) == 0 {
		return false
	}
	// A cradle inside a launcher's body keeps the product's rule: the body is
	// the launcher's operand, and a partial parse of it raises nothing.
	for _, command := range facts.Commands {
		switch strings.ToLower(command.Program) {
		case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe":
			return false
		}
	}
	for _, issue := range facts.Parse.Issues {
		switch issue {
		case actionfacts.IssueUnsupportedConstruct:
		case actionfacts.IssueUnknownOperandGrammar:
			for _, command := range facts.Commands {
				if !powerShellListSiblings[strings.ToLower(command.Program)] {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// withCradleUnknownTier raises a download-cradle finding the tokenizer could
// not prove (it is recorded, not enforced) to the unknown tier of the pack when
// psparse proves the cradle on the tree: alert-only outside the strict tier,
// enforced in it. It only raises; a finding already enforced stays.
func withCradleUnknownTier(findings []RuleFinding, request trustedActionRequest) []RuleFinding {
	if !request.EnforcementCapable {
		return findings
	}
	proven := false
	for index := range findings {
		finding := &findings[index]
		if finding.RuleID != "CMD-WIN-IWR-IEX" || finding.contributesToEnforcement() || finding.contributesToAlertOnly() {
			continue
		}
		if !proven && !actionfacts.PowerShellFetchedContentExecution(request.Input) {
			return findings
		}
		proven = true
		if request.StrictPolicy || request.ManagedInstall {
			finding.enforcement = findingEnforcementAllowed
		} else {
			finding.enforcement = findingEnforcementAlertOnly
		}
	}
	return findings
}

// withHostTwinFindings joins the findings of a script reading to those of the
// call as written (withOverLimitTwinFindings) and keeps the name the call as
// written gave a rule: a stronger finding of the same rule family from the
// reading raises the proof, never renames the finding (a Windows path rule
// stays the Windows path rule).
//
// The reading may add only what it proves. A finding of the reading that would
// enforce without a proof that authorizes the rule (a target the reading could
// not place, a path it only mentions) is recorded, not enforced: a read-only
// listing proves no write, and a launcher the tokenizer holds as partial stays
// partial (rel-1-0-10:GAP-0364).
func withHostTwinFindings(findings, twin []RuleFinding) []RuleFinding {
	before := slices.Clone(findings)
	proven := make([]RuleFinding, len(twin))
	for index, finding := range twin {
		if finding.contributesToEnforcement() && !finding.proof.authorizes(finding.RuleID) {
			finding.enforcement = findingEnforcementDetectionOnly
		}
		proven[index] = finding
	}
	joined := withOverLimitTwinFindings(findings, proven)
	for index := range before {
		if index < len(joined) && joined[index].RuleID != before[index].RuleID &&
			trustedActionFindingKey(joined[index].RuleID) == trustedActionFindingKey(before[index].RuleID) {
			joined[index].RuleID, joined[index].Title = before[index].RuleID, before[index].Title
		}
	}
	return withCarriedBoundedCaps(joined, twin)
}

// withoutLimitFindings drops the evaluation-limit finding of a reading that is
// a fragment of the call.
func withoutLimitFindings(findings []RuleFinding) []RuleFinding {
	kept := findings[:0:0]
	for _, finding := range findings {
		if canonicalTrustedRuleID(finding.RuleID) != evaluationLimitRuleID {
			kept = append(kept, finding)
		}
	}
	return kept
}

func filterExactFallbackFindings(
	findings []RuleFinding,
	input actionfacts.Input,
	facts actionfacts.Facts,
	enforcementCapable bool,
) []RuleFinding {
	enforcementFacts := facts.EnforcementProjection()
	var nestedActions []trustedNestedAction
	nestedActionsReady := false
	getNestedActions := func() []trustedNestedAction {
		if !nestedActionsReady {
			nestedActions = trustedNestedExecutionActions(input, facts)
			nestedActionsReady = true
		}
		return nestedActions
	}
	suppressAuthorizedKeysPathFallback := false
	suppressPowerShellDownloadAlias := false
	for _, finding := range findings {
		switch finding.RuleID {
		case "persistence.ssh_authorized_keys_command":
			contract := exactFallbackContracts[finding.RuleID]
			if contract.proves != nil && contract.proves(input, enforcementFacts) {
				suppressAuthorizedKeysPathFallback = true
			}
		case "CMD-PIPE-CURL":
			contract := exactFallbackContracts[finding.RuleID]
			if contract.proves != nil && contract.proves(input, enforcementFacts) &&
				powerShellDownloadExecPrerequisite(enforcementFacts) {
				suppressPowerShellDownloadAlias = true
			}
		}
	}
	filtered := findings[:0]
	preserveUnstructured := noRecoverableCommandFacts(facts)
	for _, finding := range findings {
		if suppressAuthorizedKeysPathFallback &&
			finding.RuleID == "PATH-SSH-DIR" {
			continue
		}
		if suppressPowerShellDownloadAlias &&
			finding.RuleID == "CMD-WIN-IWR-IEX" {
			continue
		}
		contract, exact := exactFallbackContracts[finding.RuleID]
		if !exact {
			filtered = append(filtered, finding)
			continue
		}
		// The Windows recognizer can lexically unwrap a PowerShell command from
		// generic shell text. That is useful for offline scanning, but a live
		// trusted action must not materialize the critical finding until the
		// connector input has complete authoritative PowerShell ActionFacts.
		if finding.RuleID == "CMD-WIN-IWR-IEX" &&
			(!facts.Authoritative() ||
				facts.Parse.Status != actionfacts.StatusComplete) &&
			!powerShellCradleShadowOnly(input, facts) {
			continue
		}
		if hasTag(finding.Tags, trustedParserUncertaintyTag) {
			finding.enforcement = findingEnforcementDetectionOnly
			filtered = append(filtered, finding)
			continue
		}
		matched := contract.proves != nil && contract.proves(input, facts)
		if !matched {
			matched = trustedNestedExactFallbackMatch(
				contract,
				getNestedActions(),
			)
		}
		boundedSubgraphProven := contract.boundedSubgraphProves != nil &&
			contract.boundedSubgraphProves(input, facts)
		matched = matched || boundedSubgraphProven
		if contract.requiresExactDetectionProof && !matched {
			continue
		}
		if !preserveUnstructured && !matched {
			continue
		}
		proofBoundary := facts.Authoritative() &&
			enforcementFacts.EnforcementEligible() &&
			enforcementFacts.Parse.Status == actionfacts.StatusComplete
		proven := proofBoundary && contract.proves != nil &&
			contract.proves(input, enforcementFacts)
		if proofBoundary && !proven {
			proven = trustedNestedExactFallbackProof(
				contract,
				getNestedActions(),
			)
		}
		proven = proven || boundedSubgraphProven
		if contract.alertOnly && enforcementCapable && matched {
			finding.enforcement = findingEnforcementAlertOnly
		} else if contract.detectionOnly || !enforcementCapable || !proven {
			finding.enforcement = findingEnforcementDetectionOnly
			// The contract proved its operation on what the analysis read, but
			// the call was read only in part, so no enforcing reader ran
			// (rel-1-0-10:GAP-0892). A detection-only contract never denies
			// itself; the caller may still floor the call at the unknown tier
			// (withPartialStateWriteFloor).
			finding.partialReading = matched && !proofBoundary && enforcementCapable && operandGrammarOnlyReading(facts)
		} else {
			finding.enforcement = findingEnforcementAllowed
		}
		if boundedSubgraphProven {
			finding = finding.withTrustedActionProof(
				newActionFactsSubgraphFindingProof(finding.RuleID, true, true),
			)
		} else {
			finding = finding.withTrustedActionProof(
				newExactFallbackFindingProof(
					finding.RuleID,
					facts.Authoritative(),
					enforcementFacts.EnforcementEligible(),
					enforcementFacts.Parse.Status == actionfacts.StatusComplete,
					proven,
				),
			)
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func trustedNestedExactFallbackMatch(
	contract exactFallbackContract,
	nestedActions []trustedNestedAction,
) bool {
	if contract.proves == nil {
		return false
	}
	for _, nested := range nestedActions {
		if !nested.rawFallback && contract.proves(nested.input, nested.facts) {
			return true
		}
	}
	return false
}

func trustedNestedExactFallbackProof(
	contract exactFallbackContract,
	nestedActions []trustedNestedAction,
) bool {
	return trustedNestedExactFallbackProofFromActions(
		contract,
		nestedActions,
	)
}

func trustedNestedExactFallbackProofFromActions(
	contract exactFallbackContract,
	nestedActions []trustedNestedAction,
) bool {
	if contract.proves == nil {
		return false
	}
	for _, nested := range nestedActions {
		if nested.rawFallback || !nested.facts.Authoritative() {
			continue
		}
		nestedEnforcementFacts := nested.facts.EnforcementProjection()
		if !nestedEnforcementFacts.EnforcementEligible() {
			continue
		}
		if contract.proves(nested.input, nestedEnforcementFacts) {
			return true
		}
	}
	return false
}

// unplacedPatchTargetTitle is the ship-authored title of a patch whose header
// names its file by a spelling no reader places; the reason follows it.
const unplacedPatchTargetTitle = "Patch names a file no rule can place, judged as unknown"

func noRecoverableCommandFacts(facts actionfacts.Facts) bool {
	if facts.Parse.Status != actionfacts.StatusInvalid &&
		facts.Parse.Status != actionfacts.StatusNotApplicable {
		return false
	}
	for _, command := range facts.Commands {
		if command.Executable != "" || command.Program != "" ||
			len(command.Argv) != 0 {
			return false
		}
	}
	return true
}

// trustedRuleScanText is the text the legacy rule scan reads for request:
// the call text without known fixture data and secret-store values, with the
// active home, and each relative operand it writes in the home, spelled as
// the path rules read them.
func trustedRuleScanText(request trustedActionRequest, facts actionfacts.Facts) string {
	text := request.LegacyText
	if trustedFixtureSourceInspectionAction(request.Input, facts) {
		text = neutralizeKnownFixtureDataLiterals(text)
	}
	text = neutralizeTrustedSecretStoreValue(request.Input, text)
	return relativeHomeWritesAsTilde(activeHomeAsTilde(text, request.Input.ActiveHome), facts)
}

// dispatchTrustedFallback judges a call with the legacy scan and the
// recovery lanes only. A write tool call over the argument limit whose
// over-limit view cannot be projected, or one judged by a generation with no
// semantic rules, gets here with that view: as in dispatchTrustedAction, the
// lanes and the context checks also judge it on the view.
func dispatchTrustedFallback(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	options ruleScanOptions,
) ([]RuleFinding, trustedActionTelemetry) {
	scanned := scanRuleGeneration(
		generation,
		trustedRuleScanText(request, facts),
		request.Input.Tool,
		options,
	)
	findings, fallbackTelemetry := trustedFallbackLanes(
		generation,
		request,
		options,
		append([]RuleFinding(nil), scanned...),
		facts,
	)
	contextFacts := facts
	if view, _, ok := actionfacts.OverLimitWriteTargetReduction(request.Input, facts); ok {
		contextFacts = view
		viewFindings, _ := trustedFallbackLanes(generation, request, options, scanned, view)
		findings = withSequenceProvenFindings(findings, viewFindings)
	}
	findings = finalizeTrustedActionFindings(generation, request, contextFacts, findings)
	findings = appendTrustedWriteTargetFindings(findings, generation, request, facts)
	return appendTrustedPrivateKeyReaderFinding(findings, generation, request, facts), fallbackTelemetry
}

// trustedFallbackLanes runs the recovery lanes over findings, the legacy scan
// of the call, on facts, then the checks that decide on those facts whether a
// fallback, content or path finding may block.
func trustedFallbackLanes(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	options ruleScanOptions,
	findings []RuleFinding,
	facts actionfacts.Facts,
) ([]RuleFinding, trustedActionTelemetry) {
	legacyFindings := append([]RuleFinding(nil), findings...)
	findings = appendTrustedFIFOListenerBindShellFinding(
		findings,
		generation,
		request.Input,
		facts,
	)
	findings = appendTrustedBoundedExactFallbackFindings(
		findings,
		generation,
		request.Input,
		facts,
	)
	findings = appendTrustedWindowsPathFactFindings(
		findings,
		facts,
		request.Input.Tool,
		options,
	)
	findings = appendTrustedEmbeddedCommandFindings(
		findings,
		generation,
		request.Input.Tool,
		facts,
		options,
	)
	findings, laneTelemetry := appendTrustedBashFallbackFindings(
		findings,
		generation,
		request.Input,
		request.Input.Tool,
		facts,
		options,
		request.EnforcementCapable,
		request.DowngradeReadOnlyDataArgs,
	)
	findings = filterTrustedLegacyActionContext(
		generation,
		findings,
		request.Input,
		request.Input.Tool,
		facts,
		request.DowngradeReadOnlyDataArgs,
	)
	findings = filterExactFallbackFindings(
		findings,
		request.Input,
		facts,
		request.EnforcementCapable,
	)
	// The exact body of a pwsh -Command call runs as written whatever left
	// the whole action partial (a profile, a runtime-expanded redirect
	// target), so a fallback that body proves, and that commands around it
	// cannot undo, stands for the call: `pwsh -Command "iwr ... | iex"`
	// blocks as the -NoProfile form does (GAP-0033).
	for _, body := range actionfacts.PowerShellCommandBodyActions(request.Input, facts) {
		bodyFindings := filterExactFallbackFindings(
			powerShellBodyMonotoneFindings(legacyFindings),
			request.Input,
			body,
			request.EnforcementCapable,
		)
		findings = withSequenceProvenFindings(findings, bodyFindings)
	}
	return findings, laneTelemetry
}

// powerShellBodyMonotoneFallbacks are the exact fallback rules whose proof
// reads only a PowerShell body's own commands and the data flow between them.
var powerShellBodyMonotoneFallbacks = map[string]struct{}{
	"CMD-WIN-IWR-IEX": {},
}

// powerShellBodyMonotoneFindings keeps the findings whose rule is in
// powerShellBodyMonotoneFallbacks. Only those are judged on a body, so
// another rule's legacy finding (strict CMD-PIPE-CURL) cannot stand in for
// them there.
func powerShellBodyMonotoneFindings(findings []RuleFinding) []RuleFinding {
	kept := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if _, ok := powerShellBodyMonotoneFallbacks[finding.RuleID]; ok {
			kept = append(kept, finding)
		}
	}
	return kept
}

// neutralizeTrustedSecretStoreValue keeps credential detectors focused on
// disclosure rather than storage. A value submitted to the exact rotate sink
// is expected to be secret-shaped, so only that value field is replaced before
// the legacy data-pattern scan. The destination and identity fields remain in
// the scan, as do all fields of malformed, extended, or mismatched requests.
//
// The second accepted envelope is the benchmark evidence wrapper used to keep
// source provenance beside the original arguments. It is accepted only when
// the wrapper is exact and independently identifies this same service action.
func neutralizeTrustedSecretStoreValue(
	input actionfacts.Input,
	legacyText string,
) string {
	if input.Tool != "secrets_store.rotate" || input.Command != "" ||
		len(input.Argv) != 0 || len(input.Args) == 0 ||
		!bytes.Equal(bytes.TrimSpace(input.Args), bytes.TrimSpace([]byte(legacyText))) {
		return legacyText
	}

	outer, ok := decodeExactTrustedJSONObject(input.Args)
	if !ok {
		return legacyText
	}
	arguments := outer
	wrapped := false
	if len(outer) == 2 {
		rawArguments, hasArguments := outer["_mole_arguments"]
		rawEvidence, hasEvidence := outer["_mole_evidence"]
		if hasArguments && hasEvidence && trustedSecretStoreEvidence(rawEvidence) {
			arguments, ok = decodeExactTrustedJSONObject(rawArguments)
			wrapped = ok
		}
	}
	if !exactTrustedSecretStoreRotateArguments(arguments) {
		return legacyText
	}

	arguments["value"] = json.RawMessage(`"provided by secret store"`)
	if wrapped {
		encoded, err := json.Marshal(arguments)
		if err != nil {
			return legacyText
		}
		outer["_mole_arguments"] = encoded
	} else {
		outer = arguments
	}
	encoded, err := json.Marshal(outer)
	if err != nil {
		return legacyText
	}
	return string(encoded)
}

func decodeExactTrustedJSONObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, false
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := object[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		object[key] = append(json.RawMessage(nil), value...)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return object, true
}

func exactTrustedSecretStoreRotateArguments(arguments map[string]json.RawMessage) bool {
	if len(arguments) != 4 {
		return false
	}
	account, accountOK := exactNonEmptyTrustedJSONString(arguments["account"])
	sender, senderOK := exactNonEmptyTrustedJSONString(arguments["sender"])
	_, valueOK := exactNonEmptyTrustedJSONString(arguments["value"])
	_, keyOK := exactNonEmptyTrustedJSONString(arguments["key"])
	_, nameOK := exactNonEmptyTrustedJSONString(arguments["name"])
	return accountOK && senderOK && valueOK && account == sender && keyOK != nameOK
}

func trustedSecretStoreEvidence(raw json.RawMessage) bool {
	evidence, ok := decodeExactTrustedJSONObject(raw)
	if !ok {
		return false
	}
	service, serviceOK := exactNonEmptyTrustedJSONString(evidence["service"])
	action, actionOK := exactNonEmptyTrustedJSONString(evidence["action"])
	return serviceOK && actionOK && service == "secrets_store" && action == "rotate"
}

func exactNonEmptyTrustedJSONString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" ||
		strings.IndexByte(value, 0) >= 0 {
		return "", false
	}
	return value, true
}

// certainControlFlowCommands is facts with only the commands outside
// uncertain control flow, so a bounded proof over a partial action is as
// precise as the owner on a complete one.
func certainControlFlowCommands(facts actionfacts.Facts) actionfacts.Facts {
	kept := make([]actionfacts.CommandFact, 0, len(facts.Commands))
	for _, command := range facts.Commands {
		if !command.ControlFlowUncertain {
			kept = append(kept, command)
		}
	}
	facts.Commands = kept
	return facts
}

// boundedRuleExpressionHolds reports whether the active pack's own
// expression for rule admits facts, the commands the bounded proof read. A
// pack that turns the rule off (expression: false) or narrows it keeps that
// meaning on the bounded lane; a rule with no expression is judged by its
// pattern, as on the complete path (rel-1-0-6:GAP-0419).
func boundedRuleExpressionHolds(
	generation *compiledRulePackCategories,
	rule *PatternRule,
	commandText string,
	facts actionfacts.Facts,
) bool {
	if strings.TrimSpace(rule.Expression) == "" {
		return strings.TrimSpace(commandText) != "" && rule.Pattern != nil &&
			rule.Pattern.MatchString(commandText)
	}
	// A partial action can carry issues the projection has no value for
	// (opaque_artifact); the view the expression judges leaves them out.
	issues := make([]actionfacts.IssueCode, 0, len(facts.Parse.Issues))
	for _, issue := range facts.Parse.Issues {
		if semantic.ProjectableIssue(issue) {
			issues = append(issues, issue)
		}
	}
	facts.Parse.Issues = issues
	ruleID := strings.ToUpper(strings.TrimSpace(rule.ID))
	for _, candidate := range generation.semanticRules {
		if candidate.program == nil ||
			strings.ToUpper(strings.TrimSpace(candidate.rule.ID)) != ruleID {
			continue
		}
		projection, code := semantic.Project(facts)
		if code != semantic.ProjectionOK {
			return false
		}
		result, evalCode := candidate.program.EvalBool(context.Background(), projection)
		return evalCode == semantic.EvalOK && result.Matched
	}
	return false
}

// exactFallbackContractIDs is the rule id of every exact fallback contract in
// ascending order. It is read once, after the init functions that add
// contracts have run.
var exactFallbackContractIDs = sync.OnceValue(func() []string {
	return slices.Sorted(maps.Keys(exactFallbackContracts))
})

// appendTrustedBoundedExactFallbackFindings scans the extracted trusted
// command, not its JSON serialization, for rules whose code-owned contract
// proves an exact bounded subgraph. Go's JSON encoder escapes shell redirect
// characters such as '>', which can otherwise hide a valid catalog candidate.
// Most recoveries require both the active profile's regex and deterministic
// contract. A contract may explicitly declare a code-owned detection grammar;
// that lane still requires the rule to exist in the active profile catalog.
func appendTrustedBoundedExactFallbackFindings(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	facts actionfacts.Facts,
) []RuleFinding {
	commandText := trustedActionInputText(input, "")
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		seen[finding.RuleID] = struct{}{}
	}
	// By rule id, never in map order: two findings that fire together keep
	// one order from call to call, so the verdict reason and the audit row
	// name the same rule (rel-1-0-10:GAP-0514).
	for _, ruleID := range exactFallbackContractIDs() {
		contract := exactFallbackContracts[ruleID]
		if contract.boundedSubgraphProves == nil ||
			!contract.boundedSubgraphProves(input, facts) {
			continue
		}
		if _, ok := seen[ruleID]; ok {
			continue
		}
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok || (!contract.codeOwnedDetection &&
			(strings.TrimSpace(commandText) == "" || rule.Pattern == nil || !rule.Pattern.MatchString(commandText))) {
			continue
		}
		if contract.boundedRequiresActiveExpression &&
			!boundedRuleExpressionHolds(generation, rule, commandText, certainControlFlowCommands(facts)) {
			continue
		}
		evidence := commandText
		if strings.TrimSpace(evidence) == "" {
			evidence = input.Tool
		}
		finding := RuleFinding{
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			Confidence:  rule.Confidence,
			Evidence:    evidence,
			Tags:        append([]string(nil), rule.Tags...),
			LineNumber:  1,
			enforcement: findingEnforcementAllowed,
		}
		if contract.boundedRequiresActiveExpression && contract.detectionOnly {
			finding.enforcement = findingEnforcementDetectionOnly
		}
		findings = append(findings, adjustConfidence(input.Tool, finding))
		seen[ruleID] = struct{}{}
	}
	return findings
}

func finalizeTrustedActionFindings(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	findings = deduplicateTrustedActionFindings(findings)
	findings = applyTrustedActionContextDisposition(generation, facts, findings, trustedActionDispositionScope{
		protectedLocalFileRead: request.CopilotSharedLocalFile && request.Input.Tool == "read_file",
		sendDestination:        request.sendDestination,
	})
	findings = withProvenScopeFindings(generation, request, facts, findings)
	if !request.StrictPolicy {
		findings = trustedActionOrdinaryCredentialCopyFindings(facts, findings)
	}
	return applyTrustedActionProofBoundary(findings, request.EnforcementCapable)
}

// deduplicateTrustedActionFindings collapses exact duplicate rule IDs and
// equivalent aliases claimed by one semantic owner within each profile.
// Recovery lanes may prove the same action independently, but findings from
// different meet members must remain for their own verdicts and audit.
func deduplicateTrustedActionFindings(findings []RuleFinding) []RuleFinding {
	deduplicated := make([]RuleFinding, 0, len(findings))
	positions := make(map[string]int, len(findings))
	for _, finding := range findings {
		key := finding.profile + "\x00" + trustedActionFindingKey(finding.RuleID)
		_, claimed := trustedSemanticOwnerClaimingRule(finding.RuleID)
		if position, duplicate := positions[key]; duplicate {
			current := deduplicated[position]
			candidateRank := severityRank[strings.ToUpper(strings.TrimSpace(finding.Severity))]
			currentRank := severityRank[strings.ToUpper(strings.TrimSpace(current.Severity))]
			ownerKey := trustedActionFindingKey(finding.RuleID)
			candidateCanonical := claimed && canonicalTrustedRuleID(finding.RuleID) == ownerKey
			currentCanonical := canonicalTrustedRuleID(current.RuleID) == ownerKey
			if candidateRank > currentRank ||
				(candidateRank == currentRank && finding.Confidence > current.Confidence) ||
				(candidateRank == currentRank && finding.Confidence == current.Confidence &&
					candidateCanonical && !currentCanonical) {
				deduplicated[position] = finding
			}
			continue
		}
		positions[key] = len(deduplicated)
		deduplicated = append(deduplicated, finding)
	}
	return deduplicated
}

// trustedActionFindingKey is the identity deduplication gives a finding: the
// owner of a rule a semantic owner claims, otherwise the rule itself.
func trustedActionFindingKey(ruleID string) string {
	if owner, claimed := trustedSemanticOwnerClaimingRule(ruleID); claimed {
		return canonicalTrustedRuleID(owner.id)
	}
	return canonicalTrustedRuleID(ruleID)
}

// trustedFixtureSourceInspectionAction identifies the one tool-call shape in
// which credential and PII literals are examples rather than submitted data:
// a read-only inspection whose every proven target is an explicit fixture or
// bundled guardrail rule source. Any mixed, unresolved, networked, or mutating
// action keeps the data detectors enabled.
func trustedFixtureSourceInspectionAction(
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if len(facts.Paths) == 0 || len(facts.Network) != 0 {
		return false
	}
	for _, path := range facts.Paths {
		if path.Access != actionfacts.PathAccessRead &&
			path.Access != actionfacts.PathAccessList {
			return false
		}
		value := firstNonEmpty(path.Resolved, path.Normalized, path.Value)
		if !fixtureOrGuardrailSourcePathLexical(value, input.CWD) {
			return false
		}
	}

	if len(facts.Commands) == 0 {
		return trustedStructuredSourceInspectionTool(input.Tool)
	}
	for _, command := range facts.Commands {
		switch strings.ToLower(strings.TrimSpace(command.Program)) {
		case "rg", "ripgrep", "grep", "sed", "awk", "head", "tail",
			"cat", "find", "fd":
		default:
			return false
		}
	}
	return true
}

func trustedStructuredSourceInspectionTool(tool string) bool {
	name := strings.ToLower(strings.TrimSpace(tool))
	name = strings.NewReplacer(".", "", "-", "", "_", "").Replace(name)
	switch name {
	case "read", "readfile", "fsread", "fileread", "catfile", "openfile",
		"viewfile", "getfile", "search", "searchfiles", "filesearch", "glob",
		"globfiles", "listfiles", "listdirectory":
		return true
	default:
		return false
	}
}

// trustedReadOnlyInspectionAction proves that secret- or PII-shaped bytes in
// a tool call are inert reader/search arguments, not data being written or
// transmitted. The returned tool output is scanned independently at
// PostToolUse, so lowering these argument-only matches does not suppress a
// credential or regulated value that the reader actually returns.
//
// Keep this proof deliberately narrower than "no network facts": every shell
// stage must be a statically projected reader, searcher, or stdin-only output
// limiter with no redirects, wrappers, expansion, or embedded execution. This
// proves argv structure, not the ambient executable/profile identity, which is
// why callers may use it only behind DowngradeReadOnlyDataArgs in Observe.
func trustedReadOnlyInspectionAction(
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if len(facts.Network) != 0 {
		return false
	}
	for _, path := range facts.Paths {
		if path.Access != actionfacts.PathAccessRead &&
			path.Access != actionfacts.PathAccessList {
			return false
		}
	}
	if facts.Parse.Dialect == actionfacts.DialectArgv &&
		facts.Authoritative() && len(facts.Commands) == 1 &&
		trustedStructuredSourceInspectionTool(input.Tool) {
		return len(facts.Paths) != 0
	}
	if len(facts.Commands) == 0 {
		return len(facts.Paths) != 0 &&
			trustedStructuredSourceInspectionTool(input.Tool)
	}

	commandText := trustedActionInputText(input, "")
	if powerShellFacts, candidate := codexStaticPowerShellReaderFacts(
		commandText, facts, input.CWD, input.Tool, input.ActiveHome,
	); candidate {
		return trustedReadOnlyPowerShellInspection(powerShellFacts)
	}
	if facts.Parse.Dialect != actionfacts.DialectPOSIX ||
		len(facts.Commands) == 0 ||
		!codexStaticReaderParseStatus(facts.Parse) ||
		!codexStaticReaderShellStructureSafe(commandText) {
		return false
	}

	pipelineHasSource := make(map[int64]bool)
	sawSource := false
	for _, command := range facts.Commands {
		if command.Kind != actionfacts.CommandKindProcess ||
			command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete || len(command.Argv) == 0 ||
			len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
			return false
		}
		for _, argument := range command.Arguments {
			if argument.Expands || codexArgumentHasBraceExpansion(argument) {
				return false
			}
		}

		inputs, ok := codexStaticReaderCommandInputs(command.Program, command.Argv)
		if !ok && trustedGitStatusInspection(command.Argv) {
			inputs = codexStaticReaderInputs{hasDataTarget: true}
			ok = true
		}
		if !ok || inputs.readsStdin && inputs.hasDataTarget {
			return false
		}
		if inputs.hasDataTarget {
			sawSource = true
			if command.PipelineID != 0 {
				pipelineHasSource[command.PipelineID] = true
			}
			continue
		}
		if !inputs.readsStdin || command.PipelineID == 0 ||
			!pipelineHasSource[command.PipelineID] {
			return false
		}
	}
	return sawSource
}

func trustedReadOnlyPowerShellInspection(facts actionfacts.Facts) bool {
	if !codexStaticPowerShellReaderParseStatus(facts.Parse) ||
		len(facts.Commands) != 1 || len(facts.Network) != 0 ||
		len(facts.DataFlows) != 0 {
		return false
	}
	command := facts.Commands[0]
	if command.Kind != actionfacts.CommandKindProcess ||
		(command.Dialect != actionfacts.DialectPowerShell &&
			command.Dialect != actionfacts.DialectCMD) ||
		command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
		len(command.Argv) == 0 || command.PipelineID != 0 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		len(command.Arguments) != len(command.Argv) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.Quote == actionfacts.QuoteMixed {
			return false
		}
	}
	var (
		inputs codexStaticReaderInputs
		ok     bool
	)
	switch strings.ToLower(command.Program) {
	case "get-content", "gc", "type":
		inputs, ok = codexPowerShellGetContentInputs(command)
	case "select-string":
		inputs, ok = codexPowerShellSelectStringInputs(command)
	}
	return ok && inputs.hasDataTarget && !inputs.readsStdin
}

func trustedGitStatusInspection(argv []string) bool {
	if len(argv) < 2 || argv[0] != "git" || argv[1] != "status" {
		return false
	}
	for index := 2; index < len(argv); index++ {
		argument := argv[index]
		switch {
		case argument == "--":
			return index+1 < len(argv)
		case argument == "--short", argument == "-s",
			argument == "--branch", argument == "-b",
			argument == "--porcelain", argument == "--ignored",
			argument == "--show-stash", argument == "--ahead-behind",
			argument == "--no-ahead-behind":
		case strings.HasPrefix(argument, "--porcelain="),
			strings.HasPrefix(argument, "--untracked-files="):
		default:
			return false
		}
	}
	return true
}

// filterTrustedLegacyActionContext prevents a search pattern, patch body, or
// other content payload from being promoted into an action by the regex
// compatibility lane. Paths, commands, cognitive mutations, and C2 destinations
// each require the corresponding typed ActionFact.
func filterTrustedLegacyActionContext(
	generation *compiledRulePackCategories,
	findings []RuleFinding,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
	downgradeReadOnlyDataArgs bool,
) []RuleFinding {
	// Each match set is read only by the findings of its category, and the
	// scan that builds it is the cost of the call: build it on first use, so
	// a call whose findings need none (or has no finding) pays for none.
	var (
		pathMatches, mutationMatches map[string]struct{}
		pathMatchesKnown             bool
		commandMatches               map[string]struct{}
		commandMatchesKnown          bool
		networkMatches               map[string]struct{}
		networkMatchesKnown          bool
	)
	loadPathMatches := func() (map[string]struct{}, map[string]struct{}) {
		if !pathMatchesKnown {
			pathMatches, mutationMatches = trustedLegacyPathRuleMatches(generation, input, toolName, facts)
			pathMatchesKnown = true
		}
		return pathMatches, mutationMatches
	}
	loadPathOnly := func() map[string]struct{} {
		path, _ := loadPathMatches()
		return path
	}
	loadMutationMatches := func() map[string]struct{} {
		_, mutation := loadPathMatches()
		return mutation
	}
	loadCommandMatches := func() map[string]struct{} {
		if !commandMatchesKnown {
			commandMatches = trustedLegacyCommandRuleMatches(generation, input, toolName, facts)
			commandMatchesKnown = true
		}
		return commandMatches
	}
	loadNetworkMatches := func() map[string]struct{} {
		if !networkMatchesKnown {
			networkMatches = trustedLegacyNetworkRuleMatches(generation, input, toolName, facts)
			networkMatchesKnown = true
		}
		return networkMatches
	}
	var (
		readOnlyInspectionKnown bool
		readOnlyInspection      bool
		nestedActionsKnown      bool
		nestedActions           []trustedNestedAction
	)
	loadNestedActions := func() []trustedNestedAction {
		if !nestedActionsKnown {
			nestedActions = trustedNestedExecutionActions(input, facts)
			nestedActionsKnown = true
		}
		return nestedActions
	}
	filtered := findings[:0]
	for _, finding := range findings {
		if hasTag(finding.Tags, trustedParserUncertaintyTag) {
			finding.enforcement = findingEnforcementDetectionOnly
			filtered = append(filtered, finding)
			continue
		}
		if contract, ok := exactFallbackContracts[finding.RuleID]; ok {
			if contract.codeOwnedDetection && contract.boundedSubgraphProves != nil &&
				contract.boundedSubgraphProves(input, facts) {
				filtered = append(filtered, finding)
				continue
			}
			proven := contract.proves != nil && contract.proves(input, facts)
			if contract.requiresExactDetectionProof && !proven {
				continue
			}
			if contract.detectionOnly &&
				(noRecoverableCommandFacts(facts) || proven) {
				filtered = append(filtered, finding)
				continue
			}
		}
		category := trustedLegacyRuleCategory(generation, finding.RuleID)
		if downgradeReadOnlyDataArgs &&
			trustedReadOnlyArgumentDataFinding(category, finding) {
			if !readOnlyInspectionKnown {
				readOnlyInspection = trustedReadOnlyInspectionAction(input, facts)
				readOnlyInspectionKnown = true
			}
			if readOnlyInspection {
				finding.Severity = "LOW"
				finding.enforcement = findingEnforcementDetectionOnly
				filtered = append(filtered, finding)
				continue
			}
		}
		switch category {
		case "enterprise-data":
			// PII rules classify message/document content, not the intent of an
			// executable action. A literal email address or phone number in a
			// benign command argument must not become a command-security finding.
			// Dedicated command and exfiltration owners still inspect the action.
			continue
		case "sensitive-path":
			if _, ok := loadPathOnly()[finding.RuleID]; ok {
				filtered = append(filtered, finding)
			}
		case "cognitive-file":
			if _, ok := loadMutationMatches()[finding.RuleID]; ok {
				if proof, proven := trustedSemanticOwnerFindingProofFromActions(
					finding.RuleID,
					facts,
					loadNestedActions(),
				); proven {
					finding = finding.withTrustedActionProof(proof)
				}
				filtered = append(filtered, finding)
			}
		case "command":
			if _, ok := loadCommandMatches()[finding.RuleID]; ok {
				filtered = append(
					filtered,
					trustedLegacyProvenCommandFinding(
						generation,
						finding,
						facts,
						loadNestedActions(),
					),
				)
			}
		case "c2":
			if _, ok := loadNetworkMatches()[finding.RuleID]; ok {
				if proof, proven := trustedNetworkFindingProofFromActions(
					generation,
					finding.RuleID,
					toolName,
					facts,
					loadNestedActions(),
				); proven {
					finding = finding.withTrustedActionProof(proof)
				}
				filtered = append(filtered, finding)
			}
		default:
			switch {
			case strings.HasPrefix(finding.RuleID, "PATH-"):
				if _, ok := loadPathOnly()[finding.RuleID]; ok {
					filtered = append(filtered, finding)
				}
			case strings.HasPrefix(finding.RuleID, "COG-"):
				if _, ok := loadMutationMatches()[finding.RuleID]; ok {
					if proof, proven := trustedSemanticOwnerFindingProofFromActions(
						finding.RuleID,
						facts,
						loadNestedActions(),
					); proven {
						finding = finding.withTrustedActionProof(proof)
					}
					filtered = append(filtered, finding)
				}
			case strings.HasPrefix(finding.RuleID, "CMD-"):
				if _, ok := loadCommandMatches()[finding.RuleID]; ok {
					filtered = append(
						filtered,
						trustedLegacyProvenCommandFinding(
							generation,
							finding,
							facts,
							loadNestedActions(),
						),
					)
				}
			case strings.HasPrefix(finding.RuleID, "C2-"):
				if _, ok := loadNetworkMatches()[finding.RuleID]; ok {
					if proof, proven := trustedNetworkFindingProofFromActions(
						generation,
						finding.RuleID,
						toolName,
						facts,
						loadNestedActions(),
					); proven {
						finding = finding.withTrustedActionProof(proof)
					}
					filtered = append(filtered, finding)
				}
			default:
				filtered = append(filtered, finding)
			}
		}
	}
	return filtered
}

func trustedLegacyProvenCommandFinding(
	generation *compiledRulePackCategories,
	finding RuleFinding,
	facts actionfacts.Facts,
	nestedActions []trustedNestedAction,
) RuleFinding {
	// CMD-PYTHON-C and CMD-BASH-C are generic interpreter-shape owners. Once
	// ActionFacts proves the command being executed, retain the LOW match as
	// audit telemetry without letting the generic shape alert or block.
	// Specific semantic owners (for example reverse shells and destructive
	// commands) remain independently enforcement-capable. Unstructured and
	// malformed literal fallback never reaches this proven-owner branch and
	// keeps its existing conservative contract.
	contract, detectionOnly := trustedLegacyProvenCommandDetectionOnly[finding.RuleID]
	if detectionOnly && trustedLegacyDetectionOnlyCommandRule(
		generation,
		finding.RuleID,
		contract,
	) && (contract.prerequisite == nil || contract.prerequisite(facts)) {
		finding.enforcement = findingEnforcementDetectionOnly
	}
	if finding.RuleID == "CMD-EVAL" &&
		finding.enforcement != findingEnforcementDetectionOnly {
		// eval's operand is only known when it runs, so no parse can prove
		// the call and the proof boundary left the finding detection-only,
		// which "defenseclaw alerts" never shows (GAP-2575). An executed
		// eval with a runtime operand alerts at the connector's threshold
		// and never confirms or blocks.
		finding.enforcement = findingEnforcementAlertOnly
	}
	if proof, proven := trustedSemanticOwnerFindingProofFromActions(
		finding.RuleID,
		facts,
		nestedActions,
	); proven {
		finding = finding.withTrustedActionProof(proof)
	}
	return finding
}

func trustedLegacyDetectionOnlyCommandRule(
	generation *compiledRulePackCategories,
	ruleID string,
	contract trustedLegacyProvenCommandDetectionOnlyContract,
) bool {
	if generation == nil {
		return false
	}
	matched := false
	for _, category := range generation.categories {
		for _, rule := range category.Rules {
			if canonicalTrustedRuleID(rule.ID) != canonicalTrustedRuleID(ruleID) {
				continue
			}
			if matched || rule.ID != ruleID || category.Name != contract.category ||
				rule.Pattern == nil ||
				rule.Pattern.String() != contract.pattern ||
				rule.Expression != "" || rule.ToolCallOnly ||
				rule.Title != contract.title ||
				rule.Severity != contract.severity ||
				rule.Confidence != contract.confidence ||
				!slices.Equal(rule.Tags, contract.tags) {
				return false
			}
			matched = true
		}
	}
	return matched
}

func canonicalTrustedRuleID(ruleID string) string {
	return strings.ToUpper(strings.TrimSpace(ruleID))
}

func trustedBashInlineCommandOwnerProven(facts actionfacts.Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectExecute &&
			command.ArgvComplete &&
			oneOfFold(command.Program, "bash", "sh") &&
			len(command.Argv) >= 3 && command.Argv[1] == "-c" &&
			strings.TrimSpace(command.Argv[2]) != "" {
			return true
		}
	}
	return false
}

func trustedPerlInlineCommandOwnerProven(facts actionfacts.Facts) bool {
	return trustedInlineCommandOwnerProven(facts, "perl", "-e")
}

func trustedRubyInlineCommandOwnerProven(facts actionfacts.Facts) bool {
	return trustedInlineCommandOwnerProven(facts, "ruby", "-e")
}

func trustedInlineCommandOwnerProven(
	facts actionfacts.Facts,
	program string,
	inlineFlag string,
) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectExecute &&
			command.ArgvComplete &&
			oneOfFold(command.Program, program) &&
			len(command.Argv) >= 3 &&
			command.Argv[1] == inlineFlag &&
			strings.TrimSpace(command.Argv[2]) != "" {
			return true
		}
	}
	return false
}

func trustedPerlInlineEffectFreeOwnerProven(facts actionfacts.Facts) bool {
	return trustedInlineEffectFreeOwnerProven(
		facts,
		"perl",
		trustedPerlInlineRegexp,
		actionfacts.RecognizesPOSIXPerlInlineBody,
	)
}

func trustedRubyInlineEffectFreeOwnerProven(facts actionfacts.Facts) bool {
	return trustedInlineEffectFreeOwnerProven(
		facts,
		"ruby",
		trustedRubyInlineRegexp,
		actionfacts.RecognizesPOSIXRubyInlineBody,
	)
}

func trustedInlineEffectFreeOwnerProven(
	facts actionfacts.Facts,
	program string,
	compiledPattern *regexp.Regexp,
	recognizes func(actionfacts.CommandFact) bool,
) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		recognizes == nil || compiledPattern == nil {
		return false
	}
	commandIndex, ok := inlineCommandIndex(facts.Commands)
	if !ok {
		return false
	}
	matched := 0
	for _, command := range facts.Commands {
		text := strings.TrimSpace(command.Executable)
		if len(command.Argv) != 0 {
			text = serializeArgvForLegacyScan(command.Argv)
		}
		patternMatches := compiledPattern.MatchString(text) ||
			compiledPattern.MatchString(normalizeShell(text))
		if command.Program != program {
			if patternMatches {
				return false
			}
			continue
		}
		if !patternMatches {
			continue
		}
		if command.ParentCommandID != 0 || command.Dialect != actionfacts.DialectPOSIX ||
			command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
			command.PipelineID != 0 || len(command.Redirects) != 0 ||
			len(command.Wrappers) != 0 || !recognizes(command) ||
			actionfacts.ProvesPOSIXInlineInterpreterForkBomb(command) ||
			len(command.Operations) != 1 || command.Operations[0] != actionfacts.OperationExecute {
			return false
		}
		matched++
	}
	if matched == 0 {
		return false
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 && (command.Program == program ||
			inlineCommandDescendsFromProgram(commandIndex, command, program)) {
			return false
		}
	}
	for _, fact := range facts.Paths {
		if inlineFactOwnedByProgram(commandIndex, fact.CommandID, program) {
			return false
		}
	}
	for _, fact := range facts.Network {
		if inlineFactOwnedByProgram(commandIndex, fact.CommandID, program) {
			return false
		}
	}
	for _, fact := range facts.DataFlows {
		if inlineFactOwnedByProgram(commandIndex, fact.FromCommandID, program) ||
			inlineFactOwnedByProgram(commandIndex, fact.ToCommandID, program) {
			return false
		}
	}
	return true
}

func inlineCommandIndex(
	commands []actionfacts.CommandFact,
) (map[int64]actionfacts.CommandFact, bool) {
	index := make(map[int64]actionfacts.CommandFact, len(commands))
	for _, command := range commands {
		if command.ID == 0 {
			return nil, false
		}
		if _, duplicate := index[command.ID]; duplicate {
			return nil, false
		}
		index[command.ID] = command
	}
	return index, true
}

func inlineCommandDescendsFromProgram(
	commandIndex map[int64]actionfacts.CommandFact,
	command actionfacts.CommandFact,
	program string,
) bool {
	parentID := command.ParentCommandID
	visited := make(map[int64]struct{}, len(commandIndex))
	for steps := 0; parentID != 0; steps++ {
		if steps >= len(commandIndex) {
			return true
		}
		if _, repeated := visited[parentID]; repeated {
			return true
		}
		visited[parentID] = struct{}{}
		parent, found := commandIndex[parentID]
		if !found {
			return true
		}
		if parent.Program == program {
			return true
		}
		parentID = parent.ParentCommandID
	}
	return false
}

func inlineFactOwnedByProgram(
	commandIndex map[int64]actionfacts.CommandFact,
	commandID int64,
	program string,
) bool {
	if commandID == 0 {
		return false
	}
	command, found := commandIndex[commandID]
	if !found {
		return true
	}
	return command.Program == program ||
		inlineCommandDescendsFromProgram(commandIndex, command, program)
}

func trustedReadOnlyArgumentDataFinding(category string, finding RuleFinding) bool {
	// Action families always win over generic data tags. Some built-in path
	// findings (notably the native Windows PATH-WIN-* rules) are not members of
	// the generated category catalog, but carry a "credential" tag to describe
	// the target. Treating that tag as submitted credential data would turn an
	// actual credential-store read into inert LOW telemetry in Observe.
	for _, prefix := range []string{"PATH-", "COG-", "CMD-", "C2-"} {
		if strings.HasPrefix(finding.RuleID, prefix) {
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "secret", "secrets", "cred", "credential", "credential-leak",
		"enterprise-data", "pii":
		return true
	case "", "general", "unknown":
		// Unclassified/custom rules may still declare a stable data tag or ID.
	default:
		// A declared action category wins over generic tags such as credential.
		// Sensitive-path rules commonly carry that tag but still describe an
		// actual read and must keep their ordinary path enforcement.
		return false
	}
	for _, tag := range finding.Tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "secret", "credential", "credential-leak", "pii":
			return true
		}
	}
	for _, prefix := range []string{
		"SEC-", "CS-SEC-", "SECRET-", "JSON-SEC-", "CG-CRED-", "CRED-",
		"ENT-", "PII-", "CS-PII-", "LP-PII-", "LP-SECRET-",
	} {
		if strings.HasPrefix(finding.RuleID, prefix) {
			return true
		}
	}
	return false
}

func trustedLegacyRuleCategory(
	generation *compiledRulePackCategories,
	ruleID string,
) string {
	if generation == nil {
		return ""
	}
	for _, category := range generation.categories {
		for _, rule := range category.Rules {
			if rule.ID == ruleID {
				return category.Name
			}
		}
	}
	return ""
}

func trustedLegacyCommandRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	type pipelineProjection struct {
		id               int64
		commands         []string
		stdinInterpreter bool
	}
	matchesByID := make(map[string]struct{})
	pipelines := make(map[int64]pipelineProjection)
	for _, command := range facts.Commands {
		scanCommand := command
		if command.Effect == actionfacts.EffectUncertain {
			staticArgv, ok := trustedStaticCommandArgv(command)
			if !ok {
				continue
			}
			scanCommand.Argv = withTrustedDynamicEvalOperand(command, staticArgv)
			scanCommand.ArgvComplete = true
		} else if command.Effect != actionfacts.EffectExecute {
			continue
		}
		text := strings.TrimSpace(scanCommand.Executable)
		if len(scanCommand.Argv) != 0 {
			text = serializeArgvForLegacyScan(scanCommand.Argv)
		} else if text == "" {
			text = strings.TrimSpace(scanCommand.Program)
		}
		if !trustedCommandLiteralCarrier(scanCommand) {
			collectTrustedLegacyCommandMatches(
				generation,
				text,
				toolName,
				matchesByID,
			)
			for _, embedded := range trustedEmbeddedCommandTexts(command) {
				collectTrustedLegacyCommandMatches(
					generation,
					embedded,
					toolName,
					matchesByID,
				)
			}
		}
		if command.Effect == actionfacts.EffectExecute && command.PipelineID != 0 {
			pipeline := pipelines[command.PipelineID]
			pipeline.id = command.PipelineID
			pipeline.commands = append(pipeline.commands, text)
			pipeline.stdinInterpreter = pipeline.stdinInterpreter ||
				(actionfacts.ProvesPOSIXStdinInterpreter(command) &&
					hasDataFlowTo(
						facts,
						command.ID,
						actionfacts.DataStdout,
						actionfacts.DataStdin,
					))
			pipelines[command.PipelineID] = pipeline
		}
	}
	for _, pipeline := range pipelines {
		if len(pipeline.commands) < 2 {
			continue
		}
		pipelineMatches := make(map[string]struct{})
		collectTrustedLegacyCommandMatches(
			generation,
			strings.Join(pipeline.commands, " | "),
			toolName,
			pipelineMatches,
		)
		for ruleID := range pipelineMatches {
			if pipeline.stdinInterpreter ||
				trustedRuleHasActionProof(ruleID, input, facts) ||
				trustedPipelineFallbackProof(ruleID, pipeline.id, facts) {
				matchesByID[ruleID] = struct{}{}
			}
		}
	}
	for ruleID := range exactFallbackContracts {
		if trustedLegacyRuleCategory(generation, ruleID) == "command" &&
			trustedRuleHasActionProof(ruleID, input, facts) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	// A download cradle is one command word (iex) over an argument that
	// fetches: no pipeline text holds it, so psparse's reading of the chain
	// (actionfacts.PowerShellFetchedContentExecution) is the match.
	if actionfacts.PowerShellFetchedContentExecution(input) {
		matchesByID["CMD-WIN-IWR-IEX"] = struct{}{}
	}
	for ruleID := range semanticOwners {
		if trustedLegacyRuleCategory(generation, ruleID) == "command" &&
			trustedRuleHasActionProof(ruleID, input, facts) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		if len(nested.facts.Commands) == 0 {
			continue
		}
		for ruleID := range trustedLegacyCommandRuleMatches(
			generation,
			nested.input,
			toolName,
			nested.facts,
		) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	return matchesByID
}

// withTrustedDynamicEvalOperand keeps the shape CMD-EVAL names: eval whose
// first operand expands at runtime (eval "$(...)", eval "$VAR"). The static
// argv stops at that operand, which left a bare "eval" that no command rule
// can match, so the rule never fired on a real tool call (GAP-2575). A "$"
// stands in for the runtime value; nothing else about the argv changes.
func withTrustedDynamicEvalOperand(
	command actionfacts.CommandFact,
	argv []string,
) []string {
	if command.Program != "eval" || len(argv) != 1 ||
		len(command.Arguments) < 2 || !command.Arguments[1].Expands {
		return argv
	}
	return append(argv, "$")
}

func trustedStaticCommandArgv(
	command actionfacts.CommandFact,
) ([]string, bool) {
	if strings.TrimSpace(command.Program) == "" || len(command.Arguments) == 0 {
		return nil, false
	}
	argv := make([]string, 0, len(command.Arguments))
	for index, argument := range command.Arguments {
		if argument.Expands {
			if index == 0 {
				return nil, false
			}
			break
		}
		if strings.TrimSpace(argument.Value) == "" {
			if index == 0 {
				return nil, false
			}
			continue
		}
		argv = append(argv, argument.Value)
	}
	if len(argv) == 0 {
		return nil, false
	}
	return argv, true
}

type trustedNestedAction struct {
	input       actionfacts.Input
	facts       actionfacts.Facts
	rawFallback bool
}

const trustedProjectedActionTool = "defenseclaw.trusted-projected-action"

const trustedParserUncertaintyTag = "parser-uncertainty"

var (
	trustedAwkSystemPattern = regexp.MustCompile(
		`(?i)\bsystem\s*\(\s*"([^"]+)"\s*\)`,
	)
	trustedAwkGetlinePattern = regexp.MustCompile(
		`"([^"]+)"\s*\|\s*getline\b`,
	)
	trustedAwkPrintPipePattern = regexp.MustCompile(
		`\|\s*"([^"]+)"`,
	)
)

// trustedBashFallbackActions is a bounded secondary projection for valid Bash
// syntax rejected by the POSIX parser before it can emit any facts. Only a
// valid server-derived command for a recognized Bash-capable execution tool is
// eligible. Walking Bash CallExpr nodes exposes commands nested in process
// substitutions, Bash redirects, here-strings, and arithmetic loops while
// quoted lookalikes remain arguments to their actual carrier command.
func trustedBashFallbackActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	if input.Tool == trustedProjectedActionTool {
		return nil
	}
	// A generic shell envelope can carry native PowerShell or CMD syntax on
	// Windows. Those dialects already have their own structural projection;
	// reparsing their bytes as Bash can turn valid quoted arguments into a raw
	// parser-uncertainty finding (for example, CMD does not treat a backslash
	// before a closing quote as an escape). Never manufacture Bash telemetry
	// for a structurally proven non-Bash dialect. Partial or invalid Windows
	// parses still retain the bounded uncertainty lane below.
	if facts.Authoritative() &&
		(facts.Parse.Dialect == actionfacts.DialectPowerShell ||
			facts.Parse.Dialect == actionfacts.DialectCMD) {
		return nil
	}
	command, ok := trustedBashCommandInput(input)
	const maxBashFallbackBytes = 64 << 10
	if !ok {
		return nil
	}
	if facts.Parse.Status == actionfacts.StatusLimitExceeded ||
		len(command) > maxBashFallbackBytes {
		return trustedRawShellFallbackAction(input, command)
	}
	file, err := syntax.NewParser(
		syntax.Variant(syntax.LangBash),
	).Parse(shellparse.Reader(command), "")
	if err != nil {
		// macOS generic shell boundaries may execute zsh syntax that mvdan's
		// Bash grammar cannot represent. The input is still a valid, trusted
		// execution envelope, so fail closed on action regexes. Normalize only
		// closing syntax delimiters so root-path rules can see an executable
		// operand immediately before `)`/`}`; quoted literals in otherwise
		// parseable commands never enter this lane.
		return trustedRawShellFallbackAction(input, command)
	}
	needsBashProjection := trustedBashTreeNeedsProjection(file)
	if facts.Authoritative() && !needsBashProjection {
		return nil
	}
	wrapperActions := trustedStaticShellWrapperFallbackActions(input, facts)
	definitions := trustedBashFunctionDefinitions(file)
	if len(facts.Commands) != 0 && len(definitions) == 0 &&
		!needsBashProjection {
		return wrapperActions
	}
	projectRoots := []syntax.Node{file}
	invoked := make(map[string]struct{})
	var queue []string
	if len(definitions) != 0 {
		queue = trustedBashStaticCallNames(file)
	}
	functionProjectionUncertain := false
	const maxInvokedFunctions = 64
	for len(queue) != 0 {
		if len(invoked) >= maxInvokedFunctions {
			functionProjectionUncertain = true
			break
		}
		name := queue[0]
		queue = queue[1:]
		definition, exists := definitions[name]
		if !exists {
			continue
		}
		if _, seen := invoked[name]; seen {
			continue
		}
		invoked[name] = struct{}{}
		projectRoots = append(projectRoots, definition.Body)
		queue = append(queue, trustedBashStaticCallNames(definition.Body)...)
	}

	const (
		maxProjectedCalls = 32
		maxRenderedBytes  = 256 << 10
	)
	actions := append([]trustedNestedAction(nil), wrapperActions...)
	projected := 0
	renderedBytes := 0
	fallbackWhole := functionProjectionUncertain
	unresolvedExecution := false
	seenBodies := make(map[string]struct{})
	project := func(root syntax.Node) {
		syntax.Walk(root, func(node syntax.Node) bool {
			if fallbackWhole {
				return false
			}
			if _, definition := node.(*syntax.FuncDecl); definition {
				return false
			}
			var (
				executable       syntax.Node
				call             *syntax.CallExpr
				unresolvedAction bool
			)
			switch node := node.(type) {
			case *syntax.Stmt:
				if _, definition := node.Cmd.(*syntax.FuncDecl); definition {
					return true
				}
				executable = node
				if assignment, ok := node.Cmd.(*syntax.CallExpr); ok &&
					len(assignment.Args) == 0 && len(node.Redirs) != 0 {
					unresolvedAction = true
				}
			case *syntax.CallExpr:
				executable = node
				call = node
			default:
				return true
			}
			var rendered bytes.Buffer
			if err := syntax.NewPrinter().Print(&rendered, executable); err != nil {
				return true
			}
			body := strings.TrimSpace(rendered.String())
			if call != nil {
				// Static field rendering can preserve glob syntax as a literal
				// argv value even though Bash will select the executable at
				// runtime. Keep that useful projection, but also retain the raw
				// detection-only uncertainty lane for the unresolved command
				// identity.
				if trustedBashCallHasDynamicExecutable(call) {
					unresolvedExecution = true
				}
				if fields, ok := trustedBashStaticFields(call); ok {
					body = serializeArgvForLegacyScan(fields)
				} else if trustedBashCallNeedsProjection(call) {
					unresolvedExecution = true
				}
			}
			if body == "" {
				return true
			}
			renderedBytes += len(body)
			if renderedBytes > maxRenderedBytes {
				fallbackWhole = true
				return false
			}
			if _, duplicate := seenBodies[body]; duplicate {
				return true
			}
			seenBodies[body] = struct{}{}
			if projected >= maxProjectedCalls {
				fallbackWhole = true
				return false
			}
			nestedInput := actionfacts.Input{
				Tool:                                     "bash",
				Command:                                  body,
				CWD:                                      input.CWD,
				ActiveHome:                               input.ActiveHome,
				ActiveAgentFiles:                         append([]string(nil), input.ActiveAgentFiles...),
				ActiveAgentFilesCaseInsensitive:          append([]string(nil), input.ActiveAgentFilesCaseInsensitive...),
				ActiveAgentFilesCaseInsensitiveUncertain: input.ActiveAgentFilesCaseInsensitiveUncertain,
				ActiveAgentFilesUncertain:                input.ActiveAgentFilesUncertain,
			}
			nestedFacts := actionfacts.Analyze(nestedInput)
			if len(nestedFacts.Commands) == 0 {
				// Assignment-only CallExpr nodes do not execute an external
				// command. In particular, a static Bash array declaration must
				// not create parser-uncertainty telemetry merely because the
				// POSIX projection cannot represent it. Any command substitutions
				// in the assignment are walked and projected independently, while
				// statement-level redirections remain unresolved actions.
				if unresolvedAction || (call != nil && len(call.Args) != 0) {
					unresolvedExecution = true
				}
				return true
			}
			actions = append(actions, trustedNestedAction{
				input: trustedTerminalNestedInput(nestedInput),
				facts: nestedFacts,
			})
			projected++
			return true
		})
	}
	for _, root := range projectRoots {
		project(root)
	}
	if fallbackWhole || unresolvedExecution {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, command)...,
		)
	}
	return actions
}

func trustedStaticShellWrapperFallbackActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	seen := make(map[string]struct{})
	var actions []trustedNestedAction
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute &&
			command.Effect != actionfacts.EffectUncertain {
			continue
		}
		program := strings.ToLower(strings.TrimSpace(command.Program))
		switch program {
		case "bash", "zsh", "ksh", "sh", "dash":
		default:
			continue
		}
		for index := 1; index+1 < len(command.Arguments); index++ {
			option := command.Arguments[index]
			if option.Expands || !trustedShellCommandOption(option.Value) {
				continue
			}
			script := command.Arguments[index+1]
			if script.Expands {
				actions = append(
					actions,
					trustedRawShellFallbackAction(
						input,
						serializeArgvForLegacyScan(command.Argv),
					)...,
				)
				break
			}
			if strings.TrimSpace(script.Value) == "" {
				continue
			}
			if _, duplicate := seen[script.Value]; duplicate {
				continue
			}
			seen[script.Value] = struct{}{}
			nestedInput := actionfacts.Input{
				Tool:                                     program,
				Command:                                  script.Value,
				CWD:                                      input.CWD,
				ActiveHome:                               input.ActiveHome,
				ActiveAgentFiles:                         append([]string(nil), input.ActiveAgentFiles...),
				ActiveAgentFilesCaseInsensitive:          append([]string(nil), input.ActiveAgentFilesCaseInsensitive...),
				ActiveAgentFilesCaseInsensitiveUncertain: input.ActiveAgentFilesCaseInsensitiveUncertain,
				ActiveAgentFilesUncertain:                input.ActiveAgentFilesUncertain,
			}
			nestedFacts := actionfacts.Analyze(nestedInput)
			actions = append(
				actions,
				trustedBashFallbackActions(nestedInput, nestedFacts)...,
			)
			break
		}
	}
	return actions
}

func trustedBashTreeNeedsProjection(root syntax.Node) bool {
	needsProjection := false
	syntax.Walk(root, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if trustedBashCallNeedsProjection(call) {
			needsProjection = true
			return false
		}
		return !needsProjection
	})
	return needsProjection
}

func trustedBashCallNeedsProjection(call *syntax.CallExpr) bool {
	if call == nil {
		return false
	}
	if trustedBashCallHasDynamicExecutable(call) {
		return true
	}
	for _, word := range call.Args {
		if trustedBashWordNeedsProjection(word) {
			return true
		}
	}
	return false
}

// trustedBashCallHasDynamicExecutable identifies a runtime expansion in the
// command word. Expansions in later argv positions do not make the executable
// identity uncertain and therefore must not create generic parser telemetry.
//
// Deliberately do not resolve parameter or array values from earlier shell
// assignments here. Doing that soundly requires control-flow, scope, quoting,
// and mutation semantics that the bounded projection does not currently own;
// the existing raw fallback instead records the uncertainty without allowing
// it to drive enforcement.
func trustedBashCallHasDynamicExecutable(call *syntax.CallExpr) bool {
	if call == nil || len(call.Args) == 0 || call.Args[0] == nil {
		return false
	}
	index := 0
	const maxTransparentWrappers = 4
	for depth := 0; depth <= maxTransparentWrappers; depth++ {
		if index >= len(call.Args) || call.Args[index] == nil {
			return false
		}
		word := call.Args[index]
		if trustedBashWordHasDynamicExecutable(word) {
			return true
		}
		program, ok := trustedBashStaticWordValue(word)
		if !ok {
			return false
		}
		program = path.Base(program)
		next, ok := trustedBashTransparentWrapperExecutable(call.Args, index, program)
		if next == trustedBashUnresolvedWrapperExecutable {
			return true
		}
		if !ok {
			return false
		}
		index = next
	}
	return true
}

func trustedBashWordHasDynamicExecutable(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	var shellPattern strings.Builder
	if trustedBashAppendExecutablePattern(&shellPattern, word.Parts, false) {
		return true
	}
	candidate := shellPattern.String()
	if !pattern.HasMeta(candidate, 0) {
		return false
	}
	// An unmatched bracket is a literal command name under ordinary Bash glob
	// semantics (for example the standard `[` command). Validate the complete
	// quote-aware word because a bracket expression may cross AST parts, as in
	// /bin/r['m']; validating each literal fragment would miss that expansion.
	_, err := pattern.Regexp(candidate, pattern.Filenames|pattern.EntireString)
	return err == nil
}

// trustedBashAppendExecutablePattern reconstructs one shell pattern while
// quoting metacharacters contributed by quoted AST parts. It returns true for
// value-producing expansions whose result can select the executable directly.
func trustedBashAppendExecutablePattern(
	destination *strings.Builder,
	parts []syntax.WordPart,
	quoted bool,
) bool {
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
			*syntax.ProcSubst:
			return true
		case *syntax.ExtGlob:
			if !quoted {
				return true
			}
		case *syntax.Lit:
			value := part.Value
			if quoted {
				value = pattern.QuoteMeta(value, 0)
			}
			destination.WriteString(value)
		case *syntax.SglQuoted:
			destination.WriteString(pattern.QuoteMeta(part.Value, 0))
		case *syntax.DblQuoted:
			// Parameter and command expansion still occur inside double
			// quotes, but pathname expansion does not.
			if trustedBashAppendExecutablePattern(destination, part.Parts, true) {
				return true
			}
		}
	}
	return false
}

func trustedBashStaticWordValue(word *syntax.Word) (string, bool) {
	if word == nil || trustedBashWordMayExpandHome(word) || shellparse.MinBraceFields(word) > 1 {
		return "", false
	}
	fields, err := shellparse.Fields(&expand.Config{}, word)
	if err != nil || len(fields) != 1 || strings.TrimSpace(fields[0]) != fields[0] {
		return "", false
	}
	return fields[0], fields[0] != ""
}

const trustedBashUnresolvedWrapperExecutable = -1

func trustedBashTransparentWrapperExecutable(
	args []*syntax.Word,
	wrapperIndex int,
	program string,
) (int, bool) {
	switch program {
	case "command":
		for index := wrapperIndex + 1; index < len(args); index++ {
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			switch argument {
			case "--":
				return index + 1, index+1 < len(args)
			case "-p":
				continue
			case "-v", "-V":
				return 0, false
			}
			if strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			return index, true
		}

	case "exec":
		for index := wrapperIndex + 1; index < len(args); index++ {
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			switch argument {
			case "--":
				return index + 1, index+1 < len(args)
			case "-c", "-l", "-cl", "-lc":
				continue
			case "-a":
				index++
				if index >= len(args) {
					return 0, false
				}
				continue
			}
			if strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			return index, true
		}

	case "env":
		for index := wrapperIndex + 1; index < len(args); index++ {
			if trustedBashEnvironmentAssignmentWord(args[index]) {
				continue
			}
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			switch argument {
			case "--":
				for index++; index < len(args); index++ {
					if trustedBashEnvironmentAssignmentWord(args[index]) {
						continue
					}
					value, ok := trustedBashStaticWordValue(args[index])
					if !ok || !trustedBashEnvironmentAssignment(value) {
						return index, true
					}
				}
				return 0, false
			case "--help", "--version":
				return 0, false
			case "-S", "--split-string":
				return trustedBashUnresolvedWrapperExecutable, false
			case "-u", "--unset", "-C", "--chdir":
				index++
				if index >= len(args) {
					return 0, false
				}
				continue
			case "-i", "--ignore-environment", "-0", "--null", "-v", "--debug":
				continue
			}
			if strings.HasPrefix(argument, "--unset=") ||
				strings.HasPrefix(argument, "--chdir=") ||
				len(argument) > 2 && strings.HasPrefix(argument, "-C") {
				continue
			}
			if strings.HasPrefix(argument, "--split-string=") ||
				strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			if trustedBashEnvironmentAssignment(argument) {
				continue
			}
			return index, true
		}

	case "sudo":
		for index := wrapperIndex + 1; index < len(args); index++ {
			if trustedBashEnvironmentAssignmentWord(args[index]) {
				continue
			}
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			if argument == "--" {
				for index++; index < len(args); index++ {
					if trustedBashEnvironmentAssignmentWord(args[index]) {
						continue
					}
					value, ok := trustedBashStaticWordValue(args[index])
					if !ok || !trustedBashEnvironmentAssignment(value) {
						return index, true
					}
				}
				return 0, false
			}
			switch argument {
			case "-i", "--login", "-s", "--shell":
				if index+1 < len(args) {
					return trustedBashUnresolvedWrapperExecutable, false
				}
				return 0, false
			case "-l", "-ll", "--list", "-e", "--edit", "-v", "--validate",
				"-V", "--version", "--help":
				return 0, false
			case "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
				"-C", "--close-from", "-T", "--command-timeout", "-r", "--role", "-t", "--type",
				"-D", "--chdir", "-R", "--chroot":
				index++
				if index >= len(args) {
					return 0, false
				}
				continue
			case "-n", "--non-interactive", "-E", "--preserve-env", "-H", "--set-home",
				"-S", "--stdin", "-k", "--reset-timestamp", "-K", "--remove-timestamp",
				"-b", "--background":
				continue
			}
			if trustedBashSudoAttachedOption(argument) {
				continue
			}
			if strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			if trustedBashEnvironmentAssignment(argument) {
				continue
			}
			return index, true
		}
	}
	return 0, false
}

func trustedBashEnvironmentAssignment(argument string) bool {
	name, _, ok := strings.Cut(argument, "=")
	return ok && name != ""
}

func trustedBashEnvironmentAssignmentWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	name, _, ok := strings.Cut(literal.Value, "=")
	return ok && name != "" && !strings.HasPrefix(name, "-")
}

func trustedBashSudoAttachedOption(argument string) bool {
	for _, prefix := range []string{
		"--user=", "--group=", "--host=", "--prompt=", "--close-from=",
		"--command-timeout=", "--role=", "--type=", "--chdir=", "--chroot=",
	} {
		if strings.HasPrefix(argument, prefix) && len(argument) > len(prefix) {
			return true
		}
	}
	return strings.HasPrefix(argument, "--preserve-env=") &&
		len(argument) > len("--preserve-env=")
}

func trustedBashWordNeedsProjection(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	copyWord := *word
	if syntax.SplitBraces(&copyWord) {
		return true
	}
	needsProjection := false
	syntax.Walk(word, func(node syntax.Node) bool {
		switch quoted := node.(type) {
		case *syntax.SglQuoted:
			needsProjection = needsProjection || quoted.Dollar
		case *syntax.DblQuoted:
			needsProjection = needsProjection || quoted.Dollar
		}
		return !needsProjection
	})
	return needsProjection
}

func trustedBashStaticFields(call *syntax.CallExpr) ([]string, bool) {
	if call == nil || len(call.Args) == 0 {
		return nil, false
	}
	for _, assignment := range call.Assigns {
		if assignment.Name == nil {
			return nil, false
		}
		switch strings.ToUpper(assignment.Name.Value) {
		case "PATH", "BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH",
			"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH":
			return nil, false
		}
	}
	fields := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		static := true
		syntax.Walk(word, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
				*syntax.ProcSubst:
				static = false
				return false
			}
			return static
		})
		if !static || trustedBashWordMayExpandHome(word) {
			if len(fields) == 0 {
				return nil, false
			}
			break
		}
		// A brace range that alone passes the field cap is refused before
		// it expands (GAP-0568).
		if uint64(len(fields))+shellparse.MinBraceFields(word) > 256 {
			return nil, false
		}
		expanded, err := shellparse.Fields(&expand.Config{}, word)
		if err != nil {
			if len(fields) == 0 {
				return nil, false
			}
			break
		}
		fields = append(fields, expanded...)
		if len(fields) > 256 {
			return nil, false
		}
	}
	if len(fields) == 0 {
		return nil, false
	}
	for _, field := range fields {
		if strings.IndexByte(field, 0) >= 0 || len(field) > 8<<10 {
			return nil, false
		}
	}
	return fields, true
}

func trustedBashWordMayExpandHome(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	return ok && strings.HasPrefix(literal.Value, "~")
}

func trustedShellCommandOption(value string) bool {
	if value == "-c" || value == "--command" {
		return true
	}
	return strings.HasPrefix(value, "-") &&
		!strings.HasPrefix(value, "--") &&
		strings.Contains(strings.TrimPrefix(value, "-"), "c")
}

func trustedEmbeddedExecutionActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	if input.Tool == trustedProjectedActionTool {
		return nil
	}
	seen := make(map[string]struct{})
	var actions []trustedNestedAction
	var uncertaintyText string
	markUncertainty := func(text string) {
		if uncertaintyText == "" {
			uncertaintyText = trustedBoundedText(text, 64<<10)
		}
	}
	const (
		maxDirectNestedCount = 32
		maxDirectNestedBytes = 128 << 10
	)
	directBytes := 0
	var overflowText string
	reserve := func(text string) bool {
		if len(actions) >= maxDirectNestedCount ||
			directBytes+len(text) > maxDirectNestedBytes {
			if overflowText == "" {
				overflowText = trustedBoundedText(
					trustedActionInputText(input, text),
					maxDirectNestedBytes,
				)
			}
			return false
		}
		directBytes += len(text)
		return true
	}
	appendText := func(text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		key := "text\x00" + text
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		if !reserve(text) {
			return
		}
		nestedInput := actionfacts.Input{
			Tool:                                     "bash",
			Command:                                  text,
			CWD:                                      input.CWD,
			ActiveHome:                               input.ActiveHome,
			ActiveAgentFiles:                         append([]string(nil), input.ActiveAgentFiles...),
			ActiveAgentFilesCaseInsensitive:          append([]string(nil), input.ActiveAgentFilesCaseInsensitive...),
			ActiveAgentFilesCaseInsensitiveUncertain: input.ActiveAgentFilesCaseInsensitiveUncertain,
			ActiveAgentFilesUncertain:                input.ActiveAgentFilesUncertain,
		}
		nestedFacts := actionfacts.Analyze(nestedInput)
		if len(nestedFacts.Commands) == 0 {
			actions = append(
				actions,
				trustedBashFallbackActions(nestedInput, nestedFacts)...,
			)
			return
		}
		actions = append(actions, trustedNestedAction{
			input: trustedTerminalNestedInput(nestedInput),
			facts: nestedFacts,
		})
	}
	appendArgv := func(argv []string) {
		if len(argv) == 0 {
			return
		}
		key := "argv\x00" + strings.Join(argv, "\x00")
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		if !reserve(serializeArgvForLegacyScan(argv)) {
			return
		}
		nestedInput := actionfacts.Input{
			Tool:                                     "shell",
			Argv:                                     append([]string(nil), argv...),
			CWD:                                      input.CWD,
			ActiveHome:                               input.ActiveHome,
			ActiveAgentFiles:                         append([]string(nil), input.ActiveAgentFiles...),
			ActiveAgentFilesCaseInsensitive:          append([]string(nil), input.ActiveAgentFilesCaseInsensitive...),
			ActiveAgentFilesCaseInsensitiveUncertain: input.ActiveAgentFilesCaseInsensitiveUncertain,
			ActiveAgentFilesUncertain:                input.ActiveAgentFilesUncertain,
		}
		actions = append(actions, trustedNestedAction{
			input: trustedTerminalNestedInput(nestedInput),
			facts: actionfacts.Analyze(nestedInput),
		})
	}

	commands := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		commands[command.ID] = command
		if command.Effect != actionfacts.EffectExecute &&
			command.Effect != actionfacts.EffectUncertain {
			continue
		}
		program := strings.ToLower(strings.TrimSpace(command.Program))
		switch program {
		case "find":
			for index := 1; index < len(command.Argv); index++ {
				if !oneOfFold(command.Argv[index], "-exec", "-execdir", "-ok", "-okdir") {
					continue
				}
				end := index + 1
				for end < len(command.Argv) && command.Argv[end] != ";" && command.Argv[end] != "+" {
					end++
				}
				appendArgv(command.Argv[index+1 : end])
				index = end
			}
		case "fd":
			for index := 1; index < len(command.Argv); index++ {
				if oneOfFold(command.Argv[index], "-x", "--exec", "-X", "--exec-batch") {
					appendArgv(command.Argv[index+1:])
					break
				}
				for _, prefix := range []string{"--exec=", "--exec-batch="} {
					if strings.HasPrefix(command.Argv[index], prefix) {
						appendText(strings.TrimPrefix(command.Argv[index], prefix))
					}
				}
			}
		case "rg", "ripgrep":
			for index := 1; index < len(command.Argv); index++ {
				if command.Argv[index] == "--pre" && index+1 < len(command.Argv) {
					appendText(command.Argv[index+1])
					break
				}
				if strings.HasPrefix(command.Argv[index], "--pre=") {
					appendText(strings.TrimPrefix(command.Argv[index], "--pre="))
					break
				}
			}
		case "sed":
			embedded := trustedEmbeddedCommandTexts(command)
			for _, text := range embedded {
				appendText(text)
			}
			if len(embedded) == 0 && sedInvocationExecutes(command.Argv) {
				markUncertainty(serializeArgvForLegacyScan(command.Argv))
			}
		case "awk":
			extracted := 0
			for _, argument := range trustedAwkProgramTexts(command.Argv) {
				argument = trustedStripAwkComments(argument)
				for _, pattern := range []*regexp.Regexp{
					trustedAwkSystemPattern,
					trustedAwkGetlinePattern,
					trustedAwkPrintPipePattern,
				} {
					for _, match := range pattern.FindAllStringSubmatch(argument, -1) {
						if len(match) > 1 {
							appendText(match[1])
							extracted++
						}
					}
				}
			}
			if extracted == 0 && awkInvocationExecutes(command.Argv) {
				markUncertainty(serializeArgvForLegacyScan(command.Argv))
			}
		case "eval":
			var fields []string
			for _, argument := range trustedCommandOperandArguments(command) {
				if argument.Expands {
					markUncertainty(serializeArgvForLegacyScan(command.Argv))
					break
				}
				fields = append(fields, argument.Value)
			}
			appendText(strings.Join(fields, " "))
		}
	}
	for _, flow := range facts.DataFlows {
		if flow.From != actionfacts.DataStdout || flow.To != actionfacts.DataStdin {
			continue
		}
		source, sourceOK := commands[flow.FromCommandID]
		sink, sinkOK := commands[flow.ToCommandID]
		if !sourceOK || !sinkOK || !actionfacts.ProvesPOSIXStdinInterpreter(sink) {
			continue
		}
		if source.Effect != actionfacts.EffectExecute ||
			sink.Effect != actionfacts.EffectExecute {
			continue
		}
		switch strings.ToLower(source.Program) {
		case "echo":
			var fields []string
			for _, argument := range trustedCommandOperandArguments(source) {
				if argument.Expands {
					markUncertainty(serializeArgvForLegacyScan(source.Argv))
					break
				}
				fields = append(fields, argument.Value)
			}
			appendText(strings.Join(fields, " "))
		case "printf":
			static := trustedCommandOperandArguments(source)
			for _, argument := range static {
				if argument.Expands {
					markUncertainty(serializeArgvForLegacyScan(source.Argv))
					break
				}
			}
			if len(static) == 1 && !static[0].Expands {
				appendText(static[0].Value)
				continue
			}
			if len(static) <= 1 {
				continue
			}
			for _, argument := range static[1:] {
				if !argument.Expands {
					appendText(argument.Value)
				}
			}
		}
	}
	if overflowText != "" {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, overflowText)...,
		)
	}
	if uncertaintyText != "" {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, uncertaintyText)...,
		)
	}
	return actions
}

func trustedAwkProgramTexts(argv []string) []string {
	var programs []string
	hasSource := false
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch argument {
		case "-f", "--file":
			hasSource = true
			if index+1 < len(argv) {
				index++
			}
		case "-e", "--source":
			hasSource = true
			if index+1 < len(argv) {
				programs = append(programs, argv[index+1])
				index++
			}
		case "-v", "-F", "--field-separator", "--assign":
			if index+1 < len(argv) {
				index++
			}
		case "--":
			if !hasSource && index+1 < len(argv) {
				programs = append(programs, argv[index+1])
			}
			return programs
		default:
			if strings.HasPrefix(argument, "-F") ||
				strings.HasPrefix(argument, "-v") ||
				strings.HasPrefix(argument, "--source=") ||
				strings.HasPrefix(argument, "--file=") {
				if strings.HasPrefix(argument, "--source=") {
					hasSource = true
					programs = append(programs, strings.TrimPrefix(argument, "--source="))
				}
				if strings.HasPrefix(argument, "--file=") {
					hasSource = true
				}
				continue
			}
			if strings.HasPrefix(argument, "-") {
				continue
			}
			if !hasSource {
				programs = append(programs, argument)
			}
			return programs
		}
	}
	return programs
}

func trustedNestedExecutionActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	if input.Tool == trustedProjectedActionTool {
		return nil
	}
	type queuedAction struct {
		action trustedNestedAction
		depth  int
	}
	direct := func(
		candidate actionfacts.Input,
		candidateFacts actionfacts.Facts,
	) []trustedNestedAction {
		actions := trustedBashFallbackActions(candidate, candidateFacts)
		return append(
			actions,
			trustedEmbeddedExecutionActions(candidate, candidateFacts)...,
		)
	}
	queue := make([]queuedAction, 0, 16)
	for _, action := range direct(input, facts) {
		queue = append(queue, queuedAction{action: action})
	}
	const (
		maxNestedDepth = 4
		maxNestedCount = 64
		maxNestedBytes = 256 << 10
	)
	seen := make(map[string]struct{})
	actions := make([]trustedNestedAction, 0, len(queue))
	processedBytes := 0
	var overflow strings.Builder
	for len(queue) != 0 {
		queued := queue[0]
		queue = queue[1:]
		text := trustedNestedActionText(queued.action)
		key := strings.Join([]string{
			text,
			string(queued.action.facts.Parse.Status),
			string(queued.action.facts.Parse.Dialect),
		}, "\x00")
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if len(actions) >= maxNestedCount ||
			processedBytes+len(text) > maxNestedBytes {
			overflow.WriteString(trustedBoundedText(
				trustedActionInputText(input, text),
				maxNestedBytes,
			))
			break
		}
		processedBytes += len(text)
		actions = append(actions, queued.action)
		if queued.action.rawFallback {
			continue
		}
		if queued.depth >= maxNestedDepth {
			overflow.WriteString(trustedBoundedText(
				trustedActionInputText(input, text),
				maxNestedBytes,
			))
			break
		}
		exploreInput := queued.action.input
		exploreInput.ActiveAgentFiles = append(
			[]string(nil),
			queued.action.input.ActiveAgentFiles...,
		)
		exploreInput.ActiveAgentFilesCaseInsensitive = append(
			[]string(nil),
			queued.action.input.ActiveAgentFilesCaseInsensitive...,
		)
		exploreInput.Tool = queued.action.facts.Tool
		if strings.TrimSpace(exploreInput.Tool) == "" {
			exploreInput.Tool = "bash"
		}
		for _, child := range direct(exploreInput, queued.action.facts) {
			queue = append(queue, queuedAction{
				action: child,
				depth:  queued.depth + 1,
			})
		}
	}
	if overflow.Len() != 0 {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, overflow.String())...,
		)
	}
	return actions
}

func trustedNestedActionText(action trustedNestedAction) string {
	if strings.TrimSpace(action.input.Command) != "" {
		return action.input.Command
	}
	if len(action.input.Argv) != 0 {
		return serializeArgvForLegacyScan(action.input.Argv)
	}
	return ""
}

func trustedActionInputText(input actionfacts.Input, fallback string) string {
	if strings.TrimSpace(input.Command) != "" {
		return input.Command
	}
	if command, present, valid := trustedTopLevelCommandField(input.Args); valid && present && strings.TrimSpace(command) != "" {
		return command
	}
	if len(input.Argv) != 0 {
		return serializeArgvForLegacyScan(input.Argv)
	}
	return fallback
}

func trustedBoundedText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit]
}

func trustedBashFunctionDefinitions(
	root syntax.Node,
) map[string]*syntax.FuncDecl {
	definitions := make(map[string]*syntax.FuncDecl)
	syntax.Walk(root, func(node syntax.Node) bool {
		definition, ok := node.(*syntax.FuncDecl)
		if !ok {
			return true
		}
		if definition.Name != nil && definition.Name.Value != "" {
			definitions[definition.Name.Value] = definition
		}
		for _, name := range definition.Names {
			if name != nil && name.Value != "" {
				definitions[name.Value] = definition
			}
		}
		return false
	})
	return definitions
}

func trustedBashStaticCallNames(root syntax.Node) []string {
	const maxStaticCalls = 64
	var names []string
	syntax.Walk(root, func(node syntax.Node) bool {
		if len(names) >= maxStaticCalls {
			return false
		}
		if _, definition := node.(*syntax.FuncDecl); definition {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		fields, ok := trustedBashStaticFields(call)
		if !ok || len(fields) == 0 || strings.TrimSpace(fields[0]) == "" {
			return true
		}
		names = append(names, fields[0])
		return true
	})
	return names
}

func trustedRawShellFallbackAction(
	input actionfacts.Input,
	command string,
) []trustedNestedAction {
	return []trustedNestedAction{{
		input: trustedTerminalNestedInput(actionfacts.Input{
			Tool:                                     "bash",
			Command:                                  trustedExecutableShellProjection(command),
			CWD:                                      input.CWD,
			ActiveHome:                               input.ActiveHome,
			ActiveAgentFiles:                         append([]string(nil), input.ActiveAgentFiles...),
			ActiveAgentFilesCaseInsensitive:          append([]string(nil), input.ActiveAgentFilesCaseInsensitive...),
			ActiveAgentFilesCaseInsensitiveUncertain: input.ActiveAgentFilesCaseInsensitiveUncertain,
			ActiveAgentFilesUncertain:                input.ActiveAgentFilesUncertain,
		}),
		rawFallback: true,
	}}
}

func trustedTerminalNestedInput(input actionfacts.Input) actionfacts.Input {
	input.Tool = trustedProjectedActionTool
	input.Args = nil
	return input
}

type trustedShellHeredoc struct {
	delimiter string
	stripTabs bool
}

// trustedExecutableShellProjection is the last-resort lane for a validated
// shell execution envelope whose dialect or size cannot be represented by
// ActionFacts. It preserves unquoted executable syntax, but masks strings,
// comments, and heredoc bodies so source-review examples do not become proof
// of an action merely because the primary parser could not classify them.
func trustedExecutableShellProjection(command string) string {
	var projected strings.Builder
	projected.Grow(len(command))
	var (
		quote    byte
		escaped  bool
		heredocs []trustedShellHeredoc
	)
	for offset := 0; offset < len(command); {
		lineEnd := strings.IndexByte(command[offset:], '\n')
		hasNewline := lineEnd >= 0
		if !hasNewline {
			lineEnd = len(command) - offset
		}
		line := command[offset : offset+lineEnd]
		if len(heredocs) != 0 {
			candidate := strings.TrimSuffix(line, "\r")
			if heredocs[0].stripTabs {
				candidate = strings.TrimLeft(candidate, "\t")
			}
			if candidate == heredocs[0].delimiter {
				heredocs = heredocs[1:]
			}
			projected.WriteString(strings.Repeat(" ", len(line)))
		} else {
			for index := 0; index < len(line); index++ {
				current := line[index]
				if quote != 0 {
					projected.WriteByte(' ')
					if escaped {
						escaped = false
						continue
					}
					if quote == '"' && current == '\\' {
						escaped = true
						continue
					}
					if current == quote {
						quote = 0
					}
					continue
				}
				if escaped {
					projected.WriteByte(' ')
					escaped = false
					continue
				}
				if current == '\\' {
					projected.WriteByte(' ')
					escaped = true
					continue
				}
				if current == '\'' || current == '"' {
					quote = current
					projected.WriteByte(' ')
					continue
				}
				if current == '#' && trustedShellCommentBoundary(line, index) {
					projected.WriteString(strings.Repeat(" ", len(line)-index))
					break
				}
				if current == '<' && index+1 < len(line) &&
					line[index+1] == '<' &&
					(index+2 >= len(line) || line[index+2] != '<') {
					if heredoc, ok := trustedShellHeredocAt(line, index); ok {
						heredocs = append(heredocs, heredoc)
					}
				}
				switch current {
				case ';':
					// Exact fallback patterns use a double-space token as the
					// masked command boundary. Preserve that boundary even for
					// compact forms such as `payload;rm`, where the source has no
					// whitespace after the separator.
					projected.WriteString("  ")
				case ')', '}':
					projected.WriteByte(' ')
				default:
					projected.WriteByte(current)
				}
			}
		}
		if hasNewline {
			projected.WriteByte('\n')
			offset += lineEnd + 1
			continue
		}
		offset += lineEnd
	}
	return projected.String()
}

func trustedShellCommentBoundary(line string, index int) bool {
	if index == 0 {
		return true
	}
	previous := line[index-1]
	return previous == ' ' || previous == '\t' ||
		strings.ContainsRune(";|&(){}<>", rune(previous))
}

func trustedShellHeredocAt(
	line string,
	operator int,
) (trustedShellHeredoc, bool) {
	index := operator + 2
	heredoc := trustedShellHeredoc{}
	if index < len(line) && line[index] == '-' {
		heredoc.stripTabs = true
		index++
	}
	for index < len(line) && (line[index] == ' ' || line[index] == '\t') {
		index++
	}
	if index >= len(line) {
		return trustedShellHeredoc{}, false
	}
	if line[index] == '\'' || line[index] == '"' {
		quote := line[index]
		index++
		start := index
		for index < len(line) && line[index] != quote {
			index++
		}
		if index == len(line) || index == start {
			return trustedShellHeredoc{}, false
		}
		heredoc.delimiter = line[start:index]
		return heredoc, true
	}
	start := index
	for index < len(line) && !strings.ContainsRune(" \t\r;|&()<>", rune(line[index])) {
		index++
	}
	if index == start {
		return trustedShellHeredoc{}, false
	}
	heredoc.delimiter = line[start:index]
	return heredoc, true
}

// homeSpellingTwinRequest returns request with its Bash command's
// ~<active user> tilde-prefixes (the home's base name or one of logins)
// spelled as the active home (actionfacts.ActiveUserTildeTwin) or, under a Windows home, its MSYS
// drive mounts spelled as drive paths (actionfacts.MSYSDrivePathTwin). A
// hook client's resolved target for the original spelling is kept for the
// new one. The twin records no audit or telemetry of its own.
func homeSpellingTwinRequest(request trustedActionRequest, logins ...string) (trustedActionRequest, bool) {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return trustedActionRequest{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return trustedActionRequest{}, false
	}
	var respell func(string) string
	rewritten, prefixes, ok := actionfacts.ActiveUserTildeTwin(command, request.Input.ActiveHome, logins...)
	if ok {
		home := strings.TrimRight(filepath.ToSlash(request.Input.ActiveHome), "/")
		respell = func(spelling string) string {
			for _, prefix := range prefixes {
				if spelling == prefix || strings.HasPrefix(spelling, prefix+"/") {
					return home + spelling[len(prefix):]
				}
			}
			return spelling
		}
	} else if rewritten, ok = actionfacts.MSYSDrivePathTwin(command, request.Input.ActiveHome); ok {
		respell = actionfacts.MSYSDrivePath
	} else {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.record, twin.recordTelemetry = nil, nil
	twin.Input.Command, twin.Input.Args, twin.Input.Argv = rewritten, nil, nil
	twin.conflictSource = nil
	if strings.Contains(request.LegacyText, command) {
		twin.LegacyText = strings.ReplaceAll(request.LegacyText, command, rewritten)
	} else {
		twin.LegacyText = rewritten
	}
	if request.ResolvedWriteTargets != nil {
		twin.ResolvedWriteTargets = make(map[string]string, len(request.ResolvedWriteTargets))
		for spelling, value := range request.ResolvedWriteTargets {
			twin.ResolvedWriteTargets[spelling] = value
		}
		for spelling, value := range request.ResolvedWriteTargets {
			if respelled := respell(spelling); respelled != spelling {
				if _, taken := twin.ResolvedWriteTargets[respelled]; !taken {
					twin.ResolvedWriteTargets[respelled] = value
				}
			}
		}
	}
	return twin, true
}

// dynamicOperandTwinRequests returns the request for each reading of
// actionfacts.DynamicOperandTwins of a POSIX Bash call. Behind ProtectHome
// (managed hook peer) the hook client map lists the targets of the same
// readings (hookpaths), so they are judged there too (GAP-2477).
func dynamicOperandTwinRequests(request trustedActionRequest) []trustedActionRequest {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return nil
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return nil
	}
	var twins []trustedActionRequest
	for _, rewritten := range actionfacts.DynamicOperandTwins(command, request.Input.ActiveHome) {
		if rewritten != command {
			twin := bashReadingRequest(request, command, rewritten)
			twin.staticOperandReading = request.ProtectedHomeHook
			twins = append(twins, twin)
		}
	}
	return twins
}

// bashReadingRequest returns request with its Bash command replaced by
// another reading of it; the reading records nothing of its own.
func bashReadingRequest(request trustedActionRequest, command, rewritten string) trustedActionRequest {
	twin := request
	twin.record, twin.recordTelemetry = nil, nil
	twin.Input.Command, twin.Input.Args, twin.Input.Argv = rewritten, nil, nil
	twin.conflictSource = nil
	if strings.Contains(request.LegacyText, command) {
		twin.LegacyText = strings.ReplaceAll(request.LegacyText, command, rewritten)
	} else {
		twin.LegacyText = rewritten
	}
	return twin
}

// wrapperUnwrapTwinRequest returns the request for the reading of a POSIX
// Bash call by actionfacts.WrapperUnwrapTwin (anyProgram) or
// WrapperUnwrapWriterTwin. Behind ProtectHome (managed hook peer) the hook
// client map lists the targets of the wider reading (hookpaths), so the
// wrapped call is judged there too (GAP-2563). A here-string pipe reading
// gets no any-program twin (hereStringPipeReading).
func wrapperUnwrapTwinRequest(request trustedActionRequest, anyProgram bool) (trustedActionRequest, bool) {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return trustedActionRequest{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || anyProgram && request.hereStringPipeReading {
		return trustedActionRequest{}, false
	}
	unwrap := actionfacts.WrapperUnwrapWriterTwin
	if anyProgram {
		unwrap = actionfacts.WrapperUnwrapTwin
	}
	rewritten, ok := unwrap(command)
	if !ok || rewritten == command {
		return trustedActionRequest{}, false
	}
	// The hook client reads a link made by a wrapper that moves the
	// directory (env -C DIR ln ...) with its cautious unknown-link reading,
	// which the map carries; judged here, the "( cd DIR && ln ... )" twin
	// would turn that caution into a block of every benign link there.
	// Behind ProtectHome such a twin is left to the client reading.
	if request.ProtectedHomeHook && strings.Count(rewritten, "( cd ") > strings.Count(command, "( cd ") &&
		tactics.RunsProgram(rewritten, "ln", "gln", "link", "glink") {
		return trustedActionRequest{}, false
	}
	return bashReadingRequest(request, command, rewritten), true
}

// wrappedStateMutationRules are the rules a call that any program runs
// through a prefix wrapper is judged by on its plain reading
// (actionfacts.WrapperUnwrapTwin): a write or delete of the DefenseClaw
// state and the agent hook files, and a recursive delete of a critical root
// such as the home (find ~ -delete). The wrapper changes nothing of what the
// program writes or removes (rel-1-0-10:GAP-1186, GAP-1246).
var wrappedStateMutationRules = map[string]bool{
	"TAMPER.DETECTOR_STATE_WRITE":      true,
	"TAMPER.AGENT_HOOK_CONFIG_WRITE":   true,
	"TAMPER.AGENT_HOOK_CONFIG_DISABLE": true,
	"CMD-RM-RF":                        true,
}

// wrappedStateMutationRule reports a rule of wrappedStateMutationRules.
func wrappedStateMutationRule(ruleID string) bool {
	return wrappedStateMutationRules[canonicalTrustedRuleID(ruleID)]
}

// runTimeShellTwinRequest returns the request for
// actionfacts.RunTimeShellTwin of a POSIX Bash call: the call read with each
// program word that names its shell at run time written as that shell.
// Behind ProtectHome (managed hook peer) the hook client map lists the
// targets of the same reading (hookpaths), so it is judged there too
// (rel-1-0-10:GAP-0980). caps is the caps that reading hit
// (rel-1-0-10:GAP-1041), with or without a twin; so is unread, a shell of
// the call that runs here-document text the reading cannot know
// (rel-1-0-10:GAP-1147).
func runTimeShellTwinRequest(request trustedActionRequest) (twin trustedActionRequest, ok bool, caps bounded.CapSet, unread bool) {
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return trustedActionRequest{}, false, caps, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return trustedActionRequest{}, false, caps, false
	}
	rewritten, ok, caps, unread := actionfacts.RunTimeShellTwin(command)
	if !ok || rewritten == command {
		return trustedActionRequest{}, false, caps, unread
	}
	return bashReadingRequest(request, command, rewritten), true, caps, unread
}

// stateGlobTwinRequest returns the request for actionfacts.StateGlobTwin of
// a POSIX Bash call. The gateway expands the pattern on its own host, so a
// gateway that may not read the user home (ProtectHome, or a request that
// skips local resolution) has no reading.
//
// Behind ProtectHome the pattern is read against the names of the protected
// state files and trees instead (actionfacts.StateGlobTwinNamed): cp a.txt
// ~/.def*/config.yaml and cp a.txt ~/.defenseclaw/conf*.yaml name
// config.yaml there too (GAP-2544). Only a block of that reading counts.
func stateGlobTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	if request.SkipLocalFilesystemResolution {
		return trustedActionRequest{}, false
	}
	if request.Input.DialectHint != actionfacts.DialectPOSIX && request.Input.DialectHint != "" {
		return trustedActionRequest{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return trustedActionRequest{}, false
	}
	var (
		rewritten string
		ok        bool
	)
	if request.ProtectedHomeHook {
		rewritten, ok = actionfacts.StateGlobTwinNamed(command, request.Input.ActiveHome, activeDefenseClawStateNames)
	} else {
		rewritten, ok = actionfacts.StateGlobTwin(command, request.Input.ActiveHome)
	}
	if !ok || rewritten == command {
		return trustedActionRequest{}, false
	}
	return bashReadingRequest(request, command, rewritten), true
}

// trustedReadingCut is the cap at which the reading of a shell call stopped
// under the statement budget, the one point every dialect's limit_exceeded
// reaches (the one bound rule): such a call is TRUNCATED.
//   - The input bound of a shell command line (actionfacts.MaxCommandBytes),
//     in every dialect, cap=bytes (a native write or read tool past the
//     bound keeps its own bounded readings, over_limit_write_targets.go):
//     a Windows-hook command padded past 64 KiB
//     was read in no dialect and was a clean allow in every pack, with no
//     limit finding (rel-1-0-10:GAP-0611). Its bounded twin (comments and
//     padding removed, overLimitCommandBoundedTwinRequest) still proves
//     what the text holds.
//   - The command cap of a CMD or PowerShell reading, cap=items: a CMD
//     reading capped at 127 to 257 statements had no limit finding and was
//     allowed in strict (rel-1-0-10:GAP-0426), and so was a PowerShell one:
//     one `$o = & git rev-parse HEAD` statement is two commands, so about 64
//     statements fill the cap, and a registry write beside 100 such lines was
//     found but allowed in every pack (rel-1-0-10:GAP-0589). The statements
//     of a capped PowerShell reading are read again in runs under the cap
//     (actionfacts.PowerShellCappedRuns).
//   - An argv command that no launcher script covers (trustedArgvReadingCut):
//     a word over 4 KiB, over 64 KiB in all, or more than 256 words
//     (rel-1-0-10:GAP-0712). bodyRead is set when the script of the launcher
//     is read on its own (launcherBodyTwinRequest), or when the POSIX reading
//     judges the call past its byte bound as the text of its words
//     (posixParseTruncation, rel-1-0-10:GAP-0689): a word over the argv
//     bounds is then not a cut of the reading, and that reading's own cuts
//     are the ones that count.
//
// A POSIX reading is not truncated by its command cap: its per-statement
// split (SimpleCommands) reads every statement up to the statement budget
// (ShellStatementsOverBudget), and each is judged.
func trustedReadingCut(input actionfacts.Input, facts actionfacts.Facts, bodyRead bool) bounded.CapSet {
	if facts.Parse.Status != actionfacts.StatusLimitExceeded {
		return bounded.CapSet{}
	}
	if command, known := trustedBashCommandInput(input); known && len(command) > actionfacts.MaxCommandBytes &&
		trustedShellCommandTool(input.Tool) {
		return bounded.Of(bounded.Bytes)
	}
	if !bodyRead {
		if cut := trustedArgvReadingCut(input, facts); cut.Any() {
			return cut
		}
	}
	if facts.Parse.Dialect == actionfacts.DialectCMD || facts.Parse.Dialect == actionfacts.DialectPowerShell {
		return bounded.Of(bounded.Items)
	}
	return bounded.CapSet{}
}

// trustedShellCommandTool reports a tool whose input is a shell command
// line: a POSIX, PowerShell or CMD execution tool.
func trustedShellCommandTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "cmd", "cmd.exe":
		return true
	}
	return trustedBashExecutionTool(tool) || trustedPowerShellExecutionTool(tool)
}

// trustedStatementBudgetExceeded reports whether a shell call whose
// analysis is limit-exceeded has more statements than one action evaluates.
// A POSIX reading, and a call of no known dialect that a POSIX shell runs
// (a POSIX hint, or no hint off Windows), are counted as the POSIX split
// counts them (actionfacts.ShellStatementsOverBudget). A call of no known
// dialect that PowerShell may run (a PowerShell tool, a PowerShell or CMD
// hint, or no hint on a Windows gateway, as Codex sends) is counted as
// PowerShell splits it (actionfacts.PowerShellStatementsOverBudget): Codex
// on Windows ran a 3000-statement call past the 64 KiB input bound through
// every reader and allowed it (rel-1-0-6:GAP-0318). A PowerShell reading
// that is not complete is counted the same way when it has an opaque
// subexpression, array, hashtable, braced variable or here-string
// (rel-1-0-6:GAP-0331). A complete PowerShell or CMD reading is held to the
// budget by its own split (SimpleCommands), and so is one the lexer read to
// its end: an ordinary 130-statement script of a partial reading stays
// allowed, as before.
func trustedStatementBudgetExceeded(input actionfacts.Input, facts actionfacts.Facts, command string) bool {
	if facts.Parse.Dialect == actionfacts.DialectPowerShell {
		// The reading stopped at the lexer's token bound or at a construct
		// it does not read past, so its split is short (rel-1-0-6:GAP-0331).
		return facts.Parse.Status != actionfacts.StatusComplete &&
			(facts.Parse.Status == actionfacts.StatusLimitExceeded || actionfacts.PowerShellReadingStopsEarly(command)) &&
			actionfacts.PowerShellStatementsOverBudget(command)
	}
	if facts.Parse.Dialect == actionfacts.DialectPOSIX {
		return actionfacts.ShellStatementsOverBudget(command)
	}
	if facts.Parse.Status != actionfacts.StatusLimitExceeded {
		return false
	}
	switch facts.Parse.Dialect {
	case actionfacts.DialectNone, "":
		powerShell := trustedPowerShellExecutionTool(input.Tool) ||
			input.DialectHint != "" && input.DialectHint != actionfacts.DialectPOSIX ||
			input.DialectHint == "" && runtime.GOOS == "windows"
		if powerShell {
			return actionfacts.PowerShellStatementsOverBudget(command)
		}
		return actionfacts.ShellStatementsOverBudget(command)
	default:
		return false
	}
}

// withOverBudgetStateMutation adds, to the budget refusal of a call over the
// statement budget, the one finding observe mode still enforces: a proven
// mutation of the active DefenseClaw state (tamper.detector_state_write,
// provenActiveStateMutation). Only the whole-call state check runs, once
// per generation and once per member of a strictest combination (each
// finding keeping its member), not the twins or the per-statement passes,
// so the refusal stays linear: about one memo unit per statement. A state
// name spelled with a pattern (~/.defense?law/config.yaml) is proved by the
// state glob twin, as on the full path: that twin is checked too and only
// its state-write finding counts (review R2-1 of rel-1-0-2:GAP-0568). A call
// that may name the state (hookpaths.MayNameState) and has no state finding
// yet is also judged in full on its reduced reading, the statements that may
// name the state and the directory changes that place them, at most 128
// (hookpaths.StateNamingStatements): that is the call the hook client
// described for a gateway behind ProtectHome, whose proof of a patterned or
// quoted state name comes from the full pipeline (review R2-2). Only the
// reduced reading's state-write finding counts.
func withOverBudgetStateMutation(parent context.Context, request trustedActionRequest, facts actionfacts.Facts, findings []RuleFinding) []RuleFinding {
	generation := request.generation
	if generation == nil {
		generation = snapshotRulePackGenerationFor(parent, request.Connector)
	}
	twin, hasTwin := stateGlobTwinRequest(request)
	var twinFacts actionfacts.Facts
	if hasTwin {
		twinFacts = actionfacts.Analyze(twin.Input)
	}
	state := func(findings []RuleFinding) []RuleFinding {
		findings = withActiveStateTargetMention(request, facts, findings)
		if !hasTwin || slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == "tamper.detector_state_write" }) {
			return findings
		}
		for _, finding := range withActiveStateTargetMention(twin, twinFacts, nil) {
			if finding.RuleID == "tamper.detector_state_write" {
				findings = append(findings, finding)
			}
		}
		return findings
	}
	if generation == nil || len(generation.members) == 0 {
		findings = state(findings)
	} else {
		for i := range generation.members {
			found := state(nil)
			if i < len(generation.memberNames) {
				for j := range found {
					found[j].profile = generation.memberNames[i]
				}
			}
			findings = append(findings, found...)
		}
	}
	findings = withReducedStateReading(parent, request, facts, findings)
	return withStaticFunctionStateMutation(parent, request, findings)
}

func withStaticFunctionStateMutation(parent context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	// The normal reduction can decline a dynamic function body such as
	// run() { "$@"; }. Check bounded static function readings for a
	// proven state mutation. A budget finding alone
	// remains advisory in observe mode.
	if slices.ContainsFunc(findings, func(f RuleFinding) bool {
		return f.RuleID == "tamper.detector_state_write" && f.contributesToEnforcement()
	}) {
		return findings
	}
	if request.Input.DialectHint == actionfacts.DialectPOSIX || request.Input.DialectHint == "" {
		if command, known := trustedBashCommandInput(request.Input); known && len(command) <= 64<<10 &&
			(strings.Contains(command, ")") || strings.Contains(command, "function")) && hookpaths.MayNameState(command) {
			generation := request.generation
			if generation == nil {
				generation = snapshotRulePackGenerationFor(parent, request.Connector)
			}
			for _, reading := range hookpaths.StaticFunctionCallReadings(command, request.Input.ActiveHome) {
				twin := bashReadingRequest(request, command, reading)
				facts := actionfacts.Analyze(twin.Input)
				// A static shell command string is an exact executed reading.
				// Check its state role directly before taking the full rule
				// path, which would repeat the whole action evaluation.
				readings := []trustedActionRequest{twin}
				for _, commandFact := range facts.Commands {
					if !commandFact.ArgvComplete {
						continue
					}
					if index, ok := actionfacts.ShellCommandStringIndex(commandFact.Argv); ok {
						child := twin
						child.Input.Command = commandFact.Argv[index]
						child.LegacyText = child.Input.Command
						readings = append(readings, child)
					}
				}
				proved := false
				add := func(profile string) {
					// Prefer the exact child reading; one proven state finding
					// completes this rule for the current profile.
					for i := len(readings) - 1; i >= 0; i-- {
						candidate := readings[i]
						candidateFacts := facts
						if candidate.Input.Command != twin.Input.Command {
							candidateFacts = actionfacts.Analyze(candidate.Input)
						}
						var candidateFindings []RuleFinding
						if candidate.ProtectedHomeHook && staticFunctionLiteralStateMutation(candidateFacts) {
							candidateFindings = withProvenActiveStateMutation(candidate, nil)
						}
						if len(candidateFindings) == 0 {
							candidateFindings = withActiveStateTargetMention(candidate, candidateFacts, nil)
						}
						for _, finding := range candidateFindings {
							if finding.RuleID != "tamper.detector_state_write" {
								continue
							}
							finding.profile = profile
							findings = withTwinProvenBlocks(findings, []RuleFinding{finding})
							proved = proved || finding.contributesToEnforcement()
							if finding.contributesToEnforcement() {
								return
							}
						}
					}
				}
				if generation == nil || len(generation.members) == 0 {
					add("")
				} else {
					for i := range generation.members {
						profile := ""
						if i < len(generation.memberNames) {
							profile = generation.memberNames[i]
						}
						add(profile)
					}
				}
				if !proved {
					for _, finding := range dispatchTrustedAction(parent, twin) {
						if finding.RuleID == "tamper.detector_state_write" {
							findings = withTwinProvenBlocks(findings, []RuleFinding{finding})
						}
					}
				}
			}
		}
	}
	return findings
}

// A projected function reading may reach an exact active-state spelling
// whose shell redirect is complete even when the gateway cannot inspect
// the managed home. This proof accepts only that lexical spelling and an
// authoritative mutating command; other aliases keep the client map path.
func staticFunctionLiteralStateMutation(facts actionfacts.Facts) bool {
	projected := facts.EnforcementProjection()
	if projected.ActiveHome == "" || !projected.Authoritative() || !projected.EnforcementEligible() {
		return false
	}
	homeState := path.Join(path.Clean(projected.ActiveHome), ".defenseclaw") + "/"
	for _, candidate := range projected.Paths {
		if !strings.HasPrefix(candidate.Value, "~/.defenseclaw/") &&
			!strings.HasPrefix(candidate.Value, homeState) {
			continue
		}
		command, ok := integrityCommandByID(projected, candidate.CommandID)
		if ok && stateCommandMutatesPath(command, candidate) && matchesActiveDefenseClawState(projected, candidate) {
			return true
		}
	}
	return false
}

// withReducedStateReading adds the state-write finding of the reduced
// reading of an over-budget call (withOverBudgetStateMutation).
func withReducedStateReading(parent context.Context, request trustedActionRequest, facts actionfacts.Facts, findings []RuleFinding) []RuleFinding {
	if slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == "tamper.detector_state_write" }) {
		return findings
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !hookpaths.MayNameState(command) {
		return findings
	}
	// A PowerShell call is kept whole and held behind ProtectHome: the
	// POSIX read-only proof is not its reading (rel-1-0-6:GAP-0413).
	reduced, overflow, ok := hookpaths.StateNamingReading(command, request.Input.ActiveHome, trustedPowerShellReading(request.Input, facts))
	if !ok {
		return findings
	}
	if overflow && (request.ProtectedHomeHook || request.ManagedHookOverflowHold) {
		// More statements that may name the state and are not proven
		// read-only than the reduced reading keeps, so the hook client
		// sent no description (review r3 finding 3, r4 finding 2). Behind
		// ProtectHome the gateway cannot read the home to prove or rule
		// out a state write among them, so the call is held as one.
		return withProvenActiveStateMutation(request, findings)
	}
	if reduced == "" || reduced == command {
		return findings
	}
	for _, finding := range dispatchTrustedAction(parent, bashReadingRequest(request, command, reduced)) {
		if finding.RuleID == "tamper.detector_state_write" {
			findings = append(findings, finding)
		}
	}
	return findings
}

// trustedCallOverStatementBudget reports a shell call that the
// simple-command pass of dispatchTrustedActionWith judges over the
// statement budget, by the same test: actionfacts.SimpleCommands reports a
// "limit" failure (more than 128 statements in the POSIX, PowerShell or CMD
// split, or nesting past its bound), or the split could not flatten a valid
// call and the independent count exceeds the budget
// (trustedStatementBudgetExceeded). That pass adds ACTION-COMPOUND-LIMIT to
// such a call whatever else it finds. A PowerShell reading the Windows lexer
// stopped early is counted past the stop (rel-1-0-6:GAP-0331), so its call
// is over the budget even where the split it made is short.
func trustedCallOverStatementBudget(input actionfacts.Input, facts actionfacts.Facts) bool {
	return trustedCallOverStatementBudgetWith(input, facts, actionfacts.SimpleCommands(input, facts))
}

// trustedCallOverStatementBudgetWith is trustedCallOverStatementBudget over
// simples, the split of input and facts.
func trustedCallOverStatementBudgetWith(input actionfacts.Input, facts actionfacts.Facts, simples []actionfacts.SimpleCommand) bool {
	if slices.ContainsFunc(simples, func(simple actionfacts.SimpleCommand) bool {
		return simple.EvaluationFailure == "limit"
	}) {
		return true
	}
	command, known := trustedBashCommandInput(input)
	if !known {
		return false
	}
	if facts.Parse.Dialect == actionfacts.DialectPOSIX && facts.Parse.Status != actionfacts.StatusLimitExceeded &&
		!slices.ContainsFunc(simples, func(simple actionfacts.SimpleCommand) bool {
			return simple.EvaluationFailure == "parse" || simple.EvaluationFailure == actionfacts.EvaluationFailureSyntax ||
				simple.EvaluationFailure == actionfacts.EvaluationFailureUnresolvedBody ||
				simple.EvaluationFailure == actionfacts.EvaluationFailureUnknownStdinConsumer ||
				simple.EvaluationFailure == actionfacts.EvaluationFailureUnknownStdinConsumerStrict
		}) {
		// A complete POSIX split already enforced the limit. The extra
		// count is needed only when the analyzer reached its own bound or
		// the semantic splitter declined a dynamic wrapper.
		return false
	}
	// A failed POSIX flatten may return one "parse" item even though the
	// analyzer reached its command limit. The independent statement count
	// still governs the whole call, including a dynamic function wrapper.
	return trustedStatementBudgetExceeded(input, facts, command)
}

// withTrustedActionLimitFinding adds the over-limit verdict once.
func withTrustedActionLimitFinding(findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	for _, finding := range findings {
		if finding.RuleID == "ACTION-COMPOUND-LIMIT" {
			return findings
		}
	}
	return append(findings, trustedActionLimitFindings(enforcementCapable)...)
}

// credentialFileExternalUploadRuleID is the exact credential-file upload rule
// (semantic owner exfil.credential_file_external_upload).
const credentialFileExternalUploadRuleID = "exfil.credential_file_external_upload"

// withCredentialSenderFinding adds the unknown-tier verdict of a call that
// hands credential material to a sender whose destination is not read in
// full. It is the evaluation-limit finding the profile decides, with the
// reason of the call as its evidence and its own title.
func withCredentialSenderFinding(
	findings []RuleFinding,
	reason actionfacts.CredentialSenderReason,
	enforcementCapable bool,
) []RuleFinding {
	for _, finding := range findings {
		if finding.RuleID == "ACTION-COMPOUND-LIMIT" {
			return findings
		}
		if reason == actionfacts.CredentialSenderFile && finding.RuleID == credentialFileExternalUploadRuleID {
			// The exact credential-file upload rule already proved this
			// upload from the same file (curl -T, scp, rsync, wget, any
			// upload option, GAP-0768) and decides it in every tier, an
			// alert in default and permissive and a block in strict
			// (GAP-0595): a part of the call the exact rule does not need
			// (a stdout redirect to ~/out.txt or out-*.txt) does not make
			// the same file an unread destination.
			return findings
		}
	}
	added := trustedActionLimitFindings(enforcementCapable)
	for index := range added {
		added[index].Title = "Credential material reaches a sender whose destination is not read"
		added[index].Evidence = string(reason)
	}
	return append(findings, added...)
}

// withOmittedOperandLimitFinding adds the over-limit verdict for a named
// write operand that the client map left out, and marks it: that finding
// blocks in every profile, as the operand may be a link to a protected file.
// A limit finding the call already carries is left as it is.
func withOmittedOperandLimitFinding(findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	had := slices.ContainsFunc(findings, func(finding RuleFinding) bool {
		return finding.RuleID == "ACTION-COMPOUND-LIMIT"
	})
	findings = withTrustedActionLimitFinding(findings, enforcementCapable)
	if !had {
		for index := range findings {
			if findings[index].RuleID == "ACTION-COMPOUND-LIMIT" {
				findings[index].omittedOperand = true
			}
		}
	}
	return findings
}

// trustedActionLimitFindings is the over-limit verdict of a shell command
// past the policy reading bounds.
func trustedActionLimitFindings(enforcementCapable bool) []RuleFinding {
	const ruleID = "ACTION-COMPOUND-LIMIT"
	failure := RuleFinding{
		RuleID: ruleID, Title: "Shell command exceeds policy evaluation limit",
		Severity: "CRITICAL", Confidence: 1,
		enforcement: findingEnforcementAllowed,
	}.withTrustedActionProof(newEvaluationFailureFindingProof(ruleID))
	return applyTrustedActionProofBoundary([]RuleFinding{failure}, enforcementCapable)
}

// parseBudgetExceededReason is the evidence of the over-limit finding of a
// call past the reading budget (shellparse.BudgetExceeded): the call is
// opaque to the readers, not a finding about its text. The profile decides
// as for any evaluation limit (guardrailActionForProfile): an alert outside
// the strict profile (managed non-strict included, rel-1-0-6:GAP-0675), a
// block in strict (managed strict included).
const parseBudgetExceededReason = "parse_budget_exceeded"

// trustedActionBudgetFindings is trustedActionLimitFindings for a call past
// the reading budget, with the reason parse_budget_exceeded.
func trustedActionBudgetFindings(enforcementCapable bool) []RuleFinding {
	findings := trustedActionLimitFindings(enforcementCapable)
	for index := range findings {
		findings[index].Evidence = parseBudgetExceededReason
	}
	return findings
}

// withBudgetStateBlock keeps, for a call the readers did not read, the
// check that works on the raw text. A call whose text may name the active
// DefenseClaw state (hookpaths.MayNameState: quotes, escapes, case and
// patterns do not hide it, and over-matching only costs a block on a call
// that is itself past the budget) is judged as a proven mutation of it, the
// one finding observe mode also blocks on. Before the budget such a call
// was read in full, and a write to the state after any padding blocked in
// every mode (rel-1-0-2:GAP-0568); no padding can now turn that into an
// alert or an allow (GAP-0281). The text is the same the readers would
// have been given: the command, the argv and the top-level command
// argument.
func withBudgetStateBlock(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	input := request.Input
	text := input.Command + "\n" + strings.Join(input.Argv, "\n") + "\n" + string(input.Args)
	if command, present, valid := trustedTopLevelCommandField(input.Args); valid && present {
		text += "\n" + command
	}
	if !hookpaths.MayNameState(text) {
		return findings
	}
	return withProvenActiveStateMutation(request, findings)
}

// parseFailureRuleID is the finding of a call the reader failed on
// internally (a recovered panic in the per-command reading or in Analyze).
// Like the evaluation limit it carries no target: it alerts outside the
// strict tier and blocks in it (guardrailActionForProfile), so a reader
// error is never a silent allow and never a refusal without a rule id
// (gas-ux-r2:GAP-0082).
const parseFailureRuleID = "ACTION-PARSE-FAILURE"

// parseFailureTitle is the ship-authored title of parseFailureRuleID.
const parseFailureTitle = "DefenseClaw could not read this command (internal reader error), so it was not checked"

// trustedActionParseFailureFindings is the verdict of a call the reader
// failed on.
func trustedActionParseFailureFindings(enforcementCapable bool) []RuleFinding {
	failure := RuleFinding{
		RuleID: parseFailureRuleID, Title: parseFailureTitle,
		Severity: "CRITICAL", Confidence: 1,
		enforcement: findingEnforcementAllowed,
	}.withTrustedActionProof(newEvaluationFailureFindingProof(parseFailureRuleID))
	return applyTrustedActionProofBoundary([]RuleFinding{failure}, enforcementCapable)
}

// syntaxUnreadTitle is the reason of a command with a shell syntax error:
// the statements that parse were judged, the rest was not read.
const syntaxUnreadTitle = "Part of this command has a shell syntax error and could not be read, so that part was not checked"

// trustedActionSyntaxUnreadFindings is the record of a command read only in
// part because of a syntax error (actionfacts.EvaluationFailureSyntax):
// detection-only (unreadPartFindings), or an alert when alert is set
// (unreadPartMayWriteProtected). A block proven on a statement that was read
// stays a block (rel-1-0-10:GAP-0526).
func trustedActionSyntaxUnreadFindings(enforcementCapable, alert bool) []RuleFinding {
	findings := unreadPartFindings(syntaxUnreadTitle, enforcementCapable)
	if alert {
		findings = unreadPartAlert(findings, enforcementCapable)
	}
	return findings
}

// unreadPartMayWriteProtected is the parser-differential check of the
// strict pack and of a managed install: the shell parser here rejects text
// that a shell may still run, so the raw text of the syntax-error remainder
// that was not read (unread) is scanned with what already exists, the
// DefenseClaw state names (hookpaths.MayNameState) and the pack's tool-call
// pattern rules of the action categories (ruleActionCategory). A hit turns
// the record into an alert; it never blocks. Measured on the owner traces
// (s7-gate syn-rel vs syn-head3, agent-transcripts-sample strict): a
// blocking check would add 150 false blocks of 56,443 calls, over the 0.1%
// bar, so 1.0.10 ships it alert-only (lead decision 2026-11-14,
// rel-1-0-10:GAP-0526). Default and permissive outside managed keep the
// detection-only record.
func unreadPartMayWriteProtected(request trustedActionRequest, generation *compiledRulePackCategories, unread string) bool {
	if !request.StrictPolicy && !request.ManagedInstall || strings.TrimSpace(unread) == "" {
		return false
	}
	if hookpaths.MayNameState(unread) {
		return true
	}
	options := ruleScanOptions{includeToolCallOnly: true, contentScope: ruleContentScopeAll}
	for _, finding := range scanRuleGeneration(generation, unread, request.Input.Tool, options) {
		if trustedActionCatalogCategoryIsAction(generation, finding.RuleID) {
			return true
		}
	}
	return false
}

// syntaxUnreadText is command with the statements shellparse.ReadSyntaxTail
// read blanked: the part a shell may run that the readers did not. A text
// whose syntax error is in a nested body (no top-level reading) is unread
// whole.
func syntaxUnreadText(command string) string {
	tail, ok := shellparse.ReadSyntaxTail(command)
	if !ok {
		return command
	}
	unread, from := []byte(command), 0
	for _, statement := range tail.Statements {
		at := strings.Index(command[from:], statement)
		if at < 0 {
			continue
		}
		at += from
		for i := at; i < at+len(statement); i++ {
			if unread[i] != '\n' {
				unread[i] = ' '
			}
		}
		from = at + len(statement)
	}
	return string(unread)
}

// trustedActionCatalogCategoryIsAction reports a rule of the generation in a
// category about what a tool call does (ruleActionCategory).
func trustedActionCatalogCategoryIsAction(generation *compiledRulePackCategories, ruleID string) bool {
	if generation == nil {
		return false
	}
	for _, member := range append([]*compiledRulePackCategories{generation}, generation.members...) {
		for _, category := range member.categories {
			if !ruleActionCategory(category.Name) {
				continue
			}
			for _, rule := range category.Rules {
				if rule.ID == ruleID {
					return true
				}
			}
		}
	}
	return false
}

// unreadPartFindings is the audit record of the part of a command the
// readers could not read (a syntax error, an unresolved shell body):
// parseFailureRuleID, detection-only. What was read is judged in full and a
// block proven there stands. The unread part itself does not raise the
// verdict: on the owner traces (agent-transcripts-sample, aidev-sample,
// small; s7-gate syn-rel vs syn-head2) about 2% of benign calls hold a
// text Bash rejects or a dynamic -c body, and an enforcing unknown tier
// alerted 984 of them in default and blocked them in strict
// (rel-1-0-10:GAP-0526, GAP-0535). The record keeps the call from being a
// silent allow in the audit log.
func unreadPartFindings(title string, enforcementCapable bool) []RuleFinding {
	findings := trustedActionParseFailureFindings(enforcementCapable)
	for index := range findings {
		findings[index].Title = title
		// A record, not a finding about the call: it does not raise the
		// severity of an allowed answer (the alert variants raise it back).
		findings[index].Severity = "LOW"
		findings[index].enforcement = findingEnforcementDetectionOnly
	}
	return findings
}

// unreadPartAlert turns unread-part records into the unknown tier as an
// alert: CRITICAL, capped below confirm and block (findingEnforcementAlertOnly).
func unreadPartAlert(findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	if !enforcementCapable {
		return findings
	}
	for index := range findings {
		findings[index].Severity = "CRITICAL"
		findings[index].enforcement = findingEnforcementAlertOnly
	}
	return findings
}

// unresolvedBodyTitle is the reason of a command that starts a shell body
// whose text, or whose -c option word, is not known before it runs.
const unresolvedBodyTitle = "This command runs a shell body that could not be read before it runs, so the body was not checked"

// trustedActionUnresolvedBodyFindings is the finding of a command with a
// nested shell body the walk cannot resolve
// (actionfacts.EvaluationFailureUnresolvedBody): the unknown tier as an
// alert in every pack, never a block (lead decision 2026-11-14,
// rel-1-0-10:GAP-0535).
func trustedActionUnresolvedBodyFindings(enforcementCapable bool) []RuleFinding {
	return unreadPartAlert(unreadPartFindings(unresolvedBodyTitle, enforcementCapable), enforcementCapable)
}

// runtimeHomeTitle and runtimeHomeReason are the unknown-tier finding of a
// command that reads the home through a HOME set at run time
// (actionfacts.SimpleCommand.UnprovenHome, rel-1-0-10:GAP-0996).
const (
	runtimeHomeTitle  = "Shell command reads the home folder through a HOME set at run time, judged as unknown"
	runtimeHomeReason = "home_set_at_run_time"
)

// unknownStdinConsumerTitle and unknownStdinConsumerReason are the
// unknown-tier finding of a here-document whose body may write DefenseClaw
// state, fed to a program whose use of its standard input is not known
// (actionfacts.EvaluationFailureUnknownStdinConsumer, rel-1-0-10:GAP-1240).
const (
	unknownStdinConsumerTitle  = "Here-document that may change DefenseClaw state goes to a program whose use of its input is not known, judged as unknown"
	unknownStdinConsumerReason = "heredoc_consumer_unknown"
)

// unreadShellTextTitle and unreadShellTextReason are the unknown-tier finding
// of a shell that runs here-document or here-string text the reading cannot
// know (actionfacts.RunTimeShellTwin, rel-1-0-10:GAP-1147).
const (
	unreadShellTextTitle  = "Shell runs here-document text that could not be read before it runs, judged as unknown"
	unreadShellTextReason = "shell_input_not_read"
)

// shellReadingBound is the reading bound a command is past
// (trustedActionCommandBound).
type shellReadingBound uint8

const (
	shellReadingWithinBounds shellReadingBound = iota
	// shellReadingTooDeep: it nests past shellparse.MaxNestingDepth. Every
	// shell reader of the gateway, the hook proofs and actionfacts recurse
	// per nesting level; such a command overflowed the Windows gateway
	// stack (GAP-2537).
	shellReadingTooDeep
	// shellReadingNestedBodies: its nested shell bodies weigh more than
	// shellparse.MaxNestedBodyBytes; the readers took seconds to read them
	// (GAP-0677).
	shellReadingNestedBodies
	// shellReadingNestedProof: its nested shell bodies weigh more than
	// shellparse.MaxNestedBodyProofBytes; the readers read it but do not
	// prove its protected targets.
	shellReadingNestedProof
	// shellReadingBudget: it is past the reading budget of
	// shellparse.BudgetExceeded other than by nesting or brace expansion:
	// too many bytes, tokens, chain operators, nodes or levels of tree, or
	// a chain that does not parse (GAP-0254, GAP-0255: a chained or flat
	// command read for seconds and held gigabytes, or killed the process).
	shellReadingBudget
)

// trustedActionCommandBound reports the reading bound the command of the
// call (the command input, or the top-level command argument of any tool
// but apply_patch) is past, as shellparse.PastReadingBounds measures it.
func trustedActionCommandBound(input actionfacts.Input) shellReadingBound {
	// The command of an apply_patch call is a patch envelope: file text,
	// not shell. Its targets are read from the envelope, and every shell
	// reader parses through shellparse.Reader, so a patch of ordinary text
	// with many unclosed (, { or [ (ANSI colour escapes) is judged by its
	// targets, not by the shell bound (GAP-2561).
	if actionfacts.ApplyPatchTool(input.Tool) {
		return shellReadingWithinBounds
	}
	command := input.Command
	if command == "" && len(bytes.TrimSpace(input.Args)) > 0 {
		if field, present, valid := trustedTopLevelCommandField(input.Args); valid && present {
			command = field
		}
	}
	// One input budget for every reader, measured before any of them runs
	// (shellparse.BudgetExceeded): nesting and brace expansion keep their
	// own over-limit path; a text refused before any parse (bytes, tokens,
	// chain operators) and a chain that does not parse are the new class.
	// A tree past the node or depth bound may be nested shell bodies
	// (quoting doubles at every level, GAP-0677), which keep their own
	// verdict: the weight of the bodies is asked first.
	switch reason := shellparse.BudgetExceeded(command); reason {
	case "":
	case shellparse.BudgetNesting, shellparse.BudgetBraces:
		return shellReadingTooDeep
	case shellparse.BudgetNodes, shellparse.BudgetDepth:
		if shellparse.NestedBodyWeight(command) > shellparse.MaxNestedBodyBytes {
			return shellReadingNestedBodies
		}
		return shellReadingBudget
	default:
		return shellReadingBudget
	}
	switch weight := shellparse.NestedBodyWeight(command); {
	case weight > shellparse.MaxNestedBodyBytes:
		return shellReadingNestedBodies
	case weight > shellparse.MaxNestedBodyProofBytes:
		return shellReadingNestedProof
	}
	return shellReadingWithinBounds
}

// trustedCallShellParseReason is the recovered-parse reading of a call:
// "shell-parse-bound" (the proof bound, the evaluation-limit path),
// hookpaths.UnprovenParserFault (the parser failed on the text), or "". The
// hook client evidence tells it; a call without that evidence on a gateway
// that reads the home (per-user: no hook client sends it) is read here with
// the client reader, so both decide the same (rel-1-0-6:GAP-0534).
func trustedCallShellParseReason(request trustedActionRequest) string {
	if reason := request.ResolvedWriteTargets[hookpaths.UnprovenReasonKey]; reason != "" || request.ProtectedHomeHook {
		if reason == "shell-parse-bound" || reason == hookpaths.UnprovenParserFault {
			return reason
		}
		return ""
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok {
		return ""
	}
	return hookpaths.ShellParseReason(request.Connector, request.Input.Tool, command, request.Input.CWD, request.Input.ActiveHome)
}

// trustedCallReadsSyntaxTail reports a call with a plain syntax error, in
// its command or in a static eval or shell -c body of it, that the
// per-command pass reads in part (actionfacts.EvaluationFailureSyntax): that
// pass judges the statements that parse (rel-1-0-10:GAP-0526). It is asked
// only of a call at the recovered-parse proof bound.
func trustedCallReadsSyntaxTail(request trustedActionRequest) bool {
	if _, ok := trustedBashCommandInput(request.Input); !ok {
		return false
	}
	simples := actionfacts.SimpleCommands(request.Input, actionfacts.Analyze(request.Input))
	return slices.ContainsFunc(simples, func(simple actionfacts.SimpleCommand) bool {
		return simple.EvaluationFailure == actionfacts.EvaluationFailureSyntax
	}) && slices.ContainsFunc(simples, func(simple actionfacts.SimpleCommand) bool {
		return simple.EvaluationFailure == "" && simple.Text != ""
	})
}

func trustedBashCommandInput(input actionfacts.Input) (string, bool) {
	if !trustedBashExecutionTool(input.Tool) && !trustedPowerShellExecutionTool(input.Tool) {
		return "", false
	}
	command := input.Command
	if len(bytes.TrimSpace(input.Args)) != 0 {
		fromArgs, present, valid := trustedTopLevelCommandField(input.Args)
		if !valid || command != "" && present && command != fromArgs {
			return "", false
		}
		if command == "" && present {
			command = fromArgs
		}
	}
	if strings.TrimSpace(command) == "" || strings.IndexByte(command, 0) >= 0 {
		return "", false
	}
	return command, true
}

func trustedBashExecutionTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "bash", "zsh", "ksh", "shell", "shell_command", "terminal",
		// Amp runs background commands through async_shell_command.
		"async_shell_command",
		"run_command", "run_shell", "run_shell_command", "runshellcommand",
		"run_terminal_cmd", "execute", "execute_command", "exec",
		"exec_command", "command", "subprocess", "system.run":
		return true
	default:
		return false
	}
}

// trustedPowerShellExecutionTool names the PowerShell shell tools (Claude
// Code PowerShell, a Codex or Copilot call that names the executable). Their
// command is read by the same whole-command proofs as a Bash call, so the
// same text gets the same decision whichever shell tool carries it
// (GAP-1779, GAP-2389). The dialect hint still chooses the grammar.
// trustedPowerShellReading reports a call the gateway reads as PowerShell:
// a PowerShell tool, a PowerShell dialect hint or a PowerShell parse.
func trustedPowerShellReading(input actionfacts.Input, facts actionfacts.Facts) bool {
	return trustedPowerShellExecutionTool(input.Tool) || input.DialectHint == actionfacts.DialectPowerShell ||
		facts.Parse.Dialect == actionfacts.DialectPowerShell
}

func trustedPowerShellExecutionTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	default:
		return false
	}
}

func decodeTrustedTopLevelCommandField(raw json.RawMessage) (string, bool, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", false, false
	}
	seen := make(map[string]struct{})
	var command string
	found := false
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return "", false, false
		}
		lower := strings.ToLower(key)
		if _, duplicate := seen[lower]; duplicate {
			return "", false, false
		}
		seen[lower] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", false, false
		}
		if !trustedCommandFieldName(lower) {
			continue
		}
		if found || json.Unmarshal(value, &command) != nil {
			return "", false, false
		}
		found = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", false, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", false, false
	}
	return command, found, true
}

func trustedCommandFieldName(name string) bool {
	switch name {
	case "command", "cmd", "script", "rawcommand", "raw_command",
		"raw-command", "shellcommand", "shell_command", "shell-command",
		"commandline", "command_line", "command-line":
		return true
	default:
		return false
	}
}

func appendTrustedBashFallbackFindings(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
	options ruleScanOptions,
	enforcementCapable bool,
	downgradeReadOnlyDataArgs bool,
) ([]RuleFinding, trustedActionTelemetry) {
	var telemetry trustedActionTelemetry
	seen := make(map[string]int, len(findings))
	for index, finding := range findings {
		seen[finding.RuleID] = index
	}
	var typedProof map[string]struct{}
	loadTypedProof := func() map[string]struct{} {
		if typedProof == nil {
			typedProof = trustedTypedLegacyActionRuleMatches(
				generation,
				input,
				toolName,
				facts,
			)
		}
		return typedProof
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			matched := false
			shadowFindings := int64(0)
			for _, finding := range scanRuleGeneration(
				generation,
				nested.input.Command,
				toolName,
				options,
			) {
				matched = true
				shadowFindings++
				finding = markTrustedParserUncertainty(finding)
				if index, exists := seen[finding.RuleID]; exists {
					if _, proven := loadTypedProof()[finding.RuleID]; !proven {
						findings[index] = finding
					}
					continue
				}
				seen[finding.RuleID] = len(findings)
				findings = append(findings, finding)
			}
			telemetry.ParserUncertaintyCount++
			telemetry.ParserUncertaintyShadowFindingCount += shadowFindings
			if matched {
				telemetry.ParserUncertaintyCatalogMatchCount++
			}
			continue
		}
		if len(nested.facts.Commands) == 0 {
			continue
		}
		nestedFindings := scanRuleGeneration(
			generation,
			nested.input.Command,
			toolName,
			options,
		)
		nestedFindings = appendTrustedEmbeddedCommandFindings(
			nestedFindings,
			generation,
			toolName,
			nested.facts,
			options,
		)
		nestedFindings = filterTrustedLegacyActionContext(
			generation,
			nestedFindings,
			nested.input,
			toolName,
			nested.facts,
			downgradeReadOnlyDataArgs,
		)
		nestedFindings = filterExactFallbackFindings(
			nestedFindings,
			nested.input,
			nested.facts,
			enforcementCapable,
		)
		for _, finding := range nestedFindings {
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				// A bounded nested parser may prove its own command, but that
				// proof cannot upgrade an outer PARTIAL or INVALID shell
				// expression. Preserve the finding for shadow analysis while
				// replacing any nested authority with an explicit shadow proof.
				finding.enforcement = findingEnforcementDetectionOnly
				finding = finding.withTrustedActionProof(
					newParserShadowFindingProof(finding.RuleID),
				)
			}
			if _, exists := seen[finding.RuleID]; exists {
				continue
			}
			seen[finding.RuleID] = len(findings)
			findings = append(findings, finding)
		}
	}
	return findings, telemetry
}

func markTrustedParserUncertainty(finding RuleFinding) RuleFinding {
	finding.enforcement = findingEnforcementDetectionOnly
	finding.disposition = findingDispositionAudit
	finding.Severity = "LOW"
	if finding.Confidence > 0.25 {
		finding.Confidence = 0.25
	}
	if !hasTag(finding.Tags, trustedParserUncertaintyTag) {
		finding.Tags = append(finding.Tags, trustedParserUncertaintyTag)
	}
	return finding.withTrustedActionProof(newParserShadowFindingProof(finding.RuleID))
}

// Keep the former rule identifier as the stable metrics identity. It must not
// be materialized as RuleFinding: parser uncertainty is not a security alert.
const trustedParserUncertaintyRuleID = "ACTION-PARSER-UNCERTAINTY"

func trustedTypedLegacyActionRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	matches := make(map[string]struct{})
	merge := func(candidate actionfacts.Input, candidateFacts actionfacts.Facts) {
		for ruleID := range trustedLegacyCommandRuleMatches(
			generation,
			candidate,
			toolName,
			candidateFacts,
		) {
			matches[ruleID] = struct{}{}
		}
		paths, mutations := trustedLegacyPathRuleMatches(
			generation,
			candidate,
			toolName,
			candidateFacts,
		)
		for ruleID := range paths {
			matches[ruleID] = struct{}{}
		}
		for ruleID := range mutations {
			matches[ruleID] = struct{}{}
		}
		for ruleID := range trustedLegacyNetworkRuleMatches(
			generation,
			candidate,
			toolName,
			candidateFacts,
		) {
			matches[ruleID] = struct{}{}
		}
	}
	if facts.Authoritative() {
		merge(input, facts)
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if !nested.rawFallback {
			merge(nested.input, nested.facts)
		}
	}
	return matches
}

// trustedPipelineFallbackProof authorizes only compatibility rules whose
// literal match is bound to the same typed pipeline that proves the underlying
// action. It intentionally does not turn arbitrary pipeline text into command
// proof.
func trustedPipelineFallbackProof(
	ruleID string,
	pipelineID int64,
	facts actionfacts.Facts,
) bool {
	if ruleID != "exfil.secret_read_and_egress_oneliner" || pipelineID == 0 {
		return false
	}
	for _, source := range facts.Commands {
		if source.PipelineID != pipelineID ||
			!hasAnyOperation(
				source,
				actionfacts.OperationRead,
				actionfacts.OperationCredentialRead,
			) ||
			!hasReadPathFact(facts, source.ID) ||
			!hasDataFlowFrom(
				facts,
				source.ID,
				actionfacts.DataStdout,
				actionfacts.DataStdin,
			) {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.PipelineID == pipelineID &&
				hasOperation(destination, actionfacts.OperationUpload) &&
				hasExternalUpload(facts, destination.ID) &&
				hasDataFlowTo(
					facts,
					destination.ID,
					actionfacts.DataStdout,
					actionfacts.DataStdin,
				) &&
				hasDataFlowFrom(
					facts,
					destination.ID,
					"",
					actionfacts.DataNetwork,
				) {
				return true
			}
		}
	}
	return false
}

func hasReadPathFact(facts actionfacts.Facts, commandID int64) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID &&
			candidate.Access == actionfacts.PathAccessRead {
			return true
		}
	}
	return false
}

func trustedRuleHasActionProof(
	ruleID string,
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if contract, ok := exactFallbackContracts[ruleID]; ok &&
		contract.proves != nil && contract.proves(input, facts) {
		return true
	}
	owner, ok := semanticOwners[ruleID]
	return ok && owner.prerequisite != nil && owner.prerequisite(facts)
}

// trustedSemanticOwnerFindingProof binds a compatibility finding to the same
// code-owned semantic prerequisite used by the ActionFacts owner. A nested
// projection may supply the matching command, but it can authorize only when
// both the outer action and the nested projection are complete and eligible.
// This preserves useful nested-command coverage without allowing a PARTIAL or
// INVALID outer shell expression to become authoritative.
func trustedSemanticOwnerFindingProof(
	ruleID string,
	input actionfacts.Input,
	facts actionfacts.Facts,
) (findingProof, bool) {
	return trustedSemanticOwnerFindingProofFromActions(
		ruleID,
		facts,
		trustedNestedExecutionActions(input, facts),
	)
}

func trustedSemanticOwnerFindingProofFromActions(
	ruleID string,
	facts actionfacts.Facts,
	nestedActions []trustedNestedAction,
) (findingProof, bool) {
	if !facts.Authoritative() {
		return findingProof{}, false
	}
	enforcementFacts := facts.EnforcementProjection()
	if !enforcementFacts.EnforcementEligible() {
		return findingProof{}, false
	}
	owner, ok := trustedSemanticOwnerClaimingRule(ruleID)
	if !ok || owner.prerequisite == nil {
		return findingProof{}, false
	}
	matched := owner.prerequisite(enforcementFacts)
	if !matched {
		for _, nested := range nestedActions {
			if nested.rawFallback || !nested.facts.Authoritative() {
				continue
			}
			nestedEnforcementFacts := nested.facts.EnforcementProjection()
			if !nestedEnforcementFacts.EnforcementEligible() {
				continue
			}
			if owner.prerequisite(nestedEnforcementFacts) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return findingProof{}, false
	}
	return newActionFactsSemanticFindingProof(
		ruleID,
		actionFactsSemanticProofInput{
			FactsAuthoritative:  facts.Authoritative(),
			EnforcementEligible: enforcementFacts.EnforcementEligible(),
			ProjectionComplete:  true,
			EvaluationComplete:  true,
			Matched:             true,
		},
	), true
}

var trustedSemanticOwnerRuleIndex = buildTrustedSemanticOwnerRuleIndex(semanticOwners)

func buildTrustedSemanticOwnerRuleIndex(
	owners map[string]semanticOwner,
) map[string]semanticOwner {
	index := make(map[string]semanticOwner, len(owners))
	for ownerID, owner := range owners {
		owner.id = ownerID
		for _, ruleID := range owner.claimedIDs(true) {
			canonicalRuleID := canonicalTrustedRuleID(ruleID)
			if canonicalRuleID == "" {
				continue
			}
			if existing, duplicate := index[canonicalRuleID]; duplicate &&
				existing.id != ownerID {
				panic("duplicate trusted semantic owner claim for " + canonicalRuleID)
			}
			index[canonicalRuleID] = owner
		}
	}
	return index
}

func trustedSemanticOwnerClaimingRule(ruleID string) (semanticOwner, bool) {
	owner, ok := trustedSemanticOwnerRuleIndex[canonicalTrustedRuleID(ruleID)]
	return owner, ok
}

func trustedNetworkFindingProofFromActions(
	generation *compiledRulePackCategories,
	ruleID string,
	toolName string,
	facts actionfacts.Facts,
	nestedActions []trustedNestedAction,
) (findingProof, bool) {
	if !facts.Authoritative() {
		return findingProof{}, false
	}
	enforcementFacts := facts.EnforcementProjection()
	if !enforcementFacts.EnforcementEligible() {
		return findingProof{}, false
	}
	matched := trustedNetworkRuleMatchesExecutingFact(
		generation,
		ruleID,
		toolName,
		enforcementFacts,
	)
	if !matched {
		for _, nested := range nestedActions {
			if nested.rawFallback || !nested.facts.Authoritative() {
				continue
			}
			nestedEnforcementFacts := nested.facts.EnforcementProjection()
			if !nestedEnforcementFacts.EnforcementEligible() {
				continue
			}
			if trustedNetworkRuleMatchesExecutingFact(
				generation,
				ruleID,
				toolName,
				nestedEnforcementFacts,
			) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return findingProof{}, false
	}
	return newActionFactsSemanticFindingProof(
		ruleID,
		actionFactsSemanticProofInput{
			FactsAuthoritative:  facts.Authoritative(),
			EnforcementEligible: enforcementFacts.EnforcementEligible(),
			ProjectionComplete:  true,
			EvaluationComplete:  true,
			Matched:             true,
		},
	), true
}

func trustedNetworkRuleMatchesExecutingFact(
	generation *compiledRulePackCategories,
	ruleID string,
	toolName string,
	facts actionfacts.Facts,
) bool {
	commands := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		commands[command.ID] = command
	}
	for _, network := range facts.Network {
		command, ok := commands[network.CommandID]
		if !ok || command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete {
			continue
		}
		values := []string{network.Host, network.NormalizedHost}
		if network.Scheme != "" && network.Host != "" {
			values = append(values, network.Scheme+"://"+network.Host)
		}
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				continue
			}
			for _, match := range scanRuleGeneration(
				generation,
				value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			) {
				if canonicalTrustedRuleID(match.RuleID) ==
					canonicalTrustedRuleID(ruleID) &&
					(trustedLegacyRuleCategory(generation, match.RuleID) == "c2" ||
						strings.HasPrefix(match.RuleID, "C2-")) {
					return true
				}
			}
		}
	}
	return false
}

func collectTrustedLegacyCommandMatches(
	generation *compiledRulePackCategories,
	text string,
	toolName string,
	matchesByID map[string]struct{},
) {
	for _, match := range scanRuleGeneration(
		generation,
		text,
		toolName,
		ruleScanOptions{
			includeToolCallOnly: true,
			excludeTrustExploit: true,
		},
	) {
		if trustedLegacyRuleCategory(generation, match.RuleID) == "command" ||
			strings.HasPrefix(match.RuleID, "CMD-") {
			matchesByID[match.RuleID] = struct{}{}
		}
	}
}

func trustedCommandLiteralCarrier(command actionfacts.CommandFact) bool {
	program := strings.ToLower(strings.TrimSpace(command.Program))
	switch program {
	case "rg", "ripgrep", "find", "fd", "awk", "sed", "grep", "echo",
		"printf", "logger", "cat", "head", "tail":
		return true
	default:
		return false
	}
}

func trustedEmbeddedCommandTexts(command actionfacts.CommandFact) []string {
	if !strings.EqualFold(strings.TrimSpace(command.Program), "sed") {
		return nil
	}
	var embedded []string
	for _, argument := range trustedSedProgramTexts(command.Argv) {
		for _, statement := range trustedSedStatements(argument) {
			statement = stripSedAddresses(statement)
			switch {
			case strings.HasPrefix(statement, "e "):
				embedded = append(embedded, strings.TrimSpace(statement[1:]))
			case strings.HasPrefix(statement, "e\t"):
				embedded = append(embedded, strings.TrimSpace(statement[1:]))
			default:
				if replacement, ok := sedSubstitutionExecutionText(statement); ok {
					embedded = append(embedded, replacement)
				}
			}
		}
	}
	return embedded
}

func trustedSedProgramTexts(argv []string) []string {
	var (
		programs   []string
		hasProgram bool
	)
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch argument {
		case "-e", "--expression":
			if index+1 < len(argv) {
				programs = append(programs, argv[index+1])
				hasProgram = true
				index++
			}
		case "-f", "--file":
			if index+1 < len(argv) {
				hasProgram = true
				index++
			}
		case "--":
			if !hasProgram && index+1 < len(argv) {
				programs = append(programs, argv[index+1])
			}
			return programs
		default:
			switch {
			case strings.HasPrefix(argument, "--expression="):
				programs = append(
					programs,
					strings.TrimPrefix(argument, "--expression="),
				)
				hasProgram = true
			case strings.HasPrefix(argument, "--file="):
				hasProgram = true
			case strings.HasPrefix(argument, "-e") && len(argument) > 2:
				programs = append(programs, argument[2:])
				hasProgram = true
			case strings.HasPrefix(argument, "-"):
				continue
			case !hasProgram:
				programs = append(programs, argument)
				return programs
			default:
				return programs
			}
		}
	}
	return programs
}

func trustedSedStatements(program string) []string {
	var statements []string
	for offset := 0; offset < len(program); {
		for offset < len(program) &&
			(program[offset] == ';' || program[offset] == '\n' ||
				program[offset] == '\r' || program[offset] == ' ' ||
				program[offset] == '\t') {
			offset++
		}
		if offset >= len(program) {
			break
		}
		start := offset
		commandIndex := trustedSedCommandIndex(program, start)
		if commandIndex < 0 {
			break
		}
		end := commandIndex + 1
		switch program[commandIndex] {
		case 's', 'y':
			if commandIndex+1 >= len(program) {
				end = trustedSedLineEnd(program, end)
				break
			}
			delimiter := program[commandIndex+1]
			first := findUnescapedByte(program, delimiter, commandIndex+2)
			if first < 0 {
				end = trustedSedLineEnd(program, commandIndex+2)
				break
			}
			second := findUnescapedByte(program, delimiter, first+1)
			if second < 0 {
				end = trustedSedLineEnd(program, first+1)
				break
			}
			end = trustedSedSeparator(program, second+1)
		case 'e', 'a', 'i', 'c', '#':
			// These commands consume command/text material through the end of
			// the sed source line. A semicolon inside that material is not
			// evidence of a second sed command.
			end = trustedSedLineEnd(program, end)
		default:
			end = trustedSedSeparator(program, end)
		}
		if statement := strings.TrimSpace(program[start:end]); statement != "" {
			statements = append(statements, statement)
		}
		offset = end
		if offset < len(program) {
			offset++
		}
	}
	return statements
}

func trustedSedCommandIndex(program string, start int) int {
	index := start
	for address := 0; address < 2; address++ {
		for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
			index++
		}
		if index >= len(program) {
			return -1
		}
		switch {
		case program[index] == '/':
			end := findUnescapedByte(program, '/', index+1)
			if end < 0 {
				return -1
			}
			index = end + 1
		case program[index] == '$':
			index++
		case program[index] >= '0' && program[index] <= '9':
			for index < len(program) && program[index] >= '0' && program[index] <= '9' {
				index++
			}
		default:
			if program[index] == '!' {
				index++
				for index < len(program) &&
					(program[index] == ' ' || program[index] == '\t') {
					index++
				}
			}
			if index >= len(program) {
				return -1
			}
			return index
		}
		for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
			index++
		}
		if index >= len(program) || program[index] != ',' {
			break
		}
		index++
	}
	for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
		index++
	}
	if index < len(program) && program[index] == '!' {
		index++
		for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
			index++
		}
	}
	if index >= len(program) {
		return -1
	}
	return index
}

func trustedSedSeparator(program string, start int) int {
	for index := start; index < len(program); index++ {
		if program[index] == ';' || program[index] == '\n' || program[index] == '\r' {
			return index
		}
	}
	return len(program)
}

func trustedSedLineEnd(program string, start int) int {
	for index := start; index < len(program); index++ {
		if program[index] == '\n' || program[index] == '\r' {
			return index
		}
	}
	return len(program)
}

func restoreTrustedEmbeddedCommandFallbacks(
	excluded map[string]struct{},
	generation *compiledRulePackCategories,
	toolName string,
	facts actionfacts.Facts,
) {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute {
			continue
		}
		for _, embedded := range trustedEmbeddedCommandTexts(command) {
			matches := make(map[string]struct{})
			collectTrustedLegacyCommandMatches(
				generation,
				embedded,
				toolName,
				matches,
			)
			for ruleID := range matches {
				delete(excluded, ruleID)
			}
		}
	}
}

func appendTrustedEmbeddedCommandFindings(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	toolName string,
	facts actionfacts.Facts,
	options ruleScanOptions,
) []RuleFinding {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		seen[finding.RuleID] = struct{}{}
	}
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute {
			continue
		}
		for _, embedded := range trustedEmbeddedCommandTexts(command) {
			for _, finding := range scanRuleGeneration(
				generation,
				embedded,
				toolName,
				options,
			) {
				if trustedLegacyRuleCategory(generation, finding.RuleID) != "command" &&
					!strings.HasPrefix(finding.RuleID, "CMD-") {
					continue
				}
				if _, exists := seen[finding.RuleID]; exists {
					continue
				}
				seen[finding.RuleID] = struct{}{}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// appendTrustedWindowsPathFactFindings materializes Windows-only sensitive
// path rules from typed filesystem facts. Keeping this bridge fact-driven lets
// curl uploads and other exact readers reach the legacy rule catalog without
// treating a path-shaped header, cookie, URL, or documentation operand as a
// filesystem action.
func appendTrustedWindowsPathFactFindings(
	findings []RuleFinding,
	facts actionfacts.Facts,
	toolName string,
	options ruleScanOptions,
) []RuleFinding {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		seen[finding.RuleID] = struct{}{}
	}
	for _, candidate := range facts.Paths {
		// A path with an extended-length prefix has the device flavor, though
		// it names the same drive path.
		if candidate.Flavor != actionfacts.PathFlavorWindows {
			if _, opened, _ := windowsOpenedPathOfFact(candidate); !opened {
				continue
			}
		}
		switch candidate.Access {
		case actionfacts.PathAccessRead,
			actionfacts.PathAccessWrite,
			actionfacts.PathAccessAppend,
			actionfacts.PathAccessDelete:
		default:
			continue
		}
		values := pathFactSpellings(candidate)
		seenValues := make(map[string]struct{}, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				continue
			}
			if _, duplicate := seenValues[value]; duplicate {
				continue
			}
			seenValues[value] = struct{}{}
			for _, finding := range windowsSensitivePathFindingsWithOptions(
				value,
				toolName,
				true,
				options,
			) {
				if _, duplicate := seen[finding.RuleID]; duplicate {
					continue
				}
				seen[finding.RuleID] = struct{}{}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func awkInvocationExecutes(argv []string) bool {
	for _, argument := range trustedAwkProgramTexts(argv) {
		argument = trustedStripAwkComments(argument)
		lower := strings.ToLower(argument)
		for {
			index := strings.Index(lower, "system")
			if index < 0 {
				break
			}
			after := strings.TrimLeft(lower[index+len("system"):], " \t\r\n")
			if strings.HasPrefix(after, "(") {
				return true
			}
			lower = lower[index+len("system"):]
		}
		for index := 0; index < len(argument); index++ {
			if argument[index] != '|' {
				continue
			}
			previousPipe := index > 0 && argument[index-1] == '|'
			nextPipe := index+1 < len(argument) && argument[index+1] == '|'
			if !previousPipe && !nextPipe {
				// awk uses a single pipe for both command-to-getline and
				// print-to-command forms. Treat regex alternation conservatively
				// as executable rather than hiding a nested command.
				return true
			}
		}
	}
	return false
}

func trustedStripAwkComments(program string) string {
	var projected strings.Builder
	projected.Grow(len(program))
	var (
		quoted        bool
		regexLiteral  bool
		escaped       bool
		expectOperand = true
	)
	for index := 0; index < len(program); index++ {
		current := program[index]
		if regexLiteral {
			projected.WriteByte(' ')
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if current == '/' {
				regexLiteral = false
				expectOperand = false
			}
			continue
		}
		if escaped {
			projected.WriteByte(current)
			escaped = false
			continue
		}
		if current == '\\' {
			projected.WriteByte(current)
			escaped = true
			continue
		}
		if current == '"' {
			quoted = !quoted
			projected.WriteByte(current)
			if !quoted {
				expectOperand = false
			}
			continue
		}
		if current == '#' && !quoted {
			for index < len(program) && program[index] != '\n' {
				projected.WriteByte(' ')
				index++
			}
			if index < len(program) {
				projected.WriteByte('\n')
			}
			expectOperand = true
			continue
		}
		if !quoted && trustedAwkIdentifierStart(current) {
			end := index + 1
			for end < len(program) && trustedAwkIdentifierContinue(program[end]) {
				end++
			}
			token := program[index:end]
			projected.WriteString(token)
			switch strings.ToLower(token) {
			case "return", "print", "printf", "delete", "exit", "nextfile":
				expectOperand = true
			default:
				expectOperand = false
			}
			index = end - 1
			continue
		}
		if !quoted && current >= '0' && current <= '9' {
			projected.WriteByte(current)
			expectOperand = false
			continue
		}
		if !quoted && current == '/' {
			if expectOperand {
				regexLiteral = true
				projected.WriteByte(' ')
			} else {
				projected.WriteByte(current)
				expectOperand = true
			}
			continue
		}
		projected.WriteByte(current)
		if !quoted {
			switch current {
			case '\n', ';', '{', '(', '[', ',', '=', '~', '!', '?', ':',
				'&', '|', '+', '-', '*', '%', '^', '<', '>':
				expectOperand = true
			case ')', ']', '}':
				expectOperand = false
			}
		}
	}
	return projected.String()
}

func trustedAwkIdentifierStart(character byte) bool {
	return character == '_' || character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z'
}

func trustedAwkIdentifierContinue(character byte) bool {
	return trustedAwkIdentifierStart(character) ||
		character >= '0' && character <= '9'
}

func sedInvocationExecutes(argv []string) bool {
	for _, argument := range trustedSedProgramTexts(argv) {
		for _, statement := range trustedSedStatements(argument) {
			statement = stripSedAddresses(statement)
			if statement == "e" || strings.HasPrefix(statement, "e ") ||
				strings.HasPrefix(statement, "e\t") ||
				sedSubstitutionExecutes(statement) {
				return true
			}
		}
	}
	return false
}

func stripSedAddresses(statement string) string {
	statement = strings.TrimSpace(statement)
	for address := 0; address < 2; address++ {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			return statement
		}
		switch {
		case statement[0] == '/':
			end := findUnescapedByte(statement, '/', 1)
			if end < 0 {
				return statement
			}
			statement = statement[end+1:]
		case statement[0] == '$':
			statement = statement[1:]
		case statement[0] >= '0' && statement[0] <= '9':
			index := 0
			for index < len(statement) &&
				statement[index] >= '0' && statement[index] <= '9' {
				index++
			}
			statement = statement[index:]
		default:
			return strings.TrimSpace(statement)
		}
		statement = strings.TrimSpace(statement)
		if !strings.HasPrefix(statement, ",") {
			return statement
		}
		statement = statement[1:]
	}
	return strings.TrimSpace(statement)
}

func sedSubstitutionExecutes(statement string) bool {
	_, executes := sedSubstitutionExecutionText(statement)
	return executes
}

func sedSubstitutionExecutionText(statement string) (string, bool) {
	statement = strings.TrimSpace(statement)
	if len(statement) < 4 || statement[0] != 's' {
		return "", false
	}
	delimiter := statement[1]
	first := findUnescapedByte(statement, delimiter, 2)
	if first < 0 {
		return "", false
	}
	second := findUnescapedByte(statement, delimiter, first+1)
	if second < 0 {
		return "", false
	}
	flags := strings.Fields(statement[second+1:])
	if len(flags) == 0 || !strings.Contains(flags[0], "e") {
		return "", false
	}
	return strings.TrimSpace(statement[first+1 : second]), true
}

func findUnescapedByte(value string, target byte, start int) int {
	escaped := false
	for index := start; index < len(value); index++ {
		if escaped {
			escaped = false
			continue
		}
		if value[index] == '\\' {
			escaped = true
			continue
		}
		if value[index] == target {
			return index
		}
	}
	return -1
}

func trustedLegacyNetworkRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	matchesByID := make(map[string]struct{})
	commands := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		commands[command.ID] = command
	}
	for _, network := range facts.Network {
		values := []string{network.Host, network.NormalizedHost}
		if network.Scheme != "" && network.Host != "" {
			values = append(values, network.Scheme+"://"+network.Host)
		}
		if command, ok := commands[network.CommandID]; ok &&
			command.Effect == actionfacts.EffectExecute &&
			!trustedCommandLiteralCarrier(command) {
			values = append(values, serializeArgvForLegacyScan(command.Argv))
		}
		seenValues := make(map[string]struct{}, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				continue
			}
			if _, seen := seenValues[value]; seen {
				continue
			}
			seenValues[value] = struct{}{}
			for _, match := range scanRuleGeneration(
				generation,
				value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			) {
				if trustedLegacyRuleCategory(generation, match.RuleID) == "c2" ||
					strings.HasPrefix(match.RuleID, "C2-") {
					matchesByID[match.RuleID] = struct{}{}
				}
			}
		}
	}
	for ruleID, contract := range exactFallbackContracts {
		if strings.HasPrefix(ruleID, "C2-") &&
			contract.proves != nil && contract.proves(input, facts) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		for ruleID := range trustedLegacyNetworkRuleMatches(
			generation,
			nested.input,
			toolName,
			nested.facts,
		) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	return matchesByID
}

func trustedLegacyPathRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) (map[string]struct{}, map[string]struct{}) {
	pathMatches := make(map[string]struct{})
	mutationMatches := make(map[string]struct{})
	for _, path := range facts.Paths {
		mutation := path.Access == actionfacts.PathAccessWrite ||
			path.Access == actionfacts.PathAccessAppend ||
			path.Access == actionfacts.PathAccessDelete
		seenValues := make(map[string]struct{}, 4)
		for _, value := range append(
			pathFactSpellings(path),
			typedTargetRuleTexts(pathFactSpelling(path), input.ActiveHome, windowsVerbatimOperand(path.Value))...,
		) {
			if strings.TrimSpace(value) == "" {
				continue
			}
			if _, seen := seenValues[value]; seen {
				continue
			}
			seenValues[value] = struct{}{}
			for _, match := range windowsSensitivePathFindingsWithOptions(
				value,
				toolName,
				true,
				ruleScanOptions{includeToolCallOnly: true},
			) {
				pathMatches[match.RuleID] = struct{}{}
			}
			matches := scanRuleGeneration(
				generation,
				value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			)
			for _, match := range matches {
				if match.RuleID == "persistence.shell_profile_write" &&
					path.Flavor == actionfacts.PathFlavorWindows &&
					looksLikeSystemShellProfilePath(value) {
					// A leading slash in CMD is rooted on the current Windows
					// drive, not the POSIX system profile. Keep the legacy
					// regex fallback from discarding the typed path flavor.
					continue
				}
				category := trustedLegacyRuleCategory(generation, match.RuleID)
				if category == "sensitive-path" ||
					strings.HasPrefix(match.RuleID, "PATH-") {
					pathMatches[match.RuleID] = struct{}{}
				}
				if mutation && (category == "cognitive-file" ||
					strings.HasPrefix(match.RuleID, "COG-")) {
					mutationMatches[match.RuleID] = struct{}{}
				}
			}
		}
	}
	// Well-known PowerShell environment roots remain statically meaningful even
	// though ActionFacts conservatively marks the expanded path uncertain and
	// therefore emits no PathFact. Require both a typed, path-reading Windows
	// command and a matching structured ArgumentFact; arbitrary/search text can
	// never enter this compatibility exception.
	for _, command := range facts.Commands {
		if !windowsCommandCanReadSensitivePath(command.Program) ||
			(command.Effect != actionfacts.EffectExecute &&
				command.Effect != actionfacts.EffectUncertain) {
			continue
		}
		for _, argument := range trustedCommandOperandArguments(command) {
			for _, match := range windowsSensitivePathFindingsWithOptions(
				argument.Value,
				toolName,
				true,
				ruleScanOptions{includeToolCallOnly: true},
			) {
				pathMatches[match.RuleID] = struct{}{}
			}
		}
	}
	// Tilde and similar shell-expanded operands can be deliberately omitted from
	// PathFacts while remaining a statically captured argument to a concrete
	// file-reading command. Preserve those narrow fallback paths without letting
	// echo/search arguments claim a read action.
	for _, command := range facts.Commands {
		if !trustedPathReadingCommand(command.Program) ||
			(command.Effect != actionfacts.EffectExecute &&
				command.Effect != actionfacts.EffectUncertain) {
			continue
		}
		for _, argument := range trustedCommandOperandArguments(command) {
			for _, match := range scanRuleGeneration(
				generation,
				argument.Value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			) {
				if trustedLegacyRuleCategory(generation, match.RuleID) == "sensitive-path" {
					pathMatches[match.RuleID] = struct{}{}
				}
			}
		}
	}
	for ruleID := range trustedUnresolvedReadRuleMatches(
		generation,
		input,
		toolName,
		facts,
	) {
		pathMatches[ruleID] = struct{}{}
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		nestedPaths, nestedMutations := trustedLegacyPathRuleMatches(
			generation,
			nested.input,
			toolName,
			nested.facts,
		)
		for ruleID := range nestedPaths {
			pathMatches[ruleID] = struct{}{}
		}
		for ruleID := range nestedMutations {
			mutationMatches[ruleID] = struct{}{}
		}
	}
	return pathMatches, mutationMatches
}

// restoreTrustedUnresolvedReadFallbacks keeps the legacy detector eligible for
// a concrete read of a shell-home path that ActionFacts deliberately cannot
// resolve. The exception is limited to typed file readers and a leading home
// expansion, so echo/search/patch literals cannot reopen the fallback lane.
func restoreTrustedUnresolvedReadFallbacks(
	excluded map[string]struct{},
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) {
	for ruleID := range trustedUnresolvedReadRuleMatches(
		generation,
		input,
		toolName,
		facts,
	) {
		delete(excluded, ruleID)
	}
}

func trustedUnresolvedReadRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	matchesByID := make(map[string]struct{})
	literalTildeOperands := make(map[string]struct{})
	if facts.Authoritative() {
		for _, candidate := range facts.Paths {
			if strings.HasPrefix(candidate.Value, "~/") &&
				strings.Contains(candidate.Resolved, "/~/") &&
				!matchesActiveSensitivePath(facts, candidate) {
				literalTildeOperands[candidate.Value] = struct{}{}
			}
		}
	}
	collect := func(value string) {
		if _, literal := literalTildeOperands[value]; literal {
			return
		}
		if !trustedUnresolvedHomePath(value) {
			return
		}
		for _, match := range scanRuleGeneration(
			generation,
			value,
			toolName,
			ruleScanOptions{
				includeToolCallOnly: true,
				excludeTrustExploit: true,
			},
		) {
			if trustedLegacyRuleCategory(generation, match.RuleID) == "sensitive-path" {
				matchesByID[match.RuleID] = struct{}{}
			}
		}
	}
	// Structured file readers carry their operand as a typed PathFact rather
	// than as command argv.  Preserve the narrowly scoped unresolved-home
	// fallback for those authoritative reads as well; arbitrary tools cannot
	// enter this branch and non-read path facts are ignored.
	if facts.Authoritative() && trustedPathReadingCommand(toolName) {
		for _, candidate := range facts.Paths {
			if candidate.Access == actionfacts.PathAccessRead {
				collect(candidate.Value)
			}
		}
	}
	for _, command := range facts.Commands {
		if !trustedPathReadingCommand(command.Program) ||
			(command.Effect != actionfacts.EffectExecute &&
				command.Effect != actionfacts.EffectUncertain) {
			continue
		}
		for _, argument := range trustedCommandOperandArguments(command) {
			collect(argument.Value)
		}
		if command.ArgvComplete || !commandHasUnresolvedExpansion(command) {
			continue
		}
		for _, field := range strings.Fields(input.Command) {
			collect(strings.Trim(field, `"'`))
		}
	}
	return matchesByID
}

func commandHasUnresolvedExpansion(command actionfacts.CommandFact) bool {
	for _, argument := range trustedCommandOperandArguments(command) {
		if argument.Expands && strings.TrimSpace(argument.Value) == "" {
			return true
		}
	}
	return false
}

func trustedCommandOperandArguments(command actionfacts.CommandFact) []actionfacts.ArgumentFact {
	if len(command.Arguments) <= 1 {
		return nil
	}
	return command.Arguments[1:]
}

func trustedUnresolvedHomePath(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	return strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, "$home/") ||
		strings.HasPrefix(value, "${home}/")
}

func trustedPathReadingCommand(program string) bool {
	switch strings.ToLower(strings.TrimSpace(program)) {
	case "cat", "type", "get-content", "gc", "more",
		"read", "readfile", "read_file", "read-file",
		"fsread", "fs_read", "fs-read", "fs.read", "fs.read_file",
		"fileread", "file_read", "file-read",
		"catfile", "cat_file", "cat-file",
		"openfile", "open_file", "open-file",
		"viewfile", "view_file", "view-file",
		"getfile", "get_file", "get-file":
		return true
	default:
		return false
	}
}

func enforceableRuleFindings(findings []RuleFinding) []RuleFinding {
	enforceable := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.contributesToEnforcement() {
			enforceable = append(enforceable, finding)
		}
	}
	return enforceable
}

func alertOnlyRuleFindings(findings []RuleFinding) []RuleFinding {
	alerts := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.contributesToAlertOnly() {
			alerts = append(alerts, finding)
		}
	}
	return alerts
}

// trustedActiveHome is the home directory action analysis resolves "~" and
// $HOME against for this request. A standalone gateway runs as a service
// account on behalf of many users, so it is the verified caller's home:
// the kernel-verified hook-socket peer's, or on the TCP API the home of the
// account a per-user credential is bound to. It is never the service
// account's own home. When the caller's home cannot be resolved it is
// unresolvedCallerHome, so home-relative and suffix rules (~/.aws/
// credentials, ~/.kube/config) still match. Everywhere else the gateway
// runs as the user and its own home is the caller's.
func trustedActiveHome(ctx context.Context) string {
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		if peer.Home != "" {
			return peer.Home
		}
		return unresolvedCallerHome
	}
	if serviceAccountGatewayFromContext(ctx) {
		if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
			if home := userScopedIdentityHome(identity); home != "" {
				return home
			}
		}
		return unresolvedCallerHome
	}
	return trustedSameHostHome()
}

// trustedActiveLogins names the login of the account whose home is
// activeHome, from the same trusted identity trustedActiveHome reads (the
// kernel-verified managed hook peer, the per-user credential's account, or
// the account this gateway runs as), so a ~<login> tilde-prefix is read
// as that home even when the login is not the home's base name or holds
// '@' (AD user@domain, GAP-2378). A Windows DOMAIN\user name gives user.
// nil when the request's home is not that account's home.
func trustedActiveLogins(ctx context.Context, activeHome string) []string {
	if ctx == nil || activeHome == "" || isSandboxHookRequest(ctx) {
		return nil
	}
	if filepath.Clean(trustedActiveHome(ctx)) != filepath.Clean(activeHome) {
		return nil
	}
	var name string
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		name = peer.Name
	} else if serviceAccountGatewayFromContext(ctx) {
		if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
			name = userScopedIdentityName(identity)
		}
	} else {
		name = trustedSameHostLogin()
	}
	if index := strings.LastIndexByte(name, '\\'); index >= 0 {
		name = name[index+1:]
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil
	}
	return []string{name}
}

// trustedSameHostLogin is the login name of the account this gateway runs
// as, looked up once.
var trustedSameHostLogin = sync.OnceValue(func() string {
	account, err := osuser.Current()
	if err != nil {
		return ""
	}
	return account.Username
})

// unresolvedCallerHome stands in for a standalone caller whose home cannot
// be resolved (a directory lookup that failed, a home of "/", or an
// unclean home path, or a TCP request with no per-user credential). It is
// absolute and does not exist, so "~" paths resolve to a path no real file
// has while keeping the ".aws/credentials"-style suffix the rules match on.
const unresolvedCallerHome = "/nonexistent-home"

type serviceAccountGatewayContextKey struct{}

// withServiceAccountGateway marks requests served by a standalone gateway,
// which runs as a service account on behalf of many users.
func withServiceAccountGateway(ctx context.Context) context.Context {
	return context.WithValue(ctx, serviceAccountGatewayContextKey{}, true)
}

func serviceAccountGatewayFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(serviceAccountGatewayContextKey{}).(bool)
	return marked
}

// sameHostHomeForTest, when set, is the same-host home trustedSameHostHome
// reports. Only tests set it: a Windows home such as C:\Users\alice is not an
// absolute path on Linux, so the own-credential rules of a Windows hook call
// could not be tested off Windows.
var sameHostHomeForTest string

func trustedSameHostHome() string {
	if sameHostHomeForTest != "" {
		return sameHostHomeForTest
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(home)
}

// clientGlobFacts is the evidence map whose pathname-pattern answers
// (hookpaths.GlobFactPrefix) the action target scan may use. Only a
// kernel-verified managed hook client expands the user's patterns for a
// gateway that ProtectHome keeps out of the home.
func clientGlobFacts(request trustedActionRequest) map[string]string {
	if !request.ProtectedHomeHook {
		return nil
	}
	return request.ResolvedWriteTargets
}

// trustedSimpleCommandEvidenceCWDs places each simple command of a managed
// hook call whose cwd the gateway cannot see (ProtectHome) in the directory
// the hook client keyed its evidence in: the client's cwd, followed through
// the command's static cd, so a child after cd is not judged in the
// starting directory. It is nil when the gateway knows the cwd, the client
// sent none, or the placed commands differ; an unplaced child stays "".
func trustedSimpleCommandEvidenceCWDs(request trustedActionRequest, simples []actionfacts.SimpleCommand) []string {
	clientCWD := request.ResolvedWriteTargets[hookpaths.CWDKey]
	if !request.ProtectedHomeHook || filepath.IsAbs(request.Input.CWD) || !filepath.IsAbs(clientCWD) {
		return nil
	}
	placed := request.Input
	placed.CWD = filepath.Clean(clientCWD)
	// The unplaced split can add evaluation failures (a relative operand in
	// an unknown directory); match the commands in order and skip those.
	var placedCommands []actionfacts.SimpleCommand
	for _, simple := range actionfacts.SimpleCommands(placed, actionfacts.Analyze(placed)) {
		// The readings of a statement in the other folders it may run in
		// pair with no statement of the unplaced split.
		if simple.EvaluationFailure == "" && !simple.OtherFolder {
			placedCommands = append(placedCommands, simple)
		}
	}
	cwds := make([]string, len(simples))
	next := 0
	for index, simple := range simples {
		if simple.EvaluationFailure != "" {
			continue
		}
		if next >= len(placedCommands) || placedCommands[next].Text != simple.Text {
			return nil
		}
		if filepath.IsAbs(placedCommands[next].CWD) {
			cwds[index] = filepath.Clean(placedCommands[next].CWD)
		}
		next++
	}
	if next != len(placedCommands) {
		return nil
	}
	return cwds
}

// cmdReadingTwinRequest is the CMD reading of a Windows shell call the hook
// placed in PowerShell when its text holds a %NAME% expansion cmd makes
// (actionfacts.ContainsCMDVariable) and its tool does not name PowerShell.
// PowerShell reads copy %USERPROFILE%\.git-credentials C:\t as a copy of the
// relative file %USERPROFILE%\.git-credentials, cmd as a copy of the home
// credential file, and the shell an exec tool runs is not proven: the CMD
// spelling of a home credential copy was allowed in strict while the same
// path written out blocked (rel-1-0-10:GAP-0999). It is a reading twin: it
// records nothing and makes no further readings. trustedToolCallFindings
// judges it with every reading of the call, as the call with the variable
// written out is judged, and only adds its findings, so a copy of an ordinary
// home file stays as it was and the call is never weaker than either reading.
func cmdReadingTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	if request.readingTwin || request.simpleCommandPass || !request.windowsDialectReadings ||
		request.Input.DialectHint != actionfacts.DialectPowerShell {
		return trustedActionRequest{}, false
	}
	if tool := strings.ToLower(request.Input.Tool); strings.Contains(tool, "powershell") || strings.Contains(tool, "pwsh") {
		return trustedActionRequest{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !actionfacts.ContainsCMDVariable(command) {
		return trustedActionRequest{}, false
	}
	twin := windowsReadingTwin(request)
	twin.Input.DialectHint = actionfacts.DialectCMD
	twin.windowsPowerShellReading, twin.posixReadingTwin = nil, false
	return twin, true
}

// posixReadingTwinRequest is the POSIX reading of a call the Windows hook
// placed in a Windows dialect when the tool does not name its shell
// (posixReadingTwin): the reading the call had before the dialect, as the
// proxy judges both readings (proxyPOSIXReading). It is a reading twin: it
// records nothing, makes no further readings, and only its proven findings
// are kept (withTwinProvenBlocks), so the call is never weaker than either
// reading.
func posixReadingTwinRequest(request trustedActionRequest) (trustedActionRequest, bool) {
	if !request.posixReadingTwin || request.readingTwin || !request.windowsShellDialect ||
		request.Input.DialectHint == actionfacts.DialectPOSIX {
		return trustedActionRequest{}, false
	}
	twin := windowsReadingTwin(request)
	twin.Input.DialectHint = ""
	twin.windowsShellDialect, twin.windowsPowerShellReading, twin.posixReadingTwin = false, nil, false
	return twin, true
}
