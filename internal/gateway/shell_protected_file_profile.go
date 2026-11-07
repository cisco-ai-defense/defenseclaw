// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellProtectedFileRules is the class of rules that decide whether a shell
// command writes, appends, copies, moves, renames, links, extracts or
// otherwise materializes content into one of the protected files of the user:
// the SSH authorized-keys and control files (hookpaths), shell startup
// profiles and active Git hooks. Owner decision 2026-11-06
// (rel-1-0-6:GAP-0675, detections round #1189): in the default (balanced)
// and permissive profiles, per-user and managed, such a finding on a shell
// command is a visible alert and never blocks; the strict profile, managed
// strict included, blocks it as before.
//
// DefenseClaw self-protection is not in this class and keeps blocking in
// every profile: its state, configuration, plugins and bridges
// (tamper.detector_state_write and the active-state owners), turning its
// hooks off or changing the hook settings of an agent, rule-pack tamper, agent
// instruction files (COG-*), native write and edit tools, MCP and skill
// admission and the fail modes.
var shellProtectedFileRules = map[string]bool{
	"PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND": true,
	"PATH-SSH-DIR":                    true,
	"PERSISTENCE.SHELL_PROFILE_WRITE": true,
	"PERSISTENCE.GIT_HOOK_WRITE":      true,
}

// shellFileMark says how sure the readers are of a finding of the class.
type shellFileMark uint8

const (
	// shellFileNone: not a finding of the class, or not on a shell command.
	shellFileNone shellFileMark = iota
	// shellFileUnproven: a reader suspects a protected target; nothing the
	// command names proves it. The balanced and permissive profiles warn.
	shellFileUnproven
	// shellFileProven: the call writes a protected file at a target it
	// names (shellWritesProvenProtectedFile). It keeps the block.
	shellFileProven
)

// shellProtectedFileRule reports a rule of the shell-command protected-file
// class.
func shellProtectedFileRule(ruleID string) bool {
	return shellProtectedFileRules[canonicalTrustedRuleID(ruleID)]
}

// trustedShellCommandInput reports an action that runs a shell command now:
// the command text or argv of a shell or execution tool. A native write or
// edit tool, an apply_patch envelope and a stored command payload are not
// shell commands here; they keep their enforcement in every profile. An
// envelope a shell call runs or feeds is judged by its directive targets
// (shellWritesProvenProtectedFile), not by the words of the call.
func trustedShellCommandInput(input actionfacts.Input) bool {
	if actionfacts.ApplyPatchTool(input.Tool) {
		return false
	}
	return input.Command != "" || len(input.Argv) > 0 ||
		actionfacts.IsImmediateShellExecutionTool(input.Tool)
}

// markShellProtectedFileFindings records, on the findings of one trusted
// action, which belong to the shell-command protected-file class. It only
// labels them; the profile decides what they do (profileClassFindings).
// The label is set afresh at every level of a nested dispatch (a statement,
// a child or a twin of the call): the outermost call, which runs last, has
// the whole command and decides.
//
// The class is the findings the readers could not prove. A call that
// writes a protected file the structure of the command names, or one it
// reaches through a link on disk, a value the command assigns, or an
// apply_patch envelope directive, is not in the class: it keeps its block in
// every profile (owner steer, Wave-3 rule: a protected file or link named
// directly or through a known value stays blocked). A call that may reach the
// DefenseClaw state is self-protection, not the class either: the
// protected-write owners also report a write that reaches the state through
// a link, and such a finding keeps its block in every profile
// (rel-1-0-6:GAP-0675 review 1 M3a). Both checks run only when a finding of
// the class is present, and each answer over-matches: a false answer only
// keeps the block the call had before GAP-0675. A native write or edit tool is
// not in the class either.
func markShellProtectedFileFindings(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return shellProtectedFileRule(f.RuleID) }) {
		for index := range findings {
			findings[index].shellFile = shellFileNone
		}
		return findings
	}
	// A level below (a twin, a child, a statement) may have proven the write
	// where the whole call is written in a way its own facts cannot read (a
	// value assigned earlier, a shell -c body): the proof stays.
	mark := shellFileNone
	if trustedShellCommandInput(request.Input) {
		switch {
		case slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.shellFile == shellFileProven }) ||
			shellWritesProvenProtectedFile(request):
			mark = shellFileProven
		case !shellCommandMayReachState(request):
			mark = shellFileUnproven
		}
	}
	for index := range findings {
		findings[index].shellFile = shellFileNone
		if shellProtectedFileRule(findings[index].RuleID) {
			findings[index].shellFile = mark
		}
	}
	return findings
}

// shellWritesProvenProtectedFile reports a shell call that mutates a
// protected file of the user (an authorized-keys or SSH control file, an SSH
// private key, a shell startup profile or an active Git hook) at a target the
// call proves, whatever the profile: a mutated path of the command structure
// (a literal or a value the command assigns), that path after the links on
// disk are followed, a target the hook client resolved, or a directive target
// of an apply_patch envelope the call runs or feeds. The finding producer adds
// its own proof (a write through an existing link, or a copy of one). A word
// the readers cannot place, a pattern, text in a comment or data, and a value
// that was overwritten prove nothing here; such a finding stays in the class.
func shellWritesProvenProtectedFile(request trustedActionRequest) bool {
	input := request.Input
	facts := actionfacts.Analyze(input)
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		if !ok || !integrityCommandMutatesPath(command, path) {
			continue
		}
		if protectedFilePath(facts, path) {
			return true
		}
		if resolved, ok := request.targetMemo.ResolveWriteTarget(placedPath(path, facts.CWD)); ok {
			path.Resolved = resolved
			if protectedFilePath(facts, path) {
				return true
			}
		}
	}
	// A mutated operand, or the target a link of the command points at, that
	// is itself a protected name (a link of the command to the SSH folder, a
	// write below it after a copy, a startup profile). Only operands count,
	// never a comment, a quoted data word or a value the command overwrites.
	// A copy, move or link names its source operand as well: moving a file of
	// that name into a place the command cannot read is the write.
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		if !ok || !protectedOperandName(path.Value, false) && !protectedOperandName(path.Normalized, false) &&
			!protectedOperandName(path.Resolved, false) {
			continue
		}
		if integrityCommandMutatesPath(command, path) || fileMovingProgram(command.Program) {
			return true
		}
	}
	for _, command := range facts.Commands {
		for index, word := range command.Argv {
			if programBaseName(word) != "ln" {
				continue
			}
			for _, operand := range command.Argv[index+1 : len(command.Argv)-1] {
				if !strings.HasPrefix(operand, "-") && protectedOperandName(operand, true) {
					return true
				}
			}
			break
		}
	}
	// A copy or move source that is, or holds, a link on disk that reaches a
	// protected file: the copy carries the link, and a write through its new
	// name is the write (the managed hook client reads the source links for a
	// gateway that cannot see the home).
	sourceCWD := facts.CWD
	if !filepath.IsAbs(sourceCWD) {
		sourceCWD = request.ResolvedWriteTargets[hookpaths.CWDKey]
	}
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		if !ok || path.Access != actionfacts.PathAccessRead || !fileMovingProgram(command.Program) {
			continue
		}
		for _, target := range hookpaths.CopySourceLinkTargets(placedPath(path, sourceCWD), request.ResolvedWriteTargets) {
			form := target
			if resolved, ok := request.targetMemo.ResolveWriteTarget(target); ok {
				form = resolved
			}
			if protectedFilePath(facts, actionfacts.PathFact{Resolved: form, Absolute: true}) ||
				protectedFilePath(facts, actionfacts.PathFact{Resolved: target, Absolute: true}) {
				return true
			}
		}
	}
	// A name the command copies from a link on disk that reaches a protected
	// file (the copy carries the link): a write through its new name is the
	// write. The links are read as the managed hook client read them for a
	// gateway that cannot see the home, else from the disk.
	if command, ok := trustedBashCommandInput(input); ok {
		cwd := facts.CWD
		if !filepath.IsAbs(cwd) {
			cwd = request.ResolvedWriteTargets[hookpaths.CWDKey]
		}
		links := hookpaths.CommandLinksWithFacts(input.Tool, command, cwd, input.ActiveHome, request.ResolvedWriteTargets)
		operands, _, _ := hookpaths.ShellWriteOperands(command, cwd, input.ActiveHome)
		placed, _ := hookpaths.ShellDirectoryWriteOperands(command, cwd, input.ActiveHome, request.ResolvedWriteTargets, false, request.ProtectedHomeHook)
		for _, operand := range placed {
			operands = append(operands, operand.Path)
		}
		for _, operand := range operands {
			for _, target := range links.CopiedLinkTargets(hookpaths.OperandPath(operand, cwd), request.ResolvedWriteTargets) {
				if protectedFilePath(facts, actionfacts.PathFact{Resolved: target, Absolute: true}) {
					return true
				}
			}
		}
	}
	// The managed hook client resolved the call to a protected target.
	if request.ProtectedHomeHook && request.ResolvedWriteTargets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision {
		return true
	}
	// The path readers of hookpaths place every target of the command in the
	// user home (links, cd, brace lists, archives and copies included); the
	// decision is theirs, not a side reader of the gateway.
	if command, ok := trustedBashCommandInput(input); ok &&
		request.targetMemo.ActionCommandDecisionWithDialectAndGlobFacts(command, input.CWD, input.ActiveHome, input.DialectHint, clientGlobFacts(request)) == hookpaths.ProtectedTargetDecision {
		return true
	}
	for _, target := range request.ResolvedWriteTargets {
		if protectedFilePath(facts, actionfacts.PathFact{Resolved: target, Absolute: true}) {
			return true
		}
	}
	targets, _ := hookpaths.ApplyPatchLexicalCommandTargets(input.Tool, input.Args, input.Command, facts.CWD, facts.ActiveHome)
	for _, target := range targets {
		for _, form := range []string{target, request.ResolvedWriteTargets[hookpaths.OperandPath(target, facts.CWD)]} {
			if form != "" && protectedFilePath(facts, actionfacts.PathFact{Resolved: form, Absolute: true}) {
				return true
			}
		}
		if resolved, ok := request.targetMemo.ResolveWriteTarget(hookpaths.OperandPath(target, facts.CWD)); ok &&
			protectedFilePath(facts, actionfacts.PathFact{Resolved: resolved, Absolute: true}) {
			return true
		}
	}
	return false
}

// fileMovingProgram reports a program that copies, moves or links a source
// operand to a destination.
func fileMovingProgram(program string) bool {
	return slices.Contains([]string{"cp", "mv", "ln", "install", "rsync", "ditto"}, programBaseName(program))
}

func programBaseName(word string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(word, "\\", "/")))
}

// protectedOperandName reports an operand that names a protected file by its
// last components: an authorized-keys file, the SSH folder, an SSH control
// file or private key below it, a shell startup profile, the Git hooks
// folder, and, with state, the DefenseClaw state folder (the target of a
// link). It reads the operand only: a comment or a data word of the call is
// never passed here.
func protectedOperandName(operand string, state bool) bool {
	operand = strings.ToLower(strings.NewReplacer("\\", "/", "\x27", "", "\"", "").Replace(operand))
	parts := strings.FieldsFunc(operand, func(r rune) bool { return r == rune(0x2f) })
	if len(parts) == 0 {
		return false
	}
	base := parts[len(parts)-1]
	parent := ""
	if len(parts) > 1 {
		parent = parts[len(parts)-2]
	}
	switch {
	case strings.HasPrefix(base, "authorized_keys"), strings.Contains(base, "administrators_authorized_keys"):
		return true
	case base == ".ssh", parent == ".ssh" && (slices.Contains(hookpaths.SSHControlFiles[:], base) || strings.HasPrefix(base, "id_")):
		return true
	case parent == ".git" && base == "hooks", parent == "hooks" && len(parts) > 2 && parts[len(parts)-3] == ".git", base == "hookspath":
		return true
	case slices.Contains(shellStartupNames, base), strings.Contains(base, "powershell_profile"):
		return true
	}
	return state && slices.Contains(parts, ".defenseclaw")
}

// shellStartupNames are the shell startup profiles of the user.
var shellStartupNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".profile",
	"config.fish", "profile.ps1", "profile",
}

// placedPath is the absolute spelling of a path fact in cwd.
func placedPath(path actionfacts.PathFact, cwd string) string {
	value := path.Resolved
	if value == "" {
		value = path.Normalized
	}
	if value == "" {
		value = path.Value
	}
	return hookpaths.OperandPath(value, cwd)
}

// protectedFilePath reports a path of the files of the shell-command
// protected-file class under the active home: the authorized-keys files, the
// SSH control files, an SSH private key, a shell startup profile and an
// active Git hook.
func protectedFilePath(facts actionfacts.Facts, path actionfacts.PathFact) bool {
	if matchesAuthorizedKeys(facts, path) || matchesActiveSSHPrivateKey(facts, path) ||
		matchesActiveShellProfile(facts, path) || matchesActiveGitHook(facts, path) {
		return true
	}
	relative, ok := activeHomeRelative(facts, path)
	if !ok {
		return false
	}
	for _, name := range hookpaths.SSHControlFiles {
		if relative == ".ssh/"+name {
			return true
		}
	}
	return false
}

// shellCommandMayReachState reports a shell call that may write the
// DefenseClaw state: the state target scan places a target in the active
// state (it follows the links on disk), a word of the command is an existing
// link into it, or the hook client resolved a write target below the state
// folder of the active home. Each answer over-matches: a false answer only
// keeps the block the call had before GAP-0675. The words and comments of the
// command do not count unless they place a target (rel-1-0-6:GAP-0675 review 2).
func shellCommandMayReachState(request trustedActionRequest) bool {
	input := request.Input
	if home := strings.TrimSpace(input.ActiveHome); home != "" {
		state := strings.ToLower(filepath.ToSlash(filepath.Join(home, ".defenseclaw")))
		for _, target := range request.ResolvedWriteTargets {
			if lower := strings.ToLower(filepath.ToSlash(target)); lower == state || strings.HasPrefix(lower, state+"/") {
				return true
			}
		}
	}
	command, ok := trustedBashCommandInput(input)
	if !ok || request.SkipLocalFilesystemResolution {
		return false
	}
	return request.targetMemo.ActionStateTargetMention(command, input.CWD, input.ActiveHome) ||
		commandWordLinksIntoState(command, input.CWD, input.ActiveHome)
}

// commandWordLinksIntoState reports a word of command that names an existing
// link whose target is the DefenseClaw state folder of home or below it:
// a command can make its own link to such a link and write through it after
// a cd the readers cannot place. One readlink per word, on at most
// stateLinkWordsMax words; it over-matches (a read through the link counts).
func commandWordLinksIntoState(command, cwd, home string) bool {
	home = strings.TrimSpace(home)
	if home == "" {
		return false
	}
	state := filepath.Clean(filepath.Join(home, ".defenseclaw"))
	inState := func(target string) bool {
		target = filepath.Clean(target)
		return strings.EqualFold(target, state) ||
			strings.HasPrefix(strings.ToLower(target), strings.ToLower(state)+string(filepath.Separator))
	}
	words := strings.FieldsFunc(command, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ';' || r == '&' || r == '|' ||
			r == '(' || r == ')' || r == '"' || r == '\'' || r == '<' || r == '>' || r == '='
	})
	for index, word := range words {
		if index == stateLinkWordsMax {
			return false
		}
		if rest, ok := strings.CutPrefix(word, "~/"); ok {
			word = filepath.Join(home, rest)
		}
		if !filepath.IsAbs(word) {
			if cwd == "" {
				continue
			}
			word = filepath.Join(cwd, word)
		}
		target, err := os.Readlink(word)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(word), target)
		}
		if inState(target) {
			return true
		}
	}
	return false
}

// stateLinkWordsMax bounds the words commandWordLinksIntoState reads.
const stateLinkWordsMax = 256

// selfProtectionRules are the rules that protect DefenseClaw itself: a
// write, append, delete or metadata change of its state, configuration,
// hooks, policies, receipts and registries (tamper.detector_state_write and
// the active-state owners that report it). An enforcing finding of these
// rules blocks in every profile, permissive included, per-user and managed
// (rel-1-0-6:GAP-0675 review 1 M3a).
var selfProtectionRules = map[string]bool{
	"TAMPER.DETECTOR_STATE_WRITE": true,
}

// profileClassFindings is the one place a rule-pack posture decides the
// shell-command protected-file class and DefenseClaw self-protection
// (rel-1-0-6:GAP-0675). It returns the findings to map with the thresholds
// and the least action the request gets whatever the thresholds say:
//   - a self-protection finding that could block: block, in every profile;
//   - a class finding that could block: outside the strict posture it is
//     capped at an alert, so the command runs, the agent shows the alert with
//     the rule id and the audit row records decision=alert; in every posture
//     it is at least an alert, so the permissive profile never allows it
//     silently; the strict posture keeps it as it is (it blocks).
//
// A finding that could not block (detection-only, alert-only, allowed) stays
// as it was. The Secure Client integration is unchanged: Cisco AI Defense
// decides there. posture is read only when a class finding is present.
func profileClassFindings(findings []RuleFinding, secureClient bool, posture func() string) ([]RuleFinding, string) {
	floor := guardrailActionAllow
	if secureClient {
		return findings, floor
	}
	class := false
	for _, finding := range findings {
		if !finding.contributesToEnforcement() {
			continue
		}
		if selfProtectionRules[canonicalTrustedRuleID(finding.RuleID)] {
			floor = guardrailActionBlock
		} else if finding.shellFile != shellFileNone {
			class = class || finding.shellFile == shellFileUnproven
			floor = strongerGuardrailAction(floor, guardrailActionAlert)
		}
	}
	if !class || posture() == config.HookPolicyTierStrict {
		return findings, floor
	}
	capped := slices.Clone(findings)
	for index := range capped {
		if capped[index].shellFile == shellFileUnproven && capped[index].contributesToEnforcement() {
			capped[index].enforcement = findingEnforcementAlertOnly
		}
	}
	return capped, floor
}

// rulePackPostureForConnector is the posture of the rule pack of connector
// in cfg, as its thresholds read it (resolveThresholds).
func rulePackPostureForConnector(cfg *config.Config, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if cfg != nil {
			ref = cfg.EffectiveRulePackRefForConnector(connector)
		}
		if cfg == nil {
			return config.HookPolicyTierDefault
		}
		return packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref))
	}
}

// guardrailRulePackPosture is rulePackPostureForConnector for a caller that
// holds only the guardrail block (resolveGuardrailThresholds).
func guardrailRulePackPosture(gc *config.GuardrailConfig, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if gc != nil {
			ref = gc.EffectiveRulePackRef(connector)
		}
		if gc == nil {
			return config.HookPolicyTierDefault
		}
		return packPosture(ref, guardrailRulePackDir(gc, ref))
	}
}
