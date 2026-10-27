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
	"encoding/base64"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const (
	semanticHistoryTamperExpression = `f.commands.exists(c, c.argv_complete && (c.program == 'history' || (c.program == 'unset' && 'HISTFILE' in c.argv)))`
	// The owner binds this mutation shape to the exact active instruction file,
	// using trusted case-sensitivity metadata captured when the file was loaded.
	// Owner eligibility accepts only executing mutations (or static redirects
	// that remain executing in the enforcement projection), so an unrelated
	// sibling mutation cannot lend it authority.
	semanticActiveAgentInstructionMutationExpression = `f.paths.exists(p, p.access in [defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE, defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_APPEND, defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_DELETE])`
)

var semanticIntegrityPersistenceOwners = map[string]semanticOwner{
	"integrity.posix_system_shell_replacement": {
		prerequisite:     actionfacts.ExactPOSIXSystemShellReplacement,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"integrity.posix_system_interpreter_wrapper": {
		prerequisite:     actionfacts.ExactPOSIXSystemInterpreterWrapper,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"integrity.dpkg_status_direct_mutation": {
		prerequisite:     actionfacts.ExactPOSIXDPKGStatusMutation,
		suppressFallback: authoritativeSemanticSafeNegative,
		alertOnly:        true,
	},
	"privilege.posix_non_root_uid_zero_account_write": {
		prerequisite:     actionfacts.ExactPOSIXNonRootUIDZeroAccountWrite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"persistence.malicious_download_execute_payload": {
		prerequisite:  actionfacts.ExactMaliciousPersistencePayload,
		detectionOnly: true,
	},
	"CMD-CRONTAB": {
		prerequisite:     crontabInstallPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// Installing a schedule is dual-use. Without proof of the scheduled
		// payload, this is a useful persistence signal but not sufficient
		// evidence for a synchronous block.
		detectionOnly: true,
	},
	"CMD-SYSTEMCTL": {
		prerequisite:     schedulerInstallPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-WIN-REG-PERSIST": {
		prerequisite:     windowsRegistryPersistencePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"COG-AGENTS-MD":    activeAgentInstructionMutationOwner("AGENTS.md"),
	"COG-CLAUDE-MD":    activeAgentInstructionMutationOwner("CLAUDE.md"),
	"COG-GATEWAY-JSON": activeAgentInstructionMutationOwner("gateway.json"),
	"COG-IDENTITY":     activeAgentInstructionMutationOwner("IDENTITY.md"),
	"COG-MEMORY":       activeAgentInstructionMutationOwner("MEMORY.md"),
	"COG-SOUL":         activeAgentInstructionMutationOwner("SOUL.md"),
	"COG-TOOLS-MD":     activeAgentInstructionMutationOwner("TOOLS.md"),
	"integrity.git_hooks_bypass": {
		prerequisite:     gitHooksBypassPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"source.git_remote_tamper": {
		prerequisite:     gitRemoteTamperPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		detectionOnly:    true,
	},
	"source.git_config_exec": {
		prerequisite:     gitConfigExecPrerequisite,
		suppressFallback: gitConfigExecSafeNegative,
	},
	"persistence.ssh_authorized_keys_command": {
		prerequisite:     sshAuthorizedKeysCommandPrerequisite,
		suppressFallback: sshAuthorizedKeysCommandSafeNegative,
	},
	// PATH-HISTORY continues to own filesystem mutations. This owner handles
	// exact HISTFILE unsets and supplies a detection-only proof for Bash-style
	// history clearing, without duplicating active history-path findings.
	"integrity.history_tamper": {
		prerequisite:     historyTamperPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		detectionOnly:    true,
	},
	"PATH-HISTORY": {
		// The generic owner handles mutations, but a read of the Windows
		// PowerShell history file remains independently useful advisory evidence.
		// Claim the Windows alias only after the mutation prerequisite matches so
		// the trusted-action disposition can classify exact reads as advisory.
		matchedOnlyAliases: []string{"PATH-WIN-PS-HISTORY"},
		prerequisite: integrityMutationPrerequisite(
			matchesActiveShellHistory,
		),
		suppressFallback: integrityMutationSafeNegative(
			matchesShellHistoryCandidate,
			matchesActiveShellHistory,
			nil,
		),
	},
	"PATH-ETC-SUDOERS": integrityMutationOwner(
		matchesSudoersCandidate, matchesActiveSudoers, nil,
	),
	"privilege.sudoers_unrestricted_nopasswd": {
		prerequisite:     unrestrictedSudoersGrantPrerequisite,
		suppressFallback: func(actionfacts.Facts) bool { return true },
	},
	"PATH-SSH-DIR": {
		prerequisite:     sshDirectoryPrerequisite,
		suppressFallback: sshAuthorizedKeysPathSafeNegative,
	},
	"privilege.container_runtime_socket_access": {
		prerequisite:     containerRuntimeSocketPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		alertOnly:        true,
	},
	"persistence.shell_profile_write": integrityMutationOwner(
		matchesShellProfileCandidate,
		matchesActiveShellProfile,
		matchesSafeShellProfileCandidate,
	),
	"persistence.git_hook_write": integrityMutationOwner(
		matchesGitHookCandidate,
		matchesActiveGitHook,
		matchesSafeGitHookCandidate,
	),
	"C2-METADATA-AWS": {
		equivalentAliases: []string{
			"C2-METADATA-GCP",
			"C2-METADATA-AZURE",
			"C2-METADATA-HEX",
			"C2-METADATA-DECIMAL",
			"C2-METADATA-OCTAL",
		},
		prerequisite:     cloudMetadataPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"COG-OPENCLAW-JSON": integrityMutationOwner(
		matchesAgentConfigCandidate, matchesActiveAgentConfig, nil,
	),
	"tamper.detector_state_write": activeStateMutationOwner(),
}

// activeStateMutationOwner is the integrity owner of DefenseClaw's active
// state, where moving a protected file or tree away removes it as surely as
// deleting it: a move source is a mutation here (GAP-1774), and so is a
// chmod that adds group or other write (GAP-2077), while the other
// integrity owners keep judging only the move destination.
func activeStateMutationOwner() semanticOwner {
	owner := integrityMutationOwner(
		matchesDefenseClawStateCandidate,
		matchesActiveDefenseClawState,
		matchesSafeDefenseClawStateCandidate,
	)
	owner.prerequisite = func(facts actionfacts.Facts) bool {
		for _, candidate := range facts.Paths {
			command, ok := integrityCommandByID(facts, candidate.CommandID)
			if !ok || !matchesActiveDefenseClawState(facts, candidate) {
				continue
			}
			if integrityCommandMutatesPath(command, candidate) ||
				command.Effect == actionfacts.EffectExecute &&
					candidate.Access == actionfacts.PathAccessDelete &&
					hasOperation(command, actionfacts.OperationMove) {
				return true
			}
			// A chmod that gives group or other write to state hands it
			// to another account (GAP-2077); tightening is not a change.
			if command.Effect == actionfacts.EffectExecute &&
				candidate.Access == actionfacts.PathAccessMetadata &&
				strings.EqualFold(command.Program, "chmod") && chmodAddsGroupOrOtherWrite(command) {
				return true
			}
		}
		return false
	}
	return owner
}

// The dispatcher integrates these aliases only after the command-specific
// owner matched. Keeping this relationship separate from equivalent aliases
// lets PATH-SSH-DIR remain the fallback when the more specific rule is
// disabled or when a structured file mutation owns the path.
var semanticIntegrityPersistenceFallbackAliasesOnMatch = map[string][]string{
	"persistence.ssh_authorized_keys_command": {"PATH-SSH-DIR"},
}

type integrityPathMatcher func(actionfacts.Facts, actionfacts.PathFact) bool

func integrityMutationOwner(
	isCandidate semanticPathCandidate,
	isActive integrityPathMatcher,
	isSafe integrityPathMatcher,
	aliases ...string,
) semanticOwner {
	return semanticOwner{
		equivalentAliases: aliases,
		prerequisite:      integrityMutationPrerequisite(isActive),
		suppressFallback: integrityMutationSafeNegative(
			isCandidate, isActive, isSafe,
		),
	}
}

func activeAgentInstructionMutationOwner(fileName string) semanticOwner {
	isCandidate := func(value string) bool {
		return pathBase(canonicalSemanticPath(value)) == strings.ToLower(fileName)
	}
	isActive := func(
		facts actionfacts.Facts,
		candidate actionfacts.PathFact,
	) bool {
		candidatePath, ok := activeAgentInstructionPath(
			exactSemanticPathValue(candidate),
			candidate.Flavor,
		)
		if !ok || !activeAgentInstructionCandidateBaseMatches(
			path.Base(candidatePath),
			candidate.Flavor,
			fileName,
		) {
			return false
		}
		for _, activePath := range facts.ActiveAgentFiles {
			canonicalActivePath, active := activeAgentInstructionPath(
				activePath,
				candidate.Flavor,
			)
			if active && activeAgentInstructionBaseMatches(
				canonicalActivePath,
				candidate.Flavor,
				fileName,
			) && activeAgentInstructionPathsMatch(
				canonicalActivePath,
				candidatePath,
				candidate.Flavor,
				activeAgentFileCaseInsensitive(facts, activePath),
			) {
				return true
			}
		}
		if facts.ActiveAgentFilesUncertain {
			// Check retained exact entries above before falling back to lost
			// context. Exact POSIX basenames always fail closed. A folded POSIX
			// basename does so only when authenticated load-time state proved that
			// at least one omitted active file used case-insensitive lookup.
			if activeAgentInstructionBaseMatches(
				candidatePath,
				candidate.Flavor,
				fileName,
			) {
				return true
			}
			return candidate.Flavor == actionfacts.PathFlavorPOSIX &&
				facts.ActiveAgentFilesCaseInsensitiveUncertain &&
				activeAgentInstructionCandidateBaseMatches(
					path.Base(candidatePath),
					candidate.Flavor,
					fileName,
				)
		}
		return false
	}
	isSafe := func(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
		resolved := candidate.Resolved
		if resolved == "" {
			resolved = candidate.Normalized
		}
		flavor := candidate.Flavor
		if flavor != actionfacts.PathFlavorPOSIX &&
			flavor != actionfacts.PathFlavorWindows {
			normalized := strings.ReplaceAll(resolved, `\`, "/")
			switch {
			case strings.HasPrefix(normalized, "//") ||
				len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/':
				flavor = actionfacts.PathFlavorWindows
			case strings.HasPrefix(normalized, "/"):
				flavor = actionfacts.PathFlavorPOSIX
			default:
				return false
			}
		}
		if _, ok := activeAgentInstructionPath(resolved, flavor); !ok {
			return false
		}
		if !activeAgentInstructionCandidateMutatesPath(facts, candidate) {
			return true
		}
		// A distinct path may still be a hard-link or symlink alias of a
		// retained active file. The synchronous decision path deliberately does
		// not touch the filesystem, so keep that ambiguity visible instead of
		// declaring it safe. A known-empty rule-specific context remains quiet.
		return !activeAgentInstructionContextPresent(facts, flavor, fileName)
	}
	owner := integrityMutationOwner(
		isCandidate,
		isActive,
		isSafe,
	)
	// A fixture-looking path can alias the active file just as any other path
	// can. Known-empty context is already handled by isSafe; do not let the
	// generic lexical fixture exemption erase an unresolved alias finding.
	pathSafeNegative := integrityMutationSafeNegativeWithFixture(
		isCandidate,
		isActive,
		isSafe,
		nil,
	)
	owner.suppressFallback = func(facts actionfacts.Facts) bool {
		if pathSafeNegative(facts) {
			return true
		}
		if !facts.Authoritative() {
			return false
		}
		for _, command := range facts.Commands {
			if hasAnyOperation(
				command,
				actionfacts.OperationWrite,
				actionfacts.OperationAppend,
				actionfacts.OperationDelete,
				actionfacts.OperationCopy,
				actionfacts.OperationMove,
				actionfacts.OperationConfigChange,
			) {
				// If ActionFacts saw a mutation but could not prove its target,
				// retain the lexical fallback as non-authoritative evidence.
				return false
			}
		}
		// A bare filename in an otherwise authoritative read/list/search or
		// prose-only command is not evidence of an instruction-file mutation.
		return true
	}
	return owner
}

// exactSemanticPathValue intentionally does not use semanticPathValue: that
// helper folds case for broad pattern matching. Active instruction-file
// authority must preserve the proven spelling and filesystem flavor until it
// is checked against authenticated, load-time identity metadata.
func exactSemanticPathValue(candidate actionfacts.PathFact) string {
	if candidate.Resolved != "" {
		return candidate.Resolved
	}
	if candidate.Normalized != "" {
		return candidate.Normalized
	}
	return candidate.Value
}

func activeAgentInstructionPath(
	value string,
	flavor actionfacts.PathFlavor,
) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	switch flavor {
	case actionfacts.PathFlavorPOSIX:
		if !strings.HasPrefix(value, "/") {
			return "", false
		}
		value = path.Clean(value)
		return value, value != "/"
	case actionfacts.PathFlavorWindows:
		value = strings.ReplaceAll(value, `\`, "/")
		unc := strings.HasPrefix(value, "//")
		if !unc && (len(value) < 3 || !isASCIIPathLetter(value[0]) ||
			value[1] != ':' || value[2] != '/') {
			return "", false
		}
		if unc {
			value = "//" + strings.TrimPrefix(
				path.Clean("/"+strings.TrimLeft(value, "/")),
				"/",
			)
		} else {
			value = path.Clean(value)
		}
		return strings.ToLower(value), value != "" && value != "//"
	default:
		return "", false
	}
}

func activeAgentInstructionBaseMatches(
	value string,
	flavor actionfacts.PathFlavor,
	fileName string,
) bool {
	// POSIX matching is deliberately exact here. This is the baseline
	// fail-closed basename gate when bounded active-file context is uncertain and
	// when validating the canonical active path itself. The caller handles the
	// separate proof-gated folded-candidate case.
	base := path.Base(value)
	if flavor == actionfacts.PathFlavorWindows {
		return strings.EqualFold(base, fileName)
	}
	return flavor == actionfacts.PathFlavorPOSIX && base == fileName
}

func activeAgentInstructionCandidateBaseMatches(
	base string,
	flavor actionfacts.PathFlavor,
	fileName string,
) bool {
	// Candidate discovery may recognize an ASCII case variant, but that alone
	// never grants authority. POSIX enforcement still requires the exact parent
	// and authenticated load-time case proof in activeAgentInstructionPathsMatch.
	if flavor == actionfacts.PathFlavorWindows {
		return strings.EqualFold(base, fileName)
	}
	return flavor == actionfacts.PathFlavorPOSIX &&
		activeAgentASCIIEqualFold(base, fileName)
}

func activeAgentInstructionPathsMatch(
	activePath string,
	candidatePath string,
	flavor actionfacts.PathFlavor,
	caseInsensitive bool,
) bool {
	if activePath == candidatePath {
		return true
	}
	if flavor != actionfacts.PathFlavorPOSIX || !caseInsensitive {
		return false
	}
	return path.Dir(activePath) == path.Dir(candidatePath) &&
		activeAgentASCIIEqualFold(
			path.Base(activePath),
			path.Base(candidatePath),
		)
}

func activeAgentFileCaseInsensitive(
	facts actionfacts.Facts,
	activePath string,
) bool {
	for _, candidate := range facts.ActiveAgentFilesCaseInsensitive {
		if candidate == activePath {
			return true
		}
	}
	return false
}

func activeAgentInstructionContextPresent(
	facts actionfacts.Facts,
	flavor actionfacts.PathFlavor,
	fileName string,
) bool {
	if facts.ActiveAgentFilesUncertain {
		return true
	}
	for _, activePath := range facts.ActiveAgentFiles {
		canonicalActivePath, active := activeAgentInstructionPath(
			activePath,
			flavor,
		)
		if active && activeAgentInstructionBaseMatches(
			canonicalActivePath,
			flavor,
			fileName,
		) {
			return true
		}
	}
	return false
}

func activeAgentInstructionCandidateMutatesPath(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	candidatePath := semanticPathValue(candidate)
	for _, pathCandidate := range facts.Paths {
		if pathCandidate.CommandID != candidate.CommandID ||
			semanticPathValue(pathCandidate) != candidatePath {
			continue
		}
		command, ok := integrityCommandByID(facts, pathCandidate.CommandID)
		if ok && integrityCommandMutatesPath(command, pathCandidate) {
			return true
		}
	}
	return false
}

func isASCIIPathLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func historyTamperPrerequisite(facts actionfacts.Facts) bool {
	for _, issue := range facts.Parse.Issues {
		if issue == actionfacts.IssueUnsupportedConstruct {
			// Subshells and background jobs isolate shell-builtin state, but
			// ActionFacts intentionally flattens those AST nodes. Never promote
			// their textual history operation through the fallback lane.
			return false
		}
	}
	if activeShellHistoryMutationPresent(facts) {
		return false
	}
	for _, command := range facts.Commands {
		if !integrityExecutingOwnedCommand(command, "history", "unset") ||
			command.Executable != command.Program ||
			command.ParentCommandID != 0 || command.PipelineID != 0 {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "history":
			if actionfacts.ProvesPOSIXHistoryClear(command) {
				return true
			}
		case "unset":
			if unsetHistoryFileVariable(command.Argv) {
				return true
			}
		}
	}
	return false
}

func unsetHistoryFileVariable(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	options := true
	functionMode := false
	variableMode := false
	found := false
	for _, argument := range argv[1:] {
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "-") && argument != "-" {
			if len(argument) < 2 || argument[1] == '-' {
				return false
			}
			for _, option := range argument[1:] {
				switch option {
				case 'f':
					functionMode = true
				case 'v':
					variableMode = true
				default:
					return false
				}
			}
			continue
		}
		options = false
		found = found || argument == "HISTFILE"
	}
	if functionMode && variableMode {
		return false
	}
	return found && !functionMode
}

func activeShellHistoryMutationPresent(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if ok &&
			matchesActiveShellHistory(facts, candidate) &&
			integrityCommandMutatesPath(command, candidate) {
			return true
		}
	}
	return false
}

func integrityMutationPrerequisite(
	matches integrityPathMatcher,
) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		for _, candidate := range facts.Paths {
			command, ok := integrityCommandByID(facts, candidate.CommandID)
			if ok &&
				matches(facts, candidate) &&
				integrityCommandMutatesPath(command, candidate) {
				return true
			}
		}
		return false
	}
}

func integrityMutationSafeNegative(
	isCandidate semanticPathCandidate,
	isActive integrityPathMatcher,
	isSafe integrityPathMatcher,
) semanticOwnerPrerequisite {
	return integrityMutationSafeNegativeWithFixture(
		isCandidate,
		isActive,
		isSafe,
		isDefiniteFixturePath,
	)
}

func integrityMutationSafeNegativeWithFixture(
	isCandidate semanticPathCandidate,
	isActive integrityPathMatcher,
	isSafe integrityPathMatcher,
	isFixture integrityPathMatcher,
) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		if !facts.Authoritative() {
			return false
		}
		safePaths := make(map[int64]map[string]struct{})
		for _, candidate := range facts.Paths {
			command, ok := integrityCommandByID(facts, candidate.CommandID)
			if !ok || !integrityPathIsProvenNonMutation(command, candidate) {
				continue
			}
			paths := safePaths[candidate.CommandID]
			if paths == nil {
				paths = make(map[string]struct{})
				safePaths[candidate.CommandID] = paths
			}
			paths[semanticPathValue(candidate)] = struct{}{}
		}
		sawCandidate := false
		for _, candidate := range semanticPathCandidates(facts) {
			if !isCandidate(semanticPathValue(candidate)) {
				continue
			}
			sawCandidate = true
			if _, safe := safePaths[candidate.CommandID][semanticPathValue(candidate)]; safe {
				continue
			}
			if isActive(facts, candidate) ||
				isSafe != nil && isSafe(facts, candidate) ||
				isFixture != nil && isFixture(facts, candidate) {
				continue
			}
			return false
		}
		return sawCandidate
	}
}

func integrityPathIsProvenNonMutation(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if command.Effect == actionfacts.EffectPreview {
		return !integrityCommandOwnsStaticRedirect(command, candidate)
	}
	if command.Effect != actionfacts.EffectExecute {
		return false
	}
	switch candidate.Access {
	case actionfacts.PathAccessRead,
		actionfacts.PathAccessList,
		actionfacts.PathAccessMetadata,
		actionfacts.PathAccessConnect,
		actionfacts.PathAccessExecute:
		return true
	case actionfacts.PathAccessDelete:
		// Classifiers represent a move source with delete access, but the
		// destination is the only mutation target owned by these rules.
		return hasOperation(command, actionfacts.OperationMove)
	default:
		return false
	}
}

func integrityCommandByID(
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

func integrityCommandMutatesPath(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if command.Effect == actionfacts.EffectPreview {
		return integrityCommandOwnsStaticRedirect(command, candidate)
	}
	if command.Effect != actionfacts.EffectExecute {
		return false
	}
	switch candidate.Access {
	case actionfacts.PathAccessWrite:
		return hasAnyOperation(
			command,
			actionfacts.OperationWrite,
			actionfacts.OperationAppend,
			actionfacts.OperationCopy,
			actionfacts.OperationMove,
			actionfacts.OperationConfigChange,
		) || (strings.EqualFold(command.Program, "curl") ||
			strings.EqualFold(command.Program, "curl.exe") ||
			strings.EqualFold(command.Program, "wget") ||
			strings.EqualFold(command.Program, "wget.exe")) &&
			hasAnyOperation(command, actionfacts.OperationFetch, actionfacts.OperationUpload)
	case actionfacts.PathAccessAppend:
		return hasAnyOperation(
			command,
			actionfacts.OperationAppend,
			actionfacts.OperationWrite,
		)
	case actionfacts.PathAccessDelete:
		// A move source is not a mutation target for these owners.
		return hasOperation(command, actionfacts.OperationDelete)
	default:
		return false
	}
}

func integrityCommandOwnsStaticRedirect(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	for _, redirect := range command.Redirects {
		if !redirect.Expands &&
			redirectMatchesPath(redirect.Target, candidate) &&
			redirect.Access == candidate.Access &&
			integrityMutationAccess(redirect.Access) {
			return true
		}
	}
	return false
}

func redirectMatchesPath(target string, candidate actionfacts.PathFact) bool {
	canonical := canonicalSemanticPath(target)
	if strings.HasPrefix(canonical, "~/") {
		return strings.HasSuffix(canonicalSemanticPath(candidate.Resolved), canonical[1:])
	}
	return canonical == canonicalSemanticPath(candidate.Value) ||
		canonical == canonicalSemanticPath(candidate.Normalized)
}

func integrityMutationAccess(access actionfacts.PathAccess) bool {
	return access == actionfacts.PathAccessWrite ||
		access == actionfacts.PathAccessAppend ||
		access == actionfacts.PathAccessDelete
}

func crontabInstallPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !integrityExecutingOwnedCommand(command, "crontab") ||
			!hasOperation(command, actionfacts.OperationSchedule) {
			continue
		}
		removeOrList := false
		for _, argument := range command.Argv[1:] {
			switch strings.ToLower(argument) {
			case "-l", "-r":
				removeOrList = true
			}
		}
		if !removeOrList {
			return true
		}
	}
	return false
}

func schedulerInstallPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "systemctl":
			if hasOperation(command, actionfacts.OperationSchedule) &&
				systemctlInstallForm(command.Argv) {
				return true
			}
		case "launchctl":
			if hasOperation(command, actionfacts.OperationSchedule) &&
				launchctlInstallForm(command.Argv) {
				return true
			}
		case "schtasks", "schtasks.exe", "register-scheduledtask":
			if hasOperation(command, actionfacts.OperationSchedule) {
				return true
			}
		}
	}
	return windowsRegistryPersistencePrerequisite(facts) ||
		integrityMutationPrerequisite(matchesActiveSchedulerPath)(facts)
}

func windowsRegistryPersistencePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			!oneOfFold(command.Program, "reg", "reg.exe", "set-itemproperty", "sp", "new-itemproperty") ||
			!hasOperation(command, actionfacts.OperationConfigChange) {
			continue
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID == command.ID &&
				candidate.Access == actionfacts.PathAccessWrite &&
				matchesActiveRegistryPersistence(command, candidate) {
				return true
			}
		}
	}
	return false
}

func systemctlInstallForm(argv []string) bool {
	verb, ok := integrityFirstPositional(argv)
	return ok && oneOfFold(verb, "enable", "reenable", "preset")
}

func launchctlInstallForm(argv []string) bool {
	if len(argv) < 2 {
		return false
	}
	switch strings.ToLower(argv[1]) {
	case "load", "bootstrap", "enable":
		return true
	default:
		return false
	}
}

func integrityFirstPositional(argv []string) (string, bool) {
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		lower := strings.ToLower(argument)
		if argument == "--" {
			if index+1 < len(argv) {
				return strings.ToLower(argv[index+1]), true
			}
			return "", false
		}
		if !strings.HasPrefix(argument, "-") {
			return lower, true
		}
		key, _, joined := strings.Cut(lower, "=")
		if systemctlValueOption(key) {
			if !joined {
				if index+1 >= len(argv) {
					return "", false
				}
				index++
			}
			continue
		}
		if systemctlFlagOption(key) && !joined {
			continue
		}
		return "", false
	}
	return "", false
}

func systemctlValueOption(option string) bool {
	switch option {
	case "-h", "--host", "-m", "--machine", "-n", "--lines",
		"-o", "--output", "-p", "--property", "--job-mode", "--root",
		"--runtime-scope", "--state", "-t", "--type":
		return true
	default:
		return false
	}
}

func systemctlFlagOption(option string) bool {
	switch option {
	case "-a", "--all", "--failed", "--force", "--global",
		"--no-ask-password", "--no-block", "--no-legend", "--no-pager",
		"--no-reload", "--now", "-q", "--quiet", "--recursive",
		"--runtime", "--system", "--user", "--dry-run", "--help",
		"--version":
		return true
	default:
		return false
	}
}

func matchesActiveRegistryPersistence(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if matchesActiveRunKey(candidate) {
		return true
	}
	if candidate.Flavor != actionfacts.PathFlavorRegistry {
		return false
	}
	if len(command.Argv) == 0 {
		return false
	}
	value := strings.Trim(canonicalSemanticPath(semanticPathValue(candidate)), "/")
	valueName := windowsRegistryValueNameForProgram(
		command.Program,
		command.Argv[1:],
	)
	switch {
	case value == "hklm/software/microsoft/windows nt/currentversion/winlogon" ||
		value == "hkcu/software/microsoft/windows nt/currentversion/winlogon":
		return valueName == "shell" || valueName == "userinit"
	case strings.HasPrefix(value, "hklm/system/currentcontrolset/services/"):
		return valueName == "imagepath" || valueName == "servicedll"
	default:
		return false
	}
}

func matchesActiveRunKey(candidate actionfacts.PathFact) bool {
	if candidate.Flavor != actionfacts.PathFlavorRegistry {
		return false
	}
	value := strings.Trim(canonicalSemanticPath(semanticPathValue(candidate)), "/")
	return value == "hkcu/software/microsoft/windows/currentversion/run" ||
		value == "hkcu/software/microsoft/windows/currentversion/runonce" ||
		value == "hklm/software/microsoft/windows/currentversion/run" ||
		value == "hklm/software/microsoft/windows/currentversion/runonce" ||
		value == "hkcu/software/wow6432node/microsoft/windows/currentversion/run" ||
		value == "hkcu/software/wow6432node/microsoft/windows/currentversion/runonce" ||
		value == "hklm/software/wow6432node/microsoft/windows/currentversion/run" ||
		value == "hklm/software/wow6432node/microsoft/windows/currentversion/runonce"
}

func matchesActiveSchedulerPath(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	if value == "/etc/crontab" ||
		integritySingleChild(value, "/etc/cron.d") ||
		integritySingleChildWithSuffix(
			value, "/etc/systemd/system",
			".service", ".timer", ".socket", ".path", ".target",
		) ||
		integritySingleChild(value, "c:/windows/system32/tasks") {
		return true
	}
	for _, parent := range []string{
		"/library/launchagents",
		"/library/launchdaemons",
	} {
		if integritySingleChildWithSuffix(value, parent, ".plist") {
			return true
		}
	}
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	if integritySingleChildWithSuffix(
		relative, ".config/systemd/user",
		".service", ".timer", ".socket", ".path", ".target",
	) || integritySingleChildWithSuffix(
		relative, ".config/autostart", ".desktop",
	) || integritySingleChildWithSuffix(
		relative, "library/launchagents", ".plist",
	) || integritySingleChild(
		relative,
		"appdata/roaming/microsoft/windows/start menu/programs/startup",
	) {
		return true
	}
	return false
}

type integrityGitInvocation struct {
	subcommand         string
	subcommandIndex    int
	configAssignments  []string
	workingDirectories []string
	gitDir             string
	bare               bool
}

func parseIntegrityGitInvocation(
	command actionfacts.CommandFact,
) (integrityGitInvocation, bool) {
	if !integrityExecutingOwnedCommand(command, "git") {
		return integrityGitInvocation{}, false
	}
	invocation := integrityGitInvocation{}
	for index := 1; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		lower := strings.ToLower(argument)
		if argument == "--" {
			index++
			if index >= len(command.Argv) {
				return integrityGitInvocation{}, false
			}
			invocation.subcommand = strings.ToLower(command.Argv[index])
			invocation.subcommandIndex = index
			return invocation, true
		}
		if argument == "-C" {
			index++
			if index >= len(command.Argv) {
				return integrityGitInvocation{}, false
			}
			invocation.workingDirectories = append(
				invocation.workingDirectories,
				command.Argv[index],
			)
			continue
		}
		if strings.HasPrefix(argument, "-C") && len(argument) > 2 {
			invocation.workingDirectories = append(
				invocation.workingDirectories,
				argument[2:],
			)
			continue
		}
		key, value, joined := strings.Cut(argument, "=")
		switch strings.ToLower(key) {
		case "-c":
			if joined {
				invocation.configAssignments = append(
					invocation.configAssignments,
					value,
				)
				continue
			}
			index++
			if index >= len(command.Argv) {
				return integrityGitInvocation{}, false
			}
			invocation.configAssignments = append(
				invocation.configAssignments,
				command.Argv[index],
			)
		case "--git-dir":
			if !joined {
				index++
				if index >= len(command.Argv) {
					return integrityGitInvocation{}, false
				}
				value = command.Argv[index]
			}
			if value == "" {
				return integrityGitInvocation{}, false
			}
			invocation.gitDir = value
		case "--config-env", "--exec-path", "--namespace",
			"--super-prefix", "--work-tree":
			if !joined {
				index++
				if index >= len(command.Argv) {
					return integrityGitInvocation{}, false
				}
			}
		case "--bare":
			if joined {
				return integrityGitInvocation{}, false
			}
			invocation.bare = true
		default:
			if strings.HasPrefix(lower, "-") {
				continue
			}
			invocation.subcommand = lower
			invocation.subcommandIndex = index
			return invocation, true
		}
	}
	return integrityGitInvocation{}, false
}

func gitHooksBypassPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		invocation, ok := parseIntegrityGitInvocation(command)
		if !ok {
			continue
		}
		switch invocation.subcommand {
		case "commit", "push":
			if gitNoVerify(command.Argv[invocation.subcommandIndex:]) ||
				gitHooksPathDisabled(invocation.configAssignments) {
				return true
			}
		case "config":
			if gitConfigDisablesHooks(
				command.Argv[invocation.subcommandIndex:],
			) {
				return true
			}
		}
	}
	return false
}

func gitConfigDisablesHooks(argv []string) bool {
	if len(argv) != 3 ||
		!strings.EqualFold(argv[0], "config") ||
		!strings.EqualFold(argv[1], "core.hookspath") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(argv[2])) {
	case "", "/dev/null", "nul", "nul:":
		return true
	default:
		return false
	}
}

func gitNoVerify(argv []string) bool {
	subcommand := ""
	if len(argv) != 0 {
		subcommand = strings.ToLower(argv[0])
	}
	valueOptions := map[string]bool{
		"-m": true, "--message": true, "-F": true, "--file": true,
		"--author": true, "--date": true, "--cleanup": true,
		"--fixup": true, "--squash": true, "-C": true,
		"--reuse-message": true, "-c": true, "--reedit-message": true,
		"--pathspec-from-file": true,
	}
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		lower := strings.ToLower(argument)
		if argument == "--" {
			return false
		}
		key, _, joined := strings.Cut(lower, "=")
		if valueOptions[key] {
			if !joined {
				index++
			}
			continue
		}
		if lower == "--no-verify" ||
			subcommand == "commit" && lower == "-n" {
			return true
		}
	}
	return false
}

func gitHooksPathDisabled(assignments []string) bool {
	for _, assignment := range assignments {
		key, value, ok := strings.Cut(assignment, "=")
		if !ok || !strings.EqualFold(key, "core.hookspath") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "", "/dev/null", "nul", "nul:":
			return true
		}
	}
	return false
}

func gitRemoteTamperPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		invocation, ok := parseIntegrityGitInvocation(command)
		if !ok || invocation.subcommand != "remote" ||
			!hasOperation(command, actionfacts.OperationConfigChange) {
			continue
		}
		argv := lowerArgv(command.Argv[invocation.subcommandIndex:])
		// Adding a remote is ordinary repository initialization. Without trusted
		// prior-state proving that the named remote already existed, only an
		// explicit set-url operation is a deterministic routing change.
		if len(argv) < 2 || argv[1] != "set-url" {
			continue
		}
		if hasExternalNetworkAction(
			facts,
			command.ID,
			actionfacts.NetworkConnect,
		) {
			return true
		}
	}
	return false
}

func gitConfigExecPrerequisite(facts actionfacts.Facts) bool {
	if gitReadOutputConfigPrerequisite(facts) {
		return true
	}
	for _, command := range facts.Commands {
		invocation, ok := parseIntegrityGitInvocation(command)
		if !ok || invocation.subcommand != "config" ||
			!hasOperation(command, actionfacts.OperationConfigChange) {
			continue
		}
		key, value, active, indirection := gitConfigExecutableSetting(
			command.Argv[invocation.subcommandIndex+1:],
		)
		if active && !indirection &&
			gitConfigValueActivatesExecution(key, value) {
			return true
		}
	}
	return false
}

func gitReadOutputConfigPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		invocation, ok := parseIntegrityGitInvocation(command)
		if !ok || !oneOfFold(
			invocation.subcommand,
			"show", "log", "diff", "whatchanged",
		) || !hasOperation(command, actionfacts.OperationWrite) {
			continue
		}
		activeGitDir, ok := integrityGitDirectory(facts, invocation)
		if !ok {
			continue
		}
		activeConfig := strings.TrimRight(activeGitDir, "/") + "/config"
		for _, candidate := range facts.Paths {
			if candidate.CommandID == command.ID &&
				candidate.Access == actionfacts.PathAccessWrite &&
				canonicalSemanticPath(semanticPathValue(candidate)) == activeConfig {
				return true
			}
		}
	}
	return false
}

func integrityGitDirectory(
	facts actionfacts.Facts,
	invocation integrityGitInvocation,
) (string, bool) {
	workingDirectory := canonicalSemanticPath(facts.CWD)
	if !isAbsoluteSemanticPath(workingDirectory) {
		return "", false
	}
	for _, directory := range invocation.workingDirectories {
		var ok bool
		workingDirectory, ok = resolveIntegrityGitPath(
			workingDirectory,
			directory,
		)
		if !ok {
			return "", false
		}
	}
	if invocation.gitDir != "" {
		return resolveIntegrityGitPath(
			workingDirectory,
			invocation.gitDir,
		)
	}
	if invocation.bare {
		return workingDirectory, true
	}
	return pathJoinSemantic(workingDirectory, ".git"), true
}

func resolveIntegrityGitPath(base, value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value ||
		strings.HasPrefix(value, "~") ||
		strings.ContainsAny(value, "$%*?[]{}\x60") {
		return "", false
	}
	canonical := canonicalSemanticPath(value)
	if canonical == "" ||
		(len(canonical) >= 2 && canonical[1] == ':' &&
			!isAbsoluteSemanticPath(canonical)) ||
		(strings.HasPrefix(value, `\`) &&
			!strings.HasPrefix(value, `\\`)) {
		return "", false
	}
	if isAbsoluteSemanticPath(canonical) {
		return canonical, true
	}
	if !isAbsoluteSemanticPath(base) {
		return "", false
	}
	return pathJoinSemantic(base, canonical), true
}

func pathJoinSemantic(base, relative string) string {
	return canonicalSemanticPath(
		strings.TrimRight(base, "/") + "/" +
			strings.TrimLeft(relative, "/"),
	)
}

func gitConfigExecSafeNegative(facts actionfacts.Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, command := range facts.Commands {
		invocation, ok := parseIntegrityGitInvocation(command)
		if !ok || invocation.subcommand != "config" {
			continue
		}
		_, _, _, indirection := gitConfigExecutableSetting(
			command.Argv[invocation.subcommandIndex+1:],
		)
		if indirection && !gitConfigIndirectionIsFixture(facts, command) {
			return false
		}
	}
	return true
}

func gitConfigExecutableSetting(
	argv []string,
) (key string, value string, active bool, indirection bool) {
	positionals := make([]string, 0, 3)
	readOnly := false
	for index := 0; index < len(argv); index++ {
		argument := argv[index]
		lower := strings.ToLower(argument)
		option, joinedValue, joined := strings.Cut(argument, "=")
		switch strings.ToLower(option) {
		case "--file", "-f", "--blob":
			indirection = true
			if !joined {
				index++
			}
		case "--default", "--comment", "--type":
			if !joined {
				index++
			}
		case "--get", "--get-all", "--get-regexp", "--get-urlmatch",
			"--list", "-l", "--show-origin", "--show-scope",
			"--name-only":
			readOnly = true
		default:
			if strings.HasPrefix(lower, "-") {
				continue
			}
			if joined && !strings.HasPrefix(argument, "-") {
				positionals = append(positionals, option, joinedValue)
				continue
			}
			positionals = append(positionals, argument)
		}
	}
	if len(positionals) > 0 &&
		strings.EqualFold(positionals[0], "set") {
		positionals = positionals[1:]
	}
	if readOnly || len(positionals) < 2 {
		return "", "", false, indirection
	}
	return strings.ToLower(positionals[0]), positionals[1], true, indirection
}

func gitConfigValueActivatesExecution(key, value string) bool {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(key, "alias."):
		return strings.HasPrefix(value, "!")
	case key == "credential.helper":
		if !strings.HasPrefix(value, "!") {
			return false
		}
		return !strings.EqualFold(
			strings.Join(strings.Fields(value), " "),
			"!gh auth git-credential",
		)
	case key == "core.sshcommand":
		return value != "" &&
			!strings.EqualFold(value, "ssh") &&
			!strings.EqualFold(value, "ssh.exe")
	case key == "core.hookspath":
		switch strings.ToLower(value) {
		case "", "/dev/null", "nul", "nul:":
			return false
		default:
			return true
		}
	default:
		return false
	}
}

func gitConfigIndirectionIsFixture(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) bool {
	for index := 1; index < len(command.Argv); index++ {
		option, value, joined := strings.Cut(command.Argv[index], "=")
		switch strings.ToLower(option) {
		case "--blob":
			return false
		case "--file", "-f":
			if !joined {
				index++
				if index >= len(command.Argv) {
					return false
				}
				value = command.Argv[index]
			}
			candidate := actionfacts.PathFact{
				CommandID:  command.ID,
				Value:      value,
				Normalized: canonicalSemanticPath(value),
			}
			if isAbsoluteSemanticPath(candidate.Normalized) {
				candidate.Resolved = candidate.Normalized
			} else if facts.CWD != "" {
				candidate.Resolved = canonicalSemanticPath(
					strings.TrimRight(
						canonicalSemanticPath(facts.CWD),
						"/",
					) + "/" + value,
				)
			}
			return isDefiniteFixturePath(facts, candidate)
		}
	}
	return false
}

func sshAuthorizedKeysCommandPrerequisite(facts actionfacts.Facts) bool {
	return sshAuthorizedKeysPrerequisite(facts, false)
}

func sshAuthorizedKeysStructuredPrerequisite(
	facts actionfacts.Facts,
) bool {
	return sshAuthorizedKeysPrerequisite(facts, true)
}

// sshDirectoryPrerequisite is PATH-SSH-DIR's: a structured write or delete
// of authorized_keys, or any write, append or delete of the active user's
// SSH private key (touch, sed -i, echo >> ~/.ssh/id_ed25519), which had no
// finding at all (GAP-1666). ssh-keygen creating the key is routine.
func sshDirectoryPrerequisite(facts actionfacts.Facts) bool {
	return sshAuthorizedKeysStructuredPrerequisite(facts) || sshPrivateKeyMutationPrerequisite(facts)
}

// sshPrivateKeyMutationPrerequisite reports a write, append or delete of the
// active user's SSH private key by anything but ssh-keygen.
func sshPrivateKeyMutationPrerequisite(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if ok && !strings.EqualFold(command.Program, "ssh-keygen") &&
			matchesActiveSSHPrivateKey(facts, candidate) &&
			integrityCommandMutatesPath(command, candidate) {
			return true
		}
	}
	return false
}

// appendTrustedHomeResolvedSSHKeyWriteFinding adds the authorized-keys write
// check when a bounded positive proof can recover the active path from a
// partial tool call. It also retains PATH-SSH-DIR's alert for a home-resolved
// private-key write, whose target is resolved under the caller's home.
func appendTrustedHomeResolvedSSHKeyWriteFinding(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	input := request.Input
	if input.Command == "" {
		if command, ok := trustedBashCommandInput(input); ok {
			input.Command = command
		}
	}
	commandText := strings.ToLower(input.Command)
	symlinkWrite := trustedExistingAuthorizedKeysSymlinkWrite(request, facts)
	if commandText != "" && !strings.Contains(commandText, "authorized_k") &&
		!strings.Contains(commandText, "administrators_authorized") &&
		!strings.Contains(commandText, "base64") && !symlinkWrite &&
		!trustedWindowsLocationAuthorizedKeysWrite(input) {
		return appendTrustedCMDPrivateKeyReadFinding(
			appendTrustedSSHPrivateKeyWriteFinding(findings, generation, request, facts),
			generation, request, input,
		)
	}
	for _, finding := range findings {
		if finding.RuleID == "persistence.ssh_authorized_keys_command" &&
			finding.contributesToEnforcement() {
			return findings
		}
	}
	if request.EnforcementCapable &&
		(trustedAuthorizedKeysWriteProof(input, facts, symlinkWrite, clientGlobFacts(request)) ||
			trustedSandboxGuestAuthorizedKeysWrite(request)) {
		_, rule, ok := trustedActionCatalogRule(generation, "persistence.ssh_authorized_keys_command")
		if ok {
			kept := findings[:0]
			for _, finding := range findings {
				if finding.RuleID != "PATH-SSH-DIR" &&
					finding.RuleID != "persistence.ssh_authorized_keys_command" {
					kept = append(kept, finding)
				}
			}
			title := rule.Title
			if hookpaths.ArchiveBeforeWrite(input.Command, input.ActiveHome) {
				title = archiveBeforeWriteTitle
			}
			return append(kept, adjustConfidence(input.Tool, RuleFinding{
				RuleID: rule.ID, Title: title, Severity: rule.Severity,
				Confidence: rule.Confidence, Evidence: trustedActionInputText(input, ""),
				Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
				enforcement: findingEnforcementAllowed,
			}))
		}
	}
	return appendTrustedCMDPrivateKeyReadFinding(
		appendTrustedSSHPrivateKeyWriteFinding(findings, generation, request, facts),
		generation, request, input,
	)
}

// trustedAuthorizedKeysWriteProof reports a bounded positive proof that the
// call writes an authorized-keys file. input is the request's input with
// the command text of a shell tool filled in; globFacts is the managed hook
// client's evidence (clientGlobFacts), nil for any other caller.
func trustedAuthorizedKeysWriteProof(input actionfacts.Input, facts actionfacts.Facts, symlinkWrite bool, globFacts map[string]string) bool {
	if input.Command != "" &&
		hookpaths.ActionCommandDecisionWithGlobFacts(input.Command, input.CWD, facts.ActiveHome, globFacts) == "protected-target" {
		return true
	}
	enforcementFacts := facts.EnforcementProjection()
	return enforcementFacts.EnforcementEligible() &&
		(sshAuthorizedKeysCommandPrerequisite(enforcementFacts) ||
			sshAuthorizedKeysStructuredPrerequisite(enforcementFacts)) ||
		trustedUnknownOutputAuthorizedKeysWrite(facts) ||
		trustedAwkOutputAuthorizedKeysWrite(facts) ||
		trustedGitConfigEnvironmentAuthorizedKeysWrite(facts) ||
		trustedUnknownKeyAuthorizedKeysWrite(input, facts) ||
		homeResolvedTwinProves(input, facts, sshAuthorizedKeysCommandPrerequisite) ||
		trustedStaticStatementAuthorizedKeysWrite(input) ||
		trustedStaticRedirectAuthorizedKeysWrite(input, facts) ||
		trustedHereStringAuthorizedKeysWrite(input) ||
		trustedDDOutputAuthorizedKeysWrite(input) ||
		trustedSedInPlaceAuthorizedKeysWrite(input) ||
		trustedAssignedAuthorizedKeysWrite(input) ||
		trustedAuthorizedKeysGlobWrite(input) ||
		trustedAuthorizedKeysSymlinkWrite(input) ||
		symlinkWrite ||
		trustedFindExecAuthorizedKeysWrite(input) ||
		trustedHomeDirectoryAuthorizedKeysWrite(input) ||
		trustedWindowsLocationAuthorizedKeysWrite(input) ||
		trustedShellWrapperAuthorizedKeysWrite(input, facts) ||
		trustedBase64ShellAuthorizedKeysWrite(input, facts) ||
		trustedInlineAuthorizedKeysWrite(input, facts) ||
		trustedPOSIXPowerShellAuthorizedKeysWrite(input, facts) ||
		trustedCMDAuthorizedKeysWrite(input) ||
		trustedNamedOutFileAuthorizedKeysWrite(input) ||
		trustedGitBashAuthorizedKeysWrite(input) ||
		trustedNestedAuthorizedKeysWrite(input, facts)
}

// An unmodeled program's output option cannot prove a safe read. When that
// possible destination is the protected file, use the tool family's strict
// decision even though the remaining operand grammar is partial.
func trustedUnknownOutputAuthorizedKeysWrite(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite ||
			!matchesAuthorizedKeys(facts, candidate) {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete {
			continue
		}
		if slices.Contains(actionfacts.UnknownOutputOptionTargets(command.Argv), candidate.Value) {
			return true
		}
	}
	return false
}

func trustedGitConfigEnvironmentAuthorizedKeysWrite(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite ||
			!matchesAuthorizedKeys(facts, candidate) {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || command.Program != "git" || command.Effect != actionfacts.EffectExecute ||
			len(command.Argv) < 3 || command.Argv[1] != "config" {
			continue
		}
		for _, arg := range command.Argv[2:] {
			if arg == "--global" {
				return true
			}
		}
	}
	return false
}

// AWK source remains opaque. A statically parsed output option or inplace
// operand is still positive evidence of a protected write on a partial call.
func trustedAwkOutputAuthorizedKeysWrite(facts actionfacts.Facts) bool {
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite ||
			!matchesAuthorizedKeys(facts, candidate) {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete {
			continue
		}
		switch command.Program {
		case "gawk", "awk", "mawk", "nawk":
			return true
		}
	}
	return false
}

// archiveBeforeWriteTitle is the title of an authorized-keys block whose
// write follows an archive extraction. It is ship-authored, so it reaches
// the user as written (trustedBuiltInFindingLabel), and it holds no "; ",
// which splits a reason into parts that were each redacted, so the
// guidance never showed (GAP-1555).
const archiveBeforeWriteTitle = "Archive extraction may create a link before a later write. " +
	"Run the extraction and the write as separate commands"

// trustedUnknownKeyAuthorizedKeysWrite judges the target of a native
// file-write tool call (write, edit, multiedit, create) whose arguments
// carry a key outside the tool's reviewed schema: the harness still writes
// the file its target key names, so each such target is judged as the same
// tool's structured write (actionfacts.UnknownKeyWriteTargetViews). Only a
// match counts.
func trustedUnknownKeyAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	for _, view := range actionfacts.UnknownKeyWriteTargetViews(input, facts) {
		projected := view.EnforcementProjection()
		if projected.EnforcementEligible() && sshAuthorizedKeysStructuredPrerequisite(projected) {
			return true
		}
	}
	return false
}

// trustedSandboxGuestAuthorizedKeysWrite judges a sandbox call once more in
// the guest's own namespace. The request's working directory is the host
// directory the guest's one is mounted from (or none), while "~" is the
// guest home, so a relative target is resolved where the guest does not
// write it. The guest resolves it against its own working directory
// (request.SandboxGuestCWD, lexical): the call is analyzed with that
// directory and the authorized-keys proofs run on it. Only a match counts;
// host-side checks that read files are left out.
func trustedSandboxGuestAuthorizedKeysWrite(request trustedActionRequest) bool {
	guestCWD := request.SandboxGuestCWD
	if guestCWD == "" || guestCWD == request.Input.CWD {
		return false
	}
	input := request.Input
	input.CWD = guestCWD
	facts := actionfacts.Analyze(input)
	if input.Command == "" {
		if command, ok := trustedBashCommandInput(input); ok {
			input.Command = command
		}
	}
	return trustedAuthorizedKeysWriteProof(input, facts, false, nil)
}

func appendTrustedSSHPrivateKeyWriteFinding(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	input := request.Input
	for _, finding := range findings {
		if finding.RuleID == "PATH-SSH-DIR" {
			return findings
		}
	}
	if !homeResolvedTwinProves(input, facts, sshPrivateKeyMutationPrerequisite) {
		return findings
	}
	_, rule, ok := trustedActionCatalogRule(generation, "PATH-SSH-DIR")
	if !ok {
		return findings
	}
	enforcement := findingEnforcementAlertOnly
	if !request.EnforcementCapable {
		enforcement = findingEnforcementDetectionOnly
	}
	return append(findings, adjustConfidence(input.Tool, RuleFinding{
		RuleID:      rule.ID,
		Title:       rule.Title,
		Severity:    rule.Severity,
		Confidence:  rule.Confidence,
		Evidence:    trustedActionInputText(input, ""),
		Tags:        append([]string(nil), rule.Tags...),
		LineNumber:  1,
		enforcement: enforcement,
	}))
}

func sshAuthorizedKeysPrerequisite(
	facts actionfacts.Facts,
	structured bool,
) bool {
	for _, candidate := range facts.Paths {
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok ||
			!matchesAuthorizedKeys(facts, candidate) ||
			!integrityCommandMutatesPath(command, candidate) {
			continue
		}
		isStructured := integrityStructuredFileMutator(facts, command)
		if isStructured == structured &&
			(structured ||
				integrityExplicitCommandMutator(command, candidate)) {
			return true
		}
	}
	return false
}

func sshAuthorizedKeysCommandSafeNegative(
	facts actionfacts.Facts,
) bool {
	return sshAuthorizedKeysSafeNegative(facts, true)
}

func sshAuthorizedKeysPathSafeNegative(
	facts actionfacts.Facts,
) bool {
	return sshAuthorizedKeysSafeNegative(facts, false)
}

func sshAuthorizedKeysSafeNegative(
	facts actionfacts.Facts,
	commandOwner bool,
) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, candidate := range facts.Paths {
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok ||
			!matchesAuthorizedKeys(facts, candidate) ||
			!integrityCommandMutatesPath(command, candidate) {
			continue
		}
		structured := integrityStructuredFileMutator(facts, command)
		if commandOwner && structured {
			continue
		}
		// Unsupported commands keep N23's fallback. Exact N23 commands keep
		// H27's fallback until match-only alias suppression is applied.
		if commandOwner ||
			!structured {
			return false
		}
	}
	return integrityMutationSafeNegative(
		matchesSSHDirectoryCandidate,
		matchesAuthorizedKeys,
		matchesSafeSSHDirectoryCandidate,
	)(facts)
}

func integrityExplicitCommandMutator(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if integrityCommandOwnsStaticRedirect(command, candidate) {
		return true
	}
	if command.Effect != actionfacts.EffectExecute ||
		!command.ArgvComplete {
		return false
	}
	switch strings.ToLower(command.Program) {
	case "tee", "truncate", "rm", "unlink", "cp", "mv", "install", "sed", "curl", "wget", "copy",
		"find", "git", "gawk", "uniq",
		"move", "set-content", "sc", "add-content", "ac", "out-file",
		"remove-item", "ri", "copy-item", "cpi", "move-item", "mi":
		return true
	default:
		return false
	}
}

func integrityStructuredFileMutator(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) bool {
	if !strings.EqualFold(facts.Tool, command.Executable) &&
		!strings.EqualFold(facts.Tool, command.Program) {
		return false
	}
	switch strings.ToLower(command.Program) {
	case "write", "edit", "multiedit", "multi_edit", "multi-edit",
		"notebookedit", "notebook_edit", "notebook-edit",
		"writefile", "write_file", "write-file",
		"fswrite", "fs_write", "fs-write", "fs.write", "fs.write_file",
		"filewrite", "file_write", "file-write",
		"create", "createfile", "create_file", "create-file",
		"editfile", "edit_file", "edit-file",
		"applypatch", "apply_patch", "apply-patch",
		"appendfile", "append_file", "append-file",
		"deletefile", "delete_file", "delete-file",
		"removefile", "remove_file", "remove-file",
		"copyfile", "copy_file", "copy-file",
		"movefile", "move_file", "move-file":
		return true
	default:
		return false
	}
}

func containerRuntimeSocketPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!hasOperation(command, actionfacts.OperationConnect) {
			continue
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID == command.ID &&
				candidate.Access == actionfacts.PathAccessConnect &&
				matchesContainerRuntimeSocket(
					semanticPathValue(candidate),
				) {
				return true
			}
		}
	}
	return false
}

func matchesContainerRuntimeSocket(value string) bool {
	value = canonicalSemanticPath(value)
	switch value {
	case "/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/run/crio/crio.sock",
		"/var/run/crio/crio.sock",
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock":
		return true
	}
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if len(parts) == 4 && parts[0] == "run" && parts[1] == "user" &&
		integrityDecimal(parts[2]) && parts[3] == "docker.sock" {
		return true
	}
	return len(parts) == 5 &&
		parts[0] == "run" &&
		parts[1] == "user" &&
		integrityDecimal(parts[2]) &&
		parts[3] == "podman" &&
		parts[4] == "podman.sock"
}

func cloudMetadataPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!hasOperation(command, actionfacts.OperationFetch) {
			continue
		}
		for _, network := range facts.Network {
			if network.CommandID == command.ID &&
				(strings.EqualFold(network.Scheme, "http") ||
					strings.EqualFold(network.Scheme, "https")) &&
				networkActionIn(
					network.Action,
					actionfacts.NetworkDownload,
					actionfacts.NetworkConnect,
				) &&
				matchesCloudMetadataHost(network.NormalizedHost) {
				return true
			}
		}
	}
	return false
}

func matchesCloudMetadataHost(value string) bool {
	value = strings.Trim(
		strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), "."),
		"[]",
	)
	switch value {
	case "169.254.169.254",
		"169.254.170.2",
		"fd00:ec2::254",
		"metadata.google.internal",
		"metadata.azure.internal",
		"100.100.100.200":
		return true
	default:
		return false
	}
}

func matchesShellHistoryCandidate(value string) bool {
	switch pathBase(canonicalSemanticPath(value)) {
	case ".bash_history", ".zsh_history", ".python_history",
		"consolehost_history.txt":
		return true
	default:
		return false
	}
}

func matchesActiveShellHistory(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	switch relative {
	case ".bash_history", ".zsh_history", ".python_history",
		".local/share/powershell/psreadline/consolehost_history.txt",
		"appdata/roaming/microsoft/windows/powershell/psreadline/consolehost_history.txt":
		return true
	default:
		return false
	}
}

func matchesSudoersCandidate(value string) bool {
	value = canonicalSemanticPath(value)
	return value == "/etc/sudoers" ||
		strings.Contains(value, "/etc/sudoers.d/")
}

func matchesGlobalLDPreload(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	return canonicalSemanticPath(semanticPathValue(candidate)) == "/etc/ld.so.preload" &&
		(candidate.Access == actionfacts.PathAccessWrite ||
			candidate.Access == actionfacts.PathAccessAppend)
}

// globalLDPreloadInstallPrerequisite proves a system-wide loader injection
// only when a closed literal producer writes one absolute shared-object path
// to the active preload file, or one exact profile fragment exports that path.
// Merely reading either location, clearing it during remediation, setting
// process-local LD_PRELOAD, or writing opaque/dynamic content is insufficient.
func globalLDPreloadInstallPrerequisite(
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	if actionfacts.ExactGlobalLDPreloadProfileWrite(input, facts) {
		return true
	}
	for _, target := range facts.Paths {
		preloadFile := matchesGlobalLDPreload(facts, target)
		profileFragment := actionfacts.ExactGlobalLDPreloadProfilePath(
			semanticPathValue(target),
		) && target.Access == actionfacts.PathAccessWrite
		if !preloadFile && !profileFragment {
			continue
		}
		destination, ok := integrityCommandByID(facts, target.CommandID)
		if !ok || !integrityCommandMutatesPath(destination, target) ||
			destination.ControlFlowUncertain {
			continue
		}
		for _, source := range facts.Commands {
			if !sudoersLiteralOutputReachesDestination(facts, source, destination) {
				continue
			}
			content, ok := sudoersLiteralCommandOutput(source)
			if ok && (preloadFile && literalSharedObjectPath(content) ||
				profileFragment && actionfacts.ExactGlobalLDPreloadProfileContent(content)) {
				return true
			}
		}
	}
	return false
}

func literalSharedObjectPath(content string) bool {
	if strings.ContainsRune(content, '\x00') {
		return false
	}
	value := strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	if value == "" || !strings.HasPrefix(value, "/") ||
		strings.IndexFunc(value, func(r rune) bool { return r == '\n' || r == '\r' || r == '\t' || r == ' ' }) >= 0 {
		return false
	}
	base := path.Base(path.Clean(value))
	marker := strings.Index(base, ".so")
	return marker > 0 && (marker+3 == len(base) || base[marker+3] == '.')
}

func matchesActiveSudoers(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	return value == "/etc/sudoers" ||
		integritySingleChild(value, "/etc/sudoers.d")
}

var unrestrictedSudoersGrantLine = regexp.MustCompile(
	`^(%?[A-Za-z_][A-Za-z0-9_.-]*|ALL)[\t ]+ALL[\t ]*=[\t ]*\([\t ]*ALL(?:[\t ]*:[\t ]*ALL)?[\t ]*\)[\t ]+NOPASSWD[\t ]*:[\t ]*ALL[\t ]*$`,
)

// unrestrictedSudoersGrantPrerequisite accepts only authoritative,
// enforcement-eligible literal content whose resolved destination is an
// active sudoers target. It supports a closed set of direct writers and
// staged writer/sed/copy flows, while rejecting expandable heredocs,
// variables, command substitutions, aliases, includes, and opaque transforms.
func unrestrictedSudoersGrantPrerequisite(facts actionfacts.Facts) bool {
	// A dedicated closed terminal envelope may prove this fact even though the
	// generic shell parser conservatively marks redirected terminal input as
	// partial. No generic or malformed input can project the fact.
	if actionfacts.ExactPOSIXUnrestrictedSudoersGrantWrite(facts) ||
		actionfacts.ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts) {
		return true
	}
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	if stagedUnrestrictedSudoersCopy(facts) {
		return true
	}
	for _, target := range facts.Paths {
		if !integrityMutationAccess(target.Access) ||
			!matchesActiveSudoers(facts, target) {
			continue
		}
		destination, ok := integrityCommandByID(facts, target.CommandID)
		if !ok || !integrityCommandMutatesPath(destination, target) ||
			destination.ControlFlowUncertain {
			continue
		}
		if content, mutationTarget, proven :=
			actionfacts.StaticPOSIXSedInPlaceLiteralMutation(destination); proven && mutationTarget == target.Value &&
			containsUnrestrictedSudoersGrant(content) {
			return true
		}
		for _, source := range facts.Commands {
			if !sudoersLiteralOutputReachesDestination(facts, source, destination) {
				continue
			}
			content, ok := sudoersLiteralCommandOutput(source)
			if !ok {
				continue
			}
			if sudoersBase64StdinDecoder(destination) {
				content, ok = decodeBoundedSudoersBase64(content)
			}
			if ok && containsUnrestrictedSudoersGrant(content) {
				return true
			}
		}
	}
	return false
}

func stagedUnrestrictedSudoersCopy(facts actionfacts.Facts) bool {
	for copyIndex, command := range facts.Commands {
		source, destination, ok := exactPOSIXCopyEndpoints(facts, command)
		if !ok || !matchesActiveSudoers(facts, destination) {
			continue
		}
		for writerIndex := 0; writerIndex < copyIndex; writerIndex++ {
			writer := facts.Commands[writerIndex]
			if writer.ControlFlowUncertain || writer.Effect != actionfacts.EffectExecute {
				continue
			}
			content, ok := sudoersLiteralCommandOutput(writer)
			if !ok || !commandWritesResolvedPath(facts, writer.ID, source.Resolved) {
				continue
			}
			valid := true
			for mutationIndex := writerIndex + 1; mutationIndex < copyIndex; mutationIndex++ {
				mutation := facts.Commands[mutationIndex]
				if !commandMutatesExactResolvedPath(facts, mutation.ID, source.Resolved) {
					continue
				}
				mutated, target, applied := actionfacts.ApplyStaticPOSIXSedInPlaceLiteralMutation(
					mutation,
					content,
				)
				if !applied || canonicalSemanticPath(target) != canonicalSemanticPath(source.Resolved) {
					valid = false
					break
				}
				content = mutated
			}
			if valid && containsUnrestrictedSudoersGrant(content) {
				return true
			}
		}
	}
	return false
}

func exactPOSIXCopyEndpoints(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) (actionfacts.PathFact, actionfacts.PathFact, bool) {
	if command.Dialect != actionfacts.DialectPOSIX ||
		command.Program != "cp" || command.Effect != actionfacts.EffectExecute ||
		command.ControlFlowUncertain || !command.ArgvComplete ||
		len(command.Argv) != 3 || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 ||
		!hasOperation(command, actionfacts.OperationCopy) {
		return actionfacts.PathFact{}, actionfacts.PathFact{}, false
	}
	var source, destination actionfacts.PathFact
	readCount := 0
	writeCount := 0
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID || !candidate.Absolute || candidate.Resolved == "" {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessRead:
			source = candidate
			readCount++
		case actionfacts.PathAccessWrite:
			destination = candidate
			writeCount++
		}
	}
	if readCount != 1 || writeCount != 1 || source.Resolved == destination.Resolved {
		return actionfacts.PathFact{}, actionfacts.PathFact{}, false
	}
	return source, destination, true
}

func commandWritesResolvedPath(facts actionfacts.Facts, commandID int64, resolved string) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID && candidate.Resolved == resolved &&
			(candidate.Access == actionfacts.PathAccessWrite ||
				candidate.Access == actionfacts.PathAccessAppend) {
			return true
		}
	}
	return false
}

func commandMutatesExactResolvedPath(facts actionfacts.Facts, commandID int64, resolved string) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID != commandID || candidate.Resolved != resolved {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			return true
		}
	}
	return false
}

func sudoersBase64StdinDecoder(command actionfacts.CommandFact) bool {
	if !strings.EqualFold(command.Program, "base64") ||
		!hasOperation(command, actionfacts.OperationDecode) ||
		len(command.Argv) < 2 {
		return false
	}
	decode := false
	for _, argument := range command.Argv[1:] {
		if argument == "--decode" {
			decode = true
			continue
		}
		if len(argument) < 2 || argument[0] != '-' {
			return false
		}
		for _, option := range argument[1:] {
			if option != 'd' {
				return false
			}
			decode = true
		}
	}
	return decode
}

func decodeBoundedSudoersBase64(encoded string) (string, bool) {
	const maximumEncodedSudoersBytes = 4096
	if encoded == "" || len(encoded) > maximumEncodedSudoersBytes ||
		strings.IndexFunc(encoded, func(value rune) bool {
			return !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", value)
		}) != -1 {
		return "", false
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding.Strict(),
		base64.RawStdEncoding.Strict(),
	} {
		decoded, err := encoding.DecodeString(encoded)
		if err == nil {
			return string(decoded), true
		}
	}
	return "", false
}

func sudoersLiteralOutputReachesDestination(
	facts actionfacts.Facts,
	source actionfacts.CommandFact,
	destination actionfacts.CommandFact,
) bool {
	if source.Effect != actionfacts.EffectExecute ||
		source.ControlFlowUncertain || !source.ArgvComplete {
		return false
	}
	if source.ID == destination.ID {
		return true
	}
	if source.PipelineID != 0 && source.PipelineID == destination.PipelineID &&
		hasCommandDataFlow(
			facts,
			source.ID,
			destination.ID,
			actionfacts.DataStdout,
			actionfacts.DataStdin,
		) {
		return true
	}
	if destination.ParentCommandID == 0 || len(destination.Wrappers) != 1 ||
		destination.Wrappers[0].Executable != "sudo" {
		return false
	}
	parent, ok := integrityCommandByID(facts, destination.ParentCommandID)
	return ok && parent.Program == "sudo" && parent.ArgvComplete &&
		len(parent.Argv) == len(destination.Argv)+1 &&
		slices.Equal(parent.Argv[1:], destination.Argv) &&
		source.PipelineID != 0 && source.PipelineID == parent.PipelineID &&
		hasCommandDataFlow(
			facts,
			source.ID,
			parent.ID,
			actionfacts.DataStdout,
			actionfacts.DataStdin,
		)
}

func sudoersLiteralCommandOutput(command actionfacts.CommandFact) (string, bool) {
	if command.Dialect != actionfacts.DialectPOSIX ||
		len(command.Argv) != len(command.Arguments) {
		return "", false
	}
	for _, argument := range command.Arguments {
		if argument.Expands {
			return "", false
		}
	}
	switch strings.ToLower(command.Program) {
	case "cat":
		return actionfacts.StaticPOSIXCatLiteralStdinOutput(command)
	case "echo":
		if len(command.Argv) != 2 || strings.HasPrefix(command.Argv[1], "-") {
			return "", false
		}
		return command.Argv[1], true
	case "printf":
		segments := actionfacts.StaticPOSIXPrintfFormatStdoutSegments(command)
		if len(segments) == 1 && segments[0].LeftExact && segments[0].RightExact {
			return segments[0].Value, true
		}
		if len(command.Argv) != 3 ||
			(command.Argv[1] != `%s\n` && command.Argv[1] != "%s") {
			return "", false
		}
		return command.Argv[2], true
	default:
		return "", false
	}
}

func containsUnrestrictedSudoersGrant(content string) bool {
	if strings.ContainsRune(content, '\x00') {
		return false
	}
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") ||
			!unrestrictedSudoersGrantLine.MatchString(line) {
			continue
		}
		principal := strings.Fields(line)[0]
		if !strings.EqualFold(strings.TrimPrefix(principal, "%"), "root") {
			return true
		}
	}
	return false
}

func matchesSSHDirectoryCandidate(value string) bool {
	value = canonicalSemanticPath(value)
	return strings.Contains(value, "/.ssh/") ||
		strings.HasPrefix(value, ".ssh/") ||
		strings.HasSuffix(
			value,
			"/programdata/ssh/administrators_authorized_keys",
		)
}

// matchesAuthorizedKeys reports an account SSH authorized_keys file: the
// active user file, another account file under a home root (/root,
// /home/<user>, /Users/<user>, C:/Users/<user>), or the Windows
// administrators_authorized_keys. A key added to another account file grants
// SSH access to that account just the same, and matching only the active home
// let `sudo tee -a /root/.ssh/authorized_keys` and a literal
// C:\Users\<other> path through with no finding at all (GAP-1252).
func matchesAuthorizedKeys(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		if resolved := canonicalSemanticPath(semanticPathValue(candidate)); isAbsoluteSemanticPath(resolved) {
			relative, ok = liveHomeRelative(resolved)
		}
	}
	if ok && authorizedKeysRelative(relative) {
		return true
	}
	value := canonicalSemanticPath(semanticPathValue(candidate))
	const adminPath = "/programdata/ssh/administrators_authorized_keys"
	return len(value) == 2+len(adminPath) &&
		value[1] == ':' &&
		value[2:] == adminPath
}

func matchesSafeSSHDirectoryCandidate(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	if strings.HasSuffix(value, ".sample") ||
		strings.HasSuffix(value, ".example") {
		return true
	}
	relative, ok := activeHomeRelative(facts, candidate)
	return ok && strings.HasPrefix(relative, ".ssh/")
}

func matchesShellProfileCandidate(value string) bool {
	value = canonicalSemanticPath(value)
	if value == "/etc/profile" {
		return true
	}
	switch pathBase(value) {
	case ".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc",
		"config.fish", "profile.ps1", "microsoft.powershell_profile.ps1":
		return true
	default:
		return false
	}
}

func looksLikeSystemShellProfilePath(value string) bool {
	value = canonicalSemanticPath(value)
	if len(value) >= 3 && value[1] == ':' && value[2] == '/' {
		value = value[2:]
	}
	return value == "/etc/profile"
}

func matchesActiveShellProfile(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	if candidate.Flavor == actionfacts.PathFlavorPOSIX &&
		canonicalSemanticPath(semanticPathValue(candidate)) == "/etc/profile" {
		return true
	}
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	switch relative {
	case ".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc",
		".config/fish/config.fish",
		".config/powershell/profile.ps1",
		".config/powershell/microsoft.powershell_profile.ps1",
		"documents/powershell/profile.ps1",
		"documents/powershell/microsoft.powershell_profile.ps1",
		"documents/windowspowershell/profile.ps1",
		"documents/windowspowershell/microsoft.powershell_profile.ps1":
		return true
	default:
		return false
	}
}

func matchesSafeShellProfileCandidate(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	if value == "" || matchesActiveShellProfile(facts, candidate) {
		return false
	}
	if strings.HasSuffix(value, ".sample") ||
		strings.HasSuffix(value, ".example") {
		return true
	}
	// Once ActionFacts has resolved a complete path, a profile-shaped basename
	// outside the active home is not an active startup file. This distinction is
	// important for dotfile repositories such as
	// /var/lib/dotfiles/users/alice/.bashrc: the nested /users/alice suffix must
	// not acquire the authority of /Users/alice/.bashrc.
	return isAbsoluteSemanticPath(value) &&
		matchesShellProfileCandidate(value) &&
		value != "/etc/profile"
}

func matchesGitHookCandidate(value string) bool {
	value = canonicalSemanticPath(value)
	components := strings.Split(strings.Trim(value, "/"), "/")
	for index := 0; index+2 < len(components); index++ {
		if components[index] == ".git" &&
			components[index+1] == "hooks" &&
			index+3 == len(components) {
			return components[index+2] != ""
		}
	}
	return false
}

func matchesActiveGitHook(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	if matchesSafeGitHookCandidate(facts, candidate) ||
		integrityPathHasFixtureSegment(facts.CWD) {
		return false
	}
	if command, ok := integrityCommandByID(facts, candidate.CommandID); ok {
		if invocation, parsed := parseIntegrityGitInvocation(command); parsed &&
			oneOfFold(
				invocation.subcommand,
				"show", "log", "diff", "whatchanged",
			) && hasOperation(command, actionfacts.OperationWrite) {
			activeGitDir, contextOK := integrityGitDirectory(facts, invocation)
			if !contextOK {
				return false
			}
			value := canonicalSemanticPath(semanticPathValue(candidate))
			return integritySingleChild(
				value,
				strings.TrimRight(activeGitDir, "/")+"/hooks",
			)
		}
	}
	cwd := canonicalSemanticPath(facts.CWD)
	value := canonicalSemanticPath(semanticPathValue(candidate))
	if cwd == "" || value == "" ||
		!strings.HasPrefix(value, strings.TrimRight(cwd, "/")+"/.git/hooks/") {
		return false
	}
	return integritySingleChild(value, strings.TrimRight(cwd, "/")+"/.git/hooks")
}

func matchesSafeGitHookCandidate(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	return strings.HasSuffix(value, ".sample") ||
		strings.HasSuffix(value, ".example")
}

func matchesAgentConfigCandidate(value string) bool {
	switch pathBase(canonicalSemanticPath(value)) {
	case "openclaw.json", "gateway.json":
		return true
	default:
		return false
	}
}

func matchesActiveAgentConfig(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	return ok &&
		(relative == ".openclaw/openclaw.json" ||
			relative == ".openclaw/gateway.json")
}

func matchesDefenseClawStateCandidate(value string) bool {
	value = canonicalSemanticPath(value)
	return strings.Contains(value, "/.defenseclaw/") ||
		strings.HasPrefix(value, ".defenseclaw/")
}

func matchesActiveDefenseClawState(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if runtime.GOOS == "linux" && candidate.Flavor == actionfacts.PathFlavorPOSIX {
		relative, ok = exactActiveDefenseClawRelative(facts, candidate)
	}
	relative = strings.TrimRight(relative, "/")
	if !ok || relative != ".defenseclaw" && !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
	}
	state := strings.TrimPrefix(strings.TrimPrefix(relative, ".defenseclaw"), "/")
	switch state {
	// The state root and the protected trees themselves: removing,
	// moving or replacing one removes every file in it (GAP-1774). Removing
	// hooks/ turns protection off; removing installer/ breaks rollback.
	// Any other access is judged by the file it reaches (GAP-2045).
	case "", "cache", "hooks", "installer", "policies", "previous",
		"previous/installer", "quarantine", "receipts", "registries":
		return stateTreeEntryChanged(facts, candidate, state)
	case ".env", "config.yaml", "confidence_policy.yaml",
		"guardrail_runtime.json", "device.key", "picked_connector",
		"custom-providers.json", "audit.db", "audit.db-wal",
		"audit.db-shm", "judge.db", "judge.db-wal", "judge.db-shm",
		"judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm":
		return true
	}
	// installer/ and previous/installer/ hold the saved installer the
	// upgrade and rollback paths run (GAP-1099); its digest record is
	// receipts/installer.sha256.
	for _, prefix := range []string{
		"cache/",
		"hooks/",
		"installer/",
		"policies/",
		"previous/installer/",
		"quarantine/",
		"receipts/",
		"registries/",
	} {
		if strings.HasPrefix(state, prefix) &&
			strings.TrimPrefix(state, prefix) != "" {
			return true
		}
	}
	return false
}

// stateTreeEntryChanged judges an operand that names the state root or a
// protected tree itself, not a file in it (GAP-1774, GAP-2045). Removing
// the tree (a delete operand or a move source; a find -delete only when no
// test narrows it to some entries) changes it, and so does a copy or move
// onto a tree name, which replaces the tree or lands in it. A copy or move
// into the root is judged by the name it lands on. Every other access
// (mkdir -p, touch, chown -R, a read or a list) reaches the directory, not
// a protected file, so the result never depends on how a destination
// directory is spelled.
func stateTreeEntryChanged(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
	state string,
) bool {
	command, ok := integrityCommandByID(facts, candidate.CommandID)
	if !ok {
		return false
	}
	switch candidate.Access {
	case actionfacts.PathAccessDelete:
		return !findDeletesOnlyUnprotectedNames(command, state)
	case actionfacts.PathAccessMetadata:
		// chmod that lets group or other write the root or a tree hands
		// every file in it to another account, and a world-writable
		// hooks/ makes every hook fail closed (GAP-2077). Tightening
		// modes and chown/chgrp are judged by the file reached.
		return strings.EqualFold(command.Program, "chmod") && chmodAddsGroupOrOtherWrite(command)
	case actionfacts.PathAccessWrite:
		if !hasAnyOperation(command, actionfacts.OperationCopy, actionfacts.OperationMove) {
			return false
		}
		if state != "" {
			return true
		}
		destination := strings.TrimRight(strings.ReplaceAll(exactSemanticPathValue(candidate), `\`, "/"), "/")
		for _, source := range facts.Paths {
			if source.CommandID != candidate.CommandID || source.Access == actionfacts.PathAccessWrite {
				continue
			}
			base := path.Base(strings.TrimRight(strings.ReplaceAll(exactSemanticPathValue(source), `\`, "/"), "/"))
			if base == "." || base == ".." || base == "/" || destination == "" {
				continue
			}
			landing := candidate
			landing.Value = destination + "/" + base
			landing.Normalized, landing.Resolved = landing.Value, landing.Value
			if matchesActiveDefenseClawState(facts, landing) {
				return true
			}
		}
	}
	return false
}

// findDeletesOnlyUnprotectedNames reports a find -delete that removes only
// entries no protected state name can be (log cleanup such as
// `find ~/.defenseclaw -name '*.log' -mtime +7 -delete`), not the tree it
// starts from (GAP-2075). It holds only for a find from the state root
// (state ""), whose tests are all joined by AND, with every -name or -iname
// pattern a cleanup pattern (findPatternIsCleanupOnly) and one of them before
// the first action. find evaluates its expression left to right, so an
// action placed before the name test (`find ~/.defenseclaw -delete -name
// '*.log'`) runs on every entry (GAP-2075). A start at a protected tree, a
// time, size or path test alone, and an OR or a negation never exempt,
// because each can still reach config.yaml, a hook, a rule pack file or the
// saved installer.
func findDeletesOnlyUnprotectedNames(command actionfacts.CommandFact, state string) bool {
	if state != "" || !strings.EqualFold(command.Program, "find") || len(command.Argv) < 2 {
		return false
	}
	named, acted := false, false
	for index := 1; index < len(command.Argv); index++ {
		argument := strings.ToLower(command.Argv[index])
		switch argument {
		case "-o", "-or", "!", "-not", ",":
			return false
		case "-name", "-iname":
			if index+1 >= len(command.Argv) {
				return false
			}
			index++
			if !findPatternIsCleanupOnly(command.Argv[index], argument == "-iname") {
				return false
			}
			named = named || !acted
		case "-delete":
			if !named {
				return false
			}
			acted = true
		case "-exec", "-execdir", "-ok", "-okdir":
			if !named {
				return false
			}
			acted = true
			// The command of the action ends at ';' or '+'; its words are
			// not find tests.
			for index+1 < len(command.Argv) && command.Argv[index+1] != ";" && command.Argv[index+1] != "+" {
				index++
			}
			index++
		}
	}
	return named && acted
}

// protectedStateNameSamples are names a file of the active state can have:
// the root's own files, the tree names and files the trees hold (hooks, the
// saved installer and its digest, policies, receipts). A cleanup pattern
// that matches one of them is not exempt.
var protectedStateNameSamples = []string{
	".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
	"device.key", "picked_connector", "custom-providers.json", "audit.db",
	"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal", "judge.db-shm",
	"judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm",
	"cache", "hooks", "installer", "policies", "previous", "quarantine",
	"receipts", "registries",
	"claude-code-hook.sh", "inspect-tool.sh", "_hardening.sh", "hook.ps1", "hook.cmd",
	"install.sh", "install.ps1", "binaries.sha256", "installer.sha256",
	"defenseclaw-hook-post", "default.yaml", "rules.yml", "policy.rego", "data.json",
}

// cleanupNameMarkers are the file kinds a state-root cleanup removes: logs,
// temporary files, backups, rotated or compressed copies and event logs.
// No hook, rule pack, config, receipt or installer file has one, while a
// hand list of protected names can never be complete (every connector adds
// its own hook names and every pack its own rule files).
var cleanupNameMarkers = []string{".log", ".tmp", ".bak", ".old", ".gz", ".jsonl"}

// findPatternIsCleanupOnly reports a -name/-iname pattern that selects only
// cleanup files: it carries a cleanup marker as literal text (outside any
// bracket expression or wildcard, findPatternLiteralText) and matches none
// of the sample protected names. Every other pattern (a hook name,
// codex*, *.yaml, *) can reach protected state and is not exempt (GAP-2075).
func findPatternIsCleanupOnly(pattern string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
	}
	literal, ok := findPatternLiteralText(pattern)
	if !ok {
		return false
	}
	literal = strings.ToLower(literal)
	marked := false
	for _, marker := range cleanupNameMarkers {
		if strings.Contains(literal, marker) {
			marked = true
			break
		}
	}
	if !marked {
		return false
	}
	for _, name := range protectedStateNameSamples {
		if fold {
			name = strings.ToLower(name)
		}
		matched, err := path.Match(pattern, name)
		if err != nil || matched {
			return false
		}
	}
	return true
}

// findPatternLiteralText returns the text a name must hold for a find glob
// pattern to match it: escaped characters are kept, while '*', '?' and a
// whole bracket expression become a separator, so a cleanup marker spelled
// inside a bracket (`codex*[.log]*` matches codex-hook.sh) is not literal
// (GAP-2075). An unterminated bracket reports false.
func findPatternLiteralText(pattern string) (string, bool) {
	var literal strings.Builder
	for index := 0; index < len(pattern); index++ {
		switch character := pattern[index]; character {
		case '\\':
			if index+1 < len(pattern) {
				index++
				literal.WriteByte(pattern[index])
			}
		case '*', '?':
			literal.WriteByte(0)
		case '[':
			end := index + 1
			if end < len(pattern) && (pattern[end] == '!' || pattern[end] == '^') {
				end++
			}
			if end < len(pattern) && pattern[end] == ']' {
				end++
			}
			for end < len(pattern) && pattern[end] != ']' {
				if pattern[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(pattern) {
				return "", false
			}
			index = end
			literal.WriteByte(0)
		default:
			literal.WriteByte(character)
		}
	}
	return literal.String(), true
}

// chmodAddsGroupOrOtherWrite reports a chmod whose mode gives group or
// other write: an octal mode with 0o022 bits, or a symbolic clause naming
// g, o or a with + or = and w, or a macOS ACL entry (+a, =a, +ai and their
// # forms) that allows a write permission. A mode with no who letters is
// filtered by the umask and is not counted. GNU (-R -c -f -v) and BSD/macOS
// (-h -H -L -P) options before the mode are skipped.
func chmodAddsGroupOrOtherWrite(command actionfacts.CommandFact) bool {
	argv := command.Argv
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch {
		case argument == "--":
			continue
		case strings.HasPrefix(argument, "--"):
			if strings.HasPrefix(argument, "--reference") {
				return false
			}
			continue
		case len(argument) > 1 && argument[0] == '-' && strings.Trim(argument[1:], "RcfvhHLP") == "":
			continue
		case argument == "+a" || argument == "=a" || argument == "+ai":
			return index+1 < len(argv) && chmodACLAllowsWrite(argv[index+1])
		case argument == "+a#" || argument == "=a#" || argument == "+ai#":
			return index+2 < len(argv) && chmodACLAllowsWrite(argv[index+2])
		}
		return chmodModeAddsGroupOrOtherWrite(argument)
	}
	return false
}

// chmodACLAllowsWrite reports a macOS ACL entry ("everyone allow write")
// that grants a permission which changes a file or a directory's entries.
func chmodACLAllowsWrite(entry string) bool {
	fields := strings.FieldsFunc(strings.ToLower(entry), func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})
	allow := false
	for _, field := range fields {
		switch field {
		case "allow":
			allow = true
		case "deny":
			return false
		case "write", "append", "add_file", "add_subdirectory", "delete", "delete_child", "writesecurity", "chown":
			if allow {
				return true
			}
		}
	}
	return false
}

func chmodModeAddsGroupOrOtherWrite(mode string) bool {
	if mode != "" && strings.Trim(mode, "01234567") == "" {
		value, err := strconv.ParseUint(mode, 8, 32)
		return err == nil && value&0o022 != 0
	}
	for _, clause := range strings.Split(mode, ",") {
		who := strings.TrimLeft(clause, "ugoa")
		groupOrOther := strings.ContainsAny(clause[:len(clause)-len(who)], "goa")
		for operations := who; operations != ""; {
			operator := operations[0]
			rest := strings.TrimLeft(operations[1:], "rwxXstugo")
			perms := operations[1 : len(operations)-len(rest)]
			if groupOrOther && (operator == '+' || operator == '=') && strings.ContainsAny(perms, "wugo") {
				return true
			}
			if operator != '+' && operator != '-' && operator != '=' {
				return false
			}
			operations = rest
		}
	}
	return false
}

func matchesSafeDefenseClawStateCandidate(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok || !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
	}
	// POSIX Linux names are case-sensitive. A distinct .DefenseClaw tree is
	// ordinary user work even though the catalog's regex is case-insensitive.
	if runtime.GOOS == "linux" && candidate.Flavor == actionfacts.PathFlavorPOSIX {
		exact, inside := exactActiveDefenseClawRelative(facts, candidate)
		if !inside || !strings.HasPrefix(exact, ".defenseclaw/") {
			return true
		}
	}
	state := strings.TrimPrefix(relative, ".defenseclaw/")
	for _, prefix := range []string{
		"logs/",
		"reports/",
		"exports/",
		"tui/",
	} {
		if strings.HasPrefix(state, prefix) {
			return true
		}
	}
	return state == "gateway.jsonl" ||
		state == "gateway.log" ||
		state == "gateway.pid"
}

func exactActiveDefenseClawRelative(facts actionfacts.Facts, candidate actionfacts.PathFact) (string, bool) {
	home := strings.TrimRight(path.Clean(facts.ActiveHome), "/")
	resolved := path.Clean(exactSemanticPathValue(candidate))
	if home == "" || !strings.HasPrefix(resolved, home+"/") {
		return "", false
	}
	return strings.TrimPrefix(resolved, home+"/"), true
}

func integritySingleChild(value, parent string) bool {
	value = strings.Trim(canonicalSemanticPath(value), "/")
	parent = strings.Trim(canonicalSemanticPath(parent), "/")
	if !strings.HasPrefix(value, parent+"/") {
		return false
	}
	child := strings.TrimPrefix(value, parent+"/")
	return child != "" && !strings.ContainsRune(child, '/')
}

func integritySingleChildWithSuffix(
	value, parent string,
	suffixes ...string,
) bool {
	if !integritySingleChild(value, parent) {
		return false
	}
	if len(suffixes) == 0 {
		return true
	}
	base := pathBase(canonicalSemanticPath(value))
	for _, suffix := range suffixes {
		if suffix == "" || strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func integrityPathHasFixtureSegment(value string) bool {
	for _, component := range strings.Split(
		strings.Trim(canonicalSemanticPath(value), "/"),
		"/",
	) {
		switch component {
		case "testdata", "test-data", "fixture", "fixtures",
			"example", "examples", "docs":
			return true
		}
	}
	return false
}

func integrityDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func integrityExecutingOwnedCommand(
	command actionfacts.CommandFact,
	programs ...string,
) bool {
	if command.Effect != actionfacts.EffectExecute ||
		!command.ArgvComplete {
		return false
	}
	return oneOfFold(command.Program, programs...)
}

const typedGuardrailsOffRuleID = "tamper.guardrails_off"

func provesTypedGuardrailsOff(
	kind string,
	trusted bool,
	previousEnforcementEnabled bool,
	newEnforcementEnabled bool,
	effect actionfacts.CommandEffect,
) bool {
	return kind == "guardrail_config_change" &&
		trusted &&
		previousEnforcementEnabled &&
		!newEnforcementEnabled &&
		effect == actionfacts.EffectExecute
}
