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
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	semanticHistoryTamperExpression = `f.commands.exists(c, c.argv_complete && (c.program == 'history' || (c.program == 'unset' && 'HISTFILE' in c.argv)))`
	// The owner binds this mutation shape to the exact active instruction file,
	// using trusted case-sensitivity metadata captured when the file was loaded.
	// Owner eligibility accepts only executing mutations (or static redirects
	// that remain executing in the enforcement projection), so an unrelated
	// sibling mutation cannot lend it authority.
	semanticActiveAgentInstructionMutationExpression = `f.commands.exists(c, f.paths.exists(p, p.command_id == c.id && p.access in [defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE, defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_APPEND, defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_DELETE]))`
)

var semanticIntegrityPersistenceOwners = map[string]semanticOwner{
	"CMD-CRONTAB": {
		prerequisite:     crontabInstallPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-SYSTEMCTL": {
		matchedOnlyAliases: []string{"CMD-WIN-REG-PERSIST"},
		prerequisite:       schedulerInstallPrerequisite,
		suppressFallback:   authoritativeSemanticSafeNegative,
	},
	"COG-AGENTS-MD": activeAgentInstructionMutationOwner("AGENTS.md"),
	"COG-MEMORY":    activeAgentInstructionMutationOwner("MEMORY.md"),
	"integrity.git_hooks_bypass": {
		prerequisite:     gitHooksBypassPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"source.git_remote_tamper": {
		prerequisite:     gitRemoteTamperPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
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
	"PATH-SSH-DIR": {
		prerequisite:     sshAuthorizedKeysStructuredPrerequisite,
		suppressFallback: sshAuthorizedKeysPathSafeNegative,
	},
	"privilege.container_runtime_socket_access": {
		prerequisite:     containerRuntimeSocketPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"persistence.shell_profile_write": integrityMutationOwner(
		matchesShellProfileCandidate, matchesActiveShellProfile, nil,
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
		"COG-GATEWAY-JSON",
	),
	"tamper.detector_state_write": integrityMutationOwner(
		matchesDefenseClawStateCandidate,
		matchesActiveDefenseClawState,
		matchesSafeDefenseClawStateCandidate,
	),
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
	owner.suppressFallback = integrityMutationSafeNegativeWithFixture(
		isCandidate,
		isActive,
		isSafe,
		nil,
	)
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
		)
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
			redirect.Target == candidate.Value &&
			redirect.Access == candidate.Access &&
			integrityMutationAccess(redirect.Access) {
			return true
		}
	}
	return false
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
		case "reg", "reg.exe", "set-itemproperty", "sp",
			"new-itemproperty":
			if !hasOperation(command, actionfacts.OperationConfigChange) {
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
	}
	return integrityMutationPrerequisite(matchesActiveSchedulerPath)(facts)
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
		if len(argv) < 2 ||
			(argv[1] != "add" && argv[1] != "set-url") {
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

func sshAuthorizedKeysPrerequisite(
	facts actionfacts.Facts,
	structured bool,
) bool {
	for _, candidate := range facts.Paths {
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok ||
			!matchesActiveAuthorizedKeys(facts, candidate) ||
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
			!matchesActiveAuthorizedKeys(facts, candidate) ||
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
		matchesActiveAuthorizedKeys,
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
	case "tee", "truncate", "rm", "unlink", "cp", "mv", "copy",
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
		"createfile", "create_file", "create-file",
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

func matchesActiveSudoers(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	return value == "/etc/sudoers" ||
		integritySingleChild(value, "/etc/sudoers.d")
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

func matchesActiveAuthorizedKeys(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if ok &&
		(relative == ".ssh/authorized_keys" ||
			relative == ".ssh/authorized_keys2") {
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
	if !ok || !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
	}
	state := strings.TrimPrefix(relative, ".defenseclaw/")
	switch state {
	case ".env", "config.yaml", "confidence_policy.yaml",
		"guardrail_runtime.json", "device.key", "picked_connector",
		"custom-providers.json", "audit.db", "audit.db-wal",
		"audit.db-shm", "judge.db", "judge.db-wal", "judge.db-shm",
		"judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm":
		return true
	}
	for _, prefix := range []string{
		"cache/",
		"policies/",
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

func matchesSafeDefenseClawStateCandidate(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok || !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
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
