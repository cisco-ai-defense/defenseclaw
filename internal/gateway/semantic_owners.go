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
	"net/netip"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

type semanticOwnerPrerequisite func(actionfacts.Facts) bool

type semanticOwner struct {
	id                     string
	equivalentAliases      []string
	matchedOnlyAliases     []string
	fallbackAliasesOnMatch []string
	unmatchedClaims        []string
	prerequisite           semanticOwnerPrerequisite
	suppressFallback       semanticOwnerPrerequisite
}

func (o semanticOwner) eligible(facts actionfacts.Facts) bool {
	return o.prerequisite == nil || o.prerequisite(facts)
}

func (o semanticOwner) claimedIDs(matched bool) []string {
	if !matched && len(o.unmatchedClaims) != 0 {
		return append([]string(nil), o.unmatchedClaims...)
	}
	ids := make([]string, 0, 1+len(o.equivalentAliases)+len(o.matchedOnlyAliases))
	ids = append(ids, o.id)
	ids = append(ids, o.equivalentAliases...)
	if matched {
		ids = append(ids, o.matchedOnlyAliases...)
	}
	return ids
}

type compiledSemanticRule struct {
	rule    PatternRule
	program *semantic.Program
	owner   semanticOwner
}

var semanticOwners = buildSemanticOwners(map[string]semanticOwner{
	"PATH-ENV-FILE": {
		prerequisite: pathOwnerPrerequisite(
			matchesContextualEnvironmentFile,
		),
		suppressFallback: sensitivePathSafeNegativePreservingWrites(
			matchesEnvironmentFile,
			matchesContextualEnvironmentFile,
		),
	},
	"PATH-SSH-KEY": {
		equivalentAliases: []string{"PATH-WIN-SSH-KEY"},
		prerequisite:      pathOwnerPrerequisite(matchesActiveSSHPrivateKey),
		suppressFallback: sensitivePathSafeNegativePreservingWrites(
			matchesSSHPrivateKey,
			matchesActiveSSHPrivateKey,
		),
	},
	"PATH-AWS-CREDS": {
		equivalentAliases: []string{"PATH-WIN-AWS-CREDS"},
		prerequisite:      pathOwnerPrerequisite(matchesActiveAWSCredentials),
		suppressFallback:  pathOwnerSafeNegative(matchesAWSCredentials, matchesActiveAWSCredentials),
	},
	"PATH-KUBE": {
		equivalentAliases: []string{"PATH-WIN-KUBE-CONFIG"},
		prerequisite:      pathOwnerPrerequisite(matchesActiveKubeConfig),
		suppressFallback:  pathOwnerSafeNegative(matchesKubeConfig, matchesActiveKubeConfig),
	},
	"PATH-DOCKER": {
		equivalentAliases: []string{"PATH-NPMRC", "PATH-PYPIRC"},
		prerequisite:      pathOwnerPrerequisite(matchesActivePackageCredentialFile),
		suppressFallback:  pathOwnerSafeNegative(matchesPackageCredentialFile, matchesActivePackageCredentialFile),
	},
	"PATH-GIT-CREDS": {
		equivalentAliases: []string{
			"PATH-NETRC",
			"PATH-WIN-GIT-CREDS",
			"PATH-WIN-NETRC",
		},
		prerequisite:     pathOwnerPrerequisite(matchesActiveGitCredentialFile),
		suppressFallback: pathOwnerSafeNegative(matchesGitCredentialFile, matchesActiveGitCredentialFile),
	},
	"PATH-PROC-ENVIRON": {
		prerequisite:     pathOwnerPrerequisite(pathValueMatcher(matchesProcEnviron)),
		suppressFallback: pathOwnerSafeNegative(matchesProcEnvironCandidate, pathValueMatcher(matchesProcEnviron)),
	},
	"CMD-ENV-DUMP": {
		matchedOnlyAliases: []string{"CMD-WGET-POST"},
		prerequisite:       environmentDumpExternalPrerequisite,
		suppressFallback:   environmentDumpSafeNegative,
	},
	"CMD-CURL-UPLOAD": {
		prerequisite:     externalFileUploadPrerequisite,
		suppressFallback: fileUploadSafeNegative,
	},
	"CMD-PIPE-CURL": {
		equivalentAliases: []string{"CMD-WIN-IWR-IEX"},
		prerequisite:      curlDownloadExecPrerequisite,
		suppressFallback:  authoritativeSemanticSafeNegative,
	},
	"CMD-PIPE-WGET": {
		prerequisite:     wgetDownloadExecPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-PIPE-BASE64": {
		prerequisite:     base64DecodeExecPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-REVSHELL-BASH": {
		equivalentAliases: []string{"CMD-REVSHELL-NC", "CMD-SOCAT-EXEC"},
		unmatchedClaims:   []string{"CMD-REVSHELL-NC", "CMD-SOCAT-EXEC"},
		prerequisite:      staticReverseShellPrerequisite,
		suppressFallback:  staticReverseShellSafeNegative,
	},
	"exec.reverse_tunnel": {
		prerequisite:     reverseTunnelPrerequisite,
		suppressFallback: reverseTunnelSafeNegative,
	},
	"exec.agent_runtime_bypass_flags": {
		prerequisite:     agentRuntimeBypassPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"secrets.cloud_credential_read": {
		prerequisite:     pathOwnerPrerequisite(matchesContextualCloudCredentialFile),
		suppressFallback: pathOwnerSafeNegative(matchesCloudCredentialFallbackCandidate, matchesContextualCloudCredentialFile),
	},
	"secrets.browser_session_store_read": {
		prerequisite:     pathOwnerPrerequisite(matchesContextualBrowserSessionStore),
		suppressFallback: pathOwnerSafeNegative(matchesBrowserSessionFallbackCandidate, matchesContextualBrowserSessionStore),
	},
	"secrets.workload_identity_token_read": {
		prerequisite:     pathOwnerPrerequisite(pathValueMatcher(matchesWorkloadIdentityToken)),
		suppressFallback: pathOwnerSafeNegative(matchesWorkloadIdentityTokenCandidate, pathValueMatcher(matchesWorkloadIdentityToken)),
	},
	"secrets.cloud_secret_manager_read": {
		prerequisite:     cloudSecretManagerPrerequisite,
		suppressFallback: cloudSecretManagerPreviewSafeNegative,
	},
	"exfil.secret_read_and_egress_oneliner": {
		prerequisite:     sensitiveReadAndEgressPrerequisite,
		suppressFallback: readAndEgressSafeNegative,
	},
})

func buildSemanticOwners(owners map[string]semanticOwner) map[string]semanticOwner {
	registerSemanticOwners(owners, semanticReconImpactOwners)
	registerSemanticOwners(owners, semanticIntegrityPersistenceOwners)
	for ownerID, aliases := range semanticIntegrityPersistenceFallbackAliasesOnMatch {
		owner, ok := owners[ownerID]
		if !ok {
			panic("semantic fallback alias registered for unknown owner " + ownerID)
		}
		owner.fallbackAliasesOnMatch = append([]string(nil), aliases...)
		owners[ownerID] = owner
	}
	return owners
}

func registerSemanticOwners(
	owners map[string]semanticOwner,
	additions map[string]semanticOwner,
) {
	for ruleID, owner := range additions {
		if _, exists := owners[ruleID]; exists {
			panic("duplicate semantic owner " + ruleID)
		}
		owners[ruleID] = owner
	}
}

func semanticOwnerForRule(ruleID string) semanticOwner {
	owner, ok := semanticOwners[ruleID]
	if !ok {
		return semanticOwner{id: ruleID}
	}
	owner.id = ruleID
	return owner
}

func powerShellDownloadExecPrerequisite(facts actionfacts.Facts) bool {
	for _, source := range facts.Commands {
		if source.Dialect != actionfacts.DialectPowerShell ||
			source.Effect != actionfacts.EffectExecute ||
			!oneOfFold(source.Program, "invoke-webrequest", "iwr", "invoke-restmethod", "irm") ||
			(!hasOperation(source, actionfacts.OperationFetch) &&
				!hasOperation(source, actionfacts.OperationUpload)) ||
			source.PipelineID == 0 || commandWritesPath(facts, source.ID) {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.Dialect == actionfacts.DialectPowerShell &&
				destination.Effect == actionfacts.EffectExecute &&
				destination.PipelineID == source.PipelineID &&
				oneOfFold(destination.Program, "invoke-expression", "iex") &&
				hasCommandDataFlow(
					facts,
					source.ID,
					destination.ID,
					actionfacts.DataStdout,
					actionfacts.DataStdin,
				) {
				return true
			}
		}
	}
	return false
}

func commandWritesPath(facts actionfacts.Facts, commandID int64) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID &&
			candidate.Access == actionfacts.PathAccessWrite {
			return true
		}
	}
	return false
}

func powerShellDownloadExecSafeNegative(facts actionfacts.Facts) bool {
	if !facts.Authoritative() ||
		facts.Parse.Dialect != actionfacts.DialectPowerShell {
		return false
	}
	sawPowerShellFetcher := false
	for _, command := range facts.Commands {
		if oneOfFold(
			command.Program,
			"invoke-webrequest",
			"iwr",
			"invoke-restmethod",
			"irm",
		) {
			sawPowerShellFetcher = true
			continue
		}
		if command.Effect != actionfacts.EffectExecute ||
			!oneOfFold(command.Program, "curl", "curl.exe") {
			continue
		}
		// A separate curl statement may still own the POSIX fallback. Do not
		// let an unrelated, benign PowerShell fetch suppress that candidate.
		return false
	}
	return sawPowerShellFetcher
}

func staticReverseShellPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ArgvComplete &&
			oneOfFold(command.Program, "nc", "nc.exe", "ncat", "ncat.exe", "netcat", "socat") &&
			hasExternalNetworkAction(
				facts,
				command.ID,
				actionfacts.NetworkConnect,
				actionfacts.NetworkListen,
			) {
			return true
		}
	}
	return false
}

func staticReverseShellSafeNegative(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ArgvComplete &&
			oneOfFold(command.Program, "nc", "nc.exe", "ncat", "ncat.exe", "netcat", "socat") &&
			hasDeterminateNonExternalNetworkAction(
				facts,
				command.ID,
				actionfacts.NetworkConnect,
				actionfacts.NetworkListen,
			) {
			return true
		}
	}
	return false
}

func reverseTunnelPrerequisite(facts actionfacts.Facts) bool {
	return reverseTunnelFallbackProof(facts)
}

func reverseTunnelPreviewPrerequisite(facts actionfacts.Facts) bool {
	foundPreview := false
	for _, command := range facts.Commands {
		if !command.ArgvComplete || !oneOfFold(command.Program, "ssh", "ssh.exe") {
			continue
		}
		hasConfigNone := false
		hasReverse := false
		hasPreview := false
		for index, argument := range command.Argv {
			if strings.EqualFold(argument, "-F") &&
				index+1 < len(command.Argv) &&
				strings.EqualFold(command.Argv[index+1], "none") {
				hasConfigNone = true
			}
			if strings.EqualFold(argument, "-R") {
				hasReverse = true
			}
			if strings.EqualFold(argument, "-G") {
				hasPreview = true
			}
		}
		if hasConfigNone && hasReverse && hasPreview {
			foundPreview = true
		}
		if hasConfigNone && hasReverse && !hasPreview {
			return false
		}
	}
	return foundPreview
}

func reverseTunnelSafeNegative(facts actionfacts.Facts) bool {
	return reverseTunnelPreviewPrerequisite(facts) ||
		reverseTunnelNonExternalPrerequisite(facts)
}

func reverseTunnelNonExternalPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			!exactReverseTunnelArgv(command) {
			continue
		}
		if hasDeterminateNonExternalNetworkAction(
			facts,
			command.ID,
			actionfacts.NetworkTunnel,
			actionfacts.NetworkConnect,
		) {
			return true
		}
	}
	return false
}

func agentRuntimeBypassPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectExecute &&
			hasOperation(command, actionfacts.OperationPolicyBypass) {
			return true
		}
	}
	return false
}

func authoritativeSemanticSafeNegative(facts actionfacts.Facts) bool {
	return facts.Authoritative()
}

type semanticPathMatcher func(actionfacts.Facts, actionfacts.PathFact) bool
type semanticPathCandidate func(string) bool

func pathOwnerPrerequisite(matches semanticPathMatcher) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		for _, command := range facts.Commands {
			if command.Effect != actionfacts.EffectExecute ||
				!hasOperation(command, actionfacts.OperationRead) {
				continue
			}
			for _, path := range facts.Paths {
				if path.CommandID == command.ID &&
					path.Access == actionfacts.PathAccessRead &&
					matches(facts, path) {
					return true
				}
			}
		}
		return false
	}
}

func pathValueMatcher(matches semanticPathCandidate) semanticPathMatcher {
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return matches(semanticPathValue(candidate))
	}
}

func pathOwnerSafeNegative(
	isCandidate semanticPathCandidate,
	isActive semanticPathMatcher,
) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		if !facts.Authoritative() {
			return false
		}
		sawCandidate := false
		for _, candidate := range semanticPathCandidates(facts) {
			if !isCandidate(semanticPathValue(candidate)) {
				continue
			}
			sawCandidate = true
			if isActive(facts, candidate) ||
				isDefiniteFixturePath(facts, candidate) {
				continue
			}
			// An unresolved path or a different user's live-home target must
			// retain the regex fallback.
			return false
		}
		return sawCandidate
	}
}

// sensitivePathSafeNegativePreservingWrites distinguishes a proven sensitive
// file mutation from a read or inert filename reference. Read expressions keep
// their semantic owner, fixture/reference-only inputs are safe negatives, and
// a live write deliberately retains the compatibility lane until a dedicated
// write expression owns it.
func sensitivePathSafeNegativePreservingWrites(
	isCandidate semanticPathCandidate,
	isActive semanticPathMatcher,
) semanticOwnerPrerequisite {
	baseSafeNegative := pathOwnerSafeNegative(isCandidate, isActive)
	return func(facts actionfacts.Facts) bool {
		if !facts.Authoritative() {
			return false
		}
		for _, candidate := range facts.Paths {
			if !isCandidate(semanticPathValue(candidate)) ||
				!isActive(facts, candidate) ||
				integrityPathHasFixtureSegment(semanticPathValue(candidate)) {
				continue
			}
			command, ok := integrityCommandByID(facts, candidate.CommandID)
			if ok && integrityCommandMutatesPath(command, candidate) {
				return false
			}
		}
		return baseSafeNegative(facts)
	}
}

func semanticPathCandidates(facts actionfacts.Facts) []actionfacts.PathFact {
	candidates := append([]actionfacts.PathFact(nil), facts.Paths...)
	for _, command := range facts.Commands {
		for argumentIndex, argument := range command.Argv {
			if argumentIndex == 0 {
				continue
			}
			value := strings.Trim(strings.TrimSpace(argument), `"'`)
			if value == "" || strings.HasPrefix(value, "-") {
				continue
			}
			candidate := actionfacts.PathFact{
				CommandID: command.ID,
				Value:     value,
			}
			normalized := canonicalSemanticPath(value)
			candidate.Normalized = normalized
			if isAbsoluteSemanticPath(normalized) {
				candidate.Resolved = normalized
			} else if facts.CWD != "" {
				candidate.Resolved = path.Clean(
					strings.TrimRight(canonicalSemanticPath(facts.CWD), "/") +
						"/" + normalized,
				)
			}
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func isDefiniteFixturePath(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	resolved := canonicalSemanticPath(candidate.Resolved)
	cwd := canonicalSemanticPath(facts.CWD)
	if resolved == "" || cwd == "" ||
		isRecognizedHomeRoot(cwd) ||
		!pathWithin(resolved, cwd) {
		return false
	}
	return true
}

func canonicalSemanticPath(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	if value == "" {
		return ""
	}
	return path.Clean(value)
}

func isAbsoluteSemanticPath(value string) bool {
	return strings.HasPrefix(value, "/") ||
		(len(value) >= 3 &&
			value[1] == ':' &&
			value[2] == '/')
}

func pathWithin(value, parent string) bool {
	value = strings.TrimRight(value, "/")
	parent = strings.TrimRight(parent, "/")
	return value == parent || strings.HasPrefix(value, parent+"/")
}

func isRecognizedHomeRoot(value string) bool {
	value = strings.TrimRight(value, "/")
	if value == "/root" ||
		isSingleUserHomeRoot(value, "/home/") ||
		isSingleUserHomeRoot(value, "/users/") {
		return true
	}
	return len(value) >= 4 &&
		value[1] == ':' &&
		isSingleUserHomeRoot(value[2:], "/users/")
}

func isSingleUserHomeRoot(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	user := strings.TrimPrefix(value, prefix)
	return user != "" && !strings.ContainsRune(user, '/')
}

func activeHomeRelative(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) (string, bool) {
	home := canonicalSemanticPath(facts.ActiveHome)
	resolved := canonicalSemanticPath(candidate.Resolved)
	if resolved == "" {
		resolved = canonicalSemanticPath(candidate.Normalized)
	}
	if resolved == "" {
		resolved = canonicalSemanticPath(candidate.Value)
	}
	if home == "" || resolved == "" || !pathWithin(resolved, home) {
		return "", false
	}
	if resolved == home {
		return "", true
	}
	return strings.TrimPrefix(resolved, strings.TrimRight(home, "/")+"/"), true
}

func contextualHomeRelative(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) (string, bool) {
	if facts.ActiveHome != "" {
		return activeHomeRelative(facts, candidate)
	}
	resolved := canonicalSemanticPath(candidate.Resolved)
	if resolved == "" || !isAbsoluteSemanticPath(resolved) {
		return "", false
	}
	return liveHomeRelative(resolved)
}

func sensitiveReadAndEgressPrerequisite(facts actionfacts.Facts) bool {
	return readAndEgressPrerequisite(facts, true, hasExternalUpload)
}

func readAndEgressSafeNegative(facts actionfacts.Facts) bool {
	sawRelevantPipeline := false
	for _, source := range facts.Commands {
		if !hasAnyOperation(source, actionfacts.OperationRead, actionfacts.OperationCredentialRead) ||
			source.PipelineID == 0 ||
			!hasDataFlowFrom(facts, source.ID, actionfacts.DataStdout, actionfacts.DataStdin) {
			continue
		}
		sawReadPath, allNonSensitive := allReadPathsDefinitelyNonSensitive(
			facts,
			source.ID,
		)
		if !sawReadPath {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.PipelineID != source.PipelineID ||
				!hasOperation(destination, actionfacts.OperationUpload) ||
				!hasDataFlowTo(
					facts,
					destination.ID,
					actionfacts.DataStdout,
					actionfacts.DataStdin,
				) ||
				!hasDataFlowFrom(
					facts,
					destination.ID,
					"",
					actionfacts.DataNetwork,
				) {
				continue
			}
			sawRelevantPipeline = true
			if hasDeterminateNonExternalUpload(facts, destination.ID) {
				continue
			}
			if !hasExternalUpload(facts, destination.ID) ||
				!allNonSensitive {
				return false
			}
		}
	}
	return sawRelevantPipeline
}

type commandNetworkPredicate func(actionfacts.Facts, int64) bool

func readAndEgressPrerequisite(
	facts actionfacts.Facts,
	sensitiveOnly bool,
	networkMatches commandNetworkPredicate,
) bool {
	for _, source := range facts.Commands {
		if !hasAnyOperation(source, actionfacts.OperationRead, actionfacts.OperationCredentialRead) ||
			source.PipelineID == 0 ||
			!hasReadPath(facts, source.ID, sensitiveOnly) ||
			!hasDataFlowFrom(facts, source.ID, actionfacts.DataStdout, actionfacts.DataStdin) {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.PipelineID == source.PipelineID &&
				hasOperation(destination, actionfacts.OperationUpload) &&
				networkMatches(facts, destination.ID) &&
				hasDataFlowTo(facts, destination.ID, actionfacts.DataStdout, actionfacts.DataStdin) &&
				hasDataFlowFrom(facts, destination.ID, "", actionfacts.DataNetwork) {
				return true
			}
		}
	}
	return false
}

func externalFileUploadPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !curlProgram(command.Program) ||
			!hasOperation(command, actionfacts.OperationUpload) ||
			!hasReadPath(facts, command.ID, true) ||
			!hasExternalUpload(facts, command.ID) ||
			!hasDataFlowTo(
				facts,
				command.ID,
				actionfacts.DataFile,
				actionfacts.DataProcess,
			) ||
			!hasDataFlowFrom(
				facts,
				command.ID,
				"",
				actionfacts.DataNetwork,
			) {
			continue
		}
		return true
	}
	return false
}

func fileUploadSafeNegative(facts actionfacts.Facts) bool {
	sawRelevantUpload := false
	for _, command := range facts.Commands {
		if !curlProgram(command.Program) ||
			!hasOperation(command, actionfacts.OperationUpload) ||
			!hasDataFlowTo(
				facts,
				command.ID,
				actionfacts.DataFile,
				actionfacts.DataProcess,
			) ||
			!hasDataFlowFrom(
				facts,
				command.ID,
				"",
				actionfacts.DataNetwork,
			) {
			continue
		}
		sawReadPath, allNonSensitive := allReadPathsDefinitelyNonSensitive(
			facts,
			command.ID,
		)
		if !sawReadPath {
			continue
		}
		sawRelevantUpload = true
		if hasDeterminateNonExternalUpload(facts, command.ID) {
			continue
		}
		if !hasExternalUpload(facts, command.ID) ||
			!allNonSensitive {
			return false
		}
	}
	return sawRelevantUpload
}

func allReadPathsDefinitelyNonSensitive(
	facts actionfacts.Facts,
	commandID int64,
) (bool, bool) {
	sawReadPath := false
	for _, candidate := range facts.Paths {
		if candidate.CommandID != commandID ||
			candidate.Access != actionfacts.PathAccessRead {
			continue
		}
		sawReadPath = true
		if !isDefinitelyNonSensitivePath(facts, candidate) {
			return true, false
		}
	}
	return sawReadPath, sawReadPath
}

func curlProgram(program string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(program, `\`, "/")))
	return base == "curl" || base == "curl.exe"
}

func cloudSecretManagerPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !command.ArgvComplete ||
			command.Effect != actionfacts.EffectExecute ||
			!hasOperation(command, actionfacts.OperationCredentialRead) {
			continue
		}
		argv := lowerArgv(command.Argv)
		switch strings.ToLower(command.Program) {
		case "aws":
			if containsArgvSequence(argv, "secretsmanager", "get-secret-value") {
				return true
			}
		case "gcloud":
			if containsArgvSequence(argv, "secrets", "versions", "access") {
				return true
			}
		case "az":
			if containsArgvSequence(argv, "keyvault", "secret", "show") {
				return true
			}
		case "vault":
			if containsArgvSequence(argv, "kv", "get") {
				return true
			}
		case "op":
			if containsArgvSequence(argv, "read") ||
				containsArgvSequence(argv, "item", "get") {
				return true
			}
		case "pass":
			if containsArgvSequence(argv, "show") {
				return true
			}
		case "security":
			if containsArgvSequence(argv, "find-generic-password") ||
				containsArgvSequence(argv, "find-internet-password") {
				return true
			}
		}
	}
	return false
}

func cloudSecretManagerPreviewSafeNegative(facts actionfacts.Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, command := range facts.Commands {
		if command.ArgvComplete &&
			command.Effect != actionfacts.EffectExecute &&
			isCloudSecretManagerCommand(command) {
			return true
		}
	}
	return false
}

func isCloudSecretManagerCommand(command actionfacts.CommandFact) bool {
	argv := lowerArgv(command.Argv)
	switch strings.ToLower(command.Program) {
	case "aws":
		return containsArgvSequence(argv, "secretsmanager", "get-secret-value")
	case "gcloud":
		return containsArgvSequence(argv, "secrets", "versions", "access")
	case "az":
		return containsArgvSequence(argv, "keyvault", "secret", "show")
	case "vault":
		return containsArgvSequence(argv, "kv", "get")
	case "op":
		return containsArgvSequence(argv, "read") ||
			containsArgvSequence(argv, "item", "get")
	case "pass":
		return containsArgvSequence(argv, "show")
	case "security":
		return containsArgvSequence(argv, "find-generic-password") ||
			containsArgvSequence(argv, "find-internet-password")
	default:
		return false
	}
}

func environmentDumpExternalPrerequisite(facts actionfacts.Facts) bool {
	return environmentDumpPrerequisite(facts, hasExternalUpload)
}

func environmentDumpSafeNegative(facts actionfacts.Facts) bool {
	return environmentDumpPrerequisite(
		facts,
		hasDeterminateNonExternalUpload,
	)
}

func environmentDumpPrerequisite(
	facts actionfacts.Facts,
	networkMatches commandNetworkPredicate,
) bool {
	for _, source := range facts.Commands {
		if !hasOperation(source, actionfacts.OperationEnvironmentRead) ||
			source.PipelineID == 0 ||
			!hasDataFlowFrom(
				facts,
				source.ID,
				actionfacts.DataStdout,
				actionfacts.DataStdin,
			) {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.PipelineID == source.PipelineID &&
				hasOperation(destination, actionfacts.OperationUpload) &&
				networkMatches(facts, destination.ID) &&
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

func hasReadPath(
	facts actionfacts.Facts,
	commandID int64,
	sensitiveOnly bool,
) bool {
	for _, path := range facts.Paths {
		if path.CommandID != commandID ||
			path.Access != actionfacts.PathAccessRead {
			continue
		}
		if sensitiveOnly && matchesActiveSensitivePath(facts, path) {
			return true
		}
		if !sensitiveOnly && isDefinitelyNonSensitivePath(facts, path) {
			return true
		}
	}
	return false
}

func isDefinitelyNonSensitivePath(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	if matchesActiveSensitivePath(facts, candidate) {
		return false
	}
	value := semanticPathValue(candidate)
	if !matchesAnySensitivePathCandidate(value) {
		return canonicalSemanticPath(candidate.Resolved) != "" ||
			canonicalSemanticPath(candidate.Normalized) != ""
	}
	return isDefiniteFixturePath(facts, candidate)
}

func matchesAnySensitivePathCandidate(value string) bool {
	return matchesEnvironmentFile(value) ||
		matchesSSHPrivateKey(value) ||
		matchesAWSCredentials(value) ||
		matchesKubeConfig(value) ||
		matchesPackageCredentialFile(value) ||
		matchesGitCredentialFile(value) ||
		matchesProcEnvironCandidate(value) ||
		matchesCloudCredentialFile(value) ||
		matchesBrowserSessionStore(value) ||
		matchesWorkloadIdentityTokenCandidate(value)
}

func hasExternalUpload(facts actionfacts.Facts, commandID int64) bool {
	return hasNetworkActionMatching(
		facts,
		commandID,
		isExternalNetwork,
		actionfacts.NetworkUpload,
	)
}

func hasDeterminateNonExternalUpload(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	return hasNetworkActionMatching(
		facts,
		commandID,
		isDeterminateNonExternalNetwork,
		actionfacts.NetworkUpload,
	)
}

func hasExternalNetworkAction(
	facts actionfacts.Facts,
	commandID int64,
	actions ...actionfacts.NetworkAction,
) bool {
	return hasNetworkActionMatching(
		facts,
		commandID,
		isExternalNetwork,
		actions...,
	)
}

func hasDeterminateNonExternalNetworkAction(
	facts actionfacts.Facts,
	commandID int64,
	actions ...actionfacts.NetworkAction,
) bool {
	return hasNetworkActionMatching(
		facts,
		commandID,
		isDeterminateNonExternalNetwork,
		actions...,
	)
}

func hasNetworkActionMatching(
	facts actionfacts.Facts,
	commandID int64,
	matches func(actionfacts.NetworkFact) bool,
	actions ...actionfacts.NetworkAction,
) bool {
	for _, network := range facts.Network {
		if network.CommandID == commandID &&
			networkActionIn(network.Action, actions...) &&
			matches(network) {
			return true
		}
	}
	return false
}

func networkActionIn(
	action actionfacts.NetworkAction,
	candidates ...actionfacts.NetworkAction,
) bool {
	for _, candidate := range candidates {
		if action == candidate {
			return true
		}
	}
	return false
}

func isExternalNetwork(network actionfacts.NetworkFact) bool {
	if network.Scope == actionfacts.NetworkScopePublic {
		return true
	}
	if network.Scope != actionfacts.NetworkScopeUnknown ||
		network.TargetKind != actionfacts.NetworkTargetSingleHost {
		return false
	}
	host := strings.TrimSuffix(
		strings.ToLower(strings.TrimSpace(network.NormalizedHost)),
		".",
	)
	if host == "" ||
		host == "localhost" ||
		strings.HasSuffix(host, ".localhost") {
		return false
	}
	_, numericError := netip.ParseAddr(strings.Trim(host, "[]"))
	return numericError != nil
}

func isDeterminateNonExternalNetwork(network actionfacts.NetworkFact) bool {
	switch network.Scope {
	case actionfacts.NetworkScopeLoopback,
		actionfacts.NetworkScopeLinkLocal,
		actionfacts.NetworkScopePrivate:
		return true
	case actionfacts.NetworkScopeUnknown:
		if network.TargetKind != actionfacts.NetworkTargetSingleHost {
			return false
		}
		host := strings.TrimSuffix(
			strings.ToLower(strings.TrimSpace(network.NormalizedHost)),
			".",
		)
		if host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return true
		}
		_, numericError := netip.ParseAddr(strings.Trim(host, "[]"))
		return numericError == nil
	default:
		return false
	}
}

func hasDataFlowFrom(
	facts actionfacts.Facts,
	commandID int64,
	from actionfacts.DataKind,
	to actionfacts.DataKind,
) bool {
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID == commandID &&
			(from == "" || flow.From == from) &&
			(to == "" || flow.To == to) {
			return true
		}
	}
	return false
}

func hasDataFlowTo(
	facts actionfacts.Facts,
	commandID int64,
	from actionfacts.DataKind,
	to actionfacts.DataKind,
) bool {
	for _, flow := range facts.DataFlows {
		if flow.ToCommandID == commandID &&
			(from == "" || flow.From == from) &&
			(to == "" || flow.To == to) {
			return true
		}
	}
	return false
}

func semanticPathValue(path actionfacts.PathFact) string {
	value := path.Resolved
	if value == "" {
		value = path.Normalized
	}
	if value == "" {
		value = path.Value
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
}

func matchesActiveSensitivePath(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := semanticPathValue(candidate)
	return matchesContextualEnvironmentFile(facts, candidate) ||
		matchesActiveSSHPrivateKey(facts, candidate) ||
		matchesActiveAWSCredentials(facts, candidate) ||
		matchesActiveKubeConfig(facts, candidate) ||
		matchesActivePackageCredentialFile(facts, candidate) ||
		matchesActiveGitCredentialFile(facts, candidate) ||
		matchesProcEnviron(value) ||
		matchesActiveCloudCredentialFile(facts, candidate) ||
		matchesActiveBrowserSessionStore(facts, candidate) ||
		matchesWorkloadIdentityToken(value)
}

func matchesEnvironmentFile(value string) bool {
	switch pathBase(value) {
	case ".env", ".env.local", ".env.production", ".env.prod",
		".env.development", ".env.dev", ".env.staging", ".env.test":
		return true
	default:
		return false
	}
}

func matchesContextualEnvironmentFile(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := semanticPathValue(candidate)
	return matchesEnvironmentFile(value) &&
		!integrityPathHasFixtureSegment(value)
}

func matchesSSHPrivateKey(value string) bool {
	switch pathBase(value) {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		return true
	default:
		return false
	}
}

func matchesActiveSSHPrivateKey(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	return ok && strings.HasPrefix(relative, ".ssh/") &&
		matchesSSHPrivateKey(relative)
}

func matchesAWSCredentials(value string) bool {
	return strings.HasSuffix(value, "/.aws/credentials") ||
		value == ".aws/credentials"
}

func matchesActiveAWSCredentials(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	return ok && relative == ".aws/credentials"
}

func matchesKubeConfig(value string) bool {
	return strings.HasSuffix(value, "/.kube/config") ||
		value == ".kube/config"
}

func matchesActiveKubeConfig(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	return ok && relative == ".kube/config"
}

func matchesPackageCredentialFile(value string) bool {
	base := pathBase(value)
	return strings.HasSuffix(value, "/.docker/config.json") ||
		value == ".docker/config.json" ||
		base == ".npmrc" ||
		base == ".pypirc"
}

func matchesActivePackageCredentialFile(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	return relative == ".docker/config.json" ||
		relative == ".npmrc" ||
		relative == ".pypirc"
}

func matchesGitCredentialFile(value string) bool {
	return matchesRelativePathAtComponentBoundary(
		value,
		matchesDeveloperCredentialRelative,
	)
}

func matchesActiveGitCredentialFile(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	return matchesDeveloperCredentialRelative(relative)
}

func matchesDeveloperCredentialRelative(relative string) bool {
	switch relative {
	case ".git-credentials",
		".netrc",
		"_netrc",
		".pgpass",
		".cache/huggingface/token",
		".huggingface/token",
		".config/huggingface/token",
		".config/pypoetry/auth.toml",
		".kaggle/kaggle.json",
		"library/application support/pypoetry/auth.toml",
		"appdata/roaming/pypoetry/auth.toml":
		return true
	default:
		return false
	}
}

func matchesProcEnviron(value string) bool {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if len(parts) != 3 || parts[0] != "proc" || parts[2] != "environ" {
		return false
	}
	if parts[1] == "self" {
		return true
	}
	if parts[1] == "" {
		return false
	}
	for _, character := range parts[1] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func matchesProcEnvironCandidate(value string) bool {
	return strings.HasSuffix(value, "/proc/self/environ") ||
		strings.Contains(value, "/proc/") && strings.HasSuffix(value, "/environ")
}

func matchesCloudCredentialFile(value string) bool {
	relative, ok := liveHomeRelative(value)
	return ok && matchesCloudCredentialRelative(relative)
}

func matchesCloudCredentialFallbackCandidate(value string) bool {
	return matchesRelativePathAtComponentBoundary(
		value,
		matchesCloudCredentialRelative,
	)
}

func matchesActiveCloudCredentialFile(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	return ok && matchesCloudCredentialRelative(relative)
}

func matchesContextualCloudCredentialFile(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := contextualHomeRelative(facts, candidate)
	return ok && matchesCloudCredentialRelative(relative)
}

func matchesCloudCredentialRelative(relative string) bool {
	switch relative {
	case ".config/gcloud/application_default_credentials.json",
		".config/gcloud/credentials.db",
		".config/gcloud/access_tokens.db",
		".config/gh/hosts.yml",
		"appdata/roaming/gcloud/application_default_credentials.json",
		"appdata/roaming/gcloud/credentials.db",
		"appdata/roaming/gcloud/access_tokens.db",
		"appdata/roaming/github cli/hosts.yml",
		".azure/azureprofile.json",
		".azure/tokencache.dat":
		return true
	}
	if !strings.HasPrefix(relative, ".azure/msal_token_cache") {
		return false
	}
	return strings.HasSuffix(relative, ".json") ||
		strings.HasSuffix(relative, ".bin")
}

func matchesBrowserSessionStore(value string) bool {
	relative, ok := liveHomeRelative(value)
	return ok && matchesBrowserSessionStoreRelative(relative)
}

func matchesBrowserSessionFallbackCandidate(value string) bool {
	return matchesRelativePathAtComponentBoundary(
		value,
		matchesBrowserSessionStoreRelative,
	)
}

func matchesBrowserSessionStoreName(value string) bool {
	switch pathBase(value) {
	case "login data", "cookies", "logins.json", "cookies.sqlite", "key4.db":
		return true
	default:
		return false
	}
}

func matchesActiveBrowserSessionStore(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	return ok && matchesBrowserSessionStoreRelative(relative)
}

func matchesContextualBrowserSessionStore(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	relative, ok := contextualHomeRelative(facts, candidate)
	return ok && matchesBrowserSessionStoreRelative(relative)
}

func matchesBrowserSessionStoreRelative(relative string) bool {
	if !matchesBrowserSessionStoreName(relative) {
		return false
	}
	for _, prefix := range []string{
		".config/google-chrome/",
		".config/chromium/",
		".config/microsoft-edge/",
		".mozilla/firefox/",
		"library/application support/google/chrome/",
		"library/application support/chromium/",
		"library/application support/microsoft edge/",
		"library/application support/firefox/profiles/",
		"appdata/local/google/chrome/user data/",
		"appdata/local/chromium/user data/",
		"appdata/local/microsoft/edge/user data/",
		"appdata/roaming/mozilla/firefox/profiles/",
	} {
		if strings.HasPrefix(relative, prefix) {
			return true
		}
	}
	return false
}

func matchesRelativePathAtComponentBoundary(
	value string,
	matches semanticPathCandidate,
) bool {
	value = canonicalSemanticPath(value)
	for value != "" && value != "." {
		if matches(value) {
			return true
		}
		separator := strings.IndexByte(value, '/')
		if separator < 0 {
			return false
		}
		value = value[separator+1:]
	}
	return false
}

func liveHomeRelative(value string) (string, bool) {
	value = canonicalSemanticPath(value)
	for _, prefix := range []string{"~/", "$home/", "${home}/", "/root/"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return strings.TrimPrefix(value, prefix), true
		}
	}
	for _, prefix := range []string{"/home/", "/users/"} {
		if relative, ok := userHomeRelative(value, prefix); ok {
			return relative, true
		}
	}
	if len(value) >= 3 && value[1] == ':' {
		return userHomeRelative(value[2:], "/users/")
	}
	return "", false
}

func userHomeRelative(value, prefix string) (string, bool) {
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	remainder := strings.TrimPrefix(value, prefix)
	separator := strings.IndexByte(remainder, '/')
	if separator <= 0 || separator == len(remainder)-1 {
		return "", false
	}
	return remainder[separator+1:], true
}

func matchesWorkloadIdentityToken(value string) bool {
	return value == "/var/run/secrets/kubernetes.io/serviceaccount/token" ||
		value == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" ||
		value == "/var/run/secrets/azure/tokens/azure-identity-token"
}

func matchesWorkloadIdentityTokenCandidate(value string) bool {
	return strings.HasSuffix(
		value,
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
	) || strings.HasSuffix(
		value,
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
	) || strings.HasSuffix(
		value,
		"/var/run/secrets/azure/tokens/azure-identity-token",
	)
}

func pathBase(value string) string {
	value = strings.TrimRight(value, "/")
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func hasOperation(command actionfacts.CommandFact, operation actionfacts.OperationKind) bool {
	for _, candidate := range command.Operations {
		if candidate == operation {
			return true
		}
	}
	return false
}

func hasAnyOperation(
	command actionfacts.CommandFact,
	operations ...actionfacts.OperationKind,
) bool {
	for _, operation := range operations {
		if hasOperation(command, operation) {
			return true
		}
	}
	return false
}

func lowerArgv(argv []string) []string {
	lowered := make([]string, len(argv))
	for index, argument := range argv {
		lowered[index] = strings.ToLower(argument)
	}
	return lowered
}

func containsArgvSequence(argv []string, sequence ...string) bool {
	if len(sequence) == 0 || len(sequence) > len(argv) {
		return false
	}
	for start := 0; start+len(sequence) <= len(argv); start++ {
		matched := true
		for offset, value := range sequence {
			if argv[start+offset] != value {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func oneOfFold(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func hardcodedToolCallOnlyRule(ruleID string) bool {
	switch ruleID {
	case "CMD-WIN-IWR-IEX",
		"PATH-WIN-SSH-KEY",
		"PATH-WIN-AWS-CREDS",
		"PATH-WIN-KUBE-CONFIG",
		"PATH-WIN-GIT-CREDS",
		"PATH-WIN-NETRC":
		return true
	default:
		return false
	}
}
