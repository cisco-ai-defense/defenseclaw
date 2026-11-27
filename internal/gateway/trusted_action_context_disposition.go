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
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// trustedActionDispositionScope is what the dispatch knows of the request
// beyond its facts. The zero value is a plain call.
type trustedActionDispositionScope struct {
	// protectedLocalFileRead: the Copilot Local file tool opens the file
	// (trustedActionRequest.CopilotSharedLocalFile).
	protectedLocalFileRead bool
	// sendDestination: the arguments are the routing values of a message
	// call, where its text is sent (trustedActionRequest.sendDestination).
	sendDestination bool
	// strictPolicy: the strict pack judges the call
	// (trustedActionRequest.StrictPolicy).
	strictPolicy bool
}

// applyTrustedActionContextDisposition is the trusted-action-only disposition
// boundary for content literals and selected advisory rules. It deliberately
// is not called by prompt, tool-result, or completion scanners: those scan
// untrusted content at a different boundary and retain their existing policy.
//
// The function returns an owned findings slice and never promotes a finding
// that an earlier boundary already marked detection-only. Its only authority
// input is ActionFacts derived from the current action, and the scope the
// dispatch derived from the same request.
func applyTrustedActionContextDisposition(
	generation *compiledRulePackCategories,
	facts actionfacts.Facts,
	findings []RuleFinding,
	scopes ...trustedActionDispositionScope,
) []RuleFinding {
	var scope trustedActionDispositionScope
	if len(scopes) != 0 {
		scope = scopes[0]
	}
	adjusted := append([]RuleFinding(nil), findings...)
	// Detection sees the complete action, while authorization considers only
	// commands and redirects statically proven to execute. A harmless preview
	// sibling must not erase proof for an independent executing mutation.
	enforcementFacts := facts.EnforcementProjection()
	for index := range adjusted {
		finding := adjusted[index]
		findingFacts := enforcementFacts
		if finding.RuleID == "CMD-WIN-REG-PERSIST" && finding.Severity == "HIGH" &&
			finding.contributesToEnforcement() {
			finding.enforcement = findingEnforcementAlertOnly
			adjusted[index] = finding
			continue
		}

		if canonicalTrustedRuleID(finding.RuleID) ==
			"PRIVILEGE.CONTAINER_RUNTIME_SOCKET_ACCESS" {
			if trustedActionProvesContainerRuntimeSocketUse(findingFacts) {
				finding = finding.withTrustedActionProof(
					trustedActionContextFindingProof(
						finding.RuleID,
						findingFacts,
					),
				)
				finding.enforcement = findingEnforcementAlertOnly
			} else {
				// Merely reading, listing, stating, or lexically mentioning a
				// runtime socket is useful local telemetry, but it does not prove
				// use of the privileged API. Partial parses remain visible here
				// without gaining alert or enforcement authority.
				finding = trustedActionAuditFinding(finding)
			}
			adjusted[index] = finding
			continue
		}

		if trustedActionSensitivePathRule(finding.RuleID) {
			switch trustedActionClassifySensitivePathRisk(findingFacts, finding.RuleID) {
			case trustedActionSensitivePathUncertain:
				// Preserve the finding's original severity so parser coverage
				// uncertainty remains visible, but never let incomplete facts
				// authorize enforcement.
				finding.enforcement = findingEnforcementDetectionOnly
			case trustedActionSensitivePathMutation,
				trustedActionSensitivePathReadEgress:
				// A typed mutation or read-to-external-network flow remains a
				// security finding. Do not promote a finding that another
				// boundary already made detection-only.
				finding = finding.withTrustedActionProof(
					trustedActionContextFindingProof(finding.RuleID, findingFacts),
				)
			case trustedActionSensitivePathRead:
				if scope.protectedLocalFileRead &&
					finding.enforcement != findingEnforcementDetectionOnly &&
					(slices.Contains(finding.Tags, "credential") || slices.Contains(finding.Tags, "privilege")) {
					// The Local file tool opens this exact credential or control
					// target. Keep its path rule enforceable, as for a direct
					// mutation of the same file.
					finding = finding.withTrustedActionProof(
						trustedActionContextFindingProof(finding.RuleID, findingFacts),
					)
					adjusted[index] = finding
					continue
				}
				if scope.strictPolicy && finding.enforcement != findingEnforcementDetectionOnly &&
					trustedActionStrictCredentialContentRead(findingFacts, finding) {
					// The strict pack blocks a proven content read of a
					// credential file, as it blocks the private key's; the
					// other packs keep the alert below (substrate-1:GAP-0706,
					// owner ruling 2026-11-19). A read is HIGH at most: the
					// CRITICAL of the rule is for its upload or mutation
					// (rel-1-0-10:GAP-0888).
					finding.Severity = trustedActionLowerSeverity(finding.Severity, "HIGH")
					finding = finding.withTrustedActionProof(
						trustedActionContextFindingProof(finding.RuleID, findingFacts),
					)
					adjusted[index] = finding
					continue
				}
				if (finding.RuleID == "PATH-SSH-KEY" || finding.RuleID == "PATH-WIN-SSH-KEY") &&
					trustedActionActiveSSHPrivateKeyContentRead(findingFacts) {
					finding = finding.withTrustedActionProof(
						trustedActionContextFindingProof(finding.RuleID, findingFacts),
					)
					adjusted[index] = finding
					continue
				}
				// A local read of a credential path is MEDIUM: alert, do not
				// block. Detection-only would also hide it from alerts
				// (GAP-1516); never promote a finding that an earlier
				// boundary already made detection-only.
				detectionOnly := finding.enforcement == findingEnforcementDetectionOnly
				finding = trustedActionAdvisoryFinding(finding)
				if !detectionOnly {
					finding.enforcement = findingEnforcementAlertOnly
				}
			default:
				// A path-shaped string without a matching, command-owned path
				// fact is a harmless reference, not a filesystem action.
				finding = trustedActionAuditFinding(finding)
			}
			adjusted[index] = finding
			continue
		}

		if trustedActionShippedGitAdvisoryRule(
			generation,
			finding.RuleID,
		) {
			// Shipped git remote changes and hook-bypass switches are useful
			// advisory evidence, but repositories legitimately use both. A
			// custom rule retains its original enforcement disposition.
			finding = trustedActionAdvisoryFinding(finding)
			adjusted[index] = finding
			continue
		}

		category, rule, _ := trustedActionCatalogRule(
			generation,
			finding.RuleID,
		)
		if !trustedReadOnlyArgumentDataFinding(category, finding) {
			continue
		}
		if !trustedActionContentFindingHasRiskPair(findingFacts, rule) {
			if trustedActionCredentialLiteralRule(finding) &&
				finding.enforcement != findingEnforcementDetectionOnly &&
				trustedActionPersistsCredentialLiteral(findingFacts, scope.sendDestination) {
				// A credential value the action writes into a file, a store
				// or a process alerts: it leaves the context for a place that
				// keeps it. Without proof of where it goes it never blocks.
				finding.enforcement = findingEnforcementAlertOnly
				adjusted[index] = finding
				continue
			}
			// Literal secret/PII material the action only looks at, and PII
			// anywhere, remains visible for local audit, but cannot alert or
			// block without command-local proof of external egress or an
			// active sensitive-path write.
			adjusted[index] = trustedActionAuditFinding(finding)
			continue
		}
		adjusted[index] = finding.withTrustedActionProof(
			trustedActionContextFindingProof(finding.RuleID, findingFacts),
		)
	}
	return adjusted
}

func trustedActionActiveSSHPrivateKeyContentRead(facts actionfacts.Facts) bool {
	return sshPrivateKeyContentReadBy(facts, matchesActiveSSHPrivateKey)
}

// trustedActionOtherHomeSSHPrivateKeyContentRead is the same proof for a key
// that is not the active user's: another account's home, a mounted or alternate
// home (matchesContextualSSHPrivateKey minus the active one). The proof is the
// same; the strict pack blocks it as it blocks the active key, the other packs
// keep the alert of the path rule (GAP-0810).
func trustedActionOtherHomeSSHPrivateKeyContentRead(facts actionfacts.Facts) bool {
	return sshPrivateKeyContentReadBy(facts, func(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return !matchesActiveSSHPrivateKey(facts, candidate) && matchesContextualSSHPrivateKey(facts, candidate)
	})
}

func sshPrivateKeyContentReadBy(
	facts actionfacts.Facts,
	isKey func(actionfacts.Facts, actionfacts.PathFact) bool,
) bool {
	return pathContentReadBy(facts, isKey, matchesSSHPrivateKey, sshPrivateKeyContentReaders)
}

// trustedActionStrictCredentialNotStore are the credential-tagged path rules
// whose files the strict pack does not block a read of: a project .env, the
// shell history and the SSH folder's other files (its keys have their own
// proof) are read in ordinary work. They keep the alert, as do the system
// files (rules tagged system-file, /etc/shadow: GAP-1058 keeps rel's tier).
var trustedActionStrictCredentialNotStore = []string{"PATH-ENV-FILE", "PATH-HISTORY", "PATH-SSH-DIR"}

// trustedActionStrictCredentialContentRead reports a content read of a file
// of finding's credential path rule by an executing command, with the proof
// of a private key read (pathContentReadBy): no copy kept in the same home,
// no glob operand, no read of no byte (substrate-1:GAP-0706). The copy
// programs read it as cat does (TestCredentialFileCopyIsJudgedLikeItsRead).
func trustedActionStrictCredentialContentRead(facts actionfacts.Facts, finding RuleFinding) bool {
	if finding.RuleID == "PATH-SSH-KEY" || finding.RuleID == "PATH-WIN-SSH-KEY" {
		// A private key read has its own proof below (the active key, the
		// key reached through a linked folder): judged here first, it was
		// capped at HIGH and skipped that proof, and the strict block of
		// cd -P <link to ~/.ssh> && cat id_ed25519 became an alert
		// (substrate-1:GAP-1165).
		return false
	}
	if !slices.Contains(finding.Tags, "credential") || slices.Contains(finding.Tags, "detection-only") ||
		slices.Contains(finding.Tags, "system-file") ||
		slices.Contains(trustedActionStrictCredentialNotStore, finding.RuleID) {
		return false
	}
	isFile := func(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return trustedActionPathMatchesRule(facts, candidate, finding.RuleID)
	}
	anyGlob := func(string) bool { return true }
	return pathContentReadBy(facts, isFile, anyGlob, credentialContentReaders)
}

// credentialContentReaders are the programs whose read of a credential file
// returns its content: the private key readers, the other copy programs and
// the common text viewers (a search may print a count or a name only).
var credentialContentReaders = append(slices.Clone(sshPrivateKeyContentReaders),
	"rsync", "install", "less", "more", "strings", "xxd", "od", "hexdump", "jq", "tac", "nl")

// pathContentReadBy reports a read of a file isFile accepts that returns its
// content: an executing content reader (one of readers; head and tail
// unless they read no byte), never a copy to a private place of the same
// home, never a command with a glob operand globTarget accepts.
func pathContentReadBy(
	facts actionfacts.Facts,
	isFile func(actionfacts.Facts, actionfacts.PathFact) bool,
	globTarget func(string) bool,
	readers []string,
) bool {
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessRead ||
			!isFile(facts, candidate) {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || command.Effect != actionfacts.EffectExecute {
			continue
		}
		if trustedActionPrivateHomeCopy(facts, command, nil) {
			// A copy of the key to a private place in the same home leaves
			// its content with the user (rel-1-0-10:GAP-0018).
			continue
		}
		expandingOperand := false
		for _, argument := range command.Arguments {
			if argument.Expands && globTarget(argument.Value) {
				expandingOperand = true
				break
			}
		}
		if expandingOperand {
			continue
		}
		switch program := strings.ToLower(command.Program); {
		case program == "head" || program == "tail":
			emptyRead := false
			for index, arg := range command.Argv {
				if arg == "-c" && index+1 < len(command.Argv) && command.Argv[index+1] == "0" ||
					arg == "--bytes=0" {
					emptyRead = true
					break
				}
			}
			if emptyRead {
				continue
			}
			return true
		case slices.Contains(readers, program):
			return true
		}
	}
	return false
}

// sshPrivateKeyContentReaders are the programs whose read of an SSH private
// key returns its content (sshPrivateKeyContentReadBy; head and tail unless
// they read no byte). The guest placement reads a candidate folder only for
// a text that may name one of them (guestCandidateMayReadKey).
var sshPrivateKeyContentReaders = []string{
	"head", "tail",
	"sed", "gsed", "awk", "gawk", "mawk", "nawk",
	"cat", "base64", "cp", "copy", "copy-item", "cpi",
	"get-content", "gc", "type", "read", "readfile", "read_file", "read-file",
	"fsread", "fs_read", "fs-read", "fs.read", "fs.read_file",
	"fileread", "file_read", "file-read", "catfile", "cat_file", "cat-file",
	"openfile", "open_file", "open-file", "viewfile", "view_file", "view-file",
}

func trustedActionProvesContainerRuntimeSocketUse(
	facts actionfacts.Facts,
) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	for _, candidate := range facts.Paths {
		if !matchesContainerRuntimeSocket(semanticPathValue(candidate)) ||
			!slices.Contains(
				[]actionfacts.PathAccess{
					actionfacts.PathAccessConnect,
					actionfacts.PathAccessWrite,
					actionfacts.PathAccessAppend,
				},
				candidate.Access,
			) ||
			!trustedActionExecutingCommand(facts, candidate.CommandID) {
			continue
		}
		for _, command := range facts.Commands {
			if command.ID != candidate.CommandID {
				continue
			}
			return slices.Contains(command.Operations, actionfacts.OperationConnect) ||
				slices.Contains(command.Operations, actionfacts.OperationWrite) ||
				slices.Contains(command.Operations, actionfacts.OperationAppend)
		}
	}
	return false
}

func trustedActionContextFindingProof(
	ruleID string,
	facts actionfacts.Facts,
) findingProof {
	// Callers invoke this only after the typed risk classifier has completed
	// and matched the same rule against this execution-only projection. The
	// remaining two booleans are therefore boundary postconditions, while the
	// Facts methods retain authority and eligibility as independent checks.
	return newActionFactsSemanticFindingProof(
		ruleID,
		actionFactsSemanticProofInput{
			FactsAuthoritative:  facts.Authoritative(),
			EnforcementEligible: facts.EnforcementEligible(),
			ProjectionComplete:  true,
			EvaluationComplete:  true,
			Matched:             true,
		},
	)
}

type trustedActionSensitivePathRisk uint8

const (
	trustedActionSensitivePathReference trustedActionSensitivePathRisk = iota
	trustedActionSensitivePathUncertain
	trustedActionSensitivePathRead
	trustedActionSensitivePathMutation
	trustedActionSensitivePathReadEgress
)

type trustedActionSensitivePathMatcher func(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool

type trustedActionSensitivePathRuleMatcher struct {
	ruleIDs []string
	matcher trustedActionSensitivePathMatcher
}

// trustedActionSensitivePathRuleMatchers is the single membership and matcher
// catalog for trusted sensitive-path findings. Keep aliases grouped when they
// intentionally share identical path semantics.
var trustedActionSensitivePathRuleMatchers = []trustedActionSensitivePathRuleMatcher{
	{
		ruleIDs: []string{"PATH-ENV-FILE"},
		matcher: matchesContextualEnvironmentFile,
	},
	{
		ruleIDs: []string{"PATH-SSH-KEY", "PATH-WIN-SSH-KEY"},
		matcher: trustedActionPathValueMatcher(matchesSSHPrivateKey),
	},
	{
		ruleIDs: []string{"PATH-SSH-DIR"},
		matcher: trustedActionSSHDirectoryMatcher,
	},
	{
		ruleIDs: []string{"PATH-ETC-SHADOW"},
		matcher: trustedActionExactPathMatcher("/etc/shadow"),
	},
	{
		ruleIDs: []string{"PATH-ETC-PASSWD"},
		matcher: trustedActionExactPathMatcher("/etc/passwd"),
	},
	{
		ruleIDs: []string{"PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS"},
		matcher: trustedActionWithFolderTree(trustedActionPathValueMatcher(matchesAWSCredentials), actionfacts.CredentialFileAWS, true),
	},
	{
		ruleIDs: []string{"PATH-PASSWORD-CRACKER-POTFILE"},
		matcher: matchesPasswordCrackerPotfile,
	},
	{
		ruleIDs: []string{"PATH-KUBE", "PATH-WIN-KUBE-CONFIG"},
		matcher: trustedActionWithFolderTree(trustedActionPathValueMatcher(matchesKubeConfig), actionfacts.CredentialFileKubeconfig, true),
	},
	{
		ruleIDs: []string{"PATH-DOCKER", "PATH-NPMRC", "PATH-PYPIRC"},
		matcher: trustedActionWithFolderTree(trustedActionPathValueMatcher(matchesPackageCredentialFile), actionfacts.CredentialFilePackageRegistry, true),
	},
	{
		ruleIDs: []string{
			"PATH-GIT-CREDS", "PATH-NETRC", "PATH-WIN-GIT-CREDS",
			"PATH-WIN-NETRC",
		},
		matcher: trustedActionPathValueMatcher(matchesGitCredentialFile),
	},
	{
		ruleIDs: []string{"PATH-WIN-CREDENTIAL-MANAGER"},
		matcher: trustedActionWindowsAppDataMatcher(
			"microsoft/credentials",
			true,
		),
	},
	{
		ruleIDs: []string{"PATH-WIN-DPAPI"},
		matcher: trustedActionWindowsAppDataMatcher(
			"microsoft/protect",
			true,
		),
	},
	{
		ruleIDs: []string{"PATH-WIN-PS-HISTORY"},
		matcher: trustedActionWindowsAppDataMatcher(
			"microsoft/windows/powershell/psreadline/consolehost_history.txt",
			false,
		),
	},
	{
		ruleIDs: []string{"PATH-WIN-SAM"},
		matcher: trustedActionWindowsSystemHiveMatcher("sam"),
	},
	{
		ruleIDs: []string{"PATH-WIN-SECURITY-HIVE"},
		matcher: trustedActionWindowsSystemHiveMatcher("security"),
	},
	{
		ruleIDs: []string{"PATH-WIN-SYSTEM-HIVE"},
		matcher: trustedActionWindowsSystemHiveMatcher("system"),
	},
	{
		ruleIDs: []string{"PATH-PROC-ENVIRON"},
		matcher: trustedActionPathValueMatcher(matchesProcEnviron),
	},
	{
		ruleIDs: []string{"SECRETS.CLOUD_CREDENTIAL_READ"},
		matcher: trustedActionWithFolderTree(matchesContextualCloudCredentialFile, actionfacts.CredentialFileCloudCLI, false),
	},
	{
		ruleIDs: []string{"SECRETS.BROWSER_SESSION_STORE_READ"},
		matcher: matchesContextualBrowserSessionStore,
	},
	{
		ruleIDs: []string{"SECRETS.WORKLOAD_IDENTITY_TOKEN_READ"},
		matcher: trustedActionPathValueMatcher(matchesWorkloadIdentityToken),
	},
}

// trustedActionWithFolderTree is matcher joined to the folder side of the
// owner of the same rule (credentialFolderTreeMatcher, semantic_owners.go):
// an archive or recursive copy of a credentials folder reads the file
// matcher names, so its read is classified as the read of that file. Before,
// only the owner took the folder (substrate-1:GAP-0995 part 2), and this
// catalog, which grades the finding, saw no read of a matched path: the
// finding was an audit record (LOW, allow) where the file read alerts.
func trustedActionWithFolderTree(
	matcher trustedActionSensitivePathMatcher,
	class actionfacts.CredentialFileClass,
	otherHomes bool,
) trustedActionSensitivePathMatcher {
	folder := credentialFolderTreeMatcher(class, otherHomes)
	return func(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return matcher(facts, candidate) || folder(facts, candidate)
	}
}

func trustedActionPathValueMatcher(
	matcher func(string) bool,
) trustedActionSensitivePathMatcher {
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return matcher(semanticPathValue(candidate))
	}
}

func trustedActionExactPathMatcher(
	expected string,
) trustedActionSensitivePathMatcher {
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return strings.TrimRight(semanticPathValue(candidate), "/") == expected
	}
}

func trustedActionWindowsAppDataMatcher(
	relative string,
	descendants bool,
) trustedActionSensitivePathMatcher {
	relative = strings.Trim(strings.ToLower(relative), "/")
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		parts := strings.Split(
			strings.Trim(canonicalSemanticPath(semanticPathValue(candidate)), "/"),
			"/",
		)
		if len(parts) < 7 || !trustedActionWindowsDrive(parts[0]) ||
			parts[1] != "users" || parts[2] == "" ||
			parts[3] != "appdata" ||
			(parts[4] != "roaming" && parts[4] != "local") {
			return false
		}
		value := strings.Join(parts[5:], "/")
		return value == relative ||
			descendants && strings.HasPrefix(value, relative+"/")
	}
}

func trustedActionWindowsSystemHiveMatcher(
	hive string,
) trustedActionSensitivePathMatcher {
	hive = strings.ToLower(strings.TrimSpace(hive))
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		parts := strings.Split(
			strings.Trim(canonicalSemanticPath(semanticPathValue(candidate)), "/"),
			"/",
		)
		return len(parts) == 5 && trustedActionWindowsDrive(parts[0]) &&
			parts[1] == "windows" && parts[2] == "system32" &&
			parts[3] == "config" && parts[4] == hive
	}
}

func trustedActionWindowsDrive(value string) bool {
	return len(value) == 2 && value[1] == ':' &&
		value[0] >= 'a' && value[0] <= 'z'
}

func trustedActionSSHDirectoryMatcher(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := strings.ToLower(strings.Trim(semanticPathValue(candidate), "/"))
	return value == ".ssh" || strings.HasSuffix(value, "/.ssh") ||
		strings.Contains(value, "/.ssh/")
}

func trustedActionSensitivePathMatcherForRule(
	ruleID string,
) (trustedActionSensitivePathMatcher, bool) {
	ruleID = canonicalTrustedRuleID(ruleID)
	for _, binding := range trustedActionSensitivePathRuleMatchers {
		if slices.Contains(binding.ruleIDs, ruleID) {
			return binding.matcher, binding.matcher != nil
		}
	}
	return nil, false
}

func trustedActionSensitivePathRule(ruleID string) bool {
	_, ok := trustedActionSensitivePathMatcherForRule(ruleID)
	return ok
}

func trustedActionClassifySensitivePathRisk(
	facts actionfacts.Facts,
	ruleID string,
) trustedActionSensitivePathRisk {
	// Partial outer shell expressions may expose useful shadow facts, but they
	// never authorize a path alert or block.
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return trustedActionSensitivePathUncertain
	}

	risk := trustedActionSensitivePathReference
	for _, candidate := range facts.Paths {
		if !trustedActionPathMatchesRule(facts, candidate, ruleID) {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessWrite,
			actionfacts.PathAccessAppend,
			actionfacts.PathAccessDelete:
			if trustedActionKeyNamedWriteOutsideSSHDir(ruleID, candidate) {
				continue
			}
			if trustedActionExecutingCommand(facts, candidate.CommandID) {
				return trustedActionSensitivePathMutation
			}
		case actionfacts.PathAccessRead:
			if !trustedActionExecutingCommand(facts, candidate.CommandID) {
				continue
			}
			if trustedActionSameCommandPathReadFeedsExternalEgress(
				facts,
				candidate,
			) || trustedActionPathReadFeedsExternalUpload(
				facts,
				candidate,
			) {
				return trustedActionSensitivePathReadEgress
			}
			risk = trustedActionSensitivePathRead
		}
	}
	return risk
}

func trustedActionPathMatchesRule(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
	ruleID string,
) bool {
	matcher, ok := trustedActionSensitivePathMatcherForRule(ruleID)
	return ok && matcher(facts, candidate)
}

func trustedActionContentFindingHasRiskPair(
	facts actionfacts.Facts,
	rule *PatternRule,
) bool {
	if rule == nil || rule.Pattern == nil ||
		!facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	for _, command := range facts.Commands {
		if !trustedActionExecutingCommand(facts, command.ID) {
			continue
		}
		if trustedActionStaticPrintfWritesSensitivePath(
			facts,
			*rule,
			command,
		) {
			return true
		}
		if trustedActionContentRuleMatchesStaticUpload(*rule, command) &&
			trustedActionCommandProvesExternalEgress(facts, command.ID) {
			return true
		}
		metadata := actionfacts.StaticCurlTransmittedMetadata(command)
		httpEgress := trustedActionCommandProvesExternalRequestForSchemes(
			facts,
			command.ID,
			"http",
			"https",
		)
		ftpEgress := trustedActionCommandProvesExternalRequestForSchemes(
			facts,
			command.ID,
			"ftp",
			"ftps",
		)
		httpMetadataEgress := httpEgress &&
			(trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				metadata.Headers,
			) || trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				metadata.HTTPOriginCredentials,
			) || trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				metadata.HTTPBearerTokens,
			))
		ftpOriginAuthEgress := ftpEgress &&
			trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				metadata.FTPOriginCredentials,
			)
		curlRequestComponentEgress :=
			trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				metadata.HTTPRequestComponents,
			) || trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				metadata.HTTPDestinationHostnameComponents,
			) || trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				metadata.FTPRequestComponents,
			) || trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				actionfacts.StaticCurlFTPControlRequestComponentsForFacts(
					facts,
					command.ID,
				),
			)
		curlTargetBoundOriginAuthEgress :=
			trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				metadata.HTTPOriginCredentialComponents,
			) || trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				metadata.FTPOriginCredentialComponents,
			)
		curlSMTPRequestEgress :=
			trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				actionfacts.StaticCurlSMTPRequestComponents(command),
			)
		curlTelnetOptionEgress :=
			trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				actionfacts.StaticCurlTelnetOptionRequestComponentsForFacts(
					facts,
					command.ID,
				),
			)
		proxyMetadata := actionfacts.StaticCurlProxyTransmittedMetadata(command)
		curlProxyMetadataEgress :=
			trustedActionContentRuleMatchesExternalProxyRequestComponents(
				facts,
				*rule,
				command.ID,
				proxyMetadata.ProxyRequestComponents,
			) || trustedActionContentRuleMatchesExternalProxyRequestComponents(
				facts,
				*rule,
				command.ID,
				proxyMetadata.ProxyDestinationHostnameComponents,
			)
		curlSOCKSProxyCredentialEgress :=
			trustedActionContentRuleMatchesExternalProxyRequestComponents(
				facts,
				*rule,
				command.ID,
				actionfacts.StaticCurlSOCKSProxyCredentialComponentsForFacts(
					facts,
					command.ID,
				),
			)
		curlFTPProxyMetadataEgress :=
			trustedActionContentRuleMatchesExternalProxyRequestComponents(
				facts,
				*rule,
				command.ID,
				actionfacts.StaticCurlFTPProxyRequestComponentsForFacts(
					facts,
					command.ID,
				),
			)
		curlProxyUploadEgress :=
			trustedActionContentRuleMatchesExternalProxyRequestComponents(
				facts,
				*rule,
				command.ID,
				actionfacts.StaticCurlProxyUploadPayloads(command),
			)
		wgetMetadata := actionfacts.StaticWgetTransmittedMetadata(command)
		wgetHTTPMetadataEgress := httpEgress &&
			(trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				wgetMetadata.HTTPHeaders,
			) || trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				wgetMetadata.HTTPOriginCredentials,
			))
		wgetFTPOriginAuthEgress := ftpEgress &&
			trustedActionContentRuleMatchesParsedCandidates(
				*rule,
				wgetMetadata.FTPOriginCredentials,
			)
		wgetRequestComponentEgress :=
			trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				wgetMetadata.HTTPRequestComponents,
			) || trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				wgetMetadata.HTTPDestinationHostnameComponents,
			)
		wgetTargetBoundOriginAuthEgress :=
			trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				wgetMetadata.HTTPOriginCredentialComponents,
			) || trustedActionContentRuleMatchesExternalRequestComponents(
				facts,
				*rule,
				command.ID,
				wgetMetadata.FTPOriginCredentialComponents,
			)
		if httpMetadataEgress || ftpOriginAuthEgress || curlProxyMetadataEgress ||
			curlSOCKSProxyCredentialEgress || curlFTPProxyMetadataEgress ||
			curlProxyUploadEgress ||
			curlRequestComponentEgress || curlTargetBoundOriginAuthEgress ||
			curlSMTPRequestEgress || curlTelnetOptionEgress ||
			wgetHTTPMetadataEgress || wgetFTPOriginAuthEgress ||
			wgetRequestComponentEgress || wgetTargetBoundOriginAuthEgress {
			return true
		}
		if trustedActionStaticContentPipesToExternalEgress(
			facts,
			*rule,
			command,
		) {
			return true
		}
	}
	return false
}

func trustedActionStaticContentPipesToExternalEgress(
	facts actionfacts.Facts,
	rule PatternRule,
	source actionfacts.CommandFact,
) bool {
	if !trustedActionStaticPrintfEmitsRuleMatch(rule, source) &&
		!trustedActionStaticEchoEmitsRuleMatch(rule, source) {
		return false
	}
	return trustedActionCommandFeedsExternalUpload(facts, source.ID)
}

func trustedActionPathReadFeedsExternalUpload(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	for _, source := range facts.Commands {
		if source.ID != candidate.CommandID ||
			!trustedActionStaticPathProducerEmitsPath(source, candidate) {
			continue
		}
		return trustedActionCommandFeedsExternalUpload(facts, source.ID)
	}
	return false
}

func trustedActionSameCommandPathReadFeedsExternalEgress(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	for _, command := range facts.Commands {
		if command.ID != candidate.CommandID {
			continue
		}
		if !oneOfFold(command.Program, "curl", "curl.exe") {
			return trustedActionCommandProvesExternalEgress(facts, command.ID)
		}
		// Resolve the route per target. A global "any SOCKS observer"
		// check would let a local HTTP observer steal a sibling noproxy
		// upload, and a global "no SOCKS observer" check would treat
		// HTTPS-through-SOCKS bodies as direct NetworkUpload facts.
		for _, source := range actionfacts.StaticCurlProxyUploadFileSources(command) {
			if source.Path != candidate.Value {
				continue
			}
			for _, network := range facts.Network {
				if network.CommandID == command.ID &&
					network.Action == actionfacts.NetworkConnect &&
					isExternalNetwork(network) &&
					strings.EqualFold(network.Scheme, source.Scheme) &&
					network.Host == source.Host && network.Port == source.Port {
					return true
				}
			}
		}
		for _, source := range actionfacts.StaticCurlDirectUploadFileSources(command) {
			if source.Path != candidate.Value {
				continue
			}
			for _, network := range facts.Network {
				if network.CommandID == command.ID && isExternalNetwork(network) &&
					networkActionIn(
						network.Action,
						actionfacts.NetworkDownload,
						actionfacts.NetworkUpload,
					) && strings.EqualFold(network.Scheme, source.Scheme) &&
					network.Host == source.Host && network.Port == source.Port {
					return true
				}
			}
		}
		return false
	}
	return false
}

func trustedActionStaticPathProducerEmitsPath(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if trustedActionStaticCatEmitsPath(command, candidate) {
		return true
	}
	base64Source, ok := actionfacts.StaticPOSIXBase64EncodeStdinSource(command)
	return ok && base64Source == candidate.Value
}

func trustedActionStaticCatEmitsPath(
	command actionfacts.CommandFact,
	candidate actionfacts.PathFact,
) bool {
	if command.Dialect != actionfacts.DialectPOSIX ||
		!command.ArgvComplete || command.ParentCommandID != 0 ||
		command.Program != "cat" || len(command.Argv) < 2 ||
		command.Executable != command.Argv[0] ||
		len(command.Wrappers) != 0 {
		return false
	}
	pathIndex := 1
	switch len(command.Argv) {
	case 2:
		if strings.HasPrefix(command.Argv[pathIndex], "-") {
			return false
		}
	case 3:
		if command.Argv[1] != "--" {
			return false
		}
		pathIndex = 2
	default:
		return false
	}
	if command.Argv[pathIndex] != candidate.Value &&
		(!trustedActionHomeRewrittenPath(candidate) || command.Argv[pathIndex] != candidate.Resolved) {
		return false
	}
	if len(command.Arguments) != len(command.Argv) {
		return false
	}
	for index, argument := range command.Arguments {
		if argument.Expands || argument.Quote == actionfacts.QuoteMixed ||
			argument.Value != command.Argv[index] {
			return false
		}
	}
	switch command.Executable {
	case "cat", "/bin/cat", "/sbin/cat", "/usr/bin/cat", "/usr/sbin/cat":
		return true
	default:
		return false
	}
}

func trustedActionHomeRewrittenPath(candidate actionfacts.PathFact) bool {
	return strings.HasPrefix(candidate.Value, "~/") ||
		strings.HasPrefix(candidate.Value, "$HOME/") ||
		strings.HasPrefix(candidate.Value, "${HOME}/")
}

func trustedActionCommandFeedsExternalUpload(
	facts actionfacts.Facts,
	sourceCommandID int64,
) bool {
	var source actionfacts.CommandFact
	for _, command := range facts.Commands {
		if command.ID == sourceCommandID {
			source = command
			break
		}
	}
	if source.PipelineID == 0 ||
		!trustedActionExecutingCommand(facts, source.ID) {
		return false
	}
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID != source.ID || flow.ToCommandID == 0 ||
			flow.From != actionfacts.DataStdout ||
			flow.To != actionfacts.DataStdin {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.ID != flow.ToCommandID ||
				destination.PipelineID != source.PipelineID ||
				!trustedActionExecutingCommand(facts, destination.ID) ||
				!hasOperation(destination, actionfacts.OperationUpload) {
				continue
			}
			if (destination.Program == "curl" || destination.Program == "curl.exe") &&
				!trustedActionCurlStdinFeedsExternalUpload(facts, destination) {
				continue
			}
			if !hasDataFlowFrom(
				facts,
				destination.ID,
				actionfacts.DataStdin,
				actionfacts.DataNetwork,
			) {
				continue
			}
			if hasExternalUpload(facts, destination.ID) ||
				trustedActionCurlStdinObservedByExternalSOCKS(facts, destination) {
				return true
			}
		}
	}
	return false
}

func trustedActionCurlStdinFeedsExternalUpload(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) bool {
	for _, target := range actionfacts.StaticCurlStdinUploadTargets(command) {
		for _, network := range facts.Network {
			if network.CommandID == command.ID &&
				network.Action == actionfacts.NetworkUpload &&
				isExternalNetwork(network) &&
				strings.EqualFold(network.Scheme, target.Scheme) &&
				network.Host == target.Host && network.Port == target.Port {
				return true
			}
		}
	}
	return trustedActionCurlStdinObservedByExternalSOCKS(facts, command)
}

func trustedActionCurlStdinObservedByExternalSOCKS(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) bool {
	if command.Program != "curl" && command.Program != "curl.exe" {
		return false
	}
	for _, target := range actionfacts.StaticCurlProxyStdinUploadTargets(command) {
		for _, network := range facts.Network {
			if network.CommandID == command.ID &&
				network.Action == actionfacts.NetworkConnect &&
				isExternalNetwork(network) &&
				strings.EqualFold(network.Scheme, target.Scheme) &&
				network.Host == target.Host && network.Port == target.Port {
				return true
			}
		}
	}
	return false
}

func trustedActionStaticPrintfEmitsRuleMatch(
	rule PatternRule,
	command actionfacts.CommandFact,
) bool {
	for _, segment := range actionfacts.StaticPOSIXPrintfFormatStdoutSegments(command) {
		if trustedActionRuleMatchesStaticOutputSegment(rule, segment) {
			return true
		}
	}
	return len(command.Redirects) == 0 &&
		trustedActionStaticPrintfArgumentMatchesRule(rule, command)
}

func trustedActionStaticEchoEmitsRuleMatch(
	rule PatternRule,
	command actionfacts.CommandFact,
) bool {
	for _, segment := range actionfacts.StaticPOSIXEchoStdoutSegments(command) {
		if trustedActionRuleMatchesStaticOutputSegment(rule, segment) {
			return true
		}
	}
	return false
}

func trustedActionRuleMatchesStaticOutputSegment(
	rule PatternRule,
	segment actionfacts.StaticOutputSegment,
) bool {
	return firstAcceptedRegexMatchAt(
		rule.Pattern,
		segment.Value,
		func(match string, start, end int) bool {
			if start == 0 && !segment.LeftExact ||
				end == len(segment.Value) && !segment.RightExact {
				return false
			}
			return acceptedRuleMatchAt(rule.ID, segment.Value, match, start, end)
		},
	) != nil
}

func trustedActionStaticPrintfArgumentMatchesRule(
	rule PatternRule,
	command actionfacts.CommandFact,
) bool {
	if command.Dialect != actionfacts.DialectPOSIX ||
		!command.ArgvComplete ||
		command.ParentCommandID != 0 ||
		command.Program != "printf" || len(command.Argv) < 3 ||
		command.Executable != command.Argv[0] ||
		len(command.Wrappers) != 0 {
		return false
	}
	formatIndex := 1
	switch len(command.Argv) {
	case 3:
	case 4:
		if command.Argv[1] != "--" {
			return false
		}
		formatIndex = 2
	default:
		return false
	}
	switch command.Executable {
	case "printf", "/bin/printf", "/sbin/printf", "/usr/bin/printf", "/usr/sbin/printf":
	default:
		return false
	}
	if len(command.Arguments) != len(command.Argv) {
		return false
	}
	for index, argument := range command.Arguments {
		if argument.Expands || argument.Quote == actionfacts.QuoteMixed ||
			argument.Value != command.Argv[index] {
			return false
		}
	}
	format := command.Argv[formatIndex]
	if format != `%s` && format != `%s\n` {
		return false
	}
	return firstAcceptedRuleMatch(rule, command.Argv[formatIndex+1]) != nil
}

func trustedActionContentRuleMatchesStaticUpload(
	rule PatternRule,
	command actionfacts.CommandFact,
) bool {
	return trustedActionContentRuleMatchesParsedCandidates(
		rule,
		actionfacts.StaticCurlUploadPayloads(command),
	) || trustedActionContentRuleMatchesParsedCandidates(
		rule,
		actionfacts.StaticWgetUploadPayloads(command),
	)
}

// These candidates are effective argv operands from complete curl/wget
// parsers. Match their bytes exactly: shell normalization here would change
// the body that the uploader actually transmits.
func trustedActionContentRuleMatchesParsedCandidates(
	rule PatternRule,
	candidates []string,
) bool {
	for _, candidate := range candidates {
		if firstAcceptedRuleMatch(rule, candidate) != nil {
			return true
		}
	}
	return false
}

func trustedActionContentRuleMatchesExternalRequestComponents(
	facts actionfacts.Facts,
	rule PatternRule,
	commandID int64,
	queries []actionfacts.TransmittedRequestComponent,
) bool {
	for _, query := range queries {
		if firstAcceptedRuleMatch(rule, query.Value) == nil {
			continue
		}
		for _, network := range facts.Network {
			if network.CommandID == commandID && isExternalNetwork(network) &&
				networkActionIn(
					network.Action,
					actionfacts.NetworkDownload,
					actionfacts.NetworkUpload,
				) && strings.EqualFold(network.Scheme, query.Scheme) &&
				network.Host == query.Host && network.Port == query.Port {
				return true
			}
		}
	}
	return false
}

func trustedActionContentRuleMatchesExternalProxyRequestComponents(
	facts actionfacts.Facts,
	rule PatternRule,
	commandID int64,
	components []actionfacts.TransmittedRequestComponent,
) bool {
	for _, component := range components {
		if firstAcceptedRuleMatch(rule, component.Value) == nil {
			continue
		}
		for _, network := range facts.Network {
			if network.CommandID == commandID &&
				network.Action == actionfacts.NetworkConnect &&
				isExternalNetwork(network) &&
				strings.EqualFold(network.Scheme, component.Scheme) &&
				network.Host == component.Host && network.Port == component.Port {
				return true
			}
		}
	}
	return false
}

func trustedActionStaticPrintfWritesSensitivePath(
	facts actionfacts.Facts,
	rule PatternRule,
	command actionfacts.CommandFact,
) bool {
	if len(command.Redirects) != 1 ||
		!trustedActionStaticPrintfArgumentMatchesRule(rule, command) {
		return false
	}
	redirect := command.Redirects[0]
	if redirect.FD != 1 || redirect.Expands ||
		(redirect.Access != actionfacts.PathAccessWrite &&
			redirect.Access != actionfacts.PathAccessAppend) {
		return false
	}
	for _, candidate := range facts.Paths {
		if candidate.CommandID == command.ID &&
			candidate.Access == redirect.Access &&
			candidate.Value == redirect.Target &&
			matchesActiveSensitivePath(facts, candidate) {
			return true
		}
	}
	return false
}

func trustedActionCommandProvesExternalEgress(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	return hasExternalUpload(facts, commandID) &&
		hasDataFlowFrom(
			facts,
			commandID,
			actionfacts.DataProcess,
			actionfacts.DataNetwork,
		)
}

func trustedActionCommandProvesExternalRequestForSchemes(
	facts actionfacts.Facts,
	commandID int64,
	schemes ...string,
) bool {
	for _, network := range facts.Network {
		if network.CommandID == commandID && isExternalNetwork(network) &&
			networkActionIn(
				network.Action,
				actionfacts.NetworkDownload,
				actionfacts.NetworkUpload,
			) && slices.Contains(schemes, strings.ToLower(network.Scheme)) {
			return true
		}
	}
	return false
}

func trustedActionExecutingCommand(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	if commandID == 0 {
		return false
	}
	for _, command := range facts.Commands {
		if command.ID == commandID {
			return command.Kind == actionfacts.CommandKindProcess &&
				command.Effect == actionfacts.EffectExecute &&
				command.ArgvComplete
		}
	}
	return false
}

// trustedActionOrdinaryCredentialCopyFindings is the balanced reading of a
// name that only starts like the AWS credentials file. Outside the strict
// tier a file such as credentials.bak is an ordinary file: its path finding
// stays visible but does not block, as for the other near names of a
// credentials file (credentials-old, .netrc.bak). The credentials file
// itself keeps its verdict in every tier, named directly or through a link (a
// path fact carries the target of a link), and so does an action that also
// names it. Only a finding whose path facts are all copies is lowered; a
// finding with no path fact for the rule keeps its verdict. The strict tier
// keeps every copy protected.
func trustedActionOrdinaryCredentialCopyFindings(
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	if !facts.Authoritative() {
		return findings
	}
	copies, exact := false, false
	for _, candidate := range facts.Paths {
		value := semanticPathValue(candidate)
		switch {
		case matchesExactAWSCredentials(value):
			exact = true
		case matchesAWSCredentials(value):
			copies = true
		}
	}
	if !copies || exact {
		return findings
	}
	for index, finding := range findings {
		if (finding.RuleID == "PATH-AWS-CREDS" || finding.RuleID == "PATH-WIN-AWS-CREDS") &&
			finding.contributesToEnforcement() {
			findings[index] = trustedActionAuditFinding(finding)
		}
	}
	return findings
}

func trustedActionAuditFinding(finding RuleFinding) RuleFinding {
	finding.enforcement = findingEnforcementDetectionOnly
	finding.disposition = findingDispositionAudit
	finding.Severity = trustedActionLowerSeverity(finding.Severity, "LOW")
	return finding
}

func trustedActionAdvisoryFinding(finding RuleFinding) RuleFinding {
	finding.enforcement = findingEnforcementDetectionOnly
	finding.disposition = findingDispositionAdvisory
	finding.Severity = trustedActionLowerSeverity(finding.Severity, "MEDIUM")
	return finding
}

func trustedActionLowerSeverity(current, ceiling string) string {
	rank := func(severity string) int {
		switch strings.ToUpper(strings.TrimSpace(severity)) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	if rank(current) > rank(ceiling) {
		return ceiling
	}
	return current
}

func trustedActionShippedGitAdvisoryRule(
	generation *compiledRulePackCategories,
	ruleID string,
) bool {
	switch canonicalTrustedRuleID(ruleID) {
	case "INTEGRITY.GIT_HOOKS_BYPASS", "SOURCE.GIT_REMOTE_TAMPER":
	default:
		return false
	}

	category, active, ok := trustedActionCatalogRule(generation, ruleID)
	if !ok {
		return false
	}
	defaultCategory, shipped, ok := trustedActionCatalogRuleInCategories(
		defaultRuleCategories(),
		ruleID,
	)
	return ok && category == defaultCategory &&
		trustedActionSamePatternRule(*active, *shipped)
}

func trustedActionCatalogRule(
	generation *compiledRulePackCategories,
	ruleID string,
) (string, *PatternRule, bool) {
	if generation == nil {
		return "", nil, false
	}
	return trustedActionCatalogRuleInCategories(generation.categories, ruleID)
}

func trustedActionCatalogRuleInCategories(
	categories []ruleCategory,
	ruleID string,
) (string, *PatternRule, bool) {
	for categoryIndex := range categories {
		category := &categories[categoryIndex]
		for ruleIndex := range category.Rules {
			rule := &category.Rules[ruleIndex]
			if rule.ID == ruleID {
				return category.Name, rule, true
			}
		}
	}
	return "", nil, false
}

func trustedActionSamePatternRule(left, right PatternRule) bool {
	leftPattern := ""
	if left.Pattern != nil {
		leftPattern = left.Pattern.String()
	}
	rightPattern := ""
	if right.Pattern != nil {
		rightPattern = right.Pattern.String()
	}
	return left.ID == right.ID &&
		leftPattern == rightPattern &&
		left.Expression == right.Expression &&
		left.ToolCallOnly == right.ToolCallOnly &&
		left.Title == right.Title &&
		left.Severity == right.Severity &&
		left.Confidence == right.Confidence &&
		slices.Equal(left.Tags, right.Tags)
}
