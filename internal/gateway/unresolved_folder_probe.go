// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A relative operand names a file in the folder its command runs in. When the
// call does not say which folder that is (a cd to "$X", to "$(...)", popd, a
// loop that moves on each pass, or no folder from the agent at all), the
// operand keeps its reading in the hook's folder (actionfacts
// working_folder.go), which is no proof it is not a protected file: `cd
// "$D" && cat credentials` reads ~/.aws/credentials when D is ~/.aws. When
// the operand is, in one of the folders that hold an account's or the host's
// named protected files, one of those files (a credentials file of the shared
// table, a private key, authorized_keys, a shell profile, an account
// database or sudoers), the call gets the unknown tier of the one bound rule:
// an alert in default, permissive and the managed default pack, a block in
// strict and managed-strict. Never the finding of the file itself (the folder
// is not known, so no confident path) and never CRITICAL from the uncertainty
// alone (rel-1-0-10:GAP-0871). A folder in which every file is protected
// (DefenseClaw state, git hooks, cron.d, the unit and autostart folders) is
// not read so: any name would be one, and `cd "$D" && echo ok > out.txt`
// would be the unknown tier.

// unresolvedFolderTitle is the reason of that unknown-tier finding.
const unresolvedFolderTitle = "A file this command names sits in a folder the command does not give, and it may be a protected file there"

// unresolvedFolderReason is the evidence code of the finding.
const unresolvedFolderReason = "unresolved_folder"

// unresolvedFolderHomeNames are the protected files of a known name directly
// in a home (the shell profiles) or in its .ssh folder; unresolvedFolderHostNames
// those of the host's /etc.
var (
	unresolvedFolderHomeNames = []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin"}
	unresolvedFolderSSHNames  = []string{"authorized_keys", "authorized_keys2"}
	unresolvedFolderHostNames = []string{"shadow", "gshadow", "passwd", "sudoers", "master.passwd"}
	// unresolvedFolderGenericNames are the names of credential files that
	// every project also has (owner traces: 12 strict false blocks of
	// `config` operands in agent-transcripts-sample, s7-td327fix tdfx-h).
	unresolvedFolderGenericNames = []string{"config", "config.json", "token", "hosts.yml", "auth.toml"}
)

// unresolvedFolderNamesProtectedFile reports a relative operand that is a
// named protected file in one of the folders an unresolved folder may be: the
// active home, a folder of it, /etc, /root.
func unresolvedFolderNamesProtectedFile(value, home string) bool {
	value = path.Clean(strings.TrimPrefix(value, "./"))
	if value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return false
	}
	base := path.Base(value)
	if slices.Contains(unresolvedFolderHostNames, value) || slices.Contains(unresolvedFolderHomeNames, value) ||
		slices.Contains(unresolvedFolderSSHNames, base) {
		return true
	}
	// The credentials-file table, read as if the operand ended a path in the
	// home (`credentials` is ~/.aws/credentials, `.kube/config` itself):
	// a shape that belongs in a home, or a private key. A name a project
	// ships (.env, .npmrc, .pypirc) is not one.
	for _, folder := range []string{"", ".ssh", ".aws", ".kube", ".docker", ".config/gh", ".config/gcloud"} {
		if folder != "" && slices.Contains(unresolvedFolderGenericNames, value) {
			// A bare config, config.json or token is a file of every
			// project; only its folder (.kube/config) names a credential.
			continue
		}
		candidate := path.Join(home, folder, value)
		shape, ok := actionfacts.MatchCredentialFileShape(candidate)
		if !ok || !strings.HasSuffix(candidate, "/"+shape.Relative) {
			continue
		}
		if shape.HomeFile || shape.Class == actionfacts.CredentialFileSSHPrivateKey {
			return true
		}
	}
	return false
}

// unresolvedFolderOperand reports a path fact the unknown tier reads: a
// relative operand that reads, writes or removes a file.
func unresolvedFolderOperand(candidate actionfacts.PathFact) bool {
	switch candidate.Access {
	case actionfacts.PathAccessRead, actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
	default:
		return false
	}
	value := candidate.Value
	return value != "" && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "~") && !strings.HasPrefix(value, "$") &&
		!strings.Contains(value, "://") && !strings.HasPrefix(value, "-")
}

// unresolvedFolderMayNameProtectedFile reports a call (facts) with a
// relative operand in a folder it does not give that may be a named
// protected file there. noFolder: the call has no folder at all.
func unresolvedFolderMayNameProtectedFile(facts actionfacts.Facts, noFolder bool) bool {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !path.IsAbs(home) || facts.Parse.Dialect != actionfacts.DialectPOSIX {
		return false
	}
	for _, candidate := range facts.Paths {
		if (noFolder || candidate.UnresolvedFolder()) && unresolvedFolderOperand(candidate) &&
			unresolvedFolderNamesProtectedFile(candidate.Value, home) {
			return true
		}
	}
	return false
}

// withUnresolvedFolderTier adds the unknown tier to the findings of a call,
// or of one statement of a split call the walk could not place (statement),
// whose relative operand may be a named protected file in a folder the call
// does not give. A twin, a statement of a split call read on its own pass and
// a managed call the hook client placed (the gateway places it where the
// client ran it) add nothing here.
func withUnresolvedFolderTier(findings []RuleFinding, request trustedActionRequest, facts actionfacts.Facts, statement bool) []RuleFinding {
	if request.hostTwinDepth != 0 || request.stateProofOnly || request.simpleCommandPass && !statement {
		return findings
	}
	noFolder := !path.IsAbs(request.Input.CWD)
	if noFolder && path.IsAbs(request.ResolvedWriteTargets[hookpaths.CWDKey]) {
		return findings
	}
	if slices.ContainsFunc(findings, RuleFinding.contributesToEnforcement) {
		// A proven finding decides on its own; the unknown tier adds nothing.
		return findings
	}
	if !unresolvedFolderMayNameProtectedFile(facts, noFolder || statement) {
		return findings
	}
	unknown := trustedActionLimitFindings(request.EnforcementCapable)
	if len(unknown) == 0 {
		return findings
	}
	unknown[0].Title = unresolvedFolderTitle
	unknown[0].Evidence = unresolvedFolderReason
	return withUnknownFinding(findings, unknown[0])
}
