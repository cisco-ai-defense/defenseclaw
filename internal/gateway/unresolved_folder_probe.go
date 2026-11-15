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

// unresolvedFolderWriteNames are the files of a known name that are
// protected against a write (a shell profile, authorized_keys, the account
// and sudoers files): reading them is ordinary work (a profile audit).
// unresolvedFolderReadNames are protected against a read as well: the
// account database, a private key, a token file of a home.
var (
	unresolvedFolderWriteNames = []string{
		".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
		"authorized_keys", "authorized_keys2", "passwd", "sudoers",
	}
	unresolvedFolderReadNames = []string{
		"shadow", "gshadow", "master.passwd", "credentials",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
		".git-credentials", ".netrc", "_netrc", ".pgpass",
	}
)

// unresolvedFolderNamesProtectedFile reports a relative operand that is a
// named protected file in one of the folders an unresolved folder may be (the
// active home, a folder of it, /etc, /root), for the access the command
// makes. A name is matched whole, or as the path the operand spells when it
// has a folder of its own: .ssh/<key> and .ssh/authorized_keys, or the
// credentials table, home files only (.aws/credentials, .kube/config). A bare config, config.json or token,
// and a copy or a source file beside a credential (credentials.py), are files
// of every project: owner traces had 12 strict false blocks of `config` and
// one of `credentials.py` (s7-td327fix tdfx-h, tdfx-f).
func unresolvedFolderNamesProtectedFile(value, home string, access actionfacts.PathAccess) bool {
	value = path.Clean(strings.TrimPrefix(value, "./"))
	if value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "/") {
		return false
	}
	base := path.Base(value)
	named := func(name string) bool {
		return slices.Contains(unresolvedFolderReadNames, name) ||
			access != actionfacts.PathAccessRead && slices.Contains(unresolvedFolderWriteNames, name)
	}
	if !strings.Contains(value, "/") {
		return named(value)
	}
	// A name below a folder of its own is the protected file only in the
	// folder that holds it in a home: .ssh/id_rsa and .ssh/authorized_keys,
	// not src/credentials or internal/openshell/credentials (owner traces: 3
	// strict false blocks of project folders named credentials, tdfx-z).
	if value == ".ssh/"+base && named(base) {
		return true
	}
	candidate := path.Join(home, value)
	shape, ok := actionfacts.MatchCredentialFileShape(candidate)
	return ok && shape.HomeFile && candidate == path.Join(home, shape.Relative)
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
			unresolvedFolderNamesProtectedFile(candidate.Value, home, candidate.Access) {
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
