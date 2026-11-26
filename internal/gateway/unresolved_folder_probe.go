// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
// not read so by a bare name: any name would be one, and `cd "$D" && echo ok
// > out.txt` would be the unknown tier. The operand that spells the folder
// itself (.defenseclaw/config.yaml) is as distinctive as .ssh/id_rsa: a
// write to it is read so (rel-1-0-10:GAP-0961). A pathname pattern
// (.ssh/id_*, .aws/*) is read as each protected spelling it may match
// (actionfacts.RelativeGlobTwinsNamed, rel-1-0-10:GAP-0960).

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
// has a folder of its own: a key or authorized_keys in a folder named .ssh,
// whichever folder holds that (alice/.ssh/id_rsa below a parent of the
// home, ../x/.ssh/id_ed25519: rel-1-0-10:GAP-0960); a write to DefenseClaw
// state spelled from the home (.defenseclaw/config.yaml, .defenseclaw/hooks/x:
// rel-1-0-10:GAP-0961); or the credentials table, home files only
// (.aws/credentials, .kube/config). A bare config, config.json or token, a
// read of a shell profile, a copy or a source file beside a credential
// (credentials.py) and a project folder named credentials are files of
// every project: owner traces had 12 strict false blocks of `config`, one
// of `credentials.py` and 3 of project folders named credentials
// (s7-td327fix tdfx-h, tdfx-f, tdfx-z).
func unresolvedFolderNamesProtectedFile(value, home string, access actionfacts.PathAccess) bool {
	// Clean first: it drops every leading ./ (./x, .//x, ././/x read as x),
	// where trimming one ./ before it left .//x as the absolute /x, which
	// named nothing (rel-1-0-10:GAP-1013).
	value = path.Clean(value)
	if value == "." || value == ".." || strings.HasPrefix(value, "/") {
		return false
	}
	if unresolvedFolderNamesKeyFile(value, access) {
		return true
	}
	if !strings.Contains(value, "/") {
		return false
	}
	if strings.HasPrefix(value, "../") {
		return false
	}
	// A parent of the home spells the same file from its own folder
	// (alice/.aws/credentials, home/alice/.defenseclaw/config.yaml): read it
	// as the spelling from the home (rel-1-0-10:GAP-1004).
	value = fromHomeSpelling(value, home)
	if state, ok := strings.CutPrefix(value, ".defenseclaw/"); ok && access != actionfacts.PathAccessRead {
		member, _, _ := strings.Cut(state, "/")
		return slices.Contains(activeDefenseClawStateNames, member)
	}
	candidate := path.Join(home, value)
	shape, ok := actionfacts.MatchCredentialFileShape(candidate)
	return ok && shape.HomeFile && candidate == path.Join(home, shape.Relative)
}

// unresolvedFolderNamed reports a file name of the name lists protected
// against the access.
func unresolvedFolderNamed(name string, access actionfacts.PathAccess) bool {
	return slices.Contains(unresolvedFolderReadNames, name) ||
		access != actionfacts.PathAccessRead && slices.Contains(unresolvedFolderWriteNames, name)
}

// unresolvedFolderNamesKeyFile reports a cleaned relative operand (/
// separators) that is a file of the name lists alone, or a key or
// authorized_keys in a folder named .ssh: that is one wherever the folder is,
// the name and its folder are distinctive together.
func unresolvedFolderNamesKeyFile(value string, access actionfacts.PathAccess) bool {
	if !strings.Contains(value, "/") {
		return unresolvedFolderNamed(value, access)
	}
	if path.Base(path.Dir(value)) != ".ssh" {
		return false
	}
	if unresolvedFolderNamed(path.Base(value), access) {
		return true
	}
	shape, ok := actionfacts.MatchCredentialFileShape(value)
	return ok && shape.Class == actionfacts.CredentialFileSSHPrivateKey
}

// powerShellUnresolvedFolderNamesKeyFile reports a PowerShell call that
// writes, appends to or removes a relative operand after a move to a folder
// the gateway cannot know (Set-Location $env:X, a -WorkingDirectory of a
// variable: the agent's environment never reaches the hook) when that operand
// is a file of the name lists, alone or in a folder named .ssh
// (unresolvedFolderNamesKeyFile, the names a POSIX call is read so by). Case
// does not matter on Windows. A read, an operand spelled from the home or the
// credentials table, DefenseClaw state and every other name keep their
// reading in the hook's folder: config.yaml, settings.json and the like are
// files of every project, so a write of config.yaml after Set-Location $env:X
// stays allowed, the documented limit of the hook (lead ruling 2026-11-26 on
// rel-1-0-10:GAP-1556).
func powerShellUnresolvedFolderNamesKeyFile(facts actionfacts.Facts) bool {
	if facts.Parse.Dialect != actionfacts.DialectPowerShell {
		return false
	}
	for _, candidate := range facts.Paths {
		if !candidate.UnresolvedFolder() || candidate.Access == actionfacts.PathAccessRead || !unresolvedFolderOperand(candidate) {
			continue
		}
		value := strings.ToLower(strings.ReplaceAll(candidate.Value, `\`, "/"))
		if strings.HasPrefix(value, "/") || strings.Contains(value, ":") {
			continue // a drive, a provider or a share path names its own folder
		}
		if value = path.Clean(value); value == "." || value == ".." {
			continue
		}
		if unresolvedFolderNamesKeyFile(value, candidate.Access) {
			return true
		}
	}
	return false
}

// powerShellHostReadingsNameKeyFile reports a call one of whose script
// readings (the body of pwsh -Command or of pwsh -wd $env:X -Command, a
// statement list) is such a PowerShell write. A reading is judged as a twin of
// the call, and a twin adds only its proven blocks to the call
// (withHostTwinFindings), so the unknown tier of the reading is the call's
// own. Only the first-level readings are asked, and only those whose text
// holds one of the names.
func powerShellHostReadingsNameKeyFile(request trustedActionRequest, facts actionfacts.Facts) bool {
	if request.hostScriptTwinOff || facts.Parse.Dialect != actionfacts.DialectPowerShell && len(request.Input.Argv) == 0 ||
		!unresolvedFolderTextHoldsName(request.Input.Command+" "+string(request.Input.Args)+" "+strings.Join(request.Input.Argv, " ")) {
		return false
	}
	for _, input := range actionfacts.HostScriptReadings(request.Input, facts, 0, false).Twins {
		if input.Command != "" && !unresolvedFolderTextHoldsName(input.Command) {
			continue
		}
		if powerShellUnresolvedFolderNamesKeyFile(actionfacts.Analyze(input)) {
			return true
		}
	}
	return false
}

// unresolvedFolderTextHoldsName is the cheap screen of
// powerShellHostReadingsNameKeyFile: text (any case) that holds no name of
// the name lists names none of those files.
func unresolvedFolderTextHoldsName(text string) bool {
	text = strings.ToLower(text)
	holds := func(name string) bool { return strings.Contains(text, name) }
	return slices.ContainsFunc(unresolvedFolderReadNames, holds) || slices.ContainsFunc(unresolvedFolderWriteNames, holds)
}

// fromHomeSpelling drops the folder names that lead from a parent of the home
// (the one that holds the account folders, or its parent) down to the home:
// alice/.aws/credentials and home/alice/.aws/credentials are .aws/credentials
// when the home is /home/alice. A value that does not start so is returned as
// it is.
func fromHomeSpelling(value, home string) string {
	user := path.Base(home)
	if user == "/" || user == "." || user == "" {
		return value
	}
	if rest, ok := strings.CutPrefix(value, user+"/"); ok {
		return rest
	}
	if parent := path.Base(path.Dir(home)); parent != "/" && parent != "." {
		if rest, ok := strings.CutPrefix(value, parent+"/"+user+"/"); ok {
			return rest
		}
	}
	return value
}

// unresolvedFolderGlobNames are the relative spellings a pathname pattern
// of an unresolved folder is matched against (RelativeGlobTwinsNamed): every
// name of the name lists, alone and in .ssh, DefenseClaw state from the
// home, and one path of each row of the credentials table. The twin is
// judged by unresolvedFolderNamesProtectedFile, so a spelling here that is
// no protected file adds nothing.
var unresolvedFolderGlobNames = sync.OnceValue(func() []string {
	var names []string
	for _, name := range slices.Concat(unresolvedFolderReadNames, unresolvedFolderWriteNames) {
		names = append(names, name, ".ssh/"+name)
	}
	for _, name := range activeDefenseClawStateNames {
		names = append(names, ".defenseclaw/"+name)
	}
	for _, name := range actionfacts.CredentialFileShapeProbePaths() {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
})

// unresolvedFolderGlobMayNameProtectedFile reports a call whose pathname
// pattern, in a folder the call does not give, may match a named protected
// file there: the twin that spells each protected name the pattern may
// match (as if each existed, one reading per match) has an operand the
// unknown tier reads. truncated is the cap the reading hit when a pattern
// that is such an operand may match more names than the twin reads
// (rel-1-0-10:GAP-1003); a capped pattern the call only lists or never
// opens is no truncated operand.
func unresolvedFolderGlobMayNameProtectedFile(request trustedActionRequest, facts actionfacts.Facts, noFolder bool) (names bool, truncated bounded.CapSet) {
	if facts.Parse.Dialect != actionfacts.DialectPOSIX || !noFolder && !facts.MayRunInUnresolvedFolder() {
		return false, truncated
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false, truncated
	}
	reading := actionfacts.RelativeGlobTwinsNamed(command, request.Input.ActiveHome, unresolvedFolderGlobNames())
	cappedOperand := false
	for _, twin := range reading.Twins {
		input := request.Input
		input.Command, input.Args, input.Argv = twin, nil, nil
		twinFacts := actionfacts.Analyze(input)
		if facts.MoverCallsUnread() {
			// Each twin is read as the call is (withSplitGapEffects).
			if unread, ok := twinFacts.WithMoverCallsUnread(input.MovedWindowsShellCWD); ok {
				twinFacts = unread
			}
		}
		names = names || unresolvedFolderMayNameProtectedFile(twinFacts, noFolder)
		cappedOperand = cappedOperand || reading.Truncated.Any() && slices.ContainsFunc(twinFacts.Paths, func(candidate actionfacts.PathFact) bool {
			return (noFolder || candidate.UnresolvedFolder()) && unresolvedFolderOperand(candidate) &&
				slices.ContainsFunc(reading.Capped, func(word string) bool {
					// Cleaned on both sides: a capped ./.ssh/id_rsa is the
					// operand ./.ssh/id_rsa, .//.ssh/id_rsa or .ssh/id_rsa
					// (rel-1-0-10:GAP-1013).
					return path.Clean(word) == path.Clean(candidate.Value)
				})
		})
		if names && (cappedOperand || !reading.Truncated.Any()) {
			break
		}
	}
	if cappedOperand {
		truncated = reading.Truncated
	}
	return names, truncated
}

// unresolvedFolderOperand reports a path fact the unknown tier reads: a
// relative operand that reads, writes or removes a file. A change of the
// file's mode or owner is not one: the tier knows only the file's name, and
// chmod 600 of a key guards it. After a split gap the call's own twins judge
// that change (withSplitGapEffects); elsewhere it is judged as rel 740c0de8fd
// judged it (substrate-1:GAP-0714).
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

// unresolvedFolderCurrentFolderTwin reads a call with no folder from the
// agent whose operand is spelled from the current folder ($PWD/.ssh/id_rsa,
// $(pwd)/.aws/*): that folder is as unknown as after a cd the walk cannot
// follow, so the twin that spells the operand alone
// (actionfacts.CurrentFolderHeadsAsRelative, the walk's own reading after
// such a cd) is read as the plain spelling is, the pattern and its cap
// included (rel-1-0-10:GAP-1023).
func unresolvedFolderCurrentFolderTwin(request trustedActionRequest) (bool, bounded.CapSet) {
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return false, bounded.CapSet{}
	}
	twin, ok := actionfacts.CurrentFolderHeadsAsRelative(command)
	if !ok {
		return false, bounded.CapSet{}
	}
	twinRequest := request
	twinRequest.Input.Command, twinRequest.Input.Args, twinRequest.Input.Argv = twin, nil, nil
	twinFacts := actionfacts.Analyze(twinRequest.Input)
	if unresolvedFolderMayNameProtectedFile(twinFacts, true) {
		return true, bounded.CapSet{}
	}
	return unresolvedFolderGlobMayNameProtectedFile(twinRequest, twinFacts, true)
}

// withUnresolvedFolderTier adds the unknown tier to the findings of a call,
// or of one statement of a split call the walk could not place (statement),
// whose relative operand may be a named protected file in a folder the call
// does not give. A twin, a statement of a split call read on its own pass and
// a managed call the hook client placed (the gateway places it where the
// client ran it) add nothing here. The folder the client places is the one
// the call starts in: a statement after a cd the walk could not follow runs
// in another folder, which that folder does not place. The Codex hook sends
// the folder with every call, so such a statement was allowed there where the
// Claude Code hook gave it the unknown tier (rel-1-0-10:GAP-1042).
func withUnresolvedFolderTier(findings []RuleFinding, request trustedActionRequest, facts actionfacts.Facts, statement bool) []RuleFinding {
	if request.hostTwinDepth != 0 || request.stateProofOnly || request.simpleCommandPass && !statement {
		return findings
	}
	noFolder := !path.IsAbs(request.Input.CWD)
	if noFolder && !statement && path.IsAbs(request.ResolvedWriteTargets[hookpaths.CWDKey]) {
		return findings
	}
	if slices.ContainsFunc(findings, RuleFinding.contributesToEnforcement) {
		// A proven finding decides on its own; the unknown tier adds nothing.
		return findings
	}
	names := unresolvedFolderMayNameProtectedFile(facts, noFolder || statement) ||
		powerShellUnresolvedFolderNamesKeyFile(facts) || powerShellHostReadingsNameKeyFile(request, facts)
	var truncated bounded.CapSet
	if !names {
		names, truncated = unresolvedFolderGlobMayNameProtectedFile(request, facts, noFolder || statement)
	}
	if !names && noFolder && !statement {
		names, truncated = unresolvedFolderCurrentFolderTwin(request)
	}
	if names {
		unknown := trustedActionLimitFindings(request.EnforcementCapable)
		if len(unknown) == 0 {
			return findings
		}
		unknown[0].Title = unresolvedFolderTitle
		unknown[0].Evidence = unresolvedFolderReason
		findings = withUnknownFinding(findings, unknown[0])
	}
	// A pattern the twin read only up to its cap is TRUNCATED: at least the
	// unknown tier, with the cap named, beside what was read before it (the
	// one bound rule, rel-1-0-10:GAP-1003).
	return withBoundedTruncation(findings, truncated, request)
}
