// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// A user who copies their own SSH key to another place in their own home (a
// backup folder, a renamed copy) exposes it to no one: the copy is as private
// as the original. The copy stays a visible alert, but it is not the content
// read of a key that leaves the user (rel-1-0-10:GAP-0018). A copy anywhere
// else (/tmp, another account's home) or any other reader of the key keeps the
// CRITICAL block.
//
// A place is private because of what the file system says about it, not
// because of its name: the destination, or the nearest folder above it that
// exists, has no group or other permission bit (hookpaths.HomePlaceOwnerOnly). A web
// root, a synced folder or a shared folder is made readable by others, and its
// bits say so; a place this gateway cannot read (a home hidden from a managed
// gateway, a Windows path) is not proven private and keeps the block of rel
// (rel-1-0-10:GAP-0710).
//
// The bits are read as they are before the call runs. A statement of the same
// call, anywhere and in any order, that may let a group or other users in makes
// them stale for that call, so nothing it writes is proven private and the
// block of rel stays (rel-1-0-10:GAP-0854): a chmod, a mkdir -m or a umask that
// opens a group or other bit or whose mode is not read, and any change of an
// owner, a group or an ACL (trustedActionCallOpensAccess). A mode that only
// takes bits away (chmod 600, go-rwx, umask 077) keeps the proof.

var (
	// trustedActionHomeCopyPrograms are the programs that copy a file.
	trustedActionHomeCopyPrograms = []string{"cp", "gcp", "copy", "copy-item", "cpi"}
	// trustedActionHomeCopyHarmless are the programs that may sit beside such
	// a copy (preparing the folder, saying that it is done). A chmod or mkdir
	// among them must not open access (trustedActionCallOpensAccess).
	trustedActionHomeCopyHarmless = []string{
		"mkdir", "md", "chmod", "echo", "printf", "true", "false", ":", "cd", "pwd",
		"ls", "dir", "test", "[", "write-host", "write-output",
	}
)

// trustedActionCallOpensAccess reports a call with a statement that may let a
// group or other users in (trustedActionCommandOpensAccess). A statement the
// dispatch judges on its own is read with the whole call it belongs to, and a
// call whose reading stopped at a bound is not proven free of one.
func trustedActionCallOpensAccess(request trustedActionRequest) bool {
	inputs := []actionfacts.Input{request.Input}
	if request.parentPatch != nil {
		inputs = append(inputs, *request.parentPatch)
	}
	for _, input := range inputs {
		facts := actionfacts.Analyze(input)
		if facts.Parse.Status == actionfacts.StatusLimitExceeded {
			return true
		}
		for _, command := range facts.Commands {
			if trustedActionCommandOpensAccess(command) {
				return true
			}
		}
	}
	return false
}

// trustedActionCommandOpensAccess reports a command of the action facts that
// may let a group or other users reach what it names: a permission change
// (chmod, chown, chgrp, setfacl, setcap, icacls, install with a mode) other
// than a chmod whose every mode clause only keeps or removes group and other
// bits, a mkdir whose -m mode opens one, or a umask that leaves one open. An
// argument list the facts did not read whole proves no such mode absent.
func trustedActionCommandOpensAccess(command actionfacts.CommandFact) bool {
	program := strings.ToLower(path.Base(command.Program))
	permission := hasOperation(command, actionfacts.OperationPermissionChange)
	if permission && program != "chmod" {
		return true
	}
	if !permission && program != "mkdir" && program != "umask" {
		return false
	}
	argv, known := trustedActionAccessArgv(command)
	switch {
	case !known:
		return true
	case program == "chmod":
		return chmodArgvOpensAccess(argv)
	case program == "mkdir":
		return mkdirArgvOpensAccess(argv)
	}
	return umaskArgvOpensAccess(argv)
}

// trustedActionAccessArgv is the argv of command for reading its options and
// mode. A word that expands is known only when it starts with a path ("~",
// "/"), which no option or mode does; it reads as that path.
func trustedActionAccessArgv(command actionfacts.CommandFact) ([]string, bool) {
	if command.ArgvComplete {
		return command.Argv, true
	}
	if len(command.Arguments) != len(command.Argv) {
		return nil, false
	}
	argv := slices.Clone(command.Argv)
	for index, argument := range command.Arguments {
		if !argument.Expands {
			continue
		}
		prefix := argument.StaticPrefix()
		if index == 0 || !strings.HasPrefix(prefix, "~") && !strings.HasPrefix(prefix, "/") {
			return nil, false
		}
		argv[index] = prefix
	}
	return argv, true
}

// umaskArgvOpensAccess reports a umask argv that sets a mask leaving a group
// or other bit open (umask 022), or a mask that cannot be read. umask alone,
// -S or -p only print the mask.
func umaskArgvOpensAccess(argv []string) bool {
	for _, arg := range argv[min(1, len(argv)):] {
		switch {
		case arg == "-S" || arg == "-p" || arg == "--":
		case arg != "" && strings.Trim(arg, "01234567") == "":
			value, err := strconv.ParseUint(arg, 8, 32)
			return err != nil || value&0o077 != 0o077
		default:
			// A symbolic umask names the bits it allows, as a chmod mode does.
			return posixModeOpensAccess(arg)
		}
	}
	return false
}

// chmodArgvOpensAccess reports a chmod argv whose mode opens a group or other
// bit, or whose mode cannot be read here (--reference, an unknown option).
func chmodArgvOpensAccess(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			return i+1 >= len(argv) || posixModeOpensAccess(argv[i+1])
		case strings.HasPrefix(arg, "--"):
			if !slices.Contains(strings.Fields("--changes --silent --quiet --verbose --recursive "+
				"--preserve-root --no-preserve-root --dereference --no-dereference"), arg) {
				return true
			}
		case len(arg) > 1 && arg[0] == '-' && strings.Trim(arg[1:], "RcfvHLPh") == "":
		default:
			// The first operand is the mode (-w is a mode too).
			return posixModeOpensAccess(arg)
		}
	}
	return true
}

// mkdirArgvOpensAccess reports a mkdir argv with a -m or --mode mode that
// opens a group or other bit or cannot be read.
func mkdirArgvOpensAccess(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			return false
		case arg == "--mode":
			return i+1 >= len(argv) || posixModeOpensAccess(argv[i+1])
		case strings.HasPrefix(arg, "--mode="):
			return posixModeOpensAccess(strings.TrimPrefix(arg, "--mode="))
		case strings.HasPrefix(arg, "--"):
		case len(arg) > 1 && arg[0] == '-':
			if index := strings.IndexByte(arg, 'm'); index >= 0 {
				if index+1 < len(arg) {
					return posixModeOpensAccess(arg[index+1:])
				}
				return i+1 >= len(argv) || posixModeOpensAccess(argv[i+1])
			}
		}
	}
	return false
}

// posixModeOpensAccess reports a chmod-style mode (octal, or symbolic clauses
// such as go-rwx,u+x) that adds or sets a read, write or search bit for the
// group or other users, a mode with no class (+x reaches everyone the umask
// lets in), a bit copied from another class (g=u), or text that is no mode.
func posixModeOpensAccess(mode string) bool {
	if mode != "" && strings.Trim(mode, "01234567") == "" {
		value, err := strconv.ParseUint(mode, 8, 32)
		return err != nil || value > 0o7777 || value&0o077 != 0
	}
	if mode == "" {
		return true
	}
	for _, clause := range strings.Split(mode, ",") {
		rest := strings.TrimLeft(clause, "ugoa")
		classes := clause[:len(clause)-len(rest)]
		reachesOthers := classes == "" || strings.ContainsAny(classes, "goa")
		if rest == "" {
			return true
		}
		for rest != "" {
			op := rest[0]
			if op != '+' && op != '-' && op != '=' {
				return true
			}
			rest = rest[1:]
			perms := rest[:len(rest)-len(strings.TrimLeft(rest, "rwxXstugo"))]
			rest = rest[len(perms):]
			if op == '-' {
				continue
			}
			if strings.ContainsAny(perms, "ugo") || reachesOthers && strings.ContainsAny(perms, "rwxX") {
				return true
			}
		}
	}
	return false
}

// trustedActionPrivateHomeDestination reports a write target below the active
// home (the home itself too) that no one else reads: the place is owner-only
// (hookpaths.HomePlaceOwnerOnly, read through places) and is not a file of the
// SSH folder that sshd or ssh read as policy.
func trustedActionPrivateHomeDestination(facts actionfacts.Facts, candidate actionfacts.PathFact, places homePlaceView) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	first, rest, _ := strings.Cut(relative, "/")
	if first == ".ssh" && !strings.Contains(rest, "/") {
		for _, protected := range []string{"authorized_keys", "authorized_keys2", "config", "environment", "rc"} {
			if rest == protected {
				return false
			}
		}
	}
	// The matchers read a folded spelling; the file system is asked about the
	// name as written, and only when the two are the same place.
	place := path.Clean(strings.ReplaceAll(strings.TrimSpace(pathFactSpelling(candidate)), `\`, "/"))
	if canonicalSemanticPath(place) != canonicalSemanticPath(semanticPathValue(candidate)) {
		return false
	}
	return places.ownerOnly(place)
}

// homePlaceView answers whether only its owner can reach a place of the
// active home. nil reads this host's file system (hookpaths.HomePlaceOwnerOnly,
// hookpaths.PrivateHomePlace); a Substrate actor's command twin and a judgment
// made only from the actor's kit claims read the kit's facts instead
// (substrateGuestClaims.homePlaces), which this gateway cannot check, so they
// are read only where the answer adds a finding to a call that would have none
// without the kit (substrate-1 GAP-0549). It points at the kit's places, a
// value, so the dispatch memo keys a request by the places it reads
// (reflect.DeepEqual compares the set): a closure is never deeply equal, and
// kept every repeat of an actor's request out of the memo (substrate-1
// GAP-0758).
type homePlaceView = *homePlaceSet

// homePlaceSet is the kit's private home places (substrateGuestClaims.homePlaces).
type homePlaceSet struct {
	places map[string]bool
	// byName: a copy-mode actor whose places neither this gateway nor a kit
	// can answer for; every place of the home outside its SSH folder is
	// taken as the owner's (substrate-1 GAP-0922). Only the by-name reading
	// of the actor's call, which adds the finding, reads such a view.
	byName bool
}

// ownerOnly is hookpaths.HomePlaceOwnerOnly read through view.
func (view *homePlaceSet) ownerOnly(place string) bool {
	if view != nil {
		return view.byName || view.places[path.Clean(place)]
	}
	return hookpaths.HomePlaceOwnerOnly(place)
}

// privateHome is hookpaths.PrivateHomePlace read through view.
func (view *homePlaceSet) privateHome(place, home string) bool {
	if view != nil {
		place = path.Clean(place)
		return pathWithin(place, home) && !pathWithin(place, home+"/.ssh") && (view.byName || view.places[place])
	}
	return hookpaths.PrivateHomePlace(place, home)
}

// trustedActionCommandWritesOnlyPrivateHome reports a command whose write
// targets are all private places in the active home. needWrite also asks for
// at least one such target.
func trustedActionCommandWritesOnlyPrivateHome(facts actionfacts.Facts, command actionfacts.CommandFact, needWrite bool, places homePlaceView) bool {
	wrote := false
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			wrote = true
			if !trustedActionPrivateHomeDestination(facts, candidate, places) {
				return false
			}
		}
	}
	for _, redirect := range command.Redirects {
		switch redirect.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend:
			if redirect.Target == "/dev/null" {
				continue
			}
			wrote = true
			if redirect.Expands || !trustedActionPrivateHomeDestination(facts, actionfacts.PathFact{Value: redirect.Target}, places) {
				return false
			}
		}
	}
	return wrote || !needWrite
}

// trustedActionPrivateHomeCopy reports one executing copy command that writes
// only private places in the active home. A wrapper (sudo, env, a shell) leaves
// the command a content read.
func trustedActionPrivateHomeCopy(facts actionfacts.Facts, command actionfacts.CommandFact, places homePlaceView) bool {
	return facts.ActiveHome != "" &&
		command.Kind == actionfacts.CommandKindProcess &&
		command.Effect == actionfacts.EffectExecute &&
		len(command.Wrappers) == 0 &&
		slices.Contains(trustedActionHomeCopyPrograms, strings.ToLower(command.Program)) &&
		trustedActionCommandWritesOnlyPrivateHome(facts, command, true, places)
}

// trustedActionHomeCopyReading reads the commands of facts: ok is set when
// every one is a copy into a private place of the active home or a harmless
// helper of that, and copied when at least one is such a copy.
func trustedActionHomeCopyReading(facts actionfacts.Facts, places homePlaceView) (ok, copied bool) {
	if !facts.Authoritative() || facts.ActiveHome == "" {
		return false, false
	}
	for _, command := range facts.Commands {
		if command.Kind != actionfacts.CommandKindProcess {
			return false, false
		}
		if command.Effect == actionfacts.EffectPreview {
			continue
		}
		if command.Effect != actionfacts.EffectExecute {
			return false, false
		}
		program := strings.ToLower(command.Program)
		switch {
		case trustedActionPrivateHomeCopy(facts, command, places):
			copied = true
		case len(command.Wrappers) == 0 && slices.Contains(trustedActionHomeCopyHarmless, program) &&
			trustedActionCommandWritesOnlyPrivateHome(facts, command, false, places):
		default:
			return false, false
		}
	}
	return true, copied
}

// trustedActionPrivateKeyOnlyCopiedInHome reports an action whose commands
// are all copies into private places of the active home or harmless helpers
// of that, with at least one such copy. A key it reads is therefore only
// copied inside the home. A list of commands (cp a b && echo done) is read
// command by command, as the hook judges each of its commands on its own; a
// command the reading cannot place keeps the block.
func trustedActionPrivateKeyOnlyCopiedInHome(input actionfacts.Input, facts actionfacts.Facts, places homePlaceView) bool {
	if input.ActiveHome == "" {
		return false
	}
	if facts.Authoritative() {
		ok, copied := trustedActionHomeCopyReading(facts, places)
		return ok && copied
	}
	simples := actionfacts.SimpleCommands(input, facts)
	if len(simples) == 0 {
		return false
	}
	anyCopy := false
	for _, simple := range simples {
		if simple.Text == "" || simple.OpaqueValueAssignment || simple.UnresolvedBoundVariable ||
			simple.LoginGuess || simple.UnboundUser || simple.EvaluationFailure != "" {
			return false
		}
		child := input
		child.Command, child.Args, child.Argv = simple.Text, nil, nil
		if simple.CWD != "" {
			child.CWD = simple.CWD
		}
		ok, copied := trustedActionHomeCopyReading(actionfacts.Analyze(child), places)
		if !ok {
			return false
		}
		anyCopy = anyCopy || copied
	}
	return anyCopy
}

// trustedActionKeyNamedWriteOutsideSSHDir reports a write, append or delete
// target that only carries the name of a private key (id_rsa, id_ed25519)
// outside an .ssh folder: a backup copy in ~/.ssh_backup, a test key made
// with ssh-keygen in a project, a file in /tmp. It is no change of a key the
// user's ssh reads, so the key rule has no mutation to judge there; the read
// of the real key that fed such a copy is judged on its own
// (rel-1-0-10:GAP-0018).
func trustedActionKeyNamedWriteOutsideSSHDir(ruleID string, candidate actionfacts.PathFact) bool {
	if ruleID != "PATH-SSH-KEY" && ruleID != "PATH-WIN-SSH-KEY" {
		return false
	}
	value := canonicalSemanticPath(semanticPathValue(candidate))
	return matchesSSHPrivateKey(value) && pathBase(path.Dir(value)) != ".ssh"
}

// appendTrustedPrivateKeyHomeCopyAlert adds the alert for a copy of a private
// key inside the active home when no earlier boundary found the key rule. A
// finding already there was judged by the disposition boundary.
func appendTrustedPrivateKeyHomeCopyAlert(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
) []RuleFinding {
	for _, finding := range findings {
		if finding.RuleID == "PATH-SSH-KEY" || finding.RuleID == "PATH-WIN-SSH-KEY" {
			return findings
		}
	}
	_, rule, ok := trustedActionCatalogRule(generation, "PATH-SSH-KEY")
	if !ok {
		return findings
	}
	finding := trustedActionAdvisoryFinding(adjustConfidence(request.Input.Tool, RuleFinding{
		RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity,
		Confidence: rule.Confidence, Evidence: trustedActionInputText(request.Input, ""),
		Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
	}))
	finding.Proof = finding.Proof.Advise()
	return append(findings, finding)
}

// ownSSHFolderCopyTitle is the title of the alert for a copy of the user's own
// SSH folder content to another place of the same home.
const ownSSHFolderCopyTitle = "A copy of your own SSH folder content to another place in your home"

// trustedActionOwnSSHFolderCopy reports a command that only copies content of
// the active user's own SSH folder (a key file, a glob of the folder, the
// folder) to a private place of the same home outside the SSH folder, with at
// most harmless helpers beside it. Such a copy exposes nothing the user did not
// already hold: the copy keeps the mode of its source, and nothing leaves the
// home. The key rules have no write to the user's authorized keys to judge there,
// so they alert (the copy widens where the keys live) and do not block
// (rel-1-0-10:GAP-0018). Where the destination is not provably inside the home
// (a link that leaves it, a shared folder, another account, /tmp), a wrapper
// runs the copy, anything else is written, or the home is hidden from this
// gateway, the block stays. Only its owner may reach the destination
// (hookpaths.PrivateHomePlace, read through request.guestHomePlaces), and
// nothing in the call opens access to it (trustedActionCallOpensAccess).
func trustedActionOwnSSHFolderCopy(request trustedActionRequest, input actionfacts.Input) bool {
	home := strings.TrimRight(input.ActiveHome, "/")
	if request.ProtectedHomeHook || home == "" || !trustedShellCommandInput(input) {
		return false
	}
	// A hook call carries the command in its arguments, not in Command.
	command := input.Command
	if command == "" {
		command, _ = trustedBashCommandInput(input)
	}
	if command == "" {
		return false
	}
	file, parsed := shellparse.ParseBash(command)
	if !parsed || len(file.Stmts) == 0 {
		return false
	}
	copied := false
	var visit func(stmt *syntax.Stmt) bool
	visit = func(stmt *syntax.Stmt) bool {
		if stmt == nil || len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || stmt.Negated {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op != syntax.AndStmt {
				return false
			}
			return visit(cmd.X) && visit(cmd.Y)
		case *syntax.CallExpr:
			if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
				return false
			}
			words := make([]string, len(cmd.Args))
			for i, arg := range cmd.Args {
				text, known := hookpaths.StaticWord(arg, home)
				if !known {
					// A glob of literal parts (/home/u/.ssh/*) is one literal here:
					// only the path before the glob is judged.
					text, known = ownSSHFolderLiteralGlob(arg)
				}
				if !known {
					return false
				}
				words[i] = text
			}
			switch strings.ToLower(path.Base(words[0])) {
			case "cp", "gcp":
				if !ownSSHFolderCopyCall(words[1:], input.CWD, home, request.guestHomePlaces) {
					return false
				}
				copied = true
				return true
			case "mkdir":
				return ownSSHFolderMkdirCall(words[1:], input.CWD, home, request.guestHomePlaces)
			case "echo", "printf", "true", ":", "pwd":
				return true
			}
		}
		return false
	}
	for _, stmt := range file.Stmts {
		if !visit(stmt) {
			return false
		}
	}
	// Read last: it analyzes the whole call, and only a call that is such a
	// copy needs it.
	return copied && !trustedActionCallOpensAccess(request)
}

// ownSSHFolderCopyCall judges the operands of one cp: safe options, sources
// inside the SSH folder of home, one destination in a private place of home.
func ownSSHFolderCopyCall(args []string, cwd, home string, places homePlaceView) bool {
	var operands []string
	target := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case arg == "-t" || arg == "--target-directory":
			if i+1 >= len(args) || target != "" {
				return false
			}
			i++
			target = args[i]
		case strings.HasPrefix(arg, "--target-directory="):
			if target != "" {
				return false
			}
			target = strings.TrimPrefix(arg, "--target-directory=")
		case strings.HasPrefix(arg, "--"):
			if !slices.Contains(strings.Fields("--recursive --archive --preserve --verbose --force --no-clobber --interactive --update --no-dereference"), arg) {
				return false
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			if strings.Trim(arg[1:], "rRapvfniuPHLTd") != "" {
				return false
			}
		default:
			operands = append(operands, arg)
		}
	}
	sources, destination := operands, target
	if target == "" {
		if len(operands) < 2 {
			return false
		}
		sources, destination = operands[:len(operands)-1], operands[len(operands)-1]
	}
	if len(sources) == 0 || destination == "" {
		return false
	}
	sshDir := home + "/.ssh"
	holdsKey := false
	for _, source := range sources {
		if clean := path.Clean(hookpaths.OperandPath(strings.TrimRight(source, "*"), cwd)); clean == sshDir ||
			strings.ContainsAny(source, "*?[") || matchesSSHPrivateKey(clean) {
			holdsKey = true
		}
		base := strings.ToLower(path.Base(strings.TrimRight(source, "/")))
		if strings.HasPrefix(base, "authorized_keys") || strings.HasPrefix(base, "authorized-keys") {
			// A named copy of the authorized keys file keeps its own rule (owner
			// ruling GAP-2590, dd and cp alike).
			return false
		}
		if !pathWithin(path.Clean(hookpaths.OperandPath(strings.TrimRight(source, "*"), cwd)), sshDir) {
			return false
		}
	}
	// A copy of a file that holds no private key (config, known_hosts, a .pub)
	// is a plain read the older rules already allow; only a copy that can carry
	// a private key is an own-key copy.
	return holdsKey && places.privateHome(hookpaths.OperandPath(destination, cwd), home)
}

// ownSSHFolderMkdirCall judges a mkdir that prepares a private place of home.
func ownSSHFolderMkdirCall(args []string, cwd, home string, places homePlaceView) bool {
	made := false
	for _, arg := range args {
		if arg == "-p" || arg == "--parents" {
			continue
		}
		if strings.HasPrefix(arg, "-") || !places.privateHome(hookpaths.OperandPath(arg, cwd), home) {
			return false
		}
		made = true
	}
	return made
}

// ownSSHFolderLiteralGlob is the text of a word that is literal text and glob
// characters only (no quote, expansion or substitution), such as /home/u/.ssh/*.
func ownSSHFolderLiteralGlob(word *syntax.Word) (string, bool) {
	var text strings.Builder
	for _, part := range word.Parts {
		literal, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		text.WriteString(literal.Value)
	}
	return text.String(), text.Len() > 0 && !strings.ContainsAny(text.String(), "$`")
}
