// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A user who copies their own SSH key to another place in their own home (a
// backup folder, a renamed copy) exposes it to no one: the copy is as private
// as the original. The copy stays a visible alert, but it is not the content
// read of a key that leaves the user (rel-1-0-10:GAP-0018). A copy anywhere
// else (/tmp, a web root, a shared folder, another account's home) or any
// other reader of the key keeps the CRITICAL block.

var (
	// trustedActionHomeCopyPrograms are the programs that copy a file.
	trustedActionHomeCopyPrograms = []string{"cp", "gcp", "copy", "copy-item", "cpi"}
	// trustedActionHomeCopyHarmless are the programs that may sit beside such
	// a copy (preparing the folder, saying that it is done).
	trustedActionHomeCopyHarmless = []string{
		"mkdir", "md", "chmod", "echo", "printf", "true", "false", ":", "cd", "pwd",
		"ls", "dir", "test", "[", "write-host", "write-output",
	}
	// trustedActionHomeSharedFolders are the folders of a home that other
	// accounts or the network can read.
	trustedActionHomeSharedFolders = []string{"public", "public_html", "sites", "www", "html", "shared"}
)

// trustedActionPrivateHomeDestination reports a write target below the active
// home (the home itself too) that no one else reads: not a shared folder and
// not a file of the SSH folder that sshd or ssh read as policy.
func trustedActionPrivateHomeDestination(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
	relative, ok := activeHomeRelative(facts, candidate)
	if !ok {
		return false
	}
	if relative == "" {
		return true
	}
	first, rest, _ := strings.Cut(relative, "/")
	if slices.Contains(trustedActionHomeSharedFolders, first) {
		return false
	}
	if first == ".ssh" && !strings.Contains(rest, "/") {
		for _, protected := range []string{"authorized_keys", "authorized_keys2", "config", "environment", "rc"} {
			if rest == protected {
				return false
			}
		}
	}
	return true
}

// trustedActionCommandWritesOnlyPrivateHome reports a command whose write
// targets are all private places in the active home. needWrite also asks for
// at least one such target.
func trustedActionCommandWritesOnlyPrivateHome(facts actionfacts.Facts, command actionfacts.CommandFact, needWrite bool) bool {
	wrote := false
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			wrote = true
			if !trustedActionPrivateHomeDestination(facts, candidate) {
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
			if redirect.Expands || !trustedActionPrivateHomeDestination(facts, actionfacts.PathFact{Value: redirect.Target}) {
				return false
			}
		}
	}
	return wrote || !needWrite
}

// trustedActionPrivateHomeCopy reports one executing copy command that writes
// only private places in the active home. A wrapper (sudo, env, a shell) leaves
// the command a content read.
func trustedActionPrivateHomeCopy(facts actionfacts.Facts, command actionfacts.CommandFact) bool {
	return facts.ActiveHome != "" &&
		command.Kind == actionfacts.CommandKindProcess &&
		command.Effect == actionfacts.EffectExecute &&
		len(command.Wrappers) == 0 &&
		slices.Contains(trustedActionHomeCopyPrograms, strings.ToLower(command.Program)) &&
		trustedActionCommandWritesOnlyPrivateHome(facts, command, true)
}

// trustedActionHomeCopyReading reads the commands of facts: ok is set when
// every one is a copy into a private place of the active home or a harmless
// helper of that, and copied when at least one is such a copy.
func trustedActionHomeCopyReading(facts actionfacts.Facts) (ok, copied bool) {
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
		case trustedActionPrivateHomeCopy(facts, command):
			copied = true
		case len(command.Wrappers) == 0 && slices.Contains(trustedActionHomeCopyHarmless, program) &&
			trustedActionCommandWritesOnlyPrivateHome(facts, command, false):
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
func trustedActionPrivateKeyOnlyCopiedInHome(input actionfacts.Input, facts actionfacts.Facts) bool {
	if input.ActiveHome == "" {
		return false
	}
	if facts.Authoritative() {
		ok, copied := trustedActionHomeCopyReading(facts)
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
		ok, copied := trustedActionHomeCopyReading(actionfacts.Analyze(child))
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
	finding.enforcement = findingEnforcementAlertOnly
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
// gateway, the block stays. The destination's mode bits are not read: a managed
// gateway cannot see the home, and a copy keeps the modes of its sources.
func trustedActionOwnSSHFolderCopy(request trustedActionRequest, input actionfacts.Input) bool {
	home := strings.TrimRight(input.ActiveHome, "/")
	if request.ProtectedHomeHook || home == "" || !trustedShellCommandInput(input) || input.Command == "" {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) == 0 {
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
				if !ownSSHFolderCopyCall(words[1:], input.CWD, home) {
					return false
				}
				copied = true
				return true
			case "mkdir":
				return ownSSHFolderMkdirCall(words[1:], input.CWD, home)
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
	return copied
}

// ownSSHFolderCopyCall judges the operands of one cp: safe options, sources
// inside the SSH folder of home, one destination in a private place of home.
func ownSSHFolderCopyCall(args []string, cwd, home string) bool {
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
	for _, source := range sources {
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
	return ownSSHFolderPrivateDestination(destination, cwd, home)
}

// ownSSHFolderMkdirCall judges a mkdir that prepares a private place of home.
func ownSSHFolderMkdirCall(args []string, cwd, home string) bool {
	made := false
	for _, arg := range args {
		if arg == "-p" || arg == "--parents" {
			continue
		}
		if strings.HasPrefix(arg, "-") || !ownSSHFolderPrivateDestination(arg, cwd, home) {
			return false
		}
		made = true
	}
	return made
}

// ownSSHFolderPrivateDestination reports a destination inside home, outside the
// SSH folder and the shared folders, whose existing part, links followed, stays
// there too; a part that does not exist yet is only a name.
func ownSSHFolderPrivateDestination(destination, cwd, home string) bool {
	value := path.Clean(hookpaths.OperandPath(destination, cwd))
	if !pathWithin(value, home) || pathWithin(value, home+"/.ssh") {
		return false
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(value, home), "/")
	first, _, _ := strings.Cut(relative, "/")
	if slices.Contains(trustedActionHomeSharedFolders, strings.ToLower(first)) {
		return false
	}
	// Nothing of the destination below the home exists on this host (the home
	// itself may be absent): there is no link to follow, the name is all there is.
	existing := value
	for existing != home && pathWithin(existing, home) {
		if _, err := hookpaths.Lstat(existing); err == nil {
			break
		}
		existing = path.Dir(existing)
	}
	if _, err := hookpaths.Lstat(existing); err != nil {
		return true
	}
	realHome, err := hookpaths.EvalSymlinks(home)
	if err != nil {
		return false
	}
	resolved, err := hookpaths.EvalSymlinks(existing)
	if err != nil {
		return false
	}
	return pathWithin(resolved, realHome) && !pathWithin(resolved, realHome+"/.ssh")
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
