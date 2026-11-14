// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
