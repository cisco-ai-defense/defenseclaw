// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package effectrules projects the pure effect model (internal/effects) onto
// the CEL activation the guardrail rules read (semanticpb.Facts.effects) and
// grades each path target against the protected sets. It is the one seam that
// may import both internal/effects (pure) and internal/hookpaths (the
// authoritative protected-set readers); the effect extractor itself stays
// free of hookpaths and the file system.
//
// The protected sets wrap the hookpaths sets: SSH authorized-keys and control
// files, shell startup files, credentials, DefenseClaw and agent hook config,
// and DefenseClaw self-protection state. Grading is read-only. A target whose
// links were never checked (the link resolver could not follow it) never comes
// back "no" for a set it could reach: it is graded unknown.
package effectrules

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Protected set keys. These are the stable strings protected(target, set)
// matches on and the rule YAML names.
const (
	SetSSHAuthorizedKeys = "ssh_authorized_keys"
	SetShellRC           = "shell_rc"
	SetCredentials       = "credentials"
	SetAgentHookConfig   = "agent_hook_config"
	SetSelfProtection    = "self_protection"
)

// AllSets is the grading order; stable for tests and output.
var AllSets = []string{
	SetSSHAuthorizedKeys,
	SetShellRC,
	SetCredentials,
	SetAgentHookConfig,
	SetSelfProtection,
}

// protectedSet is the lexical shape of one set under a home: exact files,
// protected directories (a direct child that is not a known file is still
// suspect), and whole trees (every descendant is a member).
type protectedSet struct {
	files []string
	dirs  []string
	trees []string
}

// agentConfigFolders are the per-connector configuration folders whose hook
// and settings files are protected. Kept in step with hookpaths' bound set.
var agentConfigFolders = []string{
	".claude", ".codex", ".copilot", ".cursor", ".gemini",
	".hermes", ".kiro", ".devin",
}

// agentConfigNames are the protected file names inside an agent folder.
var agentConfigNames = []string{"settings.json", "settings.local.json", "hooks.json"}

// shellStartupFiles are the user shell startup files (the system /etc copies
// are added as absolute members in buildSets).
var shellStartupFiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile",
	".zshenv", ".zprofile", ".zshrc", ".zlogin",
}

var shellStartupSystemFiles = []string{
	"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
	"/etc/zshenv", "/etc/zsh/zshenv", "/etc/zprofile", "/etc/zsh/zprofile",
	"/etc/zshrc", "/etc/zsh/zshrc", "/etc/zlogin", "/etc/zsh/zlogin",
}

// sshPrivateKeyNames are the default SSH private key names (credentials).
var sshPrivateKeyNames = []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}

// credentialRelPaths are home-relative credential files (besides SSH keys).
var credentialRelPaths = []string{
	".aws/credentials", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
	".kube/config", ".docker/config.json",
}

// defenseclawStateFiles and defenseclawStateTrees mirror hookpaths'
// active-state set under ~/.defenseclaw (self-protection).
var defenseclawStateFiles = []string{
	".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
	"device.key", "picked_connector", "custom-providers.json", "audit.db",
	"judge.db", "judge_bodies.db",
}
var defenseclawStateTrees = []string{"hooks", "policies", "installer", "registries", "receipts", "quarantine"}

// buildSets computes the lexical member shape of every protected set for home.
// flavor decides the path separator and case folding.
func buildSets(home string, flavor effects.Flavor) map[string]protectedSet {
	j := func(parts ...string) string { return joinFlavor(flavor, parts...) }
	ssh := j(home, ".ssh")
	sets := map[string]protectedSet{}

	// SSH authorized-keys and control files. ProtectedAuthorizedKeysPaths
	// already carries the authorized_keys family plus the Windows
	// administrators key; add the control files explicitly.
	akFiles := append([]string(nil), hookpaths.ProtectedAuthorizedKeysPaths(home)...)
	for _, name := range hookpaths.SSHControlFiles {
		akFiles = append(akFiles, j(ssh, name))
	}
	sets[SetSSHAuthorizedKeys] = protectedSet{files: akFiles, dirs: []string{ssh}}

	// Shell startup files.
	rc := append([]string(nil), shellStartupSystemFiles...)
	for _, name := range shellStartupFiles {
		rc = append(rc, j(home, name))
	}
	sets[SetShellRC] = protectedSet{files: rc}

	// Credentials: SSH private keys plus well-known credential files.
	cred := make([]string, 0, len(sshPrivateKeyNames)+len(credentialRelPaths))
	for _, name := range sshPrivateKeyNames {
		cred = append(cred, j(ssh, name))
	}
	for _, rel := range credentialRelPaths {
		cred = append(cred, j(home, rel))
	}
	sets[SetCredentials] = protectedSet{files: cred}

	// Agent hook config: per-connector settings/hooks files and hook trees,
	// plus the project instruction files.
	var agentFiles, agentDirs, agentTrees []string
	for _, folder := range agentConfigFolders {
		base := j(home, folder)
		for _, name := range agentConfigNames {
			agentFiles = append(agentFiles, j(base, name))
		}
		agentTrees = append(agentTrees, j(base, "hooks"))
		agentDirs = append(agentDirs, base)
	}
	agentFiles = append(agentFiles, j(home, "CLAUDE.md"), j(home, "AGENTS.md"))
	sets[SetAgentHookConfig] = protectedSet{files: agentFiles, dirs: agentDirs, trees: agentTrees}

	// DefenseClaw self-protection state under ~/.defenseclaw.
	state := j(home, ".defenseclaw")
	var stFiles, stTrees []string
	for _, name := range defenseclawStateFiles {
		stFiles = append(stFiles, j(state, name))
	}
	for _, name := range defenseclawStateTrees {
		stTrees = append(stTrees, j(state, name))
	}
	sets[SetSelfProtection] = protectedSet{files: stFiles, dirs: []string{state}, trees: stTrees}

	return sets
}

// joinFlavor joins path parts with the flavor's separator. An absolute part
// (a leading separator or a Windows drive) resets the accumulation.
func joinFlavor(flavor effects.Flavor, parts ...string) string {
	sep := "/"
	if flavor == effects.FlavorWindows {
		sep = `\`
	}
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		p = strings.TrimRight(p, "/\\")
		switch {
		case out == "":
			out = p
		default:
			out += sep + strings.TrimLeft(p, "/\\")
		}
	}
	return out
}
