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
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// repositoryPolicyProofForTrustedHookCWD is the sole production bridge from
// server-owned configuration to repository-policy finding proof. Callers must
// pass the dedicated top-level CWD from an authenticated connector hook. It is
// intentionally not used by generic connector profiles, request headers,
// tool arguments, model text, policy IDs, or rule-pack selection.
func repositoryPolicyProofForTrustedHookCWD(
	ctx context.Context,
	cfg *config.Config,
	connector string,
	cwd string,
) trustedRepositoryPolicyProof {
	if (connector != "codex" && connector != "claudecode") ||
		authenticatedHookConnector(ctx) != connector {
		return trustedRepositoryPolicyProof{}
	}
	if cfg == nil || cfg.RepositoryPolicy == nil ||
		cfg.RepositoryPolicy.Validate() != nil {
		return trustedRepositoryPolicyProof{}
	}

	physicalCWD, ok := exactPhysicalDirectory(cwd)
	if !ok || !physicalPathWithin(cfg.RepositoryPolicy.Root, physicalCWD) ||
		hasInterveningGitMarker(cfg.RepositoryPolicy.Root, physicalCWD) {
		return trustedRepositoryPolicyProof{}
	}
	return newTrustedRepositoryPolicyProof(
		cfg.RepositoryPolicy.ForbiddenRuleIDs,
		cfg.RepositoryPolicy.Root,
		physicalCWD,
	)
}

func exactPhysicalDirectory(path string) (string, bool) {
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return "", false
	}
	physical, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(physical) != path {
		return "", false
	}
	info, err := os.Stat(physical)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return physical, true
}

func physicalPathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

// hasInterveningGitMarker rejects a CWD owned by a nested worktree. The
// configured root's own .git marker is validated by RepositoryPolicyConfig;
// any marker below it changes Git's implicit repository selection and makes
// root-scoped policy proof ambiguous.
func hasInterveningGitMarker(root, candidate string) bool {
	for current := candidate; current != root; current = filepath.Dir(current) {
		if current == filepath.Dir(current) {
			return true
		}
		_, err := os.Lstat(filepath.Join(current, ".git"))
		switch {
		case err == nil:
			return true
		case !os.IsNotExist(err):
			return true
		}
	}
	return false
}

// repositoryPolicyGitScopeProven correlates repository policy to the exact
// statically parsed Git invocation. Any incomplete Git argv, unknown global
// option, or option capable of changing Git's repository/config context makes
// the whole action advisory. Conservative false negatives are intentional.
func repositoryPolicyGitScopeProven(
	facts actionfacts.Facts,
	ruleID string,
	proof trustedRepositoryPolicyProof,
) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	physicalRoot, rootOK := exactPhysicalDirectory(proof.repositoryRoot)
	physicalCWD, ok := exactPhysicalDirectory(proof.physicalCWD)
	if !rootOK || physicalRoot != proof.repositoryRoot ||
		!ok || physicalCWD != proof.physicalCWD ||
		!physicalPathWithin(proof.repositoryRoot, physicalCWD) ||
		hasInterveningGitMarker(proof.repositoryRoot, physicalCWD) {
		return false
	}
	foundMatchingInvocation := false
	for _, command := range facts.Commands {
		if repositoryPolicyWorkingDirectoryCommand(command) {
			return false
		}
		if !repositoryPolicyGitCommand(command) {
			continue
		}
		if !command.ArgvComplete || command.Effect != actionfacts.EffectExecute ||
			command.ParentCommandID != 0 || len(command.Wrappers) != 0 {
			return false
		}
		subcommand, safe := repositoryPolicyGitSubcommand(command.Argv, proof)
		if !safe {
			return false
		}
		switch ruleID {
		case "integrity.git_hooks_bypass":
			foundMatchingInvocation = foundMatchingInvocation ||
				subcommand == "commit" || subcommand == "push" ||
				subcommand == "config"
		case "source.git_remote_tamper":
			foundMatchingInvocation = foundMatchingInvocation || subcommand == "remote"
		default:
			return false
		}
	}
	return foundMatchingInvocation
}

func repositoryPolicyWorkingDirectoryCommand(command actionfacts.CommandFact) bool {
	switch strings.ToLower(filepath.Base(command.Program)) {
	case "cd", "chdir", "pushd", "popd", "set-location":
		return true
	default:
		return false
	}
}

func repositoryPolicyGitCommand(command actionfacts.CommandFact) bool {
	program := strings.ToLower(filepath.Base(command.Program))
	return program == "git" || program == "git.exe"
}

func repositoryPolicyGitSubcommand(
	argv []string,
	proof trustedRepositoryPolicyProof,
) (string, bool) {
	if len(argv) < 2 {
		return "", false
	}
	effectiveCWD := proof.physicalCWD
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if argument == "" {
			return "", false
		}
		if argument == "-C" {
			index++
			if index >= len(argv) ||
				!repositoryPolicyApplyGitCWD(
					proof.repositoryRoot,
					&effectiveCWD,
					argv[index],
				) {
				return "", false
			}
			continue
		}
		if strings.HasPrefix(argument, "-C") && len(argument) > 2 {
			if !repositoryPolicyApplyGitCWD(
				proof.repositoryRoot,
				&effectiveCWD,
				argument[2:],
			) {
				return "", false
			}
			continue
		}
		key, _, joined := strings.Cut(argument, "=")
		switch key {
		case "-c", "--config-env", "--exec-path", "--git-dir",
			"--namespace", "--super-prefix", "--work-tree", "--bare":
			return "", false
		case "-p", "--paginate", "--no-pager", "--no-replace-objects",
			"--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
			"--icase-pathspecs", "--no-optional-locks":
			if joined {
				return "", false
			}
			continue
		case "--help", "--version":
			if joined {
				return "", false
			}
			return "", true
		}
		if strings.HasPrefix(argument, "-c") && len(argument) > 2 ||
			strings.HasPrefix(argument, "-") {
			return "", false
		}
		return strings.ToLower(argument), true
	}
	return "", false
}

func repositoryPolicyApplyGitCWD(
	repositoryRoot string,
	effectiveCWD *string,
	operand string,
) bool {
	if effectiveCWD == nil || *effectiveCWD == "" || operand == "" || len(operand) > 4096 {
		return false
	}
	candidate := operand
	if !filepath.IsAbs(candidate) {
		candidate = *effectiveCWD + string(filepath.Separator) + candidate
	}
	lexical := filepath.Clean(candidate)
	physical, err := filepath.EvalSymlinks(candidate)
	if err != nil || filepath.Clean(physical) != lexical {
		// A physical path differing from the lexical resolution crossed a
		// symlink. Even an in-repository target stays advisory because the
		// hook-to-execution race cannot be bound to that link.
		return false
	}
	info, err := os.Stat(physical)
	if err != nil || !info.IsDir() ||
		!physicalPathWithin(repositoryRoot, physical) ||
		hasInterveningGitMarker(repositoryRoot, physical) {
		return false
	}
	*effectiveCWD = physical
	return true
}

func newTrustedRepositoryPolicyProof(
	ruleIDs []string,
	repositoryRoot string,
	physicalCWD string,
) trustedRepositoryPolicyProof {
	proof := trustedRepositoryPolicyProof{
		ForbiddenRuleIDs: make([]string, 0, 2),
		repositoryRoot:   repositoryRoot,
		physicalCWD:      physicalCWD,
	}
	for _, ruleID := range ruleIDs {
		if !trustedRepositoryAdvisoryRule(ruleID) || proof.forbids(ruleID) {
			continue
		}
		proof.ForbiddenRuleIDs = append(proof.ForbiddenRuleIDs, ruleID)
	}
	return proof
}

func (a *APIServer) repositoryPolicyProofForTrustedHookCWD(
	ctx context.Context,
	connector string,
	cwd string,
) trustedRepositoryPolicyProof {
	if a == nil {
		return trustedRepositoryPolicyProof{}
	}
	return repositoryPolicyProofForTrustedHookCWD(
		ctx,
		a.runtimeConfigSnapshot(),
		connector,
		cwd,
	)
}
