// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// provedHighWriteFindings joins a native action's resolved write target to a
// HIGH or CRITICAL catalog rule whose expression names a write access. The
// target is an ActionFacts path, not a regex hit on arbitrary tool text. A
// missing active-file inventory cannot turn that resolved write into an
// advisory finding (GAP-0768). The same proof covers POSIX and PowerShell.
func provedHighWriteFindings(
	ctx context.Context,
	request trustedActionRequest,
	findings []RuleFinding,
) []RuleFinding {
	if !request.EnforcementCapable {
		return findings
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	facts := actionfacts.Analyze(request.Input)
	proved := append([]RuleFinding(nil), findings...)
	seenTargets := make(map[string]struct{})
	addTarget := func(resolved string, flavor actionfacts.PathFlavor, proofForRule func(string) findingProof) {
		if _, seen := seenTargets[resolved]; seen {
			return
		}
		seenTargets[resolved] = struct{}{}
		for _, category := range generation.categories {
			for _, rule := range category.Rules {
				if !highWriteCatalogRule(rule) || !highWriteRuleMatchesTarget(rule, resolved, flavor) {
					continue
				}
				proof := proofForRule(rule.ID)
				if !proof.authorizes(rule.ID) {
					continue
				}
				index := slices.IndexFunc(proved, func(finding RuleFinding) bool {
					return finding.RuleID == rule.ID
				})
				if index >= 0 {
					proved[index].enforcement = findingEnforcementAllowed
					proved[index].proof = proof
				} else {
					name := path.Base(strings.ReplaceAll(resolved, `\`, "/"))
					proved = append(proved, adjustConfidence(request.Input.Tool, RuleFinding{
						RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity,
						Confidence: rule.Confidence, Evidence: name,
						Tags:       append([]string(nil), rule.Tags...),
						LineNumber: 1, enforcement: findingEnforcementAllowed,
						proof: proof,
					}))
				}
			}
		}
	}
	addClientTarget := func(resolved string) {
		flavor := actionfacts.PathFlavorPOSIX
		if runtime.GOOS == "windows" {
			flavor = actionfacts.PathFlavorWindows
		}
		if _, ok := activeAgentInstructionPath(resolved, flavor); !ok {
			return
		}
		// The hook resolver walked this operand in the invoking user's view.
		// A managed gateway may be unable to traverse that user's home.
		addTarget(resolved, flavor, func(ruleID string) findingProof {
			return newExactFallbackFindingProof(ruleID, true, true, true, true)
		})
	}
	for _, target := range facts.Paths {
		if target.Access != actionfacts.PathAccessWrite &&
			target.Access != actionfacts.PathAccessAppend &&
			target.Access != actionfacts.PathAccessDelete ||
			target.Resolved == "" {
			continue
		}
		// Absolute describes the operand spelling. A relative operand is
		// equally proven when ActionFacts resolved it against the hook CWD.
		if _, ok := activeAgentInstructionPath(target.Resolved, target.Flavor); !ok {
			continue
		}
		command, found := integrityCommandByID(facts, target.CommandID)
		if !found || command.Effect != actionfacts.EffectExecute {
			continue
		}
		addTarget(target.Resolved, target.Flavor, func(ruleID string) findingProof {
			return newActionFactsSubgraphFindingProof(ruleID, true, true)
		})
	}
	// The invoking user's hook also lists writes that ActionFacts cannot
	// project, including patch directives inside an exec_command and Windows
	// shell forms. Its bounded map contains only write operands; metadata keys
	// are NUL-prefixed. A resolved value is positive path evidence even when
	// the gateway cannot read the user's filesystem itself.
	for operand, resolved := range request.ResolvedWriteTargets {
		if strings.HasPrefix(operand, "\x00") || resolved == "" ||
			!filepath.IsAbs(operand) || !filepath.IsAbs(resolved) {
			continue
		}
		addClientTarget(resolved)
	}
	// A native apply_patch call or a shell invocation of apply_patch carries
	// targets in its patch envelope. ActionFacts does not project those
	// directives as command paths. Reuse the bounded hook-side parser.
	if strings.Contains(strings.ToLower(request.Input.Tool), "patch") ||
		strings.Contains(string(request.Input.Args), "apply_patch") ||
		strings.Contains(request.Input.Command, "apply_patch") {
		patchTargets, complete := hookpaths.ApplyPatchWriteTargets(
			request.Input.Tool, request.Input.Args, request.Input.Command,
			request.Input.CWD, request.Input.ActiveHome,
		)
		if complete {
			for _, target := range patchTargets {
				if !filepath.IsAbs(target) {
					continue
				}
				flavor := actionfacts.PathFlavorPOSIX
				if runtime.GOOS == "windows" {
					flavor = actionfacts.PathFlavorWindows
				}
				if _, ok := activeAgentInstructionPath(target, flavor); !ok {
					continue
				}
				addTarget(target, flavor, func(ruleID string) findingProof {
					return newExactFallbackFindingProof(ruleID, true, true, true, true)
				})
			}
		}
	}
	return proved
}

// An active instruction file may be loaded by a session that predates this
// gateway process. Its in-memory load event is unavailable after a restart,
// so a proved write to one of the catalog's instruction filenames must still
// enforce that catalog rule. AGENTS.md intentionally has no general regex in
// the rule pack; this exact basename check supplies its lost-session proof.
func highWriteRuleMatchesTarget(rule PatternRule, resolved string, flavor actionfacts.PathFlavor) bool {
	name := path.Base(strings.ReplaceAll(resolved, `\`, "/"))
	var instruction string
	switch rule.ID {
	case "COG-AGENTS-MD":
		instruction = "AGENTS.md"
	case "COG-CLAUDE-MD":
		instruction = "CLAUDE.md"
	case "COG-SOUL":
		instruction = "SOUL.md"
	case "COG-IDENTITY":
		instruction = "IDENTITY.md"
	case "COG-MEMORY":
		instruction = "MEMORY.md"
	case "COG-TOOLS-MD":
		instruction = "TOOLS.md"
	case "COG-OPENCLAW-JSON":
		instruction = "openclaw.json"
	case "COG-GATEWAY-JSON":
		instruction = "gateway.json"
	}
	if instruction != "" {
		if activeAgentInstructionBaseMatches(name, flavor, instruction) {
			return true
		}
		// A case-folded spelling can name the same inode on macOS or a
		// case-folded Linux volume. A distinct lowercase file remains separate
		// on case-sensitive POSIX filesystems. An exact file-identity check also
		// covers a hard link to the active instruction file.
		if flavor == actionfacts.PathFlavorPOSIX && activeAgentASCIIEqualFold(name, instruction) {
			aliasInfo, aliasErr := os.Stat(resolved)
			canonicalInfo, canonicalErr := os.Stat(filepath.Join(filepath.Dir(resolved), instruction))
			return aliasErr == nil && canonicalErr == nil &&
				aliasInfo.Mode().IsRegular() && canonicalInfo.Mode().IsRegular() &&
				os.SameFile(aliasInfo, canonicalInfo)
		}
		return false
	}
	return rule.Pattern.MatchString(resolved)
}

func highWriteCatalogRule(rule PatternRule) bool {
	if rule.Pattern == nil ||
		!strings.EqualFold(rule.Severity, "HIGH") &&
			!strings.EqualFold(rule.Severity, "CRITICAL") {
		return false
	}
	return strings.Contains(rule.Expression, "PATH_ACCESS_WRITE") ||
		strings.Contains(rule.Expression, "PATH_ACCESS_APPEND") ||
		strings.Contains(rule.Expression, "PATH_ACCESS_DELETE")
}
