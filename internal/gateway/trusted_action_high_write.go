// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// instructionRuleFiles maps each cognitive-file rule to the instruction file
// it protects. AGENTS.md intentionally has no general regex in the rule pack;
// this exact name supplies its proof.
var instructionRuleFiles = map[string]string{
	"COG-AGENTS-MD":     "AGENTS.md",
	"COG-CLAUDE-MD":     "CLAUDE.md",
	"COG-SOUL":          "SOUL.md",
	"COG-IDENTITY":      "IDENTITY.md",
	"COG-MEMORY":        "MEMORY.md",
	"COG-TOOLS-MD":      "TOOLS.md",
	"COG-OPENCLAW-JSON": "openclaw.json",
	"COG-GATEWAY-JSON":  "gateway.json",
}

const instructionAliasTitle = " (written through another name of the file)"

// provedHighWriteFindings joins a native action's resolved write target to a
// HIGH or CRITICAL catalog rule whose expression names a write access. The
// target is an ActionFacts path, not a regex hit on arbitrary tool text. A
// missing active-file inventory cannot turn that resolved write into an
// advisory finding (GAP-0768). The same proof covers POSIX and PowerShell.
//
// An instruction file is protected by file identity, not by the spelling of
// its name (GAP-0869): a write through a symlink, a hard link or a case,
// short-name or stream variant, and a write to the physical file a
// symlinked instruction file reaches (GAP-0971), is a write to the file.
// Another name is matched by file identity against the instruction files
// agents load and the files the session loaded (hookpaths.InstructionFiles).
// Every other file is ordinary, however many links it has, and creating a
// link writes nothing.
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
	hostFlavor := actionfacts.PathFlavorPOSIX
	if runtime.GOOS == "windows" {
		hostFlavor = actionfacts.PathFlavorWindows
	}
	exactProof := func(ruleID string) findingProof {
		return newExactFallbackFindingProof(ruleID, true, true, true, true)
	}
	addTarget := func(resolved string, flavor actionfacts.PathFlavor, proofForRule func(string) findingProof, note string) {
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
					continue
				}
				proved = append(proved, adjustConfidence(request.Input.Tool, RuleFinding{
					RuleID: rule.ID, Title: rule.Title + note, Severity: rule.Severity,
					Confidence: rule.Confidence, Evidence: path.Base(strings.ReplaceAll(resolved, `\`, "/")),
					Tags:       append([]string(nil), rule.Tags...),
					LineNumber: 1, enforcement: findingEnforcementAllowed,
					proof: proof,
				}))
			}
		}
	}
	// gatewayIdentity checks a write target on this host's file system. A
	// managed gateway that cannot read the user's home sees no file and
	// relies on the hook client's InstructionIdentityKey below.
	instructions := hookpaths.NewInstructionFiles(request.Input.CWD, request.Input.ActiveHome, request.Input.ActiveAgentFiles)
	gatewayIdentity := func(resolved string, flavor actionfacts.PathFlavor) {
		// A sandboxed agent's paths name its own file system, not this
		// host's; its hook client's evidence speaks for it.
		if flavor != hostFlavor || isSandboxHookRequest(ctx) {
			return
		}
		if instruction := instructions.Alias(filepath.FromSlash(resolved)); instruction != "" {
			addTarget(instruction, flavor, exactProof, instructionAliasTitle)
		}
	}
	addClientTarget := func(resolved, note string) {
		if _, ok := activeAgentInstructionPath(resolved, hostFlavor); !ok {
			return
		}
		// The hook resolver walked this operand in the invoking user's view.
		// A managed gateway may be unable to traverse that user's home.
		addTarget(resolved, hostFlavor, exactProof, note)
	}
	for _, target := range facts.Paths {
		write := target.Access == actionfacts.PathAccessWrite || target.Access == actionfacts.PathAccessAppend
		if !write && target.Access != actionfacts.PathAccessDelete || target.Resolved == "" {
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
		}, "")
		// Removing one name of a file leaves the others intact; writing any
		// name writes the file.
		if write {
			gatewayIdentity(target.Resolved, target.Flavor)
		}
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
		addClientTarget(resolved, "")
	}
	// The hook client's file-identity check of the same targets: every
	// instruction file they write under another name
	// (hookpaths.InstructionIdentityKey, GAP-1065), and the targets' own
	// identities matched with those of the files the session loaded
	// (hookpaths.FileIdentitiesKey, GAP-1064).
	for _, identity := range hookpaths.InstructionIdentities(request.ResolvedWriteTargets) {
		if filepath.IsAbs(identity) {
			addClientTarget(identity, instructionAliasTitle)
		}
	}
	for _, identity := range hookpaths.FileIdentities(request.ResolvedWriteTargets) {
		if loaded := request.ActiveAgentFileIdentities[identity]; filepath.IsAbs(loaded) {
			addClientTarget(loaded, instructionAliasTitle)
		}
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
				if _, ok := activeAgentInstructionPath(target, hostFlavor); !ok {
					continue
				}
				addTarget(target, hostFlavor, exactProof, "")
				gatewayIdentity(target, hostFlavor)
			}
		}
	}
	return proved
}

// An active instruction file may be loaded by a session that predates this
// gateway process. Its in-memory load event is unavailable after a restart,
// so a proved write to one of the catalog's instruction filenames must still
// enforce that catalog rule. Another name of the same file reaches this
// check as the file's own path (hookpaths.InstructionFiles).
func highWriteRuleMatchesTarget(rule PatternRule, resolved string, flavor actionfacts.PathFlavor) bool {
	if instruction, ok := instructionRuleFiles[rule.ID]; ok {
		name := path.Base(strings.ReplaceAll(resolved, `\`, "/"))
		return activeAgentInstructionBaseMatches(name, flavor, instruction)
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
