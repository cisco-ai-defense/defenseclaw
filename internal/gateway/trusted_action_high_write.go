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
// A file spelled with an instruction name is an instruction file only there
// (instructionLoadLocation): a SOUL.md fixture or template elsewhere that the
// session did not load is ordinary. Every other file is ordinary, however
// many links it has, and creating a link writes nothing.
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
	hostFlavor := actionfacts.PathFlavorPOSIX
	if runtime.GOOS == "windows" {
		hostFlavor = actionfacts.PathFlavorWindows
	}
	exactProof := func(ruleID string) findingProof {
		return newExactFallbackFindingProof(ruleID, true, true, true, true)
	}
	instructions := hookpaths.NewInstructionFiles(request.Input.CWD, request.Input.ActiveHome, request.Input.ActiveAgentFiles)
	// The places a call's instruction files are in: the working directory,
	// also as the sandbox guest and the managed hook's physical directory
	// name it, and the files the session loaded, also those the hook client
	// identified for a gateway that cannot read them.
	locations := instructionLocations{
		cwds: []string{
			request.Input.CWD, request.SandboxGuestCWD,
			request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+request.Input.CWD],
		},
		home:   request.Input.ActiveHome,
		loaded: append([]string(nil), request.Input.ActiveAgentFiles...),
	}
	for _, loaded := range request.ActiveAgentFileIdentities {
		locations.loaded = append(locations.loaded, loaded)
	}
	instructionTarget := func(resolved string, flavor actionfacts.PathFlavor) bool {
		if instructionLoadLocation(resolved, flavor, locations) {
			return true
		}
		// A symlinked or case-variant spelling of a load location's
		// directory, on this host's file system.
		return flavor == hostFlavor && !isSandboxHookRequest(ctx) &&
			instructions.Located(filepath.FromSlash(resolved))
	}
	// seenTargets records whether a target was checked as an instruction
	// file. Identity evidence for a target already checked as an ordinary
	// file checks it again.
	seenTargets := make(map[string]bool)
	addTarget := func(resolved string, flavor actionfacts.PathFlavor, proofForRule func(string) findingProof, note string) {
		// A note marks file-identity evidence: the target is one of the
		// call's instruction files under its own name.
		instruction := note != "" || instructionTarget(resolved, flavor)
		if checked, seen := seenTargets[resolved]; seen && (checked || !instruction) {
			return
		}
		seenTargets[resolved] = instruction
		for _, category := range generation.categories {
			for _, rule := range category.Rules {
				if !highWriteCatalogRule(rule) || !highWriteRuleMatchesTarget(rule, resolved, flavor, instruction) {
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
// so a proved write to one of the catalog's instruction filenames in a place
// agents load it from must still enforce that catalog rule. instruction
// reports that place (instructionLoadLocation) or file-identity evidence;
// without it the name is an ordinary file's. Another name of the same file
// reaches this check as the file's own path (hookpaths.InstructionFiles).
func highWriteRuleMatchesTarget(rule PatternRule, resolved string, flavor actionfacts.PathFlavor, instruction bool) bool {
	if name, ok := instructionRuleFiles[rule.ID]; ok {
		return instruction && activeAgentInstructionBaseMatches(
			path.Base(strings.ReplaceAll(resolved, `\`, "/")), flavor, name)
	}
	return rule.Pattern.MatchString(resolved)
}

// instructionLocations are the places of one call that agents load
// instruction files from, as the call names them.
type instructionLocations struct {
	cwds   []string
	home   string
	loaded []string
}

// instructionLoadLocation reports whether target, spelled with an
// instruction file name, is in a place agents load it from, by its
// spelling in flavor: a file the session loaded, the working directory or
// one of its parents or their .claude folders, an agent folder of the home
// (hookpaths.InstructionHomeFolders) or an agent's configured home
// (hookpaths.InstructionHomeVariables). Windows spellings compare without
// case. Any other file of that name is ordinary.
func instructionLoadLocation(target string, flavor actionfacts.PathFlavor, locations instructionLocations) bool {
	normal := func(value string) string {
		normalized, ok := activeAgentInstructionPath(value, flavor)
		if !ok {
			return ""
		}
		return normalized
	}
	file := normal(target)
	if file == "" {
		return false
	}
	if _, named := hookpaths.InstructionFileName(path.Base(file), flavor == actionfacts.PathFlavorWindows); !named {
		return false
	}
	for _, loaded := range locations.loaded {
		if normal(loaded) == file {
			return true
		}
	}
	directory := instructionParent(file)
	// within reports whether the working directory is base or under it.
	within := func(base string) bool {
		for _, cwd := range locations.cwds {
			if cwd = normal(cwd); cwd != "" &&
				(cwd == base || strings.HasPrefix(cwd, strings.TrimSuffix(base, "/")+"/")) {
				return true
			}
		}
		return false
	}
	if within(directory) || path.Base(directory) == ".claude" && within(instructionParent(directory)) {
		return true
	}
	if home := normal(locations.home); home != "" {
		for _, folder := range hookpaths.InstructionHomeFolders {
			candidate := home
			if folder != "" {
				candidate = normal(home + "/" + folder)
			}
			if candidate == directory {
				return true
			}
		}
	}
	for _, variable := range hookpaths.InstructionHomeVariables {
		if value := normal(os.Getenv(variable)); value != "" && value == directory {
			return true
		}
	}
	return false
}

// instructionParent is the directory of a path activeAgentInstructionPath
// normalized: "/" for a file at the POSIX root and the drive ("c:") for one
// at a Windows drive root.
func instructionParent(normalized string) string {
	index := strings.LastIndex(normalized, "/")
	if index <= 0 {
		return "/"
	}
	return normalized[:index]
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
