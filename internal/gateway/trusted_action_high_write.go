// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

// instructionProof is how a write target is proved to be an instruction
// file the session must keep: by identity (a load the session reported, or
// the file its snapshot recorded when the session reached the directory),
// or only by existing now in a directory the snapshot does not record.
type instructionProof int

const (
	instructionNotProved instructionProof = iota
	instructionExistenceProved
	instructionIdentityProved
)

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
// Either way the file is an instruction file of the call only when the
// session loaded it or the session's own agent loads it at every start
// (instructionLoadLocation, connectorInstructionLoads): a SOUL.md in a Claude
// Code project, an AGENTS.md beside a Claude Code session or a CLAUDE.md
// beside a Codex one is ordinary, under any of its names. Every other file is
// ordinary, however many links it has, and creating a link writes nothing.
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
	request.Input.CWD = managedClientCWD(ctx, request.Input.CWD, request.ResolvedWriteTargets)
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
		loads: connectorInstructionLoads(request.Connector),
		cwds: []string{
			request.Input.CWD, request.SandboxGuestCWD,
			request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+request.Input.CWD],
		},
		home:   request.Input.ActiveHome,
		loaded: append([]string(nil), request.Input.ActiveAgentFiles...),
	}
	locations.loaded = append(locations.loaded, slices.Sorted(maps.Keys(request.ActiveAgentFileIdentities))...)
	startupView := instructionStartupFromContext(ctx)
	startup := startupView.snapshot
	if startupView.extend != nil {
		// The directories this call works in or writes to are snapshotted
		// before it is judged, the first time the session reaches them.
		reached := hookpaths.StartupDirectories(request.Input.CWD, request.Input.ActiveHome)
		for _, target := range facts.Paths {
			if target.Resolved != "" && target.Flavor == hostFlavor {
				reached = append(reached, filepath.Dir(filepath.FromSlash(target.Resolved)))
			}
		}
		for operand, resolved := range request.ResolvedWriteTargets {
			if !strings.HasPrefix(operand, "\x00") && filepath.IsAbs(resolved) {
				reached = append(reached, filepath.Dir(resolved))
			}
		}
		startup = startupView.extend(reached)
	}
	clientInstructions := hookpaths.InstructionIdentities(request.ResolvedWriteTargets)
	loadedAtRuntime := func(location string, flavor actionfacts.PathFlavor) bool {
		normalized, ok := activeAgentInstructionPath(location, flavor)
		if !ok {
			return false
		}
		for _, loaded := range locations.loaded {
			if known, ok := activeAgentInstructionPath(loaded, flavor); ok && known == normalized {
				return true
			}
		}
		return false
	}
	clientIdentified := func(location string, flavor actionfacts.PathFlavor) bool {
		normalized, ok := activeAgentInstructionPath(location, flavor)
		if !ok {
			return false
		}
		for _, identified := range clientInstructions {
			if known, ok := activeAgentInstructionPath(identified, flavor); ok && known == normalized {
				return true
			}
		}
		return false
	}
	// targetIdentity is the identity of the file a write target names: this
	// host's when it reads the file, else the hook client's as the user.
	targetIdentity := func(location, target string, flavor actionfacts.PathFlavor) string {
		identity := ""
		if flavor == hostFlavor && !isSandboxHookRequest(ctx) {
			identity = hookpaths.FileIdentity(filepath.FromSlash(target))
		}
		if identity == "" {
			identity = request.ResolvedWriteTargets[hookpaths.WriteIdentityPrefix+target]
		}
		if identity == "" {
			identity = request.ResolvedWriteTargets[hookpaths.WriteIdentityPrefix+location]
		}
		return identity
	}
	provedLocation := func(location, target string, flavor actionfacts.PathFlavor) instructionProof {
		if !instructionLoadLocation(location, flavor, locations) {
			return instructionNotProved
		}
		// A file in a directory the session's snapshot records is protected
		// only while it is the file that was there when the session reached
		// the directory; one the session created since is ordinary, also
		// once the agent reports it loaded (GAP-2046). The snapshot records
		// only the names the agent loads at every start, so a loaded file of
		// another name (an @include) is not known to be the session's own.
		normalized, normalizedOK := activeAgentInstructionPath(location, flavor)
		covered := normalizedOK && startup.startupCovers(instructionParent(normalized))
		if covered && startup.startupFiles[normalized] == "" && snapshotRecordsName(request.Connector, normalized) {
			return instructionNotProved
		}
		if loadedAtRuntime(location, flavor) {
			return instructionIdentityProved
		}
		if covered {
			if identity := targetIdentity(location, target, flavor); identity != "" && identity == startup.startupFiles[normalized] {
				return instructionIdentityProved
			}
			return instructionNotProved
		}
		// A session whose first sighting is lost still knows the files it
		// proved by identity: one of them is the file the session found,
		// in every tier; any other file may be one it created.
		if !startup.startupKnown && len(startupView.lostIdentities) > 0 {
			if identity := targetIdentity(location, target, flavor); identity != "" && slices.Contains(startupView.lostIdentities, identity) {
				return instructionIdentityProved
			}
		}
		// A directory the snapshot does not record, or a session without a
		// snapshot: only the file existing now is known, not that it existed
		// before the session (instructionExistenceProved). The hook client's
		// identity is that proof when a managed gateway cannot read the
		// user's files.
		if clientIdentified(location, flavor) {
			return instructionExistenceProved
		}
		if flavor != hostFlavor || isSandboxHookRequest(ctx) {
			return instructionNotProved
		}
		if info, err := os.Stat(filepath.FromSlash(location)); err == nil && info.Mode().IsRegular() {
			return instructionExistenceProved
		}
		return instructionNotProved
	}
	instructionTarget := func(resolved string, flavor actionfacts.PathFlavor) instructionProof {
		proof := provedLocation(resolved, resolved, flavor)
		// A symlinked or case-variant spelling of a load location's
		// directory, on this host's file system, is judged as the spelling
		// of the location it reaches.
		if proof == instructionIdentityProved || flavor != hostFlavor || isSandboxHookRequest(ctx) {
			return proof
		}
		if located := instructions.Located(filepath.FromSlash(resolved)); located != "" {
			proof = max(proof, provedLocation(located, resolved, flavor))
		}
		return proof
	}
	// Existence alone protects a file only in the strict tier; elsewhere it
	// is a warning with an audit row (BALANCED-DEFAULTS: no snapshot or an
	// unknown directory never blocks in default/permissive).
	existenceBlocks := startupView.existenceBlocks()
	// File-identity evidence names the instruction file a target writes
	// under its own path, so every target, however it was found, is judged
	// by the same instructionTarget once.
	seenTargets := make(map[string]bool)
	addTarget := func(resolved string, flavor actionfacts.PathFlavor, proofForRule func(string) findingProof, note string) {
		if seenTargets[resolved] {
			return
		}
		seenTargets[resolved] = true
		instructionProof := instructionTarget(resolved, flavor)
		instruction := instructionProof != instructionNotProved
		for _, category := range generation.categories {
			for _, rule := range category.Rules {
				if !highWriteCatalogRule(rule) || !highWriteRuleMatchesTarget(rule, resolved, flavor, instruction) {
					continue
				}
				proof := proofForRule(rule.ID)
				if !proof.authorizes(rule.ID) {
					continue
				}
				_, instructionRule := instructionRuleFiles[rule.ID]
				alertOnly := instructionRule && instructionProof == instructionExistenceProved && !existenceBlocks
				// A write to an instruction file the session loaded or found
				// at its start, proved by the file's identity, is unambiguous
				// and high impact: CRITICAL (SignalStrengthToSeverity). Action
				// mode therefore blocks it under the default and strict packs;
				// observe only records it (GAP-1503). The permissive pack
				// keeps the rule's severity, so it alerts there (GAP-2049).
				severity := rule.Severity
				if instructionRule && instructionProof == instructionIdentityProved && !startupView.permissive &&
					strings.EqualFold(severity, "HIGH") {
					severity = "CRITICAL"
				}
				index := slices.IndexFunc(proved, func(finding RuleFinding) bool {
					return finding.RuleID == rule.ID
				})
				if index >= 0 {
					// Existence alone never makes a finding enforceable.
					if !alertOnly {
						proved[index].enforcement = findingEnforcementAllowed
						proved[index].proof = proof
					}
					if severity != rule.Severity {
						proved[index].Severity = severity
					}
					continue
				}
				enforcement := findingEnforcementAllowed
				if alertOnly {
					enforcement = findingEnforcementAlertOnly
				}
				proved = append(proved, adjustConfidence(request.Input.Tool, RuleFinding{
					RuleID: rule.ID, Title: rule.Title + note, Severity: severity,
					Confidence: rule.Confidence, Evidence: path.Base(strings.ReplaceAll(resolved, `\`, "/")),
					Tags:       append([]string(nil), rule.Tags...),
					LineNumber: 1, enforcement: enforcement,
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
		// Every instruction name of the file (GAP-1127).
		for _, instruction := range instructions.Aliases(filepath.FromSlash(resolved)) {
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
	judgePath := func(facts actionfacts.Facts, target actionfacts.PathFact) {
		// A POSIX shell on a Windows host (Git Bash, the shell of Claude
		// Code's Bash tool) writes host paths (GAP-0768).
		if hostFlavor == actionfacts.PathFlavorWindows && target.Flavor == actionfacts.PathFlavorPOSIX && !isSandboxHookRequest(ctx) {
			if host, ok := windowsHostPathOfPOSIXOperand(target.Value, request.Input.CWD, request.Input.ActiveHome); ok {
				target.Resolved, target.Flavor = host, actionfacts.PathFlavorWindows
			}
		}
		write := target.Access == actionfacts.PathAccessWrite || target.Access == actionfacts.PathAccessAppend
		if !write && target.Access != actionfacts.PathAccessDelete || target.Resolved == "" {
			return
		}
		// Absolute describes the operand spelling. A relative operand is
		// equally proven when ActionFacts resolved it against the hook CWD.
		if _, ok := activeAgentInstructionPath(target.Resolved, target.Flavor); !ok {
			return
		}
		command, found := integrityCommandByID(facts, target.CommandID)
		if !found || command.Effect != actionfacts.EffectExecute {
			return
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
	judgePaths := func(facts actionfacts.Facts) {
		for _, target := range facts.Paths {
			judgePath(facts, target)
		}
	}
	judgePaths(facts)
	// `powershell -Command "Add-Content CLAUDE.md x"` from a POSIX shell
	// (Git Bash, Claude Code's Bash tool on Windows): the outer shell call
	// names no path, the PowerShell body does. Its writes are judged like
	// the shell's own (GAP-2370).
	shellInput := request.Input
	if shellInput.Command == "" {
		if command, ok := trustedBashCommandInput(shellInput); ok {
			shellInput.Command = command
		}
	}
	for _, inner := range actionfacts.POSIXPowerShellCommandFacts(shellInput, facts) {
		if inner.EnforcementEligible() {
			judgePaths(inner)
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
	// Every loaded name of a written file counts (GAP-1414).
	written := hookpaths.FileIdentities(request.ResolvedWriteTargets)
	for _, loaded := range slices.Sorted(maps.Keys(request.ActiveAgentFileIdentities)) {
		if filepath.IsAbs(loaded) && slices.Contains(written, request.ActiveAgentFileIdentities[loaded]) {
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
// so a proved write to an instruction file the session's agent loads at
// every start must still enforce that catalog rule. instruction reports such
// a file or one the session loaded (instructionLoadLocation); without it the
// name is an ordinary file's. Another name of the same file reaches this
// check as the file's own path (hookpaths.InstructionFiles).
func highWriteRuleMatchesTarget(rule PatternRule, resolved string, flavor actionfacts.PathFlavor, instruction bool) bool {
	if name, ok := instructionRuleFiles[rule.ID]; ok {
		return instruction && activeAgentInstructionBaseMatches(
			path.Base(strings.ReplaceAll(resolved, `\`, "/")), flavor, name)
	}
	return rule.Pattern.MatchString(resolved)
}

// instructionLocations are the places of one call that its agent loads
// instruction files from, as the call names them.
type instructionLocations struct {
	loads  instructionLoads
	cwds   []string
	home   string
	loaded []string
}

// instructionLoads are the instruction files an agent reads at the start of
// every session without reporting the load: the names it reads in the
// working directory and each parent (project), in their .claude folders
// (claudeFolder), in folders of the home (home, slash separated, from
// hookpaths.InstructionHomeFolders) and in the folders its home variables
// name (variables, from hookpaths.InstructionHomeVariables).
type instructionLoads struct {
	project, claudeFolder []string
	home, variables       map[string][]string
}

var (
	allInstructionNames     = hookpaths.InstructionFileNames[:]
	projectInstructionNames = []string{"AGENTS.md", "CLAUDE.md"}
	clawInstructionLoads    = instructionLoads{project: allInstructionNames, home: map[string][]string{".openclaw": allInstructionNames, ".openclaw/workspace": allInstructionNames}}
	builtinInstructionLoads = map[string]instructionLoads{
		"claudecode": {
			project: []string{"CLAUDE.md"}, claudeFolder: []string{"CLAUDE.md"},
			home: map[string][]string{".claude": {"CLAUDE.md"}}, variables: map[string][]string{"CLAUDE_CONFIG_DIR": {"CLAUDE.md"}},
		},
		"codex": {
			project: []string{"AGENTS.md"},
			home:    map[string][]string{".codex": {"AGENTS.md"}}, variables: map[string][]string{"CODEX_HOME": {"AGENTS.md"}},
		},
		"opencode": {project: projectInstructionNames, home: map[string][]string{".config/opencode": {"AGENTS.md"}, ".claude": {"CLAUDE.md"}}},
		"amp":      {project: projectInstructionNames, home: map[string][]string{".config/amp": {"AGENTS.md"}, ".config": {"AGENTS.md"}}},
		"openclaw": clawInstructionLoads, "zeptoclaw": clawInstructionLoads,
	}
)

// connectorInstructionLoads are the instruction files connector's agent
// loads at every start. Another built-in agent reads AGENTS.md and CLAUDE.md
// in its project. An agent DefenseClaw does not know (a plugin connector, or
// none) may read any instruction name in any of the places, so all of them
// count for it.
func connectorInstructionLoads(connector string) instructionLoads {
	name := canonicalConnectorRulePackKey(connector)
	if loads, ok := builtinInstructionLoads[name]; ok {
		return loads
	}
	if gatewayconnector.IsKnownBuiltinConnector(name) {
		return instructionLoads{project: projectInstructionNames}
	}
	every := instructionLoads{
		project: allInstructionNames, claudeFolder: allInstructionNames,
		home: map[string][]string{}, variables: map[string][]string{},
	}
	for _, folder := range hookpaths.InstructionHomeFolders {
		every.home[folder] = allInstructionNames
	}
	for _, variable := range hookpaths.InstructionHomeVariables {
		every.variables[variable] = allInstructionNames
	}
	return every
}

// snapshotRecordsName reports whether a startup snapshot of connector
// records a file named like file (instructionSnapshot keeps only the names
// connectorInstructionLoadNames lists).
func snapshotRecordsName(connector, file string) bool {
	name, named := hookpaths.InstructionFileName(path.Base(strings.ReplaceAll(file, `\`, "/")), runtime.GOOS == "windows")
	return named && slices.Contains(connectorInstructionLoadNames(connector), name)
}

// connectorInstructionLoadNames are the instruction file names connector's
// agent loads in any of its places.
func connectorInstructionLoadNames(connector string) []string {
	loads := connectorInstructionLoads(connector)
	var names []string
	add := func(list []string) {
		for _, name := range list {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	add(loads.project)
	add(loads.claudeFolder)
	for _, list := range loads.home {
		add(list)
	}
	for _, list := range loads.variables {
		add(list)
	}
	return names
}

// instructionLoadLocation reports whether target, spelled with an
// instruction file name, is an instruction file of the call by its spelling
// in flavor: a file the session loaded, or one the call's agent loads at
// every start (instructionLoads) from the working directory or one of its
// parents or their .claude folders, a folder of the home or a folder its
// home variables name. Windows spellings compare without case. Any other
// file of that name is ordinary.
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
	name, named := hookpaths.InstructionFileName(path.Base(file), flavor == actionfacts.PathFlavorWindows)
	if !named {
		return false
	}
	for _, loaded := range locations.loaded {
		if normal(loaded) == file {
			return true
		}
	}
	loads := locations.loads
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
	if slices.Contains(loads.project, name) && within(directory) ||
		slices.Contains(loads.claudeFolder, name) && path.Base(directory) == ".claude" && within(instructionParent(directory)) {
		return true
	}
	if home := normal(locations.home); home != "" {
		for folder, names := range loads.home {
			candidate := home
			if folder != "" {
				candidate = normal(home + "/" + folder)
			}
			if candidate == directory && slices.Contains(names, name) {
				return true
			}
		}
	}
	for variable, names := range loads.variables {
		if value := normal(os.Getenv(variable)); value != "" && value == directory && slices.Contains(names, name) {
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

// windowsHostPathOfPOSIXOperand is the Windows path a POSIX-shell operand
// names on a Windows host, where Git Bash (MSYS) runs it: a drive path
// (C:\x, C:/x), an MSYS drive mount (/c/x), a path under ~ when the home
// is a Windows path, or a relative path against a Windows working
// directory, in the forward-slash spelling ActionFacts gives Windows paths.
// Any other operand (/tmp, /etc: the MSYS root) is not placed (ok false).
func windowsHostPathOfPOSIXOperand(value, cwd, home string) (string, bool) {
	drive := func(p string) bool {
		return len(p) >= 3 && (p[1] == ':') && (p[2] == '/' || p[2] == '\\') &&
			('a' <= p[0] && p[0] <= 'z' || 'A' <= p[0] && p[0] <= 'Z')
	}
	clean := func(p string) string { return path.Clean(strings.ReplaceAll(p, `\`, "/")) }
	switch {
	case value == "" || strings.ContainsRune(value, 0) || strings.ContainsAny(value, "$`*?[{"):
		return "", false
	case drive(value):
		return clean(value), true
	case len(value) >= 2 && value[0] == '/' && ('a' <= value[1] && value[1] <= 'z' || 'A' <= value[1] && value[1] <= 'Z') &&
		(len(value) == 2 || value[2] == '/'):
		return clean(strings.ToUpper(value[1:2]) + ":/" + value[min(3, len(value)):]), true
	case strings.HasPrefix(value, "/"):
		return "", false
	case value == "~" || strings.HasPrefix(value, "~/"):
		if !drive(home) {
			return "", false
		}
		return clean(home + "/" + strings.TrimPrefix(value, "~")), true
	case strings.HasPrefix(value, "~"):
		return "", false
	}
	if !drive(cwd) {
		return "", false
	}
	return clean(cwd + "/" + value), true
}
