// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/agentpaths"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	maxPathFacts = 32
	// Shell calls can carry a few link places after the ordinary path cap.
	// The original 32 facts stay byte-identical and in order.
	maxShellLinkFacts = 8
	maxLinkHops       = 40
	maxWalkDepth      = 4
	// maxProjectHookBytes bounds the project settings file the kit reads;
	// maxProjectHookEvents and maxProjectHookEventLen bound what it reports.
	maxProjectHookBytes    = 1 << 20
	maxProjectHookEvents   = 32
	maxProjectHookEventLen = 64
	// maxCommandWordChecks bounds the (word, folder) places of one shell
	// command the kit resolves (PlacedCommandPathWords); past it the claims
	// are cut (substrate-1 GAP-0622).
	maxCommandWordChecks = 2048
	// A bounded directory snapshot filters missing padding operands after the
	// path-fact cap without a file-system walk per word.
	maxCommandFactDirEntries = 4096
	maxCommandFactDirs       = 16
	// maxDroppedPathChecks bounds the path arguments past maxPathFacts the
	// kit still checks for a link; past it the claims are cut.
	maxDroppedPathChecks = 4 * maxPathFacts
)

// projectHookFiles are, per connector, the project settings files (relative
// to the session's cwd) whose hooks the actor's managed settings ignore:
// Claude Code's drop-in sets allowManagedHooksOnly (claudecode_sandbox.go),
// so a hook an uploaded repository declares never runs. The kit reports
// them at SessionStart so the attempt is recorded (GAP-0479).
var projectHookFiles = map[string][]string{
	"claudecode": {".claude/settings.json", ".claude/settings.local.json"},
}

// pathKeys are tool argument keys whose string value is a file-system path
// in the connectors' file tools: every key the reviewed file-tool schemas
// read as the path (actionfacts.FileToolPathKeys, root included; substrate-1
// GAP-0545) and the other file tools' names for a file.
var pathKeys = func() map[string]bool {
	keys := map[string]bool{
		"target_file": true, "filename": true, "old_path": true, "new_path": true,
		"source": true, "destination": true,
	}
	for _, key := range actionfacts.FileToolPathKeys() {
		keys[key] = true
	}
	return keys
}()

// readTools are tools whose PreToolUse target the gateway may want to see:
// the kit attaches the file it is about to read. OpenCode's read tool
// (filePath, before tool.execute.before) runs the skill folder pass like
// Claude Code's Read (GAP-1143).
var readTools = map[string]map[string]bool{
	"claudecode": {"Read": true, "NotebookRead": true},
	"opencode":   {"read": true},
}

// skillTools are the tools that load a skill by name (B5.4 use gate).
var skillTools = map[string]map[string]bool{
	"claudecode": {"Skill": true},
}

// payloadView is the part of a hook payload the kit inspects; the tool's
// arguments are read by ToolArgsOf.
type payloadView struct {
	Event    string `json:"hook_event_name"`
	CWD      string `json:"cwd"`
	ToolName string `json:"tool_name"`
}

// CollectFacts inspects the event and returns the facts to attach, or nil
// when there are none. It never fails: an unreadable path becomes a fact
// with an Error, and an unparseable payload yields no facts.
func CollectFacts(connector, event string, payload []byte, attachCap int64) *Facts {
	var view payloadView
	if json.Unmarshal(payload, &view) != nil {
		return nil
	}
	if event == "" {
		event = view.Event
	}
	cwd := filepath.Clean(view.CWD)
	if !filepath.IsAbs(cwd) {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}
	f := &Facts{}
	budget := attachCap

	var input any
	if args := ToolArgsOf(connector, event, payload); len(args) > 0 {
		_ = json.Unmarshal(args, &input)
	}
	seen := map[string]bool{}
	dropped := 0
	add := func(field, p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[field+"\x00"+p] {
			return
		}
		seen[field+"\x00"+p] = true
		if len(f.Paths) >= maxPathFacts {
			f.Truncated = true
			// A dropped plain file is no lost claim (a patch of 40 files);
			// a dropped link is (substrate-1 GAP-0622).
			if dropped++; dropped > maxDroppedPathChecks {
				f.claimsCut = true
			} else if pf := inspectPath(field, p, cwd); pf.Resolved != "" && pf.Resolved != pf.Abs {
				f.claimsCut = true
			}
			return
		}
		f.Paths = append(f.Paths, inspectPath(field, p, cwd))
	}
	walkPaths("tool_input", input, 0, add)

	isPre := event == "PreToolUse" || event == "preToolUse"
	if shellProofEvent(connector, event) {
		addShellCommandFacts(f, connector, event, payload, cwd)
	}
	if (isPre || event == "tool.execute.before") && readTools[connector][view.ToolName] {
		for _, pf := range f.Paths {
			// A read of a skill's files runs the skill folder pass in this
			// call (one rule for every skill: the folder's content digest,
			// GAP-0039/0164), so a folder that arrived since the last pass is
			// decided before its files reach the model.
			if pf.Type == "file" && (pf.Field == "tool_input.file_path" || pf.Field == "tool_input.notebook_path" || pf.Field == "tool_input.filePath") &&
				(inSkillRoot(pf.Abs) || inSkillRoot(pf.Resolved)) {
				f.readsSkill = true
			}
		}
	}
	// The Claude Code Skill tool loads a skill: the folder pass runs in this
	// call too (B5.4 use gate), so the folder is re-digested before the skill
	// reaches the model and a receipt only holds for the same content.
	if isPre && skillTools[connector][view.ToolName] {
		f.readsSkill = true
	}
	// Every MCP config the connector reads (project, user and local scope)
	// and the in-repository server files: at SessionStart (the agent starts
	// the servers) and before every call of an MCP tool, which the gateway
	// refuses when the scan blocks its server (E20, GAP-0185).
	if event == "SessionStart" || event == "sessionStart" || (isPre && strings.HasPrefix(view.ToolName, "mcp__")) {
		budget = attachMCP(f, connector, cwd, budget)
	} else if isPre {
		budget = attachAgentHookBefore(f, view.ToolName, budget)
		// A Write or Edit of one of those configs: its next content.
		budget = attachMCPWrite(f, connector, cwd, input, budget)
		// A command that may add an MCP server (claude mcp add, codex mcp
		// add), as a string (Bash) or an argv list (the Codex shell tool,
		// which the gateway reads joined): what the folder offers a
		// registry fetcher (GAP-0573, GAP-0643).
		if in, ok := input.(map[string]any); ok && strings.Contains(strings.ToLower(commandText(in["command"])), "mcp") {
			budget = attachFetchFacts(f, cwd, budget)
		}
	}
	_ = budget
	if event == "SessionStart" || event == "sessionStart" {
		f.ProjectHooks = collectProjectHooks(connector, cwd)
	}
	if f.claimsCut {
		f.Proofs = append(f.Proofs, ProofClaimsCut)
	}
	if len(f.Paths) == 0 && len(f.Files) == 0 && len(f.ProjectHooks) == 0 && len(f.Proofs) == 0 && !f.Truncated && !f.readsSkill {
		return nil
	}
	return f
}

// attachAgentHookBefore supplies exact current settings bytes for semantic
// native-edit and replacement judgement. One bounded read per settings target;
// the shared post budget also bounds multi-file patches. Unrelated calls attach
// nothing, and oversized files receive no digest pass. Claude's settings
// register its hooks whichever agent edits them, so every connector attaches
// them (a Codex actor's Write {} there went unjudged, substrate-1 GAP-0616),
// and so does a path that reaches them through a link, by its own name (the
// gateway reads the link's target from the path fact, substrate-1 GAP-0618).
func attachAgentHookBefore(f *Facts, tool string, budget int64) int64 {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "edit", "edit_file", "str_replace", "multiedit", "multi_edit", "multi-edit",
		"write", "write_file", "writefile", "write-file", "create", "create_file",
		"apply_patch", "applypatch", "apply-patch", "patch":
	default:
		return budget
	}
	attached := map[string]bool{}
	for _, pf := range f.Paths {
		if pf.Field != "tool_input.file_path" && pf.Field != "tool_input.filePath" && pf.Field != "tool_input.path" && !strings.HasSuffix(pf.Field, ".patch") {
			continue
		}
		if !claudeSettingsPath(pf.Abs) && !claudeSettingsPath(pf.Resolved) &&
			(len(pf.LinkChain) == 0 || !claudeSettingsPath(pf.LinkChain[len(pf.LinkChain)-1])) {
			continue
		}
		if attached[pf.Abs] {
			continue
		}
		attached[pf.Abs] = true
		a := AttachedFile{Role: "agent_hook_config_before", Path: pf.Abs, Resolved: pf.Resolved, Size: -1, Truncated: true}
		limit := budget
		if limit > 64<<10 {
			limit = 64 << 10
		}
		if limit < 0 {
			limit = 0
		}
		file, err := os.Open(pf.Abs)
		if err == nil {
			info, statErr := file.Stat()
			if statErr == nil && info.Mode().IsRegular() {
				a.Size = info.Size()
				if info.Size() <= limit {
					content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
					if readErr == nil && int64(len(content)) == info.Size() {
						a.Content = content
						a.Truncated = false
						sum := sha256.Sum256(content)
						a.SHA256 = hex.EncodeToString(sum[:])
					}
				}
			}
			file.Close()
		}
		if os.IsNotExist(err) && (pf.Type == "missing" || pf.Type == "symlink") {
			// A missing file, or a link to one, is an exact empty
			// before-state, not a failed read.
			a.Size, a.Truncated = 0, false
			sum := sha256.Sum256(nil)
			a.SHA256 = hex.EncodeToString(sum[:])
		}
		if a.Truncated {
			f.Truncated = true
		}
		f.Files = append(f.Files, a)
		budget -= int64(len(a.Content))
	}
	return budget
}

// claudeSettingsPath reports a Claude Code settings file name.
func claudeSettingsPath(p string) bool {
	p = filepath.ToSlash(p)
	return strings.HasSuffix(p, "/.claude/settings.json") || strings.HasSuffix(p, "/.claude/settings.local.json")
}

// collectProjectHooks returns the connector's project settings files under
// cwd that declare at least one hook, with the events they name. A file
// that is missing, too big or not JSON declares nothing the agent loads.
func collectProjectHooks(connectorName, cwd string) []ProjectHooks {
	var out []ProjectHooks
	for _, rel := range projectHookFiles[connectorName] {
		p := filepath.Join(cwd, filepath.FromSlash(rel))
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxProjectHookBytes {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) > maxProjectHookBytes {
			continue
		}
		var doc struct {
			Hooks map[string]json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}
		ph := ProjectHooks{Path: p}
		for event, groups := range doc.Hooks {
			var list []struct {
				Hooks []json.RawMessage `json:"hooks"`
			}
			if json.Unmarshal(groups, &list) != nil {
				continue
			}
			n := 0
			for _, g := range list {
				n += len(g.Hooks)
			}
			if n == 0 {
				continue
			}
			ph.Hooks += n
			if len(event) > maxProjectHookEventLen {
				event = event[:maxProjectHookEventLen]
			}
			ph.Events = append(ph.Events, event)
		}
		if ph.Hooks == 0 {
			continue
		}
		sort.Strings(ph.Events)
		if len(ph.Events) > maxProjectHookEvents {
			ph.Events = ph.Events[:maxProjectHookEvents]
		}
		sum := sha256.Sum256(raw)
		ph.SHA256 = hex.EncodeToString(sum[:])
		out = append(out, ph)
	}
	return out
}

// addShellCommandFacts makes, in the actor's file system, the file-system
// proofs the laptop's gateway makes for the call's shell command
// (ShellCommandOf, for every connector's shell tool): the private-key read
// proof and the protected-target write decision. It also lists each path word
// of the command (hookpaths.CommandPathWords: arguments, redirect targets, the
// words of an eval or -c body) whose physical place differs from its
// spelling: a symlink, a symlinked folder, a `..` after one. The gateway has
// no view of this file system: without these, cat key-link, cat
// a/b/ssh/id_ed25519, cd -P a/b/ssh && cat id_ed25519, eval "cat key-link" and
// echo x >> link-to-defenseclaw-state read or write the actor's protected
// files where the laptop blocks (substrate-1 GAP-0471, GAP-0545, GAP-0546,
// GAP-0547). Only POSIX shells run in an actor.
func addShellCommandFacts(f *Facts, connectorName, event string, payload []byte, cwd string) {
	if runtime.GOOS == "windows" {
		return
	}
	command, workdir, ok := ShellCommandOf(connectorName, event, payload)
	if !ok {
		return
	}
	// The gateway cannot place an explicit tilde workdir. Keep the p47b
	// refusal to make a protected-write claim in a guessed folder.
	unresolvedToolWorkdir := strings.HasPrefix(strings.TrimSpace(workdir), "~")
	cwd = shellWorkdir(cwd, workdir)
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return
	}
	if hookpaths.ActionPrivateKeyReadWithDialect(command, cwd, home, actionfacts.DialectPOSIX) ||
		hookpaths.ActionMakePrivateKeyRead(command, cwd, home) {
		f.Proofs = append(f.Proofs, ProofPrivateKeyRead)
	}
	var words []hookpaths.CommandPathWord
	// Every placed word is walked from the same working folders: one memo
	// for this call walks each folder once, not once per word and pass. An
	// 8 KB script of function calls made 4,200 lstat calls for its 840
	// words without it, each a sandbox system call in the actor
	// (substrate-1 GAP-1153). The answers are the walk's, for one call.
	memo := hookpaths.NewTargetMemo()
	// Past the statement budget the gateway reads no statement alone, so
	// the words that may reach a protected file (a hard link, a place in
	// the SSH folder) carry a claim of their own, and links to protected
	// files go first in the late slots (substrate-1 GAP-1156). A call
	// under the budget keeps its p47b facts.
	overBudget := !unresolvedToolWorkdir && shellStatementsOverBudget(command)
	// A call beyond the statement budget needs the protected-target
	// decision only when its placed words can give the gateway a link,
	// private-home or protected-word claim. Keep the p47b placement for
	// every word and dir.
	if overBudget && !overBudgetDecisionForTest.Load() {
		words = hookpaths.PlacedCommandPathWords(command, cwd, home)
		paths, truncated, claimsCut := len(f.Paths), f.Truncated, f.claimsCut
		if !addPlacedCommandWordFacts(f, words, cwd, home, len(f.Proofs) > 0, true, true, memo) {
			return
		}
		f.Paths, f.Truncated, f.claimsCut = f.Paths[:paths], truncated, claimsCut
	}
	if !unresolvedToolWorkdir &&
		hookpaths.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil) ==
			hookpaths.ProtectedTargetDecision {
		f.Proofs = append(f.Proofs, ProofProtectedWrite)
	}
	if words == nil {
		words = hookpaths.PlacedCommandPathWords(command, cwd, home)
	}
	addPlacedCommandWordFacts(f, words, cwd, home, len(f.Proofs) > 0, false, overBudget, memo)
}

// addPlacedCommandWordFacts uses the p47b word and directory bound.
// ask reports whether a visited word can carry a gateway claim even if
// privacy has not yet been granted by the protected-write decision.
// overBudget marks a call past the statement budget: a word that may reach
// a protected file (hookpaths.ProtectedReach) is then a fact of its own
// (PathFact.Protected), and a late slot goes first to such a word or to a
// link whose place may be protected, before a link to an ordinary file
// (substrate-1 GAP-1156). memo keeps the file system answers of this hook
// call (substrate-1 GAP-1153).
func addPlacedCommandWordFacts(f *Facts, words []hookpaths.CommandPathWord, cwd, home string, privacy, ask, overBudget bool, memo *hookpaths.TargetMemo) bool {
	type placed struct{ text, dir string }
	seen := map[placed]bool{}
	// mayProtect marks the late facts that may name a protected file.
	var mayProtect []bool
	dirNames := map[string]commandFactDirNames{}
	privateHomeDirs := map[string]bool{}
	privateHomeSeen := map[string]bool{}
	for _, word := range words {
		dirs := word.Dirs
		if len(dirs) == 0 || strings.HasPrefix(word.Value, "/") {
			dirs = []string{cwd}
		}
		for _, dir := range dirs {
			if seen[placed{word.Text, dir}] {
				continue
			}
			if len(seen) == maxCommandWordChecks {
				f.Truncated, f.claimsCut = true, true
				return false
			}
			seen[placed{word.Text, dir}] = true
			if len(f.Paths) >= maxPathFacts && !commandWordMayExist(word.Value, dir, dirNames) {
				// A missing first component cannot reach a link. Its private
				// home status depends on the existing directory, so check that
				// directory once for the ask pass or the old truncation flag.
				if ask || (privacy && !f.Truncated) {
					abs := hookpaths.CommandWordAbs(word, dir)
					ssh := filepath.Join(home, ".ssh")
					if abs != ssh && !strings.HasPrefix(abs, ssh+string(filepath.Separator)) {
						if !privateHomeSeen[dir] {
							privateHomeDirs[dir] = hookpaths.PrivateHomePlace(dir, home)
							privateHomeSeen[dir] = true
						}
						if privateHomeDirs[dir] {
							if ask {
								return true
							}
							f.Truncated, f.claimsCut = true, true
						}
					}
				}
				continue
			}
			fact, listed := commandWordFact(word, dir, home, privacy, overBudget, memo)
			link := fact.Resolved != "" || fact.Entry != ""
			if ask && (link || fact.Protected || hookpaths.PrivateHomePlace(hookpaths.CommandWordAbs(word, dir), home)) {
				return true
			}
			if listed {
				if len(f.Paths) >= maxPathFacts {
					f.Truncated, f.claimsCut = true, true
					// Preserve the original 32 facts, then retain a bounded
					// set of late link places for the guest command twin.
					if !link && !fact.Protected {
						continue
					}
					protected := overBudget && (fact.Protected ||
						lateFactMayProtect(fact.Resolved, home, memo) || lateFactMayProtect(fact.Entry, home, memo))
					if len(f.Paths) < maxPathFacts+maxShellLinkFacts {
						f.Paths = append(f.Paths, fact)
						mayProtect = append(mayProtect, protected)
						continue
					}
					if protected {
						if i := slices.Index(mayProtect, false); i >= 0 {
							f.Paths[maxPathFacts+i], mayProtect[i] = fact, true
						}
					}
					continue
				}
				f.Paths = append(f.Paths, fact)
			}
		}
	}
	return false
}

// lateFactMayProtect reports whether place, a link place of a late command
// word fact, may be a protected file (hookpaths.ProtectedReach names it).
func lateFactMayProtect(place, home string, memo *hookpaths.TargetMemo) bool {
	return place != "" && hookpaths.ProtectedReach(place, home, memo) == hookpaths.GradeNamed
}

// minBudgetCheckBytes is the shortest shell command shellStatementsOverBudget
// counts. A call over the statement budget has more than 128 statements,
// each a word and a separator; a shorter call is never counted and gets
// the decision, as before, so ordinary calls pay nothing for the check.
const minBudgetCheckBytes = 256

// overBudgetDecisionForTest makes the protected-target decision on every
// call over the statement budget, as rel/1.0.11 dfb6d9c707 did: only the
// tests that judge the same calls with both sets of facts set it
// (SetOverBudgetShellProofsForTest).
var overBudgetDecisionForTest atomic.Bool

// SetOverBudgetShellProofsForTest makes the kit's protected-target decision
// on every call over the statement budget, until restore is called. Tests
// only: they compare the gateway's answers with and without that proof.
func SetOverBudgetShellProofsForTest(on bool) (restore func()) {
	was := overBudgetDecisionForTest.Swap(on)
	return func() { overBudgetDecisionForTest.Store(was) }
}

// shellStatementsOverBudget reports a POSIX shell command over the
// statement budget, as the laptop hook client reads a POSIX call
// (clientStatementBudgetExceeded: actionfacts.ShellStatementsOverBudget,
// the same function), which describes no such call to its gateway
// (rel-1-0-2:GAP-0568). The gateway refuses it at the budget before any
// reader that reads the kit's protected-write proof of the whole command
// runs (dispatchTrustedAction), except the budget refusal itself, which
// reads it with a word claim (substrate-1 GAP-1156); the readers its twins
// and cap-floor pieces run judge other text, and read only the kit's word
// claims, which the caller keeps the decision for. Run on such a call, the
// decision re-read each statement alone after a dynamic program and cost
// the actor's hook 140 to 290 ms on an 8 KB script (substrate-1 GAP-1153).
// The answer does not depend on SetOverBudgetShellProofsForTest: the facts
// of such a call are the same whether the kit makes the decision or not.
func shellStatementsOverBudget(command string) bool {
	return len(command) >= minBudgetCheckBytes && actionfacts.ShellStatementsOverBudget(command)
}

// commandFactDirNames is one bounded snapshot. An incomplete or unreadable
// directory cannot rule a word out, so its words are inspected normally.
type commandFactDirNames struct {
	names    map[string]bool
	complete bool
}

// commandWordMayExist filters only a relative word whose first component is
// absent from its known directory. Such a word cannot reach a link or hard
// link there. This runs only after the path-fact cap: no ordinary call pays
// for a directory snapshot, and a padded command does not walk every
// missing operand after the cap.
func commandWordMayExist(value, dir string, cache map[string]commandFactDirNames) bool {
	if !filepath.IsAbs(dir) || filepath.IsAbs(value) || strings.HasPrefix(value, "~") || strings.Contains(value, "..") {
		return true
	}
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	first, _, _ := strings.Cut(value, "/")
	if first == "" || first == "." || first == ".." {
		return true
	}
	listing, cached := cache[dir]
	if !cached {
		if len(cache) >= maxCommandFactDirs {
			return true
		}
		listing = commandFactDirNames{}
		// A moved directory can give even a missing child an Entry
		// fact; never filter its words by the logical directory.
		if physical, ok := hookpaths.ResolveWriteTarget(dir); !ok || physical != filepath.Clean(dir) {
			cache[dir] = listing
			return true
		}
		folder, err := os.Open(dir)
		if err == nil {
			names, readErr := folder.Readdirnames(maxCommandFactDirEntries + 1)
			_ = folder.Close()
			if (readErr == nil || readErr == io.EOF) && len(names) <= maxCommandFactDirEntries {
				listing.complete = true
				listing.names = make(map[string]bool, len(names))
				for _, name := range names {
					listing.names[name] = true
				}
			}
		}
		cache[dir] = listing
	}
	return !listing.complete || listing.names[first]
}

// commandWordFact is the CommandWordField fact of one command word: its place
// with every link followed and with its last name kept, each as the kernel
// walks it from dir (hookpaths.ResolveWriteTarget, through memo), and, when
// privacy is asked, whether it is a private place of home. listed is false
// when both places are the one the word spells and it is no private place.
// overBudget, set past the statement budget, also lists a word with no
// other place that may reach a protected file (PathFact.Protected).
func commandWordFact(word hookpaths.CommandPathWord, dir, home string, privacy, overBudget bool, memo *hookpaths.TargetMemo) (PathFact, bool) {
	full := word.Value
	if !strings.HasPrefix(full, "/") {
		full = strings.TrimRight(dir, "/") + "/" + full
	}
	lexical := hookpaths.CommandWordAbs(word, dir)
	fact := PathFact{Field: CommandWordField, Path: word.Text, Abs: lexical, UID: -1, GID: -1, Type: "missing"}
	if followed, ok := memo.ResolveWriteTarget(full); ok && followed != lexical {
		fact.Resolved = followed
	}
	if dir, name := filepath.Split(strings.TrimRight(full, "/")); dir != "" && name != "" && name != "." && name != ".." {
		if parent, ok := memo.ResolveWriteTarget(dir); ok {
			if entry := filepath.Join(parent, name); entry != lexical {
				fact.Entry = entry
			}
		}
	}
	fact.PrivateHome = privacy && hookpaths.PrivateHomePlace(lexical, home)
	if fact.Resolved == "" && fact.Entry == "" && !fact.PrivateHome {
		if !overBudget || hookpaths.ProtectedReach(lexical, home, memo) != hookpaths.GradeNamed {
			return PathFact{}, false
		}
		fact.Protected = true
	}
	if info, err := os.Stat(full); err == nil {
		fact.Type = "other"
		switch {
		case info.Mode().IsRegular():
			fact.Type = "file"
		case info.IsDir():
			fact.Type = "dir"
		}
	}
	return fact, true
}

// walkPaths calls add for every path-valued key and for every file an
// apply_patch body names, depth-first in key order.
func walkPaths(field string, v any, depth int, add func(field, path string)) {
	if depth > maxWalkDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := field + "." + k
			if s, ok := t[k].(string); ok {
				if pathKeys[k] {
					add(child, s)
				}
				for _, p := range patchPaths(s) {
					add(child, p)
				}
				continue
			}
			walkPaths(child, t[k], depth+1, add)
		}
	case []any:
		for i, e := range t {
			child := fmt.Sprintf("%s[%d]", field, i)
			if s, ok := e.(string); ok {
				for _, p := range patchPaths(s) {
					add(child, p)
				}
				continue
			}
			walkPaths(child, e, depth+1, add)
		}
	}
}

// patchPaths returns the files an apply_patch body adds, updates, deletes or
// moves to (the Codex patch format).
func patchPaths(s string) []string {
	if !strings.Contains(s, "*** Begin Patch") {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if strings.HasPrefix(line, prefix) {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(line, prefix)))
			}
		}
	}
	return out
}

func inspectPath(field, p, cwd string) PathFact {
	pf := PathFact{Field: field, Path: p, UID: -1, GID: -1}
	// walk is the path as the kernel walks it: joined, not cleaned, so a
	// `..` after a symlinked folder ascends from the link's target
	// (a/b/ssh/../.ssh/id_ed25519 is the actor's key when a/b/ssh links to
	// ~/.ssh; cleaned first it was the missing a/b/.ssh/id_ed25519,
	// substrate-1 GAP-0546). Abs is the cleaned spelling.
	walk := p
	if strings.HasPrefix(walk, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			walk = strings.TrimRight(home, "/") + "/" + walk[2:]
		}
	}
	if !filepath.IsAbs(walk) {
		walk = strings.TrimRight(cwd, "/") + "/" + walk
	}
	pf.Abs = filepath.Clean(walk)
	cur := walk
	for i := 0; i < maxLinkHops; i++ {
		info, err := os.Lstat(cur)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			break
		}
		target, err := os.Readlink(cur)
		if err != nil {
			break
		}
		if !filepath.IsAbs(target) {
			if dir, err := winpath.EvalLinks(filepath.Dir(cur)); err == nil {
				target = filepath.Join(dir, target)
			} else {
				target = filepath.Join(filepath.Dir(cur), target)
			}
		}
		target = filepath.Clean(target)
		pf.LinkChain = append(pf.LinkChain, target)
		cur = target
	}
	if resolved, err := winpath.EvalLinks(walk); err == nil {
		pf.Resolved = resolved
	}
	info, err := os.Stat(walk)
	switch {
	case err == nil:
		pf.Type = "other"
		switch {
		case info.Mode().IsRegular():
			pf.Type = "file"
		case info.IsDir():
			pf.Type = "dir"
		}
		pf.Mode = fmt.Sprintf("%04o", uint32(info.Mode().Perm()))
		pf.UID, pf.GID, pf.NLink = fileOwner(info)
		pf.Size = info.Size()
	case os.IsNotExist(err):
		if l, lerr := os.Lstat(walk); lerr == nil && l.Mode()&os.ModeSymlink != 0 {
			pf.Type = "symlink"
		} else {
			pf.Type = "missing"
		}
	default:
		pf.Type = "other"
		pf.Error = err.Error()
	}
	target := pf.Resolved
	if target == "" {
		target = pf.Abs
	}
	pf.InsideCWD = within(target, cwd)
	return pf
}

// inSkillRoot reports whether p is inside a skill root of the connector
// table (agentpaths, the one skillRoots and quarantine read) or a Claude
// Code plugin's skills. GAP-1143: it was its own list of .claude, .codex
// and .agents, so a read in the other connectors' roots (OpenCode's
// .opencode/skill, Cursor's, Copilot's, ...) did not run the folder pass.
func inSkillRoot(p string) bool {
	p = filepath.ToSlash(p)
	if p == "" {
		return false
	}
	under := func(dir string) bool {
		dir = strings.TrimSuffix(filepath.ToSlash(dir), "/")
		return dir != "" && strings.HasPrefix(p, dir+"/")
	}
	for _, e := range agentpaths.ActorEntries() {
		if e.Kind != agentpaths.Skills {
			continue
		}
		switch e.Base {
		case agentpaths.Home, agentpaths.Project:
			if strings.Contains(p, "/"+e.Rel+"/") {
				return true
			}
		case agentpaths.Config:
			mark := "/" + e.Rel + "/"
			if e.ConfigRel != "" {
				mark = "/" + e.ConfigRel + mark
			}
			if strings.Contains(p, mark) {
				return true
			}
			if v := strings.TrimSpace(os.Getenv(e.ConfigEnv)); e.ConfigEnv != "" && filepath.IsAbs(v) && under(filepath.Join(filepath.Clean(v), filepath.FromSlash(e.Rel))) {
				return true
			}
		case agentpaths.Abs:
			if under(e.Rel) {
				return true
			}
		}
	}
	// A Claude Code plugin's skills (skillRoots watches them too).
	if i := strings.Index(p, "/.claude/plugins/"); i >= 0 && strings.Contains(p[i:], "/skills/") {
		return true
	}
	return false
}

func within(p, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

// attach adds up to budget bytes of the regular file at path and returns the
// budget left.
func attach(f *Facts, role, path, resolved string, budget int64) int64 {
	for _, a := range f.Files {
		if a.Path == path {
			return budget
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return budget
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return budget
	}
	a := AttachedFile{Role: role, Path: path, Resolved: resolved, Size: info.Size()}
	h := sha256.New()
	limit := budget
	if limit < 0 {
		limit = 0
	}
	content, _ := io.ReadAll(io.LimitReader(file, limit))
	h.Write(content)
	if int64(len(content)) < info.Size() {
		a.Truncated, f.Truncated = true, true
		// The digest covers the whole file even when the content is cut.
		_, _ = io.Copy(h, file)
	}
	a.SHA256 = hex.EncodeToString(h.Sum(nil))
	a.Content = content
	f.Files = append(f.Files, a)
	return budget - int64(len(content))
}

// mcpConfigPaths are the files the connector reads MCP servers from, in
// every scope (project, user, local), taken from the connector's own MCP
// surface (connector.ConnectorCapabilities.MCP, the paths the host
// inventory and setup use), so every connector the kit runs gets its
// sources by construction (GAP-0185).
func mcpConfigPaths(connectorName, cwd string) []string {
	c, ok := connector.NewDefaultRegistry().Get(connectorName)
	if !ok {
		return nil
	}
	cp, ok := c.(connector.ConnectorCapabilityProvider)
	if !ok {
		return nil
	}
	m := cp.Capabilities(connector.SetupOpts{WorkspaceDir: cwd}).MCP
	if !m.Supported {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{m.ConfigPaths, m.ReadPaths, m.WritePaths} {
		for _, p := range list {
			if p == "" || !filepath.IsAbs(p) {
				continue
			}
			p = filepath.Clean(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// moduleCandidates are the files of the folder a Python module name runs
// (python -m a.b runs a/b.py or the package a/b); attest.ModuleCandidates
// is the gateway's copy of the same rule.
func moduleCandidates(module string) []string {
	p := strings.ReplaceAll(strings.TrimSpace(module), ".", "/")
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return nil
	}
	return []string{p + ".py", p + "/__main__.py", p + "/__init__.py"}
}

// attachMCP attaches every MCP config of the connector that exists and the
// in-repository files its stdio servers start (E20), so the gateway can
// scan them before the agent starts or calls them.
func attachMCP(f *Facts, connectorName, cwd string, budget int64) int64 {
	found := false
	for _, cfgPath := range mcpConfigPaths(connectorName, cwd) {
		if _, err := os.Lstat(cfgPath); err != nil {
			continue
		}
		found = true
		budget = attach(f, "mcp_config", cfgPath, "", budget)
		var servers []mcpServer
		switch {
		case strings.HasSuffix(cfgPath, ".toml"):
			servers = codexMCPServers(cfgPath)
		case strings.HasSuffix(cfgPath, ".json"):
			servers = claudeMCPServers(cfgPath, cwd)
		}
		for _, s := range servers {
			// Where a bare command is found, so an installed program is
			// told from the folder's (GAP-0575).
			attachCommandPath(f, s.Command)
			// A Python module the server runs (-m a.b): its file when it is
			// in the folder, else a record that the kit looked and found
			// none, so the gateway can tell the image's module from the
			// folder's (GAP-0556).
			for i, a := range s.Args {
				if a != "-m" || i+1 >= len(s.Args) {
					continue
				}
				found := false
				for _, c := range moduleCandidates(s.Args[i+1]) {
					p := filepath.Join(cwd, filepath.FromSlash(c))
					if resolved, err := winpath.EvalLinks(p); err == nil && within(resolved, cwd) {
						budget = attach(f, "mcp_server", p, resolved, budget)
						found = true
					}
				}
				if !found {
					f.Files = append(f.Files, AttachedFile{Role: "mcp_module_absent", Path: s.Args[i+1]})
				}
			}
			for _, cand := range append([]string{s.Command}, s.Args...) {
				if !looksLikePath(cand) {
					continue
				}
				p := cand
				if !filepath.IsAbs(p) {
					p = filepath.Join(cwd, p)
				}
				p = filepath.Clean(p)
				resolved, err := winpath.EvalLinks(p)
				if err != nil || !within(resolved, cwd) {
					continue
				}
				budget = attach(f, "mcp_server", p, resolved, budget)
			}
		}
	}
	if found {
		// What the folder offers a registry fetcher (npx, uvx): its own
		// programs and configs decide what a fetched server runs (GAP-0573).
		budget = attachFetchFacts(f, cwd, budget)
	}
	return budget
}

// attachMCPWrite attaches, for a file tool call that writes or edits one of
// the connector's MCP configs, the content the file will have after it
// (role mcp_config_write): a Write's content, or the edits applied to the
// file as it is now. A call shape the kit cannot apply attaches nothing;
// the gateway then reads the call itself and an edit fragment follows the
// fail mode.
func attachMCPWrite(f *Facts, connectorName, cwd string, input any, budget int64) int64 {
	in, ok := input.(map[string]any)
	if !ok {
		return budget
	}
	target := firstString(in, "file_path", "filePath", "path")
	if target == "" {
		return budget
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(cwd, target)
	}
	target = filepath.Clean(target)
	resolvedTarget, terr := winpath.EvalLinks(target)
	match := false
	for _, p := range mcpConfigPaths(connectorName, cwd) {
		if p == target {
			match = true
			break
		}
		if rp, err := winpath.EvalLinks(p); terr == nil && err == nil && rp == resolvedTarget {
			match = true
			break
		}
	}
	if !match {
		// A config the connector does not load (sub/.mcp.json): the gateway
		// reads the servers of a whole write (its content) from the call
		// itself and decides a fetched one with the folder's facts, so the
		// kit sends them (GAP-0643). A partial edit gives the gateway no
		// server; it needs none.
		if _, whole := in["content"].(string); whole && mcpConfigWriteNames[filepath.Base(target)] {
			budget = attachFetchFacts(f, MCPConfigProject(target, cwd), budget)
		}
		return budget
	}
	content, cut, ok := nextContent(in, target, budget)
	if !ok {
		return budget
	}
	sum := sha256.Sum256(content)
	a := AttachedFile{Role: "mcp_config_write", Path: target, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), Content: content, Truncated: cut}
	if cut {
		f.Truncated = true
	}
	f.Files = append(f.Files, a)
	return attachFetchFacts(f, MCPConfigProject(target, cwd), budget-int64(len(content)))
}

// MCPConfigProject is the folder the servers of an MCP config written at
// target run in, as the gateway judges them: the config's folder (the folder
// above a config folder such as .cursor or .claude) when it lies below cwd,
// else cwd. A whole write of sub/.mcp.json from /work is checked for what a
// fetcher resolves in /work/sub, where the agent loads it (substrate-1
// GAP-0646); a home config stays in cwd. Both paths are absolute or the
// result is cwd.
func MCPConfigProject(target, cwd string) string {
	if !filepath.IsAbs(target) || !filepath.IsAbs(cwd) {
		return cwd
	}
	cwd = filepath.Clean(cwd)
	folder := filepath.Dir(filepath.Clean(target))
	if strings.HasPrefix(filepath.Base(folder), ".") && folder != cwd {
		folder = filepath.Dir(folder)
	}
	if rel, err := filepath.Rel(cwd, folder); err == nil && rel != "." && rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return folder
	}
	return cwd
}

// mcpConfigWriteNames are the file names whose write the gateway reads for
// MCP servers wherever they are (attest mcpConfigWrite, the kit's copy of
// the same rule).
var mcpConfigWriteNames = map[string]bool{".mcp.json": true, "mcp.json": true, ".claude.json": true,
	"settings.json": true, "settings.local.json": true, "config.toml": true}

// commandText is a tool call's command as the gateway reads it: the string,
// or the strings of an argv list joined by spaces.
func commandText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, e := range c {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// nextContent is the file's content after a Write (content) or an Edit
// (old_string/new_string, oldString/newString, edits[]), cut to limit.
func nextContent(in map[string]any, target string, limit int64) (content []byte, cut, ok bool) {
	if limit < 0 {
		limit = 0
	}
	clip := func(b []byte) ([]byte, bool, bool) {
		if int64(len(b)) > limit {
			return b[:limit], true, true
		}
		return b, false, true
	}
	if s, isStr := in["content"].(string); isStr {
		return clip([]byte(s))
	}
	edits := []map[string]any{in}
	if list, isList := in["edits"].([]any); isList {
		edits = edits[:0]
		for _, e := range list {
			if m, isMap := e.(map[string]any); isMap {
				edits = append(edits, m)
			}
		}
	}
	file, err := os.Open(target)
	var cur []byte
	if err == nil {
		cur, _ = io.ReadAll(io.LimitReader(file, limit+1))
		file.Close()
		if int64(len(cur)) > limit {
			return cur[:limit], true, true
		}
	}
	text, applied := string(cur), false
	for _, e := range edits {
		oldS, okOld := e["old_string"].(string)
		newS, okNew := e["new_string"].(string)
		if !okOld && !okNew {
			oldS, _ = e["oldString"].(string)
			newS, okNew = e["newString"].(string)
		}
		if !okNew {
			continue
		}
		applied = true
		all, _ := e["replace_all"].(bool)
		if !all {
			all, _ = e["replaceAll"].(bool)
		}
		switch {
		case oldS == "" && text == "":
			text = newS
		case oldS == "":
			// The agent refuses an empty old_string on a file with content.
		case all:
			text = strings.ReplaceAll(text, oldS, newS)
		default:
			text = strings.Replace(text, oldS, newS, 1)
		}
	}
	if !applied {
		return nil, false, false
	}
	return clip([]byte(text))
}

type mcpServer struct {
	Command string
	Args    []string
}

func looksLikePath(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	if strings.Contains(s, "/") {
		return true
	}
	switch strings.ToLower(filepath.Ext(s)) {
	case ".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".rb", ".pl", ".jar":
		return true
	}
	return false
}

func readSmall(path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	b, _ := io.ReadAll(io.LimitReader(file, MaxAttachBytes))
	return b
}

// claudeMCPServers reads the stdio servers of a Claude Code MCP config by
// the exact keys Claude Code reads (encoding/json's struct matching folds
// case, GAP-0176): the kit attaches the files these servers start.
func claudeMCPServers(path, cwd string) []mcpServer {
	var doc map[string]json.RawMessage
	if json.Unmarshal(readSmall(path), &doc) != nil {
		return nil
	}
	servers := map[string]map[string]json.RawMessage{}
	_ = json.Unmarshal(doc["mcpServers"], &servers)
	if cwd != "" {
		// ~/.claude.json: the local scope of this folder (claude mcp add's
		// default) starts servers too.
		var projects map[string]map[string]json.RawMessage
		if json.Unmarshal(doc["projects"], &projects) == nil {
			var local map[string]map[string]json.RawMessage
			if json.Unmarshal(projects[cwd]["mcpServers"], &local) == nil {
				for n, v := range local {
					servers["local\x00"+n] = v
				}
			}
		}
	}
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []mcpServer
	for _, n := range names {
		var s struct {
			Type, Command string
			Args          []string
		}
		_ = json.Unmarshal(servers[n]["type"], &s.Type)
		_ = json.Unmarshal(servers[n]["command"], &s.Command)
		_ = json.Unmarshal(servers[n]["args"], &s.Args)
		if s.Command != "" && (s.Type == "" || s.Type == "stdio") {
			out = append(out, mcpServer{Command: s.Command, Args: s.Args})
		}
	}
	return out
}

func codexMCPServers(path string) []mcpServer {
	var doc struct {
		MCPServers map[string]struct {
			Command string   `toml:"command"`
			Args    []string `toml:"args"`
		} `toml:"mcp_servers"`
	}
	if toml.Unmarshal(readSmall(path), &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc.MCPServers))
	for n := range doc.MCPServers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []mcpServer
	for _, n := range names {
		s := doc.MCPServers[n]
		if s.Command != "" {
			out = append(out, mcpServer{Command: s.Command, Args: s.Args})
		}
	}
	return out
}
