// Package agentpaths is the one table of the folders each agent connector
// loads skills, commands and plugins from (GAP-0788).
//
// The laptop (config.SkillDirsForConnector, config.PluginDirsForConnector),
// the actor kit (kit.skillRoots) and the gateway's skill-path regexes
// (attest.skillRootRE, attest.skillPathInCommand) all read this table, so a
// folder added for one of them is seen by all of them. Before it each kept
// its own hand list and they drifted: the actor did not look at the Cursor,
// Copilot, Devin, Amp, Antigravity or Hermes folders the laptop watched.
//
// The package is a leaf (stdlib only): the home, the working directory, the
// connector's config home and the laptop-only lookups are inputs. Folders
// the laptop finds by reading files (Claude Code's nested project skills,
// Codex project layers and plugin marketplaces, Amp settings, Devin Desktop
// legacy folders) are Dynamic entries: the laptop resolves them, and the
// actor, which has no such lookups, uses the entry's static stand-ins.
package agentpaths

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Kind says what a folder holds.
type Kind uint8

const (
	// Skills folders hold one skill per subfolder (<root>/<name>/SKILL.md).
	Skills Kind = iota + 1
	// Commands folders hold single-file commands (Claude Code
	// .claude/commands/<name>.md). The laptop scans them with the skills;
	// the actor kit lists subfolders only, so it leaves them out.
	Commands
	// Plugins folders hold installed plugins; the actor looks for the skills
	// folders inside them.
	Plugins
)

// Base is what an entry's Rel is relative to.
type Base uint8

const (
	// Home is the user's home folder.
	Home Base = iota + 1
	// Project is the agent's working folder.
	Project
	// Config is the connector's config home (ConfigEnv, else
	// <home>/ConfigRel).
	Config
	// Abs entries are absolute; Rel is the path.
	Abs
	// Dynamic entries are resolved by the laptop (Inputs.Dynamic(Rel));
	// the actor uses Stand instead.
	Dynamic
)

// Scope says which side reads an entry.
type Scope uint8

const (
	// Both is the default: the laptop and the actor read the entry.
	Both Scope = iota
	// LaptopOnly entries are not part of the actor's view.
	LaptopOnly
	// ActorOnly entries are read by the actor kit and the gateway regexes,
	// not by the laptop lists (the kit also searches the project's
	// .claude/plugins, which the laptop list never had).
	ActorOnly
)

// Entry is one folder of a connector.
type Entry struct {
	Kind  Kind
	Base  Base
	Rel   string // slash-separated; for Dynamic, the resolver key
	Scope Scope
	// UnixOnly entries are skipped when Inputs.GOOS is "windows".
	UnixOnly bool
	// Stand is the static stand-in the actor uses for a Dynamic entry.
	Stand []Entry
}

// Connector is one connector's row.
type Connector struct {
	Name string
	// ConfigRel is the default config home under the user's home
	// (slash-separated), for Config entries in the actor.
	ConfigRel string
	// ConfigEnv names the vendor variable that moves the config home.
	ConfigEnv string
	// NeedConfig connectors have no folders when the laptop cannot
	// resolve a config home (Inputs.ConfigHome == "").
	NeedConfig bool
	// Actor connectors run in a Substrate actor (kit HarnessReleases).
	Actor   bool
	Entries []Entry
}

// Dynamic resolver keys (Entry.Rel of Dynamic entries).
const (
	DynClaudeProjectSkills   = "claudecode.project-skills"
	DynClaudePluginCache     = "claudecode.plugin-cache"
	DynCodexProjectLayers    = "codex.project-layer-skills"
	DynCodexPersonalSkills   = "codex.personal-skills"
	DynCodexPluginSources    = "codex.plugin-sources"
	DynDevinLegacySkills     = "devin.legacy-skills"
	DynAmpSkills             = "amp.skills"
	DynOpenCodeProjectConfig = "opencode.project-config-skills"
	DynOpenCodeProjectShared = "opencode.project-shared-skills"
)

func sk(b Base, rel string) Entry  { return Entry{Kind: Skills, Base: b, Rel: rel} }
func cmd(b Base, rel string) Entry { return Entry{Kind: Commands, Base: b, Rel: rel} }
func pl(b Base, rel string) Entry  { return Entry{Kind: Plugins, Base: b, Rel: rel} }
func dyn(k Kind, key string, stand ...Entry) Entry {
	return Entry{Kind: k, Base: Dynamic, Rel: key, Stand: stand}
}
func laptopOnly(e Entry) Entry { e.Scope = LaptopOnly; return e }
func actorOnly(e Entry) Entry  { e.Scope = ActorOnly; return e }

// table keeps the laptop's order per connector (the lists are
// precedence-ordered for some callers). OpenClaw is not here: its folders
// come from its own config (config.skillDirsOpenClaw).
//
// Kiro has no entries: Kiro CLI loads skills only through skill:// resources
// listed in an agent file, and neither the laptop nor the actor kit's
// defenseclaw agent lists any.
var table = []Connector{
	{Name: "claudecode", ConfigRel: ".claude", ConfigEnv: "CLAUDE_CONFIG_DIR", Actor: true, Entries: []Entry{
		sk(Config, "skills"),
		cmd(Config, "commands"),
		cmd(Project, ".claude/commands"),
		dyn(Skills, DynClaudeProjectSkills, sk(Project, ".claude/skills")),
		dyn(Plugins, DynClaudePluginCache, pl(Config, "plugins")),
		laptopOnly(pl(Config, "skills")),
		laptopOnly(dyn(Plugins, DynClaudeProjectSkills)),
		actorOnly(pl(Project, ".claude/plugins")),
	}},
	{Name: "codex", ConfigRel: ".codex", ConfigEnv: "CODEX_HOME", Actor: true, Entries: []Entry{
		dyn(Skills, DynCodexProjectLayers, sk(Project, ".agents/skills")),
		dyn(Skills, DynCodexPersonalSkills, sk(Home, ".agents/skills")),
		sk(Config, "skills"),
		{Kind: Skills, Base: Abs, Rel: "/etc/codex/skills", UnixOnly: true},
		laptopOnly(dyn(Plugins, DynCodexPluginSources)),
		laptopOnly(pl(Config, "plugins/cache")),
		actorOnly(pl(Config, "plugins")),
	}},
	{Name: "zeptoclaw", ConfigRel: ".zeptoclaw", Entries: []Entry{
		sk(Home, ".zeptoclaw/skills"),
		sk(Project, ".zeptoclaw/skills"),
		pl(Home, ".zeptoclaw/plugins"),
	}},
	{Name: "hermes", ConfigRel: ".hermes", ConfigEnv: "HERMES_HOME", Actor: true, Entries: []Entry{
		sk(Config, "skills"),
		pl(Config, "plugins"),
		pl(Project, ".hermes/plugins"),
	}},
	{Name: "cursor", ConfigRel: ".cursor", Actor: true, Entries: []Entry{
		sk(Home, ".cursor/skills"),
		sk(Home, ".agents/skills"),
		sk(Project, ".cursor/skills"),
		sk(Project, ".agents/skills"),
	}},
	{Name: "devin", ConfigRel: ".config/devin", NeedConfig: true, Actor: true, Entries: []Entry{
		sk(Config, "skills"),
		sk(Home, ".agents/skills"),
		sk(Project, ".devin/skills"),
		sk(Project, ".agents/skills"),
		laptopOnly(dyn(Skills, DynDevinLegacySkills)),
	}},
	{Name: "opencode", ConfigRel: ".config/opencode", ConfigEnv: "OPENCODE_CONFIG_DIR", Actor: true, Entries: []Entry{
		// OpenCode 2.2.7 reads skill/ and skills/ under each config root
		// (~/.config/opencode, the project's .opencode folders, ~/.opencode,
		// OPENCODE_CONFIG_DIR), then .claude/skills and .agents/skills in
		// the project folders and the home. Same order as the Python
		// mirror (connector_paths._opencode_skill_dirs).
		sk(Home, ".config/opencode/skill"),
		sk(Home, ".config/opencode/skills"),
		dyn(Skills, DynOpenCodeProjectConfig, sk(Project, ".opencode/skill"), sk(Project, ".opencode/skills")),
		sk(Home, ".opencode/skill"),
		sk(Home, ".opencode/skills"),
		sk(Config, "skill"),
		sk(Config, "skills"),
		dyn(Skills, DynOpenCodeProjectShared, sk(Project, ".claude/skills"), sk(Project, ".agents/skills")),
		sk(Home, ".claude/skills"),
		sk(Home, ".agents/skills"),
	}},
	{Name: "kiro", ConfigRel: ".kiro", Actor: true},
	{Name: "amp", ConfigRel: ".config/amp", Actor: true, Entries: []Entry{
		dyn(Skills, DynAmpSkills,
			sk(Home, ".config/agents/skills"),
			sk(Home, ".agents/skills"),
			sk(Home, ".config/amp/skills"),
			sk(Project, ".agents/skills"),
			sk(Project, ".claude/skills"),
			sk(Home, ".claude/skills"),
		),
		pl(Home, ".config/amp/plugins"),
		pl(Project, ".amp/plugins"),
	}},
	{Name: "antigravity", ConfigRel: ".gemini/antigravity-cli", Actor: true, Entries: []Entry{
		sk(Home, ".gemini/config/skills"),
		sk(Project, ".agents/skills"),
		sk(Project, ".agent/skills"),
		pl(Home, ".gemini/config/plugins"),
		pl(Home, ".gemini/antigravity-cli/plugins"),
		pl(Project, ".agents/plugins"),
		pl(Project, "_agents/plugins"),
	}},
	{Name: "copilot", ConfigRel: ".copilot", Actor: true, Entries: []Entry{
		sk(Home, ".copilot/skills"),
		sk(Project, ".github/skills"),
		sk(Project, ".agents/skills"),
	}},
}

// Lookup returns the row of a connector (already normalized, such as
// "claudecode").
func Lookup(name string) (Connector, bool) {
	for _, c := range table {
		if c.Name == name {
			return c, true
		}
	}
	return Connector{}, false
}

// Connectors returns every row, in table order.
func Connectors() []Connector {
	return append([]Connector(nil), table...)
}

// Inputs are what the laptop resolves a row against.
type Inputs struct {
	Home       string
	Cwd        string // "" drops Project entries
	ConfigHome string
	GOOS       string
	// Dynamic resolves a Dynamic entry's key; nil drops Dynamic entries.
	Dynamic func(key string) []string
}

// Dirs returns the laptop folders of a connector for the given kinds, in
// table order, without empty names or duplicates. Unknown connectors and
// NeedConfig connectors without a config home return nil.
func Dirs(name string, in Inputs, kinds ...Kind) []string {
	c, ok := Lookup(name)
	if !ok || (c.NeedConfig && strings.TrimSpace(in.ConfigHome) == "") {
		return nil
	}
	var out []string
	for _, e := range c.Entries {
		if e.Scope == ActorOnly || !hasKind(kinds, e.Kind) || (e.UnixOnly && in.GOOS == "windows") {
			continue
		}
		switch e.Base {
		case Home:
			out = append(out, filepath.Join(in.Home, filepath.FromSlash(e.Rel)))
		case Project:
			if strings.TrimSpace(in.Cwd) != "" {
				out = append(out, filepath.Join(strings.TrimSpace(in.Cwd), filepath.FromSlash(e.Rel)))
			}
		case Config:
			out = append(out, filepath.Join(in.ConfigHome, filepath.FromSlash(e.Rel)))
		case Abs:
			out = append(out, filepath.FromSlash(e.Rel))
		case Dynamic:
			if in.Dynamic != nil {
				out = append(out, in.Dynamic(e.Rel)...)
			}
		}
	}
	return dedup(out)
}

// ActorEntry is one folder of the actor's view, with Dynamic entries
// replaced by their stand-ins.
type ActorEntry struct {
	Connector string
	Kind      Kind
	Base      Base // Home, Project, Config or Abs
	Rel       string
	ConfigRel string // the row's ConfigRel (Config entries)
	ConfigEnv string // the row's ConfigEnv (Config entries)
}

// ActorEntries returns the actor's view of the table: every Actor row's
// entries that are not LaptopOnly, Dynamic ones replaced by their stand-ins,
// in table order.
func ActorEntries() []ActorEntry {
	var out []ActorEntry
	for _, c := range table {
		if !c.Actor {
			continue
		}
		var add func(e Entry)
		add = func(e Entry) {
			if e.Scope == LaptopOnly {
				return
			}
			if e.Base == Dynamic {
				for _, s := range e.Stand {
					add(s)
				}
				return
			}
			out = append(out, ActorEntry{Connector: c.Name, Kind: e.Kind, Base: e.Base, Rel: e.Rel, ConfigRel: c.ConfigRel, ConfigEnv: c.ConfigEnv})
		}
		for _, e := range c.Entries {
			add(e)
		}
	}
	return out
}

// HomeRel returns an actor entry's path relative to the home folder for
// Home and default-Config entries, the absolute path for Abs entries, and
// the project-relative path for Project entries (all slash-separated).
func (e ActorEntry) HomeRel() string {
	if e.Base == Config {
		return path.Join(e.ConfigRel, e.Rel)
	}
	return e.Rel
}

// configHomeExtra is the XDG-style config home of agents that are not rows
// here; the gateway regex has always matched .config/<name>/skills.
const configHomeExtra = `\.config/[a-z]+/skills`

// SkillRootPattern is the regexp alternation (no group) of the actor's
// skill roots, as a path suffix: <root>/<skill>/... in the gateway's
// skillRootRE. Plugin rows add <plugins>/.+?/skills. Commands are left out
// (single files, not skill folders).
func SkillRootPattern() string {
	seen := map[string]bool{}
	var alts []string
	addAlt := func(a string) {
		if !seen[a] {
			seen[a] = true
			alts = append(alts, a)
		}
	}
	for _, e := range ActorEntries() {
		rel := strings.TrimPrefix(e.HomeRel(), "/")
		switch e.Kind {
		case Skills:
			addAlt(regexp.QuoteMeta(rel))
		case Plugins:
			addAlt(regexp.QuoteMeta(rel) + `/.+?/skills`)
		}
	}
	addAlt(configHomeExtra)
	return strings.Join(alts, "|")
}

// SkillCommandPattern is the regexp alternation (no group) of the actor's
// skill roots that a shell command may name (skills folders only; plugins
// are installed by their CLIs, which the MCP and plugin checks see).
func SkillCommandPattern() string {
	seen := map[string]bool{}
	var alts []string
	for _, e := range ActorEntries() {
		if e.Kind != Skills {
			continue
		}
		a := regexp.QuoteMeta(strings.TrimPrefix(e.HomeRel(), "/"))
		if !seen[a] {
			seen[a] = true
			alts = append(alts, a)
		}
	}
	return strings.Join(alts, "|")
}

func hasKind(kinds []Kind, k Kind) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

func dedup(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
