package agentpaths

import (
	"path"
	"path/filepath"
	"regexp"
	"testing"
)

func TestDirsLaptopOrderAndScopes(t *testing.T) {
	in := Inputs{Home: "/h", Cwd: "/w", ConfigHome: "/cfg", GOOS: "linux", Dynamic: func(k string) []string {
		if k == DynClaudeProjectSkills {
			// The real provider (claudecodepath.ProjectSkillDirs) joins with
			// filepath, so its folders are OS-native; Dirs does not rewrite them.
			return []string{filepath.FromSlash("/w/.claude/skills"), filepath.FromSlash("/w/sub/.claude/skills")}
		}
		return nil
	}}
	got := Dirs("claudecode", in, Skills, Commands)
	want := []string{"/cfg/skills", "/cfg/commands", "/w/.claude/commands", "/w/.claude/skills", "/w/sub/.claude/skills"}
	if len(got) != len(want) {
		t.Fatalf("claudecode skills = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != filepath.FromSlash(want[i]) {
			t.Fatalf("claudecode skills = %v, want %v", got, want)
		}
	}
	// ActorOnly ./.claude/plugins never reaches the laptop list.
	for _, d := range Dirs("claudecode", in, Plugins) {
		if d == filepath.FromSlash("/w/.claude/plugins") {
			t.Fatalf("actor-only entry in laptop plugins: %v", d)
		}
	}
	// /etc/codex/skills is Unix-only; Devin needs a config home.
	in.GOOS = "windows"
	for _, d := range Dirs("codex", in, Skills) {
		if d == filepath.FromSlash("/etc/codex/skills") {
			t.Fatal("/etc/codex/skills on windows")
		}
	}
	if got := Dirs("devin", Inputs{Home: "/h", Cwd: "/w"}, Skills); got != nil {
		t.Fatalf("devin without config home = %v", got)
	}
	if got := Dirs("kiro", in, Skills, Plugins); got != nil {
		t.Fatalf("kiro = %v", got)
	}
	if got := Dirs("nope", in, Skills); got != nil {
		t.Fatalf("unknown = %v", got)
	}
}

func rootRE() *regexp.Regexp {
	return regexp.MustCompile(`(?:^|/)(?:` + SkillRootPattern() + `)/([^/]+)(?:/(.*))?$`)
}

// The gateway regex built from the table stays a superset of the 1.0.10
// hand-written one (no weaker than the parent) and matches every actor root.
func TestSkillRootPatternCoversParentAndTable(t *testing.T) {
	re := rootRE()
	parent := []string{
		"/home/u/.claude/skills/x/SKILL.md",
		"/home/u/.codex/skills/x/SKILL.md",
		"/w/.agents/skills/x/SKILL.md",
		"/home/u/.config/anything/skills/x/SKILL.md",
		"/home/u/.claude/plugins/cache/m/p/1.0.0/skills/x/SKILL.md",
		"/w/.claude/plugins/p/skills/x/SKILL.md",
		"/home/u/.codex/plugins/cache/m/p/skills/x/SKILL.md",
	}
	for _, p := range parent {
		if m := re.FindStringSubmatch(p); m == nil || m[1] != "x" {
			t.Errorf("parent path %s: %v", p, m)
		}
	}
	for _, e := range ActorEntries() {
		if e.Kind == Commands {
			continue
		}
		root := e.HomeRel()
		if e.Kind == Plugins {
			root = path.Join(root, "p", "skills")
		}
		base := "/home/u"
		if e.Base == Abs {
			base = ""
		}
		p := path.Join(base, root, "x", "SKILL.md")
		if m := re.FindStringSubmatch(p); m == nil || m[1] != "x" || m[2] != "SKILL.md" {
			t.Errorf("%s %s: %s not matched (%v)", e.Connector, e.Rel, p, m)
		}
	}
	cmdRE := regexp.MustCompile(`(\S*(?:` + SkillCommandPattern() + `)/[A-Za-z0-9._\-]+)(?:/(\S*))?`)
	for _, c := range []string{"mkdir -p ~/.claude/skills/x", "cat > .codex/skills/x/SKILL.md", "cp -r a .agents/skills/x", "cp -r a .cursor/skills/x", "tee .github/skills/x/SKILL.md"} {
		if m := cmdRE.FindStringSubmatch(c); m == nil || path.Base(m[1]) != "x" {
			t.Errorf("command %q: %v", c, m)
		}
	}
}

func TestEveryActorRowHasSkillRoots(t *testing.T) {
	has := map[string]bool{}
	for _, e := range ActorEntries() {
		if e.Kind == Skills {
			has[e.Connector] = true
		}
	}
	for _, c := range Connectors() {
		if c.Actor && c.Name != "kiro" && !has[c.Name] {
			t.Errorf("actor row %s has no skill roots", c.Name)
		}
	}
}
