package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultDataPath(t *testing.T) {
	dp := DefaultDataPath()
	if !filepath.IsAbs(dp) {
		t.Errorf("DefaultDataPath() returned non-absolute path: %s", dp)
	}
	if filepath.Base(dp) != DefaultDataDirName {
		t.Errorf("expected base dir %q, got %q", DefaultDataDirName, filepath.Base(dp))
	}
}

func TestConfigPath(t *testing.T) {
	cp := ConfigPath()
	if filepath.Base(cp) != DefaultConfigName {
		t.Errorf("expected config file %q, got %q", DefaultConfigName, filepath.Base(cp))
	}
}

func TestDetectEnvironment(t *testing.T) {
	env := DetectEnvironment()
	switch runtime.GOOS {
	case "darwin":
		if env != EnvMacOS {
			t.Errorf("expected macos on darwin, got %s", env)
		}
	case "linux":
		if env != EnvLinux && env != EnvDGXSpark {
			t.Errorf("expected linux or dgx-spark on linux, got %s", env)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if cfg.DataDir == "" {
		t.Error("DataDir is empty")
	}
	if cfg.Claw.Mode != ClawOpenClaw {
		t.Errorf("expected mode %q, got %q", ClawOpenClaw, cfg.Claw.Mode)
	}
	if cfg.Scanners.SkillScanner.Binary != "skill-scanner" {
		t.Errorf("expected skill-scanner binary, got %q", cfg.Scanners.SkillScanner.Binary)
	}
	if cfg.Gateway.Port != 18789 {
		t.Errorf("expected gateway port 18789, got %d", cfg.Gateway.Port)
	}
	if cfg.Watch.DebounceMs != 500 {
		t.Errorf("expected debounce 500ms, got %d", cfg.Watch.DebounceMs)
	}
}

func TestDefaultSkillActions(t *testing.T) {
	sa := DefaultSkillActions()

	tests := []struct {
		severity string
		file     FileAction
		runtime  RuntimeAction
		install  InstallAction
	}{
		{"CRITICAL", FileActionQuarantine, RuntimeDisable, InstallBlock},
		{"HIGH", FileActionQuarantine, RuntimeDisable, InstallBlock},
		{"MEDIUM", FileActionNone, RuntimeEnable, InstallNone},
		{"LOW", FileActionNone, RuntimeEnable, InstallNone},
		{"INFO", FileActionNone, RuntimeEnable, InstallNone},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			action := sa.ForSeverity(tt.severity)
			if action.File != tt.file {
				t.Errorf("File: got %q, want %q", action.File, tt.file)
			}
			if action.Runtime != tt.runtime {
				t.Errorf("Runtime: got %q, want %q", action.Runtime, tt.runtime)
			}
			if action.Install != tt.install {
				t.Errorf("Install: got %q, want %q", action.Install, tt.install)
			}
		})
	}
}

func TestForSeverity_CaseInsensitive(t *testing.T) {
	sa := DefaultSkillActions()
	got := sa.ForSeverity("critical")
	if got.Install != InstallBlock {
		t.Errorf("expected block for lowercase critical, got %q", got.Install)
	}
}

func TestForSeverity_Unknown(t *testing.T) {
	sa := DefaultSkillActions()
	got := sa.ForSeverity("BOGUS")
	if got.Runtime != RuntimeEnable {
		t.Errorf("expected enable for unknown severity, got %q", got.Runtime)
	}
}

func TestShouldDisable(t *testing.T) {
	sa := DefaultSkillActions()
	if !sa.ShouldDisable("CRITICAL") {
		t.Error("expected ShouldDisable(CRITICAL)=true")
	}
	if sa.ShouldDisable("LOW") {
		t.Error("expected ShouldDisable(LOW)=false")
	}
}

func TestShouldQuarantine(t *testing.T) {
	sa := DefaultSkillActions()
	if !sa.ShouldQuarantine("HIGH") {
		t.Error("expected ShouldQuarantine(HIGH)=true")
	}
	if sa.ShouldQuarantine("MEDIUM") {
		t.Error("expected ShouldQuarantine(MEDIUM)=false")
	}
}

func TestShouldInstallBlock(t *testing.T) {
	sa := DefaultSkillActions()
	if !sa.ShouldInstallBlock("CRITICAL") {
		t.Error("expected ShouldInstallBlock(CRITICAL)=true")
	}
	if sa.ShouldInstallBlock("INFO") {
		t.Error("expected ShouldInstallBlock(INFO)=false")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	sa := DefaultSkillActions()
	if err := sa.Validate(); err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

func TestValidate_InvalidRuntime(t *testing.T) {
	sa := DefaultSkillActions()
	sa.Critical.Runtime = "invalid"
	if err := sa.Validate(); err == nil {
		t.Error("expected Validate() to return error for invalid runtime")
	}
}

func TestValidate_InvalidFile(t *testing.T) {
	sa := DefaultSkillActions()
	sa.High.File = "delete"
	if err := sa.Validate(); err == nil {
		t.Error("expected Validate() to return error for invalid file action")
	}
}

func TestValidate_InvalidInstall(t *testing.T) {
	sa := DefaultSkillActions()
	sa.Medium.Install = "reject"
	if err := sa.Validate(); err == nil {
		t.Error("expected Validate() to return error for invalid install action")
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input string
		want  string
	}{
		{"~/foo", filepath.Join(home, "foo")},
		{"/abs/path", "/abs/path"},
		{"relative", "relative"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := expandPath(tt.input)
			if got != tt.want {
				t.Errorf("expandPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"empty", nil, []string{}},
		{"no dups", []string{"a", "b"}, []string{"a", "b"}},
		{"with dups", []string{"x", "y", "x", "z", "y"}, []string{"x", "y", "z"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedup(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("dedup() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("dedup()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestMCPDirsForMode(t *testing.T) {
	dirs := MCPDirsForMode(ClawOpenClaw, "/tmp/test-oc")
	if len(dirs) != 2 {
		t.Fatalf("expected 2 MCP dirs, got %d", len(dirs))
	}
	if dirs[0] != "/tmp/test-oc/mcp-servers" {
		t.Errorf("dirs[0] = %q, want /tmp/test-oc/mcp-servers", dirs[0])
	}
	if dirs[1] != "/tmp/test-oc/mcps" {
		t.Errorf("dirs[1] = %q, want /tmp/test-oc/mcps", dirs[1])
	}
}

func TestMCPDirsForMode_DefaultHome(t *testing.T) {
	dirs := MCPDirsForMode(ClawOpenClaw, "")
	if len(dirs) != 2 {
		t.Fatalf("expected 2 MCP dirs, got %d", len(dirs))
	}
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			t.Errorf("expected absolute path, got %q", d)
		}
	}
}

func TestSkillDirsForMode_NoOpenclawJSON(t *testing.T) {
	dirs := SkillDirsForMode(ClawOpenClaw, "/tmp/nonexistent-home")
	if len(dirs) == 0 {
		t.Fatal("expected at least one skill dir")
	}
	if dirs[len(dirs)-1] != "/tmp/nonexistent-home/skills" {
		t.Errorf("last dir = %q, want /tmp/nonexistent-home/skills", dirs[len(dirs)-1])
	}
}

func TestSkillDirsForMode_WithOpenclawJSON(t *testing.T) {
	tmpDir := t.TempDir()

	ocConfig := map[string]interface{}{
		"agents": map[string]interface{}{
			"defaults": map[string]interface{}{
				"workspace": tmpDir,
			},
		},
		"skills": map[string]interface{}{
			"load": map[string]interface{}{
				"extraDirs": []string{"/tmp/extra-skills"},
			},
		},
	}

	data, _ := json.Marshal(ocConfig)
	ocPath := filepath.Join(tmpDir, "openclaw.json")
	if err := os.WriteFile(ocPath, data, 0o644); err != nil {
		t.Fatalf("write openclaw.json: %v", err)
	}

	dirs := SkillDirsForMode(ClawOpenClaw, tmpDir)

	found := false
	for _, d := range dirs {
		if d == "/tmp/extra-skills" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /tmp/extra-skills in dirs: %v", dirs)
	}

	wsSkills := filepath.Join(tmpDir, "skills")
	foundWs := false
	for _, d := range dirs {
		if d == wsSkills {
			foundWs = true
			break
		}
	}
	if !foundWs {
		t.Errorf("expected workspace/skills %q in dirs: %v", wsSkills, dirs)
	}
}

func TestConfig_MCPDirs(t *testing.T) {
	cfg := &Config{
		Claw: ClawConfig{
			HomeDir: "/tmp/test-home",
		},
	}
	dirs := cfg.MCPDirs()
	if len(dirs) != 2 {
		t.Fatalf("expected 2 dirs, got %d", len(dirs))
	}
}

func TestConfig_InstalledSkillCandidates(t *testing.T) {
	cfg := &Config{
		Claw: ClawConfig{
			HomeDir:    "/tmp/test-home",
			ConfigFile: "/tmp/nonexistent/openclaw.json",
		},
	}

	tests := []struct {
		name string
		want string
	}{
		{"my-skill", "my-skill"},
		{"@org/my-skill", "my-skill"},
		{"scope/sub-skill", "sub-skill"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := cfg.InstalledSkillCandidates(tt.name)
			if len(candidates) == 0 {
				t.Fatal("expected at least one candidate")
			}
			for _, c := range candidates {
				if filepath.Base(c) != tt.want {
					t.Errorf("candidate base = %q, want %q", filepath.Base(c), tt.want)
				}
			}
		})
	}
}

func TestConfig_ClawHomeDir(t *testing.T) {
	cfg := &Config{
		Claw: ClawConfig{HomeDir: "/tmp/my-claw"},
	}
	if cfg.ClawHomeDir() != "/tmp/my-claw" {
		t.Errorf("ClawHomeDir() = %q, want /tmp/my-claw", cfg.ClawHomeDir())
	}
}

func TestConfig_Save(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultConfig()
	cfg.DataDir = tmpDir

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}

	configFile := filepath.Join(tmpDir, DefaultConfigName)
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Error("config file was not created")
	}
}
