package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// openclawConfig represents the structure of openclaw.json.
type openclawConfig struct {
	Agents struct {
		Defaults struct {
			Workspace string `json:"workspace"`
		} `json:"defaults"`
	} `json:"agents"`
	Skills struct {
		Load struct {
			ExtraDirs []string `json:"extraDirs"`
		} `json:"load"`
	} `json:"skills"`
}

// expandPath expands ~ to home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, path[2:])
		}
	}
	return path
}

// readOpenclawConfig reads and parses the openclaw.json config file.
func readOpenclawConfig(configFile string) (*openclawConfig, error) {
	path := expandPath(configFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var oc openclawConfig
	if err := json.Unmarshal(data, &oc); err != nil {
		return nil, err
	}
	return &oc, nil
}

// SkillDirs returns the skill directories for the active claw mode.
// Order: workspace/skills → extraDirs from openclaw.json → home_dir/skills
func (c *Config) SkillDirs() []string {
	homeDir := expandPath(c.Claw.HomeDir)
	var dirs []string

	// Read openclaw.json for workspace and extraDirs
	if oc, err := readOpenclawConfig(c.Claw.ConfigFile); err == nil {
		// Workspace skills
		if oc.Agents.Defaults.Workspace != "" {
			ws := expandPath(oc.Agents.Defaults.Workspace)
			dirs = append(dirs, filepath.Join(ws, "skills"))
		}

		// Extra skill directories
		for _, d := range oc.Skills.Load.ExtraDirs {
			dirs = append(dirs, expandPath(d))
		}
	}

	// Global skills in home_dir
	dirs = append(dirs, filepath.Join(homeDir, "skills"))

	return dedup(dirs)
}

// MCPDirs returns the MCP directories for the active claw mode.
func (c *Config) MCPDirs() []string {
	homeDir := expandPath(c.Claw.HomeDir)
	return []string{
		filepath.Join(homeDir, "mcp-servers"),
		filepath.Join(homeDir, "mcps"),
	}
}

// InstalledSkillCandidates returns possible on-disk paths for a named skill,
// ordered by the claw mode's resolution priority.
func (c *Config) InstalledSkillCandidates(skillName string) []string {
	name := skillName
	if strings.Contains(name, "/") {
		parts := strings.SplitN(name, "/", 2)
		name = parts[len(parts)-1]
	}
	name = strings.TrimPrefix(name, "@")

	dirs := c.SkillDirs()
	candidates := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	return candidates
}

// ClawHomeDir returns the resolved home directory for the active claw framework.
func (c *Config) ClawHomeDir() string {
	return expandPath(c.Claw.HomeDir)
}

// dedup removes duplicate paths while preserving order.
func dedup(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// SkillDirsForMode returns skill directories for a given mode.
// Used when config is not yet available.
func SkillDirsForMode(mode ClawMode, homeDir string) []string {
	if homeDir == "" {
		homeDir = "~/.openclaw"
	}
	homeDir = expandPath(homeDir)

	configFile := filepath.Join(homeDir, "openclaw.json")
	var dirs []string

	if oc, err := readOpenclawConfig(configFile); err == nil {
		if oc.Agents.Defaults.Workspace != "" {
			ws := expandPath(oc.Agents.Defaults.Workspace)
			dirs = append(dirs, filepath.Join(ws, "skills"))
		}
		for _, d := range oc.Skills.Load.ExtraDirs {
			dirs = append(dirs, expandPath(d))
		}
	}

	dirs = append(dirs, filepath.Join(homeDir, "skills"))
	return dedup(dirs)
}

// MCPDirsForMode returns MCP directories for a given mode.
// Used when config is not yet available.
func MCPDirsForMode(mode ClawMode, homeDir string) []string {
	if homeDir == "" {
		homeDir = "~/.openclaw"
	}
	homeDir = expandPath(homeDir)

	return []string{
		filepath.Join(homeDir, "mcp-servers"),
		filepath.Join(homeDir, "mcps"),
	}
}
