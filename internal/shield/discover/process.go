package discover

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

type AgentInfo struct {
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	AgentType   string `json:"agent_type"`
	BinaryPath  string `json:"binary_path,omitempty"`
}

var knownAgents = map[string]string{
	"claude":       "claude-code",
	"codex":        "codex",
	"cursor":       "cursor",
	"node":         "node-agent",
	"python":       "python-agent",
	"python3":      "python-agent",
	"devin":        "devin",
	"hermes":       "hermes",
	"copilot":      "copilot",
	"openhands":    "openhands",
	"antigravity":  "antigravity",
	"opencode":     "opencode",
	"amp":          "amp",
	"aider":        "aider",
	"continue":     "continue",
	"windsurf":     "windsurf",
	"curl":         "curl",
	"wget":         "wget",
}

func IdentifyProcess(pid int) AgentInfo {
	info := AgentInfo{PID: pid}

	switch runtime.GOOS {
	case "darwin":
		info.BinaryPath = readDarwinExe(pid)
	case "linux":
		info.BinaryPath = readLinuxExe(pid)
	case "windows":
		info.BinaryPath = readWindowsExe(pid)
	}

	info.ProcessName = extractName(info.BinaryPath)
	info.AgentType = classifyAgent(info.ProcessName)
	return info
}

func readDarwinExe(pid int) string {
	// ps -p PID -o comm= gives the binary name on macOS.
	// For POC we read /proc on Linux; macOS needs sysctl approach.
	// Simplified: read from environment passed by the interposition library.
	return os.Getenv("SHIELD_CALLER_EXE")
}

func readLinuxExe(pid int) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return link
}

func readWindowsExe(_ int) string {
	return os.Getenv("SHIELD_CALLER_EXE")
}

func extractName(path string) string {
	if path == "" {
		return "unknown"
	}
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	parts = strings.Split(name, "\\")
	return parts[len(parts)-1]
}

func classifyAgent(processName string) string {
	lower := strings.ToLower(processName)
	for prefix, agentType := range knownAgents {
		if strings.HasPrefix(lower, prefix) {
			return agentType
		}
	}
	return "unknown"
}
