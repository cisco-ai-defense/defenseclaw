// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// accountAgentProcessMayRun reports whether a running process of the account
// that owns dataDir, other than this one, names agent in its command line
// (Linux /proc). Anything it cannot read counts as a process that may run it.
func accountAgentProcessMayRun(dataDir, agent string) bool {
	info, err := os.Lstat(dataDir)
	if err != nil {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true
	}
	agent = strings.ToLower(agent)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		process, err := os.Lstat(dir)
		if err != nil {
			continue // it ended
		}
		if owner, ok := process.Sys().(*syscall.Stat_t); !ok || owner.Uid != stat.Uid {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return true
		}
		// The setup-remove command also names the agent. It is not an
		// agent process; all other uncertain matches keep the tombstone.
		if bytes.Contains(bytes.ToLower(cmdline), []byte(agent)) &&
			!isConnectorRemovalProcess(cmdline, agent) {
			return true
		}
	}
	return false
}

func isConnectorRemovalProcess(cmdline []byte, agent string) bool {
	args := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(args) < 3 {
		return false
	}
	program := 0
	image := strings.ToLower(filepath.Base(string(args[0])))
	if image == "sh" || image == "bash" || image == "dash" || image == "zsh" {
		option := string(args[1])
		if strings.HasPrefix(option, "-") && strings.Contains(option, "c") {
			for _, extra := range args[3:] {
				if bytes.Contains(bytes.ToLower(extra), []byte(agent)) {
					return false
				}
			}
			if isShellConnectorRemovalCommand(string(args[2]), agent) {
				return true
			}
		}
	}
	if image == "python" || strings.HasPrefix(image, "python3") ||
		image == "sh" || image == "bash" {
		if len(args) > 4 && string(args[1]) == "-m" && string(args[2]) == "defenseclaw" {
			program = 2
		} else if len(args) > 4 && filepath.Base(string(args[1])) == "defenseclaw" {
			program = 1
		} else {
			return false
		}
	} else if image != "defenseclaw" {
		return false
	}
	return len(args) > program+3 && string(args[program+1]) == "setup" &&
		string(args[program+2]) == "remove" && strings.EqualFold(string(args[program+3]), agent)
}

// A shell retained after a completed setup removal still has the connector
// name in its -c argument. Other mentions keep the hook for a possible agent.
func isShellConnectorRemovalCommand(command, agent string) bool {
	if strings.Contains(command, "$(") || strings.Contains(command, "`") || strings.Contains(command, "<<") {
		return false
	}
	segments, ok := splitSimpleShellCommands(command)
	if !ok {
		return false
	}
	found := false
	for _, segment := range segments {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		if len(fields) >= 4 && strings.ToLower(filepath.Base(strings.Trim(fields[0], "\"'"))) == "defenseclaw" &&
			fields[1] == "setup" && fields[2] == "remove" &&
			strings.EqualFold(strings.Trim(fields[3], "\"'"), agent) &&
			!strings.Contains(strings.ToLower(strings.Join(fields[4:], " ")), agent) {
			found = true
			continue
		}
		if strings.Contains(strings.ToLower(segment), agent) {
			return false
		}
		switch fields[0] {
		case ":", "cd", "echo", "export", "false", "printf", "pwd", "set", "sleep", "true", "unset", "wait":
		default:
			return false
		}
	}
	return found
}

// splitSimpleShellCommands keeps quoted and escaped separators in the same
// command. An incomplete command stays uncertain.
func splitSimpleShellCommands(command string) ([]string, bool) {
	var segments []string
	var current strings.Builder
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		char := command[i]
		if escaped {
			current.WriteByte(char)
			escaped = false
			continue
		}
		if char == '\\' && quote != '\'' {
			current.WriteByte(char)
			escaped = true
			continue
		}
		if char == '\'' || char == '"' {
			if quote == 0 {
				quote = char
			} else if quote == char {
				quote = 0
			}
		}
		if quote == 0 && (char == ';' || char == '&' || char == '|' || char == '\n') {
			segments = append(segments, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(char)
	}
	if quote != 0 || escaped {
		return nil, false
	}
	return append(segments, current.String()), true
}
