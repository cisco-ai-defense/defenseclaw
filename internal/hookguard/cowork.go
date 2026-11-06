// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CoworkSubcommand is the account plugin's native Windows entrypoint. Paths
// stay separate arguments and are never passed through a command processor.
const CoworkSubcommand = "cowork-guard"

const CoworkRemovalMarkerSuffix = ".cowork-uninstalled"

const CoworkUninstalledMessage = "DefenseClaw was uninstalled for this user. Remove the DefenseClaw plugin in Claude Desktop under Customize > Plugins."

var coworkEvents = map[string]bool{
	"SessionStart": true, "UserPromptSubmit": true, "PreToolUse": true,
	"PermissionRequest": true, "PostToolUse": true, "PostToolUseFailure": true,
	"SubagentStart": true, "SubagentStop": true, "Stop": true, "SessionEnd": true,
}

// CoworkArgv accepts only the plugin's fixed Claude Code hook invocation.
func CoworkArgv(args []string) (dataDir, launcher, event string, ok bool) {
	if len(args) != 4 || args[0] != CoworkSubcommand || !coworkEvents[args[3]] ||
		!filepath.IsAbs(args[1]) || !AbsoluteHookExecutable(args[2]) ||
		strings.TrimSpace(args[1]) != args[1] || strings.TrimSpace(args[2]) != args[2] {
		return "", "", "", false
	}
	return args[1], args[2], args[3], true
}

// CoworkRemovalPaths names the completed-removal marker and records that
// must be gone before an account plugin can stop calling its installed hook.
func CoworkRemovalPaths(dataDir string) (string, []string) {
	return filepath.Clean(dataDir) + CoworkRemovalMarkerSuffix, []string{
		filepath.Join(dataDir, "config.yaml"),
		filepath.Join(dataDir, "hook_contract_lock.json"),
		filepath.Join(dataDir, "cowork", "plugin-state.json"),
		filepath.Join(dataDir, "gateway.pid"),
		filepath.Join(dataDir, "gateway-api.json"),
	}
}

func CoworkUninstalledJSON(event string, notice bool) string {
	message := map[string]interface{}{}
	if notice {
		message["systemMessage"] = CoworkUninstalledMessage
	}
	if event == "UserPromptSubmit" {
		message["hookSpecificOutput"] = map[string]string{
			"hookEventName": "UserPromptSubmit", "additionalContext": CoworkUninstalledMessage,
		}
	}
	data, _ := json.Marshal(message) // All values are static strings.
	return string(data)
}

func coworkRemovalComplete(dataDir string) bool {
	marker, installed := CoworkRemovalPaths(dataDir)
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	for _, path := range installed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// RunCowork uses filesystem calls for the account-removal check, then runs
// the installed launcher with the ordinary Claude Code hook argv. A missing
// or failed launcher remains a blocking hook result while installed.
func RunCowork(dataDir, launcher, event string, stdin io.Reader, stdout, stderr io.Writer) int {
	if !coworkRemovalComplete(dataDir) {
		return Run(launcher, []string{"hook", "--connector", "claudecode"}, stdin, stdout, stderr)
	}
	marker, _ := CoworkRemovalPaths(dataDir)
	if event == "UserPromptSubmit" {
		if err := os.Mkdir(marker+".context", 0o700); err != nil {
			return 0
		}
		_, noticeErr := os.Stat(marker + ".notice")
		if errors.Is(noticeErr, os.ErrNotExist) {
			if err := os.Mkdir(marker+".notice", 0o700); err == nil {
				fmt.Fprintln(stdout, CoworkUninstalledJSON(event, true))
				return 0
			}
		}
		fmt.Fprintln(stdout, CoworkUninstalledJSON(event, false))
		return 0
	}
	if err := os.Mkdir(marker+".notice", 0o700); err == nil {
		fmt.Fprintln(stdout, CoworkUninstalledJSON(event, true))
	}
	return 0
}
