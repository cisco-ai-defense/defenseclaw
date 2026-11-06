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

	"github.com/defenseclaw/defenseclaw/internal/winowner"
)

// CoworkSubcommand is the account plugin's native Windows entrypoint. Paths
// stay separate arguments and are never passed through a command processor.
const CoworkSubcommand = "cowork-guard"

const CoworkRemovalMarkerSuffix = ".cowork-uninstalled"

const CoworkUninstalledMessage = "DefenseClaw was uninstalled for this user. Remove the DefenseClaw plugin in Claude Desktop under Customize > Plugins."

// CoworkMarkerRefusedMessage follows the launcher sentence when the launcher
// cannot start and the removal marker is there, with DefenseClaw's records
// gone, but is not trusted (cowork-1-0-8 GAP-0085): the plugin keeps blocking
// until one of the two steps it names is taken.
const CoworkMarkerRefusedMessage = "DefenseClaw's removal record for this user is not trusted, so the DefenseClaw plugin keeps blocking. " +
	"Remove the DefenseClaw plugin in Claude Desktop under Customize > Plugins, or run the DefenseClaw installer again."

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

// coworkOwnersTrusted applies the Windows owner trust set to the removal
// marker and the folder that holds it (cowork-1-0-8 GAP-0085). The uninstall
// writes no marker into a folder whose owner is outside the set, and the
// guard ignores one found there: whoever owns a folder controls it, and could
// otherwise rename the data folder away and leave a marker so that Cowork
// looked uninstalled. A marker another account planted is owned by that
// account (an account cannot give a file it creates to someone else), so it
// is ignored too, and the guard keeps running the installed launcher. On
// Windows coworkMarkerTrusted also refuses a folder others may write and a
// marker with more than one link.
func coworkOwnersTrusted(markerOwner, folderOwner, current string) bool {
	return winowner.Trusted(markerOwner, current) && winowner.Trusted(folderOwner, current)
}

// coworkRemovalState reports whether the removal is complete: the marker is
// a trusted regular file and every installed record is gone. refused is set
// when the records are gone and something is at the marker path that is not
// honoured.
func coworkRemovalState(dataDir string) (complete, refused bool) {
	marker, installed := CoworkRemovalPaths(dataDir)
	info, err := os.Lstat(marker)
	if err != nil {
		return false, false
	}
	for _, path := range installed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return false, false
		}
	}
	if !info.Mode().IsRegular() || !coworkMarkerTrusted(marker) {
		return false, true
	}
	return true, false
}

// RunCowork uses filesystem calls for the account-removal check, then runs
// the installed launcher with the ordinary Claude Code hook argv. A missing
// or failed launcher remains a blocking hook result while installed, and
// after a refused marker it also prints CoworkMarkerRefusedMessage.
func RunCowork(dataDir, launcher, event string, stdin io.Reader, stdout, stderr io.Writer) int {
	complete, refused := coworkRemovalState(dataDir)
	if !complete {
		code, started := run(launcher, []string{"hook", "--connector", "claudecode"}, event, stdin, stdout, stderr)
		if !started && refused {
			fmt.Fprintln(stderr, CoworkMarkerRefusedMessage)
		}
		return code
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
