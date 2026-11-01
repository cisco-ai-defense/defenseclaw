// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// PermissionToolArgs projects the toolInput of Copilot CLI's native
// PermissionRequest hook onto the arguments PreToolUse judges for the same
// call. An edit carries a single-file diff instead of its call arguments
// (PermissionEditArgs). Every other tool carries its call arguments as
// PreToolUse's toolArgs does, the bash and powershell shells
// {"command": ...} included, so it takes the CLI projection (CLIToolArgs).
// A value neither reads has no arguments (nil), and the gateway refuses the
// call as unverified (TOOL-ARGS-UNVERIFIED for a shell, an unproven write).
func PermissionToolArgs(toolName string, value any) json.RawMessage {
	if toolName == "edit" {
		return PermissionEditArgs(toolName, value)
	}
	return CLIToolArgs(toolName, value)
}

var permissionEditHunk = lazyregexp.New(`^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@(?: .*)?$`)

// PermissionEditArgs projects Copilot CLI's native PermissionRequest edit
// input onto the same reviewed edit call as PreToolUse. The diff must prove
// that every hunk changes the one declared file. Unknown metadata, another
// file, or an incomplete hunk leaves the call unproven.
func PermissionEditArgs(toolName string, value any) json.RawMessage {
	if toolName != "edit" {
		return nil
	}
	input, ok := value.(map[string]any)
	if !ok || !onlyKeys(input, "file_path", "diff") || len(input) != 2 {
		return nil
	}
	path, pathOK := input["file_path"].(string)
	diff, diffOK := input["diff"].(string)
	if !pathOK || !diffOK || strings.TrimSpace(path) != path || path == "" ||
		strings.ContainsAny(path, "\r\n\x00") || len(diff) > 1<<20 {
		return nil
	}
	oldText, newText, ok := permissionEditDiff(path, diff)
	if !ok {
		return nil
	}
	args, err := json.Marshal(map[string]string{"path": path, "old_str": oldText, "new_str": newText})
	if err != nil {
		return nil
	}
	return args
}

func permissionEditDiff(path, diff string) (string, string, bool) {
	diff = strings.ReplaceAll(diff, "\r\n", "\n")
	if strings.ContainsRune(diff, '\r') {
		return "", "", false
	}
	diff = strings.TrimLeft(diff, "\n")
	// Native Copilot diffs may end with more than one bare separator newline;
	// blank content lines still carry their '+' prefix and remain intact.
	diff = strings.TrimRight(diff, "\n")
	lines := strings.Split(diff, "\n")
	if len(lines) < 5 {
		return "", "", false
	}
	gitPath := strings.ReplaceAll(path, "\\", "/")
	if !strings.HasPrefix(gitPath, "/") {
		gitPath = "/" + gitPath
	}
	aPath, bPath := "a"+gitPath, "b"+gitPath
	if lines[0] != "diff --git "+aPath+" "+bPath {
		return "", "", false
	}
	i := 1
	created := false
	if lines[i] == "create file mode 100644" || lines[i] == "create file mode 100755" ||
		lines[i] == "new file mode 100644" || lines[i] == "new file mode 100755" {
		created = true
		i++
	}
	if i >= len(lines) {
		return "", "", false
	}
	if strings.HasPrefix(lines[i], "index ") {
		i++
	}
	oldPath := aPath
	if created {
		oldPath = "a/dev/null"
	}
	if i+2 >= len(lines) || lines[i] != "--- "+oldPath || lines[i+1] != "+++ "+bPath {
		return "", "", false
	}
	i += 2
	var oldLines, newLines []string
	var oldExpected, newExpected, oldSeen, newSeen int
	seenHunk, changed := false, false
	hunks, bodyLines := 0, 0
	for ; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "@@ ") {
			if seenHunk && (oldSeen != oldExpected || newSeen != newExpected) {
				return "", "", false
			}
			counts := permissionEditHunk.FindStringSubmatch(line)
			if counts == nil {
				return "", "", false
			}
			var ok bool
			oldExpected, ok = hunkCount(counts[1])
			if !ok {
				return "", "", false
			}
			newExpected, ok = hunkCount(counts[2])
			if !ok {
				return "", "", false
			}
			oldSeen, newSeen, seenHunk = 0, 0, true
			hunks++
			continue
		}
		if !seenHunk {
			return "", "", false
		}
		bodyLines++
		switch {
		case strings.HasPrefix(line, "-"):
			oldSeen++
			oldLines = append(oldLines, line[1:])
			changed = true
		case strings.HasPrefix(line, "+"):
			newSeen++
			newLines = append(newLines, line[1:])
			changed = true
		case strings.HasPrefix(line, " "):
			oldSeen++
			newSeen++
		case line == `\ No newline at end of file`:
			// This marker describes the preceding line, not another mutation.
		default:
			return "", "", false
		}
		if oldSeen > oldExpected || newSeen > newExpected {
			return "", "", false
		}
	}
	// Copilot CLI asks an edit that changes no line (an apply_patch of
	// context lines only) with one empty "@@ -0,0 +0,0 @@" hunk. It still
	// names its one file: it is that file's edit with no text, judged as a
	// write to it like any edit, never an unread call (GAP-1832).
	noChange := hunks == 1 && bodyLines == 0 && oldExpected == 0 && newExpected == 0 && !created
	if !seenHunk || !changed && !noChange || oldSeen != oldExpected || newSeen != newExpected ||
		created && len(oldLines) != 0 {
		return "", "", false
	}
	return strings.Join(oldLines, "\n"), strings.Join(newLines, "\n"), true
}

func hunkCount(raw string) (int, bool) {
	if raw == "" {
		return 1, true
	}
	count, err := strconv.Atoi(raw)
	return count, err == nil
}
