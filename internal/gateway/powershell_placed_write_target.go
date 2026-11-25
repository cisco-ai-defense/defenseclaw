// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// powerShellReadingPlacesEveryWrite reports a managed Copilot CLI powershell
// call, read POSIX only because the Windows hook placed it in no dialect
// (selectWindowsShellDialectReading), whose PowerShell reading reads every
// write the POSIX reading reads and places each in an ordinary file, one of
// them named as target is. Copilot runs the call in PowerShell, so the POSIX
// reading of a Windows path is an inference: `cd C:\x` reads as the folder
// C:x under the hook's folder, a name Windows rejects, so the managed hook
// client answers the write after it (C:x\notes.txt) empty, and the managed
// gateway judged that answer an unresolved key write and blocked a
// project-file append (rel-1-0-10:GAP-1157). Such an empty answer proves no
// possible key write when the PowerShell reading places the same write in
// each folder the shell may stand in (the moved one and the one a failed move
// leaves, GAP-1150) and none of them is a protected file.
//
// It answers false, and the empty answer keeps its block, unless every
// condition holds: the PowerShell reading is the same statements (one command
// for each POSIX command, the same program), read with nothing skipped; each
// POSIX command that writes has a PowerShell command that writes; every write
// of the PowerShell reading is static and ordinary
// (powerShellOrdinaryPlacement: never a key file, the DefenseClaw state, a
// credential, a hook configuration, a startup file, another account's home
// or a system folder); and the base name of target is the base name of one of
// those writes. Claude Code and Codex judge their empty answers by the shell
// reading (scopedClientEvidence) and the other routes keep their answer, so
// only this one Copilot route changes (DET111 ruling 2026-11-24, option B).
func powerShellReadingPlacesEveryWrite(request trustedActionRequest, posix actionfacts.Facts, target string,
	isProtected func(string) bool) bool {
	tool := strings.TrimSpace(request.Input.Tool)
	if request.Connector != "copilot" || !request.ProtectedHomeHook ||
		!strings.EqualFold(tool, "shell") && !strings.EqualFold(tool, "powershell") {
		return false
	}
	// The command-only reading of Copilot's explicit powershell tool can
	// arrive without the dialect selector's cached reading. Rebuild both
	// bounded readings of that same call; a generic shell without the
	// cache has no proved PowerShell runtime (GAP-1157).
	uncached := request.windowsPowerShellReading == nil
	if uncached && (!strings.EqualFold(tool, "powershell") ||
		request.simpleCommandPass || request.readingTwin) {
		return false
	}
	// A simple-command pass sees only the write statement, without the cd
	// that places it. A reading twin sees the PowerShell reading instead of
	// the original POSIX reading. In both cases compare the *whole* original
	// call, so neither can clear an answer for a write it has not read.
	whole := request.Input
	switch {
	case request.simpleCommandPass:
		if request.parentPatch == nil || request.parentPatch.Command == "" {
			return false
		}
		whole = *request.parentPatch
	case request.readingTwin:
		if request.Input.DialectHint != actionfacts.DialectPowerShell ||
			request.Input.Command != request.windowsPowerShellReading.input.Command {
			return false
		}
	case request.windowsDialectReadings && request.Input.DialectHint == "":
		// The call's own unhinted reading is the inferred POSIX one.
	default:
		return false
	}
	whole.DialectHint = actionfacts.DialectPOSIX
	if request.simpleCommandPass || request.readingTwin || uncached {
		posix = actionfacts.Analyze(whole)
	}
	if posix.Parse.Dialect != actionfacts.DialectPOSIX || posix.Parse.Unread ||
		posix.Parse.Status != actionfacts.StatusComplete && posix.Parse.Status != actionfacts.StatusPartial {
		return false
	}
	whole.DialectHint = actionfacts.DialectPowerShell
	reading := actionfacts.Facts{}
	if uncached {
		reading = actionfacts.Analyze(whole)
	} else {
		reading = request.windowsPowerShellReading.factsFor(whole)
	}
	if reading.Parse.Dialect != actionfacts.DialectPowerShell || reading.Parse.Unread ||
		reading.Parse.Status != actionfacts.StatusComplete && reading.Parse.Status != actionfacts.StatusPartial ||
		len(reading.Commands) == 0 || len(reading.Commands) != len(posix.Commands) {
		return false
	}
	posixWrites, readingWrites := placedWritesByCommand(posix), placedWritesByCommand(reading)
	home := reading.ActiveHome
	if home == "" {
		home = posix.ActiveHome
	}
	base := placedWriteBase(target)
	named := false
	for index, command := range reading.Commands {
		other := posix.Commands[index]
		if !strings.EqualFold(command.Program, other.Program) {
			return false
		}
		for _, write := range posixWrites[other.ID] {
			matched := false
			for _, placed := range readingWrites[command.ID] {
				if write.Access == placed.Access &&
					placedWriteBase(write.Value) == placedWriteBase(placed.Value) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		for _, write := range readingWrites[command.ID] {
			placed := write.Resolved
			if !powerShellOrdinaryPlacement(placed, home) || isProtected(placed) {
				return false
			}
			named = named || base != "" && placedWriteBase(placed) == base
		}
	}
	return named
}

// placedWritesByCommand is the path facts of facts that change a file, by
// the id of their command.
func placedWritesByCommand(facts actionfacts.Facts) map[int64][]actionfacts.PathFact {
	writes := map[int64][]actionfacts.PathFact{}
	for _, fact := range facts.Paths {
		switch fact.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete,
			actionfacts.PathAccessMetadata:
			writes[fact.CommandID] = append(writes[fact.CommandID], fact)
		}
	}
	return writes
}

// placedWriteBase is the base name Windows opens for value: lower case,
// without the trailing dots and spaces Windows drops.
func placedWriteBase(value string) string {
	value = strings.ReplaceAll(value, `\`, "/")
	return strings.TrimRight(strings.ToLower(path.Base(value)), ". ")
}

// powerShellOrdinaryPlacement reports an absolute Windows path that is in no
// protected set: a plain, static path (windowsLocationOrdinaryWriteTarget: no
// key file name, stream, wildcard, variable or short name) with no folder or
// file whose name starts with "." or "$" (the home's dot-folders hold the
// DefenseClaw state, the keys, the credentials, the agent hook configurations
// and the shell startup files), either in a folder of the active home other
// than AppData, Documents and OneDrive (the PowerShell profiles, the startup
// folder, the application credentials) or a file directly in the home other
// than the account hive, or outside every account's home and the system
// folders. A share path is another host's and never ordinary.
func powerShellOrdinaryPlacement(value, home string) bool {
	if !windowsLocationAbsolute(value) || !windowsLocationOrdinaryWriteTarget(value) || !windowsLocationAbsolute(home) {
		return false
	}
	canonical := windowsLocationCanonical(value)
	if len(canonical) < 4 || canonical[1] != ':' || canonical[2] != '/' {
		return false
	}
	parts := strings.Split(canonical[3:], "/")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasPrefix(part, "$") {
			return false
		}
	}
	activeHome := windowsLocationCanonical(home)
	if relative, ok := strings.CutPrefix(canonical, activeHome+"/"); ok {
		first, _, nested := strings.Cut(relative, "/")
		if strings.HasPrefix(first, "ntuser") {
			return false
		}
		return !nested || first != "appdata" && first != "documents" && !strings.HasPrefix(first, "onedrive")
	}
	users := path.Dir(activeHome)
	if canonical == users || strings.HasPrefix(canonical, users+"/") {
		return false
	}
	switch parts[0] {
	case "windows", "program files", "program files (x86)", "programdata", "users", "system volume information",
		"recovery", "boot", "efi", "perflogs", "inetpub":
		return false
	}
	return len(parts) > 1
}
