// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// machineLayout is where a managed (standalone) deployment keeps DefenseClaw
// on the machine: its install root and binaries, configuration, policy and
// secret folders, guardian and lifecycle state, data, logs and hook runtime.
// Self-protection covers it like the per-user ~/.defenseclaw: the operating
// system refuses an agent that is not root, but the verdict must not depend
// on file modes (rel-1-0-6:GAP-0796). Every root comes from
// managed.StandaloneLayout, the one definition the installers, the services
// and the hook runtime use, so a path the lifecycle adds is protected
// without a second list.
type machineLayout struct {
	// posix are the absolute Linux and macOS roots in posixMachineKey form,
	// as written (case sensitive file systems) and folded (macOS).
	posix, posixFolded []string
	// windows are the "cisco/<folder>" folders below Program Files or
	// ProgramData, lower case.
	windows []string
}

var defenseClawMachineLayout = sync.OnceValue(func() machineLayout {
	var layout machineLayout
	for _, goos := range []string{"linux", "darwin"} {
		unix, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			continue
		}
		for _, root := range unix.OwnedPaths() {
			// Both operating systems are read on either: a Linux path under
			// the macOS layout is as much DefenseClaw as under its own.
			layout.posix = append(layout.posix, posixMachineKey(root, false))
			layout.posixFolded = append(layout.posixFolded, posixMachineKey(root, true))
		}
	}
	for _, roots := range []*[]string{&layout.posix, &layout.posixFolded} {
		slices.Sort(*roots)
		*roots = slices.Compact(*roots)
	}
	for _, folder := range managed.StandaloneWindowsOwnFolders() {
		layout.windows = append(layout.windows, strings.ToLower(strings.ReplaceAll(folder, `\`, "/")))
	}
	return layout
})

// posixMachineKey is the form in which POSIX machine paths are compared:
// cleaned, /var/run read as /run (the Linux link), and on a case-insensitive
// file system (macOS) lower case with the /private prefix of /etc, /var and
// /tmp removed.
func posixMachineKey(value string, caseFold bool) string {
	value = path.Clean(value)
	if caseFold {
		value = strings.ToLower(value)
		for _, name := range []string{"/etc", "/var", "/tmp"} {
			if value == "/private"+name || strings.HasPrefix(value, "/private"+name+"/") {
				value = strings.TrimPrefix(value, "/private")
				break
			}
		}
	}
	if value == "/var/run" || strings.HasPrefix(value, "/var/run/") {
		value = "/run" + strings.TrimPrefix(value, "/var/run")
	}
	return value
}

// matchesDefenseClawMachineLayout reports a path that is, or is below, a
// DefenseClaw machine root on Linux, macOS or Windows. Every spelling the
// fact carries is read (as written, normalized and link-resolved), so a
// project link to a machine file is named by its target.
func matchesDefenseClawMachineLayout(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
	layout := defenseClawMachineLayout()
	caseFold := runtime.GOOS == "darwin" || strings.HasPrefix(facts.ActiveHome, "/Users/")
	seen := make(map[string]bool, 4)
	for _, value := range []string{exactSemanticPathValue(candidate), candidate.Value, candidate.Normalized, candidate.Resolved} {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		if layout.posixPath(value, caseFold) || layout.windowsPath(value) {
			return true
		}
	}
	return false
}

func (l machineLayout) posixPath(value string, caseFold bool) bool {
	if !strings.HasPrefix(value, "/") {
		return false
	}
	key := posixMachineKey(value, caseFold)
	roots := l.posix
	if caseFold {
		roots = l.posixFolded
	}
	for _, root := range roots {
		if key == root || strings.HasPrefix(key, root+"/") {
			return true
		}
	}
	return false
}

// windowsPath reads a Windows spelling of a path: C:\ or C:/, the \\?\ and
// \\.\ namespaces, a \\host\C$ administrative share, and the /c/ , /mnt/c/
// and /cygdrive/c/ forms of a POSIX shell on Windows. Names are compared
// without case, without trailing dots and spaces and without a stream
// suffix, as NTFS does, and the 8.3 short forms of Program Files,
// ProgramData and the DefenseClaw folders count.
func (l machineLayout) windowsPath(value string) bool {
	slashed := strings.ReplaceAll(value, `\`, "/")
	if rest, ok := strings.CutPrefix(slashed, "//?/"); ok {
		slashed = rest
	} else if rest, ok := strings.CutPrefix(slashed, "//./"); ok {
		slashed = rest
	}
	if len(slashed) >= 4 && strings.EqualFold(slashed[:4], "unc/") {
		slashed = "//" + slashed[4:]
	}
	var rest string
	switch {
	case strings.HasPrefix(slashed, "//"):
		// //host/C$/rest: the share names the volume.
		parts := strings.SplitN(slashed[2:], "/", 3)
		if len(parts) < 3 || len(parts[1]) != 2 || parts[1][1] != '$' || !isASCIILetterByte(parts[1][0]) {
			return false
		}
		rest = parts[2]
	case len(slashed) >= 3 && isASCIILetterByte(slashed[0]) && slashed[1] == ':' && slashed[2] == '/':
		rest = slashed[3:]
	case len(slashed) >= 3 && slashed[0] == '/' && isASCIILetterByte(slashed[1]) && slashed[2] == '/':
		rest = slashed[3:]
	default:
		rest = strings.TrimPrefix(slashed, "/")
		for _, prefix := range []string{"mnt/", "cygdrive/"} {
			if tail, ok := strings.CutPrefix(rest, prefix); ok && len(tail) >= 2 && isASCIILetterByte(tail[0]) && tail[1] == '/' {
				rest = tail[2:]
				break
			}
		}
	}
	var names []string
	for _, name := range strings.Split(rest, "/") {
		if before, _, found := strings.Cut(name, ":"); found {
			name = before
		}
		if name != "." && name != ".." {
			name = strings.TrimRight(name, ". ")
		}
		switch name {
		case "", ".":
		case "..":
			if len(names) > 0 {
				names = names[:len(names)-1]
			}
		default:
			names = append(names, strings.ToLower(name))
		}
	}
	if len(names) < 3 || !windowsMachineBase(names[0]) {
		return false
	}
	for _, folder := range l.windows {
		cisco, own, _ := strings.Cut(folder, "/")
		if names[1] == cisco && (names[2] == own || windowsShortNameOf(names[2], own)) {
			return true
		}
	}
	return false
}

// windowsMachineBase reports the Program Files and ProgramData folders, by
// name or by the 8.3 short name NTFS gives them (PROGRA~1, PROGRA~2, ...).
func windowsMachineBase(name string) bool {
	return name == "program files" || name == "program files (x86)" || name == "programdata" ||
		windowsShortNameOf(name, "program files")
}

// windowsShortNameOf reports the 8.3 short form of a long name: its first
// six characters, a tilde and a number (DEFENS~1 for DefenseClaw).
func windowsShortNameOf(name, long string) bool {
	compact := strings.ReplaceAll(long, " ", "")
	if len(compact) <= 8 {
		return false
	}
	stem, number, found := strings.Cut(name, "~")
	return found && integrityDecimal(number) && len(stem) >= 1 && len(stem) <= 6 && strings.HasPrefix(compact, stem)
}

func isASCIILetterByte(b byte) bool {
	return b >= 0x41 && b <= 0x5a || b >= 0x61 && b <= 0x7a
}
