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
	// windows are the folders of a standalone Windows deployment.
	windows []windowsMachineFolder
}

// windowsMachineFolder is one Windows folder that holds DefenseClaw: the
// drive it is on and its names below the drive, lower case.
type windowsMachineFolder struct {
	drive string
	names []string
}

// defenseClawMachineLayout is replaced by tests.
var defenseClawMachineLayout = sync.OnceValue(func() machineLayout {
	return newMachineLayout(managed.TrustedStandaloneWindowsRoots)
})

// newMachineLayout reads the Linux and macOS layouts, and the Windows layout
// under the Program Files and ProgramData roots that registered returns (the
// protected machine registration, on Windows), so a Windows path is read on
// any host. Where nothing is registered (a host without a managed Windows
// install) the layout is the default one, on the C: drive. The registered
// roots replace the default ones: the same folder names on another drive are
// project files.
func newMachineLayout(registered func() (programFiles, programData string, err error)) machineLayout {
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
	programFiles, programData, err := registered()
	if err != nil {
		programFiles, programData = `C:\Program Files`, `C:\ProgramData`
	}
	layout.windows = windowsMachineFolders(programFiles, programData)
	return layout
}

func windowsMachineFolders(programFiles, programData string) []windowsMachineFolder {
	var folders []windowsMachineFolder
	for _, folder := range managed.StandaloneWindowsOwnFolders(programFiles, programData) {
		entry := windowsMachineFolder{drive: strings.ToLower(folder[:1])}
		for _, name := range strings.Split(folder[3:], `\`) {
			entry.names = append(entry.names, strings.ToLower(name))
		}
		folders = append(folders, entry)
	}
	return folders
}

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
	current, currentKnown := windowsCurrentDrive(facts)
	seen := make(map[string]bool, 4)
	for _, value := range []string{exactSemanticPathValue(candidate), candidate.Value, candidate.Normalized, candidate.Resolved} {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		if layout.posixPath(value, caseFold) || layout.windowsPath(value, current, currentKnown) {
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

// windowsCurrentDrive is the drive the hook runs on: a path with no drive of
// its own is on it. It is read from the working directory the gateway placed
// (facts.CWD) and, where the gateway could not place it (a service account
// that cannot reach the user directories), from the directory the hook
// payload reported. known is false when neither is given on a Windows target;
// the drive is empty when the directory has none (a UNC share), and a path with
// no drive is then not on any drive of the layout. A POSIX target has no
// drive-less Windows reading at all (see windowsTarget).
func windowsCurrentDrive(facts actionfacts.Facts) (drive string, known bool) {
	if !windowsTarget(facts) {
		return "", true
	}
	if facts.CWD != "" {
		drive, _, _ = windowsVolumeAndNames(facts.CWD)
		return drive, true
	}
	if facts.CurrentWindowsDrive != "" {
		return facts.CurrentWindowsDrive, true
	}
	return "", false
}

// windowsTarget reports whether the machine the call runs on is a Windows
// one. The gateway on Windows serves Windows hooks only. Elsewhere the target
// is Windows when its home or working directory, or the one the hook reported,
// is written as a Windows path (a drive letter or a UNC share); a directory that starts with a slash is a
// POSIX one, and /mnt/c below it is a Windows drive mounted into the Linux
// tree (WSL), not a Windows root, so no drive-less Windows reading applies to
// a path of that target.
func windowsTarget(facts actionfacts.Facts) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	for _, dir := range []string{facts.ActiveHome, facts.CWD} {
		if _, _, ok := windowsVolumeAndNames(dir); ok && !strings.HasPrefix(dir, "/") {
			return true
		}
	}
	return facts.CurrentWindowsDrive != ""
}

// reportedWindowsDrive is the drive of the directory a hook payload reported,
// empty when it names none. Off Windows, a directory that starts with a slash
// is a POSIX one (/mnt/c/proj is a mounted drive inside the Linux tree), so it
// names no drive.
func reportedWindowsDrive(reportedCWD string) string {
	if runtime.GOOS != "windows" && strings.HasPrefix(reportedCWD, "/") {
		return ""
	}
	drive, _, _ := windowsVolumeAndNames(reportedCWD)
	return drive
}

// windowsPath reads a Windows spelling of a path that is, or is below, one of
// the folders of the layout. See windowsVolumeAndNames for the spellings. A
// path with no drive is on the current drive; when the working directory is
// not given it is read on every drive, the protective side.
func (l machineLayout) windowsPath(value, current string, currentKnown bool) bool {
	drive, names, ok := windowsVolumeAndNames(value)
	if !ok {
		return false
	}
	if drive == "" && currentKnown {
		if current == "" {
			return false
		}
		drive = current
	}
	for _, folder := range l.windows {
		if folder.holds(drive, names) {
			return true
		}
	}
	return false
}

// holds reports a path on drive (empty when it is on any drive) whose leading
// names are those of the folder, each by its long name or its 8.3 short name.
func (f windowsMachineFolder) holds(drive string, names []string) bool {
	if drive != "" && f.drive != drive || len(names) < len(f.names) {
		return false
	}
	for i, name := range f.names {
		if names[i] != name && !windowsShortNameOf(names[i], name) {
			return false
		}
	}
	return true
}

// windowsVolumeAndNames reads a Windows spelling of an absolute path: C:\ or
// C:/, the \\?\ and \\.\ namespaces, a \\host\C$ administrative share, a path
// on the current drive (\dir, drive empty), and the /c/ , /mnt/c/ and
// /cygdrive/c/ forms of a POSIX shell on Windows. A relative path is not
// absolute, so it is not a machine path whatever its names. Names are
// returned lower case, without trailing dots and spaces and without a stream
// suffix, as NTFS compares them, with . and .. applied. This holds under the
// \\?\ , \\.\ and \\?\UNC\ prefixes too, although those skip Windows name
// normalization and can name a distinct DefenseClaw. or "DefenseClaw " folder:
// a machine path is read by its trimmed, case folded names under every prefix,
// so such a spelling is protected and an ordinary file there is a documented
// false block (nobody keeps project files in a look-alike machine folder). The
// OS ACLs on ProgramData and the judge cover any spelling this does not read.
func windowsVolumeAndNames(value string) (drive string, names []string, ok bool) {
	slashed := strings.ReplaceAll(value, `\`, "/")
	// The \\?\ and \\.\ namespaces name the volume next (C:\ or UNC\host\share);
	// what follows the prefix is not itself a UNC or a rooted path.
	namespaced := false
	if rest, found := strings.CutPrefix(slashed, "//?/"); found {
		slashed, namespaced = rest, true
	} else if rest, found := strings.CutPrefix(slashed, "//./"); found {
		slashed, namespaced = rest, true
	}
	// Windows reads exactly two leading separators and a server name as a
	// UNC path. One separator, or three or more (an empty server name), is
	// rooted on the current drive, as the platform resolvers read them.
	unc := !namespaced && strings.HasPrefix(slashed, "//") && !strings.HasPrefix(slashed, "///")
	rooted := !namespaced && strings.HasPrefix(slashed, "/") && !unc
	if namespaced && len(slashed) >= 4 && strings.EqualFold(slashed[:4], "unc/") {
		slashed, unc = "//"+slashed[4:], true
	}
	shellDrive, shellRest := posixShellDrive(slashed)
	var rest string
	switch {
	case unc:
		// //host/C$/rest: the share names the volume.
		parts := strings.SplitN(slashed[2:], "/", 3)
		if len(parts) < 3 {
			return "", nil, false
		}
		// The share is compared like every other name: without trailing
		// dots and spaces.
		share := strings.TrimRight(parts[1], ". ")
		if len(share) != 2 || share[1] != '$' || !isASCIILetterByte(share[0]) {
			return "", nil, false
		}
		drive, rest = strings.ToLower(share[:1]), parts[2]
	case len(slashed) >= 3 && isASCIILetterByte(slashed[0]) && slashed[1] == ':' && slashed[2] == '/':
		drive, rest = strings.ToLower(slashed[:1]), slashed[3:]
	case len(slashed) >= 3 && slashed[0] == '/' && isASCIILetterByte(slashed[1]) && slashed[2] == '/':
		drive, rest = strings.ToLower(slashed[1:2]), slashed[3:]
	case shellDrive != "":
		drive, rest = shellDrive, shellRest
	case rooted:
		// \dir and /dir are both on the current drive: Windows reads
		// either separator, and a file tool resolves the path against
		// the drive of the working directory.
		rest = slashed[1:]
	default:
		return "", nil, false
	}
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
	return drive, names, true
}

// posixShellDrive splits a /mnt/c/ or /cygdrive/c/ path (a POSIX shell on
// Windows) into its lower case drive letter and the path below the drive; the
// drive is empty for any other path.
func posixShellDrive(slashed string) (drive, rest string) {
	for _, prefix := range []string{"/mnt/", "/cygdrive/"} {
		if tail, found := strings.CutPrefix(slashed, prefix); found && len(tail) >= 2 && isASCIILetterByte(tail[0]) && tail[1] == '/' {
			return strings.ToLower(tail[:1]), tail[2:]
		}
	}
	return "", ""
}

// windowsShortNameOf reports the 8.3 short form NTFS gives a long name: its
// first six characters without spaces, a tilde and a number (DEFENS~1 for
// DefenseClaw, PROGRA~1 for Program Files). A name that is already 8.3 has no
// short form, and a stem of any other length is not one NTFS makes.
func windowsShortNameOf(name, long string) bool {
	compact := strings.ReplaceAll(long, " ", "")
	if len(long) <= 8 && compact == long {
		return false
	}
	stem, number, found := strings.Cut(name, "~")
	return found && integrityDecimal(number) && stem == compact[:min(6, len(compact))]
}

func isASCIILetterByte(b byte) bool {
	return b >= 0x41 && b <= 0x5a || b >= 0x61 && b <= 0x7a
}
