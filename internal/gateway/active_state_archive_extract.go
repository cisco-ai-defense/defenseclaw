// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// stateReachFunc returns the judge of one absolute path: it is the active
// state root or a path in it, spelled there or reached through a link
// (followed with the hook's target map first, a managed gateway cannot read
// the home, then the local filesystem when the hook allows it). ok is false
// when the home is neither a POSIX one nor, on a native Windows gateway, a
// drive or UNC one.
//
// A drive home (C:\Users\x) or UNC home (\\server\share\x) is judged in its
// slash spelling: the extraction and inline hand-off readers place a Git
// Bash word (~/.defenseclaw, $HOME/x, a relative folder) and a PowerShell
// path with filepath against the Windows home and cwd, so a tar -C or unzip
// -d into the state and a python -c hand-off of a state file were never
// judged on a Windows home (rel-1-0-10:GAP-0154, GAP-1173).
func stateReachFunc(facts actionfacts.Facts, request trustedActionRequest) (func(string) bool, bool) {
	judge, ok := newStateJudge(facts, request)
	return judge.reaches, ok
}

// stateJudge judges paths against the active state root.
type stateJudge struct {
	// reaches reports the root or a path in it (stateReachFunc).
	reaches func(string) bool
	// holds reports a folder the root is in: the root itself, the home, any
	// folder above it, or a link to one of them.
	holds func(string) bool
}

func newStateJudge(facts actionfacts.Facts, request trustedActionRequest) (stateJudge, bool) {
	home := strings.TrimRight(facts.ActiveHome, "/")
	windows := false
	if !strings.HasPrefix(home, "/") {
		slashed := windowsSlashClean(home)
		if runtime.GOOS != "windows" || !actionfacts.DriveSlashPath(slashed) && !uncSlashPath(slashed) {
			return stateJudge{}, false
		}
		home, windows = slashed, true
	}
	clean := path.Clean
	if windows {
		clean = windowsSlashClean
	}
	resolve := stateLinkResolver(request)
	spelledRoot := strings.TrimSuffix(home, "/") + "/.defenseclaw"
	fold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	under := func(value, root string) bool {
		if fold {
			value, root = strings.ToLower(value), strings.ToLower(root)
		}
		return value == root || strings.HasPrefix(value, strings.TrimSuffix(root, "/")+"/")
	}
	var physicalRoot string
	var inState func(string) bool
	if windows {
		// The physical state root and the physical path of a link are drive
		// or UNC paths; both are compared in the slash spelling.
		root, _ := stateRootOf(filepath.FromSlash(home), resolve)
		physicalRoot = windowsSlashClean(root)
		inState = func(value string) bool { return under(windowsSlashClean(value), physicalRoot) }
	} else {
		physicalRoot, inState = stateRootOf(home, resolve)
	}
	absolute := func(value string) bool {
		if windows {
			slashed := windowsSlashClean(value)
			return actionfacts.DriveSlashPath(slashed) || uncSlashPath(slashed)
		}
		return path.IsAbs(value)
	}
	physical := func(full string) (string, bool) {
		lookup := full
		if windows {
			lookup = filepath.FromSlash(full)
		}
		target, ok := resolve(lookup)
		if !ok {
			target, ok = request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+full]
		}
		return target, ok && absolute(target)
	}
	return stateJudge{
		reaches: func(full string) bool {
			full = clean(filepath.ToSlash(full))
			if under(full, spelledRoot) {
				return true
			}
			target, ok := physical(full)
			return ok && inState(target)
		},
		holds: func(folder string) bool {
			folder = clean(filepath.ToSlash(folder))
			if under(spelledRoot, folder) {
				return true
			}
			target, ok := physical(folder)
			if !ok {
				return false
			}
			if windows {
				target = windowsSlashClean(target)
			}
			return under(physicalRoot, target) || under(target, physicalRoot)
		},
	}, true
}

// windowsSlashClean is path.Clean of the slash spelling of a Windows path
// that keeps the two leading slashes of a UNC path (\\server\share\x).
func windowsSlashClean(value string) string {
	slashed := filepath.ToSlash(value)
	if strings.HasPrefix(slashed, "//") && !strings.HasPrefix(slashed, "///") {
		return "/" + path.Clean(slashed)
	}
	return path.Clean(slashed)
}

// uncSlashPath reports a UNC path in the slash spelling: //server/share
// and below it. A device path (//./x, //?/x) is not one.
func uncSlashPath(value string) bool {
	rest, ok := strings.CutPrefix(value, "//")
	if !ok {
		return false
	}
	server, share, _ := strings.Cut(rest, "/")
	share, _, _ = strings.Cut(share, "/")
	return server != "" && server != "." && server != "?" && share != ""
}

// archiveStateReading is the archive extractions of one call read against
// the active state (rel-1-0-10:GAP-1173).
type archiveStateReading struct {
	// writes: a folder the call extracts into is in the state, or a member
	// lands there (named by the call or listed from the archive).
	writes bool
	// possible: a folder that holds the state receives members nothing
	// tells: the call does not name them (a glob, tar -T, a rename), or it
	// extracts a whole archive that is there but cannot be listed.
	possible bool
	caps     bounded.CapSet
}

// readArchiveState reads the archive extractions of a shell or PowerShell
// call (hookpaths.ReadArchiveExtractions) against the active state:
//   - a folder in the state is a write of it, whatever the archive holds;
//   - a folder that holds the state (the home, a folder above it) with an
//     archive that can be listed is a write of the state when a member lands
//     there, and no state write when none does;
//   - such a folder with an archive that is there but cannot be listed, or
//     whose members the call does not tell, is a possible write;
//   - an archive that is not there to read keeps the verdict of the words
//     alone (an extraction into the home that names no member is allowed).
func readArchiveState(facts actionfacts.Facts, request trustedActionRequest) archiveStateReading {
	command, known := trustedBashCommandInput(request.Input)
	if !known || !mentionsArchiveExtractor(command) {
		return archiveStateReading{}
	}
	judge, ok := newStateJudge(facts, request)
	if !ok {
		return archiveStateReading{}
	}
	read := hookpaths.ReadArchiveExtractions(command, facts.CWD, strings.TrimRight(facts.ActiveHome, "/"))
	reading := archiveStateReading{caps: read.Caps}
	for _, full := range read.Paths {
		if judge.reaches(full) {
			reading.writes = true
			return reading
		}
	}
	for _, folder := range read.Unknown {
		reading.possible = reading.possible || judge.holds(folder)
	}
	for _, whole := range read.Whole {
		if !judge.holds(whole.Folder) {
			continue
		}
		landing, present, listed := whole.Landing()
		if !present {
			continue
		}
		if !listed {
			reading.possible = true
			continue
		}
		for _, full := range landing {
			if judge.reaches(full) {
				reading.writes = true
				return reading
			}
		}
	}
	return reading
}

// archiveExtractsIntoState reports an archive extraction (unzip -d, tar -C,
// 7z -o, cpio -D, ditto, Expand-Archive, ZipFile ExtractToDirectory, Python
// tarfile, zipfile and shutil.unpack_archive) whose folder is the active
// state root or a folder in it, or whose member lands there: named by the
// call (tar -xf x.tar -C ~ .defenseclaw/config.yaml, rel-1-0-10:GAP-0142) or
// listed from the archive it extracts whole (tar -xf x.tar -C ~ with a
// .defenseclaw/config.yaml member, GAP-1173), spelled there or reached
// through a link: `yes | unzip -q -d ~/proj/evil x.zip` with ~/proj/evil ->
// ~/.defenseclaw replaces config.yaml and hooks/ as a redirect through the
// same link would (GAP-2415). ActionFacts gives an extraction no path fact,
// so it is proved from the words (readArchiveState).
func archiveExtractsIntoState(facts actionfacts.Facts, request trustedActionRequest) bool {
	return readArchiveState(facts, request).writes
}
