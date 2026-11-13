// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Which launch folders (GAP-0751) a DefenseClaw-written file still names.
// Prune keeps every folder a config, selector, state file or journal names,
// and retire waits until none does. The decisions are OS-independent; the
// Windows file list is windowsHookImageConfigFiles.

// windowsHookImageConfigFile is one file (or, before expansion, one path the
// connector watches, which can be a folder) the scan reads. User marks an
// account file: one an account can write (in an enrolled account's home, or
// in a ProgramData vendor folder that is not owned by SYSTEM or
// Administrators), so it can keep a folder (a live session's hook) but never
// stop prune or retire.
type windowsHookImageConfigFile struct {
	Path string
	User bool
	// Home is the folder an account file is read below: the enrolled
	// account's home, or ProgramData for a vendor folder file. The file is
	// read only when no link lies at or below Home on its path
	// (link_in_account_path otherwise: skipped, never read).
	Home string
	// Note says why a file outside an account's home is an account file
	// ("not_admin_owned: <element>"); it is shown with a skipped line.
	// Home is then ProgramData: the file is opened from ProgramData's handle.
	Note string
}

// line is the Incomplete or Skipped line of file for err.
func (f windowsHookImageConfigFile) line(err error) string {
	if f.Note != "" {
		return fmt.Sprintf("%s (%s): %v", f.Path, f.Note, err)
	}
	return fmt.Sprintf("%s: %v", f.Path, err)
}

// windowsHookImageLinkInAccountPath starts the skipped line of an account
// file whose path has a link at or below the account home.
const windowsHookImageLinkInAccountPath = "link_in_account_path"

var errWindowsHookImageNoAccountHome = errors.New("account file without an account home; not read")

// windowsHookImageAccountPathError marks a winpath.ErrLinkBelowRoot error as
// link_in_account_path and a winpath.ErrNotRegularBelow one (a folder or a
// device opened as a file) as errWindowsHookImageScanUnsafe; other errors
// pass unchanged.
func windowsHookImageAccountPathError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, winpath.ErrLinkBelowRoot):
		return fmt.Errorf("%s: %w; not read", windowsHookImageLinkInAccountPath, err)
	case errors.Is(err, winpath.ErrNotRegularBelow):
		return errWindowsHookImageScanUnsafe
	}
	return err
}

// windowsHookImageAccountView is how an account path is looked at before it
// is listed or read: view (viewWindowsHookImageAccountPath on Windows) opens
// it from the account home's handle with no link followed anywhere from the
// home down, and returns what it is and, for a folder, its entries listed
// through that handle. SYSTEM would resolve every folder of the path with its
// own rights if it opened the path by name, so a folder the account replaced
// with a junction would point SYSTEM's open anywhere the account chooses.
func windowsHookImageAccountView(view func(home, path string) (fs.FileInfo, []fs.DirEntry, error)) func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
	return func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		if strings.TrimSpace(home) == "" {
			return nil, nil, errWindowsHookImageNoAccountHome
		}
		info, children, err := view(home, path)
		if err != nil {
			return nil, nil, windowsHookImageAccountPathError(err)
		}
		return info, children, nil
	}
}

// windowsHookImageLinkAtMachineFolder starts the incomplete line of a link
// (reparse point) owned by SYSTEM or Administrators in a ProgramData vendor
// folder: it is not followed, and the scan cannot vouch for what it points
// to.
const windowsHookImageLinkAtMachineFolder = "link_at_machine_folder"

// windowsHookImageVendorFS reads a ProgramData vendor folder through
// handles opened from ProgramData's (winpath.InspectBelow and a listing
// through winpath.OpenBelow on Windows), so no folder of it is ever resolved
// by name.
type windowsHookImageVendorFS struct {
	// Inspect opens path below root without following a link (a link at
	// the last element is opened itself) and reports what it is and who
	// owns it, read on the opened handle.
	Inspect func(root, path string) (winpath.BelowInfo, error)
	// List lists the folder path below root through its handle; a link
	// anywhere from root down fails the open.
	List func(root, path string) ([]fs.DirEntry, error)
}

// windowsHookImageVendorFiles lists the files of a ProgramData vendor folder
// that a standard user can create when it is absent (ProgramData\OpenAI\Codex,
// ProgramData\Cursor) to depth below dir, and classifies them. A file is a
// machine file only when it and every folder from ProgramData down to it is
// owned by SYSTEM or Administrators; from the first element that is not, the
// rest is account files read below ProgramData (Note not_admin_owned:
// <element>), so one the user made unreadable, or a link the user made, is
// skipped and never voids the scan (which would keep every folder and leave
// retire pending). A link owned by SYSTEM or Administrators is not followed
// either: it makes the scan incomplete (link_at_machine_folder), since only
// an administrator can make it and what it points to is not known. A folder
// SYSTEM cannot list is a problem (the scan is incomplete) when it is a
// machine folder and an account entry (skipped by the scan) otherwise; the
// listing goes on with its siblings, so one unreadable folder cannot hide
// the other files. A missing vendor folder lists nothing. Owners do not
// change under the scan: a standard user cannot make a folder of theirs
// owned by SYSTEM or Administrators, nor replace one that is.
func windowsHookImageVendorFiles(programData, dir string, depth int, vfs windowsHookImageVendorFS) ([]windowsHookImageConfigFile, []string) {
	var files []windowsHookImageConfigFile
	var problems []string
	entry := func(path, note string) windowsHookImageConfigFile {
		if note == "" {
			return windowsHookImageConfigFile{Path: path}
		}
		return windowsHookImageConfigFile{Path: path, User: true, Home: programData, Note: note}
	}
	// classify returns the account note of path ("" for a machine element)
	// or the problem that voids the scan; missing is a path that is gone.
	classify := func(path string) (note, problem string, missing bool) {
		info, err := vfs.Inspect(programData, path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", "", true
		case err != nil:
			return "", fmt.Sprintf("%s: %v", path, err), false
		case !info.AdminOwned:
			return "not_admin_owned: " + path, "", false
		case info.Link:
			return "", fmt.Sprintf("%s: %s: a link (reparse point) owned by SYSTEM or Administrators is not followed; replace it with a plain folder", path, windowsHookImageLinkAtMachineFolder), false
		}
		return "", "", false
	}
	elements, err := winpath.ElementsBelow(programData, dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	note := ""
	for _, element := range elements[1:] {
		elementNote, problem, missing := classify(element)
		switch {
		case missing:
			return nil, nil
		case problem != "":
			return nil, []string{problem}
		}
		if elementNote != "" {
			note = elementNote
			break
		}
	}
	var walk func(dir string, depth int, note string)
	walk = func(dir string, depth int, note string) {
		children, err := vfs.List(programData, dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return
		case err != nil && note != "":
			// The scan looks at it again as an account path and skips it.
			files = append(files, entry(dir, note))
			return
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", dir, err))
			return
		}
		for _, child := range children {
			path := windowsHookImageJoin(dir, child.Name())
			childNote := note
			if childNote == "" {
				elementNote, problem, missing := classify(path)
				switch {
				case missing:
					continue
				case problem != "":
					problems = append(problems, problem)
					continue
				}
				childNote = elementNote
			}
			switch mode := child.Type(); {
			case mode&(fs.ModeSymlink|fs.ModeIrregular) != 0:
				// Refused when it is opened (link_in_account_path or
				// not a regular file).
				files = append(files, entry(path, childNote))
			case child.IsDir():
				if depth > 0 {
					walk(path, depth-1, childNote)
				}
			case windowsHookImageScanSkipsName(path):
			default:
				files = append(files, entry(path, childNote))
			}
		}
	}
	walk(dir, depth, note)
	return files, problems
}

// windowsHookImageConfigScan is the result of one scan.
type windowsHookImageConfigScan struct {
	// Named maps a launch folder name (16 lowercase hex digits) to the files
	// that name an image of this install's bin in it.
	Named map[string][]string
	// UserFiles are the files of Named that are an account's own.
	UserFiles map[string]bool
	// Incomplete lists "<file>: <error>" for each machine file (written by
	// DefenseClaw as SYSTEM) that exists but could not be read. A scan with
	// any entry here proves nothing about the folders: prune removes none
	// and retire stays pending.
	Incomplete []string
	// Skipped lists "<file>: <error>" for each account file that was a
	// link, had a link at or below its account home (link_in_account_path),
	// was not a regular file, too large, unreadable or did not answer in
	// time. It is reported (skipped_unsafe) and does not void the scan: a
	// folder it might name is still kept while it is current, the replaced
	// one or replaced less than hookImageRetainAfterSupersede ago.
	Skipped []string
}

// NamedBySystem reports the folders a machine file names (retire waits
// only for those: the older release's Setup reads only them).
func (s windowsHookImageConfigScan) NamedBySystem() map[string][]string {
	out := map[string][]string{}
	for folder, files := range s.Named {
		for _, file := range files {
			if !s.UserFiles[strings.ToLower(file)] {
				out[folder] = append(out[folder], file)
			}
		}
	}
	return out
}

// errWindowsHookImageScanUnsafe is a scanned path that is a link, a folder
// or another non-regular file: it is never read.
var errWindowsHookImageScanUnsafe = errors.New("not a regular file (a link, a folder or a device); not read")

// windowsHookImageMachineFileBusy starts the incomplete line of a machine
// file another process still held open without read sharing after the
// retries: any account that can read a machine file (Claude Code's
// managed-settings.json, an admin-owned vendor file) can hold it that way.
// The scan is then incomplete (prune removes nothing, retire stays pending)
// until the holder lets go; the line says so, and retire or prune can be run
// again.
const windowsHookImageMachineFileBusy = "machine_file_busy"

// windowsHookImageBusyRetries are the waits between reads of a machine file
// held open without read sharing: 1.5 s in all, inside the per-file timeout.
var windowsHookImageBusyRetries = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond}

// readWindowsHookImageRetryingBusy runs read again while busy reports its
// error as a sharing violation, waiting windowsHookImageBusyRetries between
// tries, and then reports machine_file_busy.
func readWindowsHookImageRetryingBusy(read func() ([]byte, error), busy func(error) bool, sleep func(time.Duration)) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		body, err := read()
		if err == nil || !busy(err) {
			return body, err
		}
		if attempt == len(windowsHookImageBusyRetries) {
			return nil, fmt.Errorf("%s: another process holds the file open without read sharing (%d tries): %w; run again once it is closed",
				windowsHookImageMachineFileBusy, attempt+1, err)
		}
		sleep(windowsHookImageBusyRetries[attempt])
	}
}

// expandWindowsHookImageConfigFiles turns the watched paths into the regular
// files to read: a folder (Claude Code's managed-settings.d) becomes its
// regular files, a missing path is dropped, a link or other non-regular entry
// is refused (machine: incomplete; account: skipped). A machine path is
// looked at with lstat and readDir; an account path only through viewAccount
// (windowsHookImageAccountView): one with a link at or below its home is
// skipped (link_in_account_path) and never listed or read, and a watched
// account folder is listed through the handle the view opened. Lock files
// and temporaries are left out: writers hold them without sharing and they
// never name a hook.
func expandWindowsHookImageConfigFiles(
	entries []windowsHookImageConfigFile,
	lstat func(string) (fs.FileInfo, error),
	readDir func(string) ([]fs.DirEntry, error),
	viewAccount func(home, path string) (fs.FileInfo, []fs.DirEntry, error),
) ([]windowsHookImageConfigFile, []string, []string) {
	var files []windowsHookImageConfigFile
	var incomplete, skipped []string
	refuse := func(entry windowsHookImageConfigFile, err error) {
		line := entry.line(err)
		if entry.User {
			skipped = append(skipped, line)
		} else {
			incomplete = append(incomplete, line)
		}
	}
	seen := map[string]bool{}
	add := func(entry windowsHookImageConfigFile) {
		key := strings.ToLower(strings.TrimSpace(entry.Path))
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		files = append(files, entry)
	}
	expanded := map[string]bool{}
	for _, entry := range entries {
		entryKey := strings.ToLower(strings.TrimSpace(entry.Path))
		if entryKey == "" || expanded[entryKey] {
			continue
		}
		expanded[entryKey] = true
		var info fs.FileInfo
		var children []fs.DirEntry
		var err error
		if entry.User {
			info, children, err = viewAccount(entry.Home, entry.Path)
		} else {
			info, err = lstat(entry.Path)
		}
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			refuse(entry, err)
			continue
		case info.Mode()&(fs.ModeSymlink|fs.ModeIrregular|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket) != 0:
			refuse(entry, errWindowsHookImageScanUnsafe)
			continue
		case info.Mode().IsRegular():
			if !windowsHookImageScanSkipsName(entry.Path) {
				add(entry)
			}
			continue
		case !info.IsDir():
			refuse(entry, errWindowsHookImageScanUnsafe)
			continue
		}
		if !entry.User {
			children, err = readDir(entry.Path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				refuse(entry, err)
				continue
			}
		}
		for _, dirEntry := range children {
			child := windowsHookImageConfigFile{Path: windowsHookImageJoin(entry.Path, dirEntry.Name()), User: entry.User, Home: entry.Home, Note: entry.Note}
			switch mode := dirEntry.Type(); {
			case mode&(fs.ModeSymlink|fs.ModeIrregular) != 0:
				refuse(child, errWindowsHookImageScanUnsafe)
			case dirEntry.IsDir() || !mode.IsRegular():
				// One level: a folder the connector watches holds its files
				// directly (managed-settings.d\*.json).
				continue
			case windowsHookImageScanSkipsName(child.Path):
				continue
			default:
				add(child)
			}
		}
	}
	return files, incomplete, skipped
}

func windowsHookImageScanSkipsName(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".lock") || strings.Contains(lower, ".tmp")
}

// scanWindowsHookImageConfigFiles reads each regular file (a missing one is
// skipped) and records the launch folders of bin it names. A machine file
// that cannot be read makes the scan incomplete; an account file that
// cannot be read is skipped (see windowsHookImageConfigScan). read gets the
// whole entry: an account file is read only below its Home.
func scanWindowsHookImageConfigFiles(files []windowsHookImageConfigFile, bin string, read func(windowsHookImageConfigFile) ([]byte, error)) windowsHookImageConfigScan {
	scan := windowsHookImageConfigScan{Named: map[string][]string{}, UserFiles: map[string]bool{}}
	seen := map[string]bool{}
	for _, file := range files {
		key := strings.ToLower(strings.TrimSpace(file.Path))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		body, err := read(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			line := file.line(err)
			if file.User {
				scan.Skipped = append(scan.Skipped, line)
			} else {
				scan.Incomplete = append(scan.Incomplete, line)
			}
			continue
		}
		for _, folder := range windowsHookImageFoldersNamedIn(body, bin) {
			scan.Named[folder] = append(scan.Named[folder], file.Path)
			if file.User {
				scan.UserFiles[key] = true
			}
		}
	}
	return scan
}

// windowsHookImageFoldersNamedIn returns the launch folders of bin that an
// image path in body names: an absolute <bin>\hooks\<16 hex>\defenseclaw-hook.exe
// (or -guard.exe) in a plain Windows path, a JSON or TOML string
// (backslashes doubled) or with forward slashes, in any case. Only a path the
// R3 ownership helper (winpath.SameEnterpriseHookImageFamily) admits as an
// image of this install's bin counts, so a string an account writes about
// another folder, another install or a relative path keeps nothing.
func windowsHookImageFoldersNamedIn(body []byte, bin string) []string {
	text := strings.ReplaceAll(strings.ToLower(string(body)), "/", `\`)
	for strings.Contains(text, `\\`) {
		text = strings.ReplaceAll(text, `\\`, `\`)
	}
	own := windowsHookImageJoin(strings.ToLower(strings.TrimRight(strings.TrimSpace(bin), `\`)), winpath.EnterpriseHookImageName)
	found := map[string]bool{}
	const name = `\defenseclaw-hook`
	for index := 0; ; {
		at := strings.Index(text[index:], name)
		if at < 0 {
			break
		}
		end := index + at + len(name)
		index = end
		switch {
		case strings.HasPrefix(text[end:], ".exe"):
			end += len(".exe")
		case strings.HasPrefix(text[end:], "-guard.exe"):
			end += len("-guard.exe")
		default:
			continue
		}
		start := windowsHookImagePathStart(text, index-len(name))
		if start < 0 {
			continue
		}
		candidate := text[start:end]
		location, ok := winpath.ParseEnterpriseHookImagePath(candidate)
		if !ok || !location.Versioned() {
			continue
		}
		// The guard's family check runs against the guard of this bin.
		ownImage := own
		if strings.HasSuffix(candidate, "-guard.exe") {
			ownImage = windowsHookImageJoin(strings.ToLower(strings.TrimRight(strings.TrimSpace(bin), `\`)), winpath.EnterpriseHookGuardImageName)
		}
		if winpath.SameEnterpriseHookImageFamily(candidate, ownImage) {
			found[location.Digest] = true
		}
	}
	out := make([]string, 0, len(found))
	for digest := range found {
		out = append(out, digest)
	}
	sort.Strings(out)
	return out
}

// windowsHookImagePathStart finds where the absolute path that ends at end
// begins: the drive letter of the nearest "X:\" before it, with no quote,
// newline or other delimiter between (a path may hold spaces). -1 when none
// is within 1024 bytes.
func windowsHookImagePathStart(text string, end int) int {
	low := end - 1024
	if low < 0 {
		low = 0
	}
	for i := end - 1; i >= low+1; i-- {
		switch text[i] {
		case '"', '\'', '\n', '\r', '\t', '=', '[', ']', '{', '}', ',', ';', '<', '>', '|', '`':
			return -1
		}
		if text[i] == ':' && i+1 < len(text) && text[i+1] == '\\' {
			drive := text[i-1]
			if drive >= 'a' && drive <= 'z' {
				return i - 1
			}
		}
	}
	return -1
}

// windowsHookImageStageTimes is the time each launch folder of root was
// staged: the modification time of its hook image, which stage writes new.
// A folder whose hook cannot be read has no entry.
func windowsHookImageStageTimes(fsys windowsHookImageFS, root string, entries []fs.DirEntry) map[string]time.Time {
	staged := map[string]time.Time{}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if !winpath.IsEnterpriseHookImageDirName(name) || !entry.IsDir() {
			continue
		}
		info, err := fsys.Lstat(windowsHookImageJoin(root, entry.Name(), winpath.EnterpriseHookImageName))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		staged[name] = info.ModTime()
	}
	return staged
}

// windowsHookImageRetainReason says why prune keeps the launch folder name
// (neither current nor kept), or "" when it may go. A folder is superseded
// when the first folder staged after it was staged; a folder no later one
// followed (a stage that failed to start) counts from its own stage time.
func windowsHookImageRetainReason(name string, staged map[string]time.Time, policy windowsHookImagePrunePolicy) string {
	if len(policy.Scan.Incomplete) > 0 {
		return "scan_incomplete"
	}
	if files := policy.Scan.Named[name]; len(files) > 0 {
		return "named_by:" + files[0]
	}
	own, ok := staged[name]
	if !ok {
		return "superseded_recently:unknown"
	}
	superseded := time.Time{}
	for other, at := range staged {
		if other == name || !at.After(own) {
			continue
		}
		if superseded.IsZero() || at.Before(superseded) {
			superseded = at
		}
	}
	if superseded.IsZero() {
		superseded = own
	}
	if policy.Now.Sub(superseded) < hookImageRetainAfterSupersede {
		return "superseded_recently:" + superseded.UTC().Format(time.RFC3339)
	}
	return ""
}

// clearWindowsHookImagesRetired removes the retire marker once this
// release's launch set is staged and started again: an administrator who
// retired the folders and then ran this release's Setup un-retires them.
func clearWindowsHookImagesRetired(fsys windowsHookImageFS, root string) []string {
	marker := windowsHookImageJoin(root, winpath.EnterpriseHookImagesRetiredMarker)
	info, err := fsys.Lstat(marker)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []string{fmt.Sprintf("inspect the retire marker %s: %v", marker, err)}
	}
	if !info.Mode().IsRegular() {
		return []string{fmt.Sprintf("left %s: not a file", marker)}
	}
	if err := fsys.RemoveAll(marker); err != nil {
		return []string{fmt.Sprintf("the retire marker %s stays: %v", marker, err)}
	}
	return []string{"removed the retire marker " + marker + ": agent configs name the launch set again"}
}
