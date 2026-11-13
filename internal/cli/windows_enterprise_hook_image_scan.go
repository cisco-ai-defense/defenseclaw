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
// link_in_account_path; other errors pass unchanged.
func windowsHookImageAccountPathError(err error) error {
	if err != nil && errors.Is(err, winpath.ErrLinkBelowRoot) {
		return fmt.Errorf("%s: %w; not read", windowsHookImageLinkInAccountPath, err)
	}
	return err
}

// windowsHookImageAccountPathCheck is the check run before an account path
// is opened or listed: walk (winpath.RejectReparseBelow on Windows) must find
// no link from the account home down to the path. SYSTEM resolves every
// folder of that path with its own rights, so a folder the account replaced
// with a junction would point SYSTEM's open anywhere the account chooses.
func windowsHookImageAccountPathCheck(walk func(root, path string) error) func(home, path string) error {
	return func(home, path string) error {
		if strings.TrimSpace(home) == "" {
			return errWindowsHookImageNoAccountHome
		}
		return windowsHookImageAccountPathError(walk(home, path))
	}
}

// windowsHookImageVendorFiles classifies the files listed in a ProgramData
// vendor folder that a standard user can create when it is absent
// (ProgramData\OpenAI\Codex, ProgramData\Cursor): a file is a machine file
// only when it and every folder from ProgramData down to it is owned by
// SYSTEM or Administrators (adminOwned); otherwise it is an account file read
// below ProgramData, so one the user made unreadable is skipped and never
// voids the scan (which would keep every folder and leave retire pending).
func windowsHookImageVendorFiles(programData string, paths []string, adminOwned func(string) (bool, error)) []windowsHookImageConfigFile {
	owned := map[string]bool{}
	isOwned := func(path string) bool {
		key := strings.ToLower(path)
		if value, ok := owned[key]; ok {
			return value
		}
		ok, err := adminOwned(path)
		owned[key] = err == nil && ok
		return owned[key]
	}
	files := make([]windowsHookImageConfigFile, 0, len(paths))
	for _, path := range paths {
		file := windowsHookImageConfigFile{Path: path}
		elements, err := winpath.ElementsBelow(programData, path)
		if err != nil {
			file.User, file.Home, file.Note = true, programData, "not_admin_owned: "+err.Error()
			files = append(files, file)
			continue
		}
		for _, element := range elements[1:] {
			if !isOwned(element) {
				file.User, file.Home, file.Note = true, programData, "not_admin_owned: "+element
				break
			}
		}
		files = append(files, file)
	}
	return files
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

// expandWindowsHookImageConfigFiles turns the watched paths into the regular
// files to read: a folder (Claude Code's managed-settings.d) becomes its
// regular files, a missing path is dropped, a link or other non-regular entry
// is refused (machine: incomplete; account: skipped). An account path is
// first checked with checkAccount (windowsHookImageAccountPathCheck): one
// with a link at or below its home is skipped and never listed or read. Lock
// files and temporaries are left out: writers hold them without sharing and
// they never name a hook.
func expandWindowsHookImageConfigFiles(
	entries []windowsHookImageConfigFile,
	lstat func(string) (fs.FileInfo, error),
	readDir func(string) ([]fs.DirEntry, error),
	checkAccount func(home, path string) error,
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
		if entry.User {
			if err := checkAccount(entry.Home, entry.Path); errors.Is(err, fs.ErrNotExist) {
				continue
			} else if err != nil {
				refuse(entry, err)
				continue
			}
		}
		info, err := lstat(entry.Path)
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
		children, err := readDir(entry.Path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			refuse(entry, err)
			continue
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
