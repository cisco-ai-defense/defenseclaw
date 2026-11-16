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
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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
	// (link_in_account_path otherwise: unverified, never read).
	Home string
	// Note says why a file outside an account's home is an account file
	// ("not_admin_owned: <element>"); it is shown with an unverified line.
	// Home is then ProgramData: the file is opened from ProgramData's handle.
	Note string
	// SID is the enrolled account an account file in its home belongs to
	// (the profile `hook-image retire --skip-profile` names); "" otherwise.
	SID string
	// Unverified, when set, is why the list could not vouch for this
	// account file (its agent home is not resolvable, or outside the home):
	// it is never read and is unverified (rel-1-0-10 GAP-0884).
	Unverified string
}

// line is the Incomplete or Unverified line of file for err.
func (f windowsHookImageConfigFile) line(err error) string {
	if f.Note != "" {
		return fmt.Sprintf("%s (%s): %v", f.Path, f.Note, err)
	}
	return fmt.Sprintf("%s: %v", f.Path, err)
}

// windowsHookImageLinkInAccountPath starts the unverified line of an account
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
//
// Each view is bounded (windowsHookImageBounded): an account that holds an
// oplock on its own agent config kept retire, which holds lifecycle.lock,
// waiting in the open (rel-1-0-10 GAP-0886); it is unverified instead.
func windowsHookImageAccountView(view func(home, path string) (fs.FileInfo, []fs.DirEntry, error)) func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
	type viewed struct {
		info     fs.FileInfo
		children []fs.DirEntry
	}
	return func(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
		if strings.TrimSpace(home) == "" {
			return nil, nil, errWindowsHookImageNoAccountHome
		}
		got, err := windowsHookImageBounded(func() (viewed, error) {
			info, children, err := view(home, path)
			return viewed{info, children}, err
		})
		if err != nil {
			return nil, nil, windowsHookImageAccountPathError(err)
		}
		return got.info, got.children, nil
	}
}

// windowsHookImageScanTimeout bounds one open, listing or read of the scan,
// so a path held with an oplock, or one that does not answer, cannot keep
// retire or prune (which hold the lifecycle lock) waiting. A call still
// blocked at the timeout is given up on; its goroutine ends with the process.
const windowsHookImageScanTimeout = 5 * time.Second

var errWindowsHookImageScanTimeout = errors.New("did not answer in time (an oplock, or a path that does not answer); not read")

// windowsHookImageBounded runs do within windowsHookImageScanTimeout.
func windowsHookImageBounded[T any](do func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := do()
		done <- result{value, err}
	}()
	timer := time.NewTimer(windowsHookImageScanTimeout)
	defer timer.Stop()
	select {
	case got := <-done:
		return got.value, got.err
	case <-timer.C:
		var zero T
		return zero, errWindowsHookImageScanTimeout
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
// unverified and never voids the scan (prune keeps every superseded folder
// while one is left; retire names it and stays pending until it is readable
// or its profile skipped). A link owned by SYSTEM or Administrators is not followed
// either: it makes the scan incomplete (link_at_machine_folder), since only
// an administrator can make it and what it points to is not known. A folder
// SYSTEM cannot list is a problem (the scan is incomplete) when it is a
// machine folder and an account entry (unverified by the scan) otherwise; the
// listing goes on with its siblings, so one unreadable folder cannot hide
// the other files. A missing vendor folder lists nothing. Owners do not
// change under the scan: a standard user cannot make a folder of theirs
// owned by SYSTEM or Administrators, nor replace one that is.
func windowsHookImageVendorFiles(programData, dir string, depth int, vfs windowsHookImageVendorFS) ([]windowsHookImageConfigFile, []string) {
	// Bounded like an account view (GAP-0886): a standard user can hold an
	// oplock on an element it made in a vendor folder.
	inspect, list := vfs.Inspect, vfs.List
	vfs.Inspect = func(root, path string) (winpath.BelowInfo, error) {
		return windowsHookImageBounded(func() (winpath.BelowInfo, error) { return inspect(root, path) })
	}
	vfs.List = func(root, path string) ([]fs.DirEntry, error) {
		return windowsHookImageBounded(func() ([]fs.DirEntry, error) { return list(root, path) })
	}
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
		case errors.Is(err, errWindowsHookImageScanTimeout):
			// Not known to be an account's: the scan is incomplete.
			return "", fmt.Sprintf("%s: %v", path, err), false
		case err != nil:
			// SYSTEM is not the owner of an object a standard user made and
			// does not get READ_CONTROL on one whose ACL the user set, so an
			// unreadable owner is an account entry, never a problem that
			// would void the scan (review 5).
			return "not_admin_owned: " + path + " (owner unreadable)", "", false
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
	// FileSIDs maps an account file of Named (lower case) to the enrolled
	// account's SID, when the file is in that account's home.
	FileSIDs map[string]string
	// Incomplete lists "<file>: <error>" for each machine file (written by
	// DefenseClaw as SYSTEM) that exists but could not be read. A scan with
	// any entry here proves nothing about the folders: prune removes none
	// and retire stays pending.
	Incomplete []string
	// Unverified are the account files that were a link, had a link at or
	// below their account home (link_in_account_path), were not a regular
	// file, too large, unreadable, did not answer in time, or that the list
	// could not locate for certain (a signed-out Hermes account, a moved
	// agent home). Prune notes them (skipped_unsafe) and keeps every
	// superseded folder while one is left (unverified_account_file). Retire cannot
	// tell whether they name a launch folder, so it names each in
	// still_named (unreadable) and never ends ok over one (rel-1-0-10
	// GAP-0882: an Administrator's retire was denied an account's .codex
	// folder and ended ok without reading its config).
	Unverified []windowsHookImageUnverifiedFile
}

// windowsHookImageUnverifiedFile is an account file the scan could not read
// or vouch for, and Err why.
type windowsHookImageUnverifiedFile struct {
	File windowsHookImageConfigFile
	Err  string
}

// Line is the "<file>: <error>" line of u.
func (u windowsHookImageUnverifiedFile) Line() string {
	return u.File.line(errors.New(u.Err))
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
// is refused (machine: incomplete; account: unverified). A machine path is
// looked at with lstat and readDir; an account path only through viewAccount
// (windowsHookImageAccountView): one with a link at or below its home is
// unverified (link_in_account_path) and never listed or read, and a watched
// account folder is listed through the handle the view opened. Lock files
// and temporaries are left out: writers hold them without sharing and they
// never name a hook.
func expandWindowsHookImageConfigFiles(
	entries []windowsHookImageConfigFile,
	lstat func(string) (fs.FileInfo, error),
	readDir func(string) ([]fs.DirEntry, error),
	viewAccount func(home, path string) (fs.FileInfo, []fs.DirEntry, error),
) ([]windowsHookImageConfigFile, []string, []windowsHookImageUnverifiedFile) {
	var files []windowsHookImageConfigFile
	var incomplete []string
	var unverified []windowsHookImageUnverifiedFile
	refuse := func(entry windowsHookImageConfigFile, err error) {
		if entry.User {
			unverified = append(unverified, windowsHookImageUnverifiedFile{File: entry, Err: err.Error()})
		} else {
			incomplete = append(incomplete, entry.line(err))
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
		if entry.Unverified != "" {
			refuse(entry, errors.New(entry.Unverified))
			continue
		}
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
	return files, incomplete, unverified
}

func windowsHookImageScanSkipsName(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".lock") || strings.Contains(lower, ".tmp")
}

// scanWindowsHookImageConfigFiles reads each regular file (a missing one is
// skipped) and records the launch folders of bin it names. A machine file
// that cannot be read makes the scan incomplete; an account file that
// cannot be read is unverified (see windowsHookImageConfigScan). read gets the
// whole entry: an account file is read only below its Home.
func scanWindowsHookImageConfigFiles(files []windowsHookImageConfigFile, bin string, read func(windowsHookImageConfigFile) ([]byte, error)) windowsHookImageConfigScan {
	scan := windowsHookImageConfigScan{Named: map[string][]string{}, UserFiles: map[string]bool{}, FileSIDs: map[string]string{}}
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
			if file.User {
				scan.Unverified = append(scan.Unverified, windowsHookImageUnverifiedFile{File: file, Err: err.Error()})
			} else {
				scan.Incomplete = append(scan.Incomplete, file.line(err))
			}
			continue
		}
		for _, folder := range windowsHookImageFoldersNamedIn(body, bin) {
			if folder == windowsHookImageUnknownFolder && !file.User {
				// A machine file that may name a folder: nothing is known.
				scan.Incomplete = append(scan.Incomplete, file.line(errWindowsHookImageUndecodable))
				continue
			}
			scan.Named[folder] = append(scan.Named[folder], file.Path)
			if file.User {
				scan.UserFiles[key] = true
				if file.SID != "" {
					scan.FileSIDs[key] = file.SID
				}
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
	// A PowerShell bridge names the hook only inside the base64 script of
	// its -EncodedCommand (the Copilot VS Code Local hooks, the Codex and
	// Cursor machine commands): read those scripts too, before the case is
	// folded (base64 is case-sensitive). Without them retire ended ok over a
	// Copilot file that named a launch folder, and the 1.0.9 guardian failed
	// that account (rel-1-0-10 GAP-0794); prune could remove such a folder.
	raw := string(body)
	scripts, undecodable := windowsHookImageEncodedScripts(raw, windowsHookImageEncodedScriptDepth)
	for _, script := range scripts {
		raw += "\n" + script
	}
	text := strings.ReplaceAll(strings.ToLower(raw), "/", `\`)
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
	out := make([]string, 0, len(found)+1)
	for digest := range found {
		out = append(out, digest)
	}
	sort.Strings(out)
	if undecodable {
		// A script that cannot be read may name any folder (GAP-0794
		// review F4): unknown keeps retire pending; prune keeps what it
		// keeps for an unreadable file.
		out = append(out, windowsHookImageUnknownFolder)
	}
	return out
}

// windowsHookImageEncodedArgument is a command-line switch (a hyphen, two,
// a slash, or the en dash, em dash or horizontal bar PowerShell reads as a
// hyphen); one followed by a blank or a colon is read, and its value is the word after it (windowsHookImageSwitchValue). Only
// a switch PowerShell reads as -EncodedCommand counts
// (windowsHookImageEncodedSwitch), and only on a line that starts
// powershell or pwsh.
var windowsHookImageEncodedArgument = lazyregexp.New(`(?:^|[\s"'])(?:--?|/|\x{2013}|\x{2014}|\x{2015})([A-Za-z]+)`)

// windowsHookImageSwitchValue is the word at text[at:] after blanks: up to
// a blank, a quote, a comma or a semicolon.
func windowsHookImageSwitchValue(text string, at int) string {
	for at < len(text) && (text[at] == ' ' || text[at] == '\t') {
		at++
	}
	end := at
	for end < len(text) && !strings.ContainsRune(" \t\r\n\"',;", rune(text[end])) {
		end++
	}
	return text[at:end]
}

// windowsHookImageUnknownFolder stands for the folders a file may name in a
// PowerShell script that could not be decoded (too large, not base64 of
// UTF-16LE): an account file holds retire back with it, a machine file
// makes the scan incomplete.
const windowsHookImageUnknownFolder = "unknown"

var errWindowsHookImageUndecodable = errors.New("holds a PowerShell -EncodedCommand value that could not be decoded, so it is not known which hook it starts")

// windowsHookImageEncodedScriptLimit bounds one base64 value the scan
// decodes; windowsHookImageEncodedScriptDepth how deep a decoded script's
// own -EncodedCommand is read.
const (
	windowsHookImageEncodedScriptLimit = 256 << 10
	windowsHookImageEncodedScriptDepth = 2
)

// windowsHookImageEncodedSwitch reports a switch name PowerShell (5.1 and
// 7) binds to -EncodedCommand: -e, -ec and every prefix of encodedcommand
// from -e on, with one or two dashes or a slash.
func windowsHookImageEncodedSwitch(name string) bool {
	name = strings.ToLower(name)
	return name == "ec" || strings.HasPrefix("encodedcommand", name)
}

// windowsHookImagePowerShellLine reports whether the line of text that holds
// offset starts a PowerShell (powershell or pwsh) command before offset.
func windowsHookImagePowerShellLine(text string, offset int) bool {
	start := strings.LastIndexAny(text[:offset], "\r\n") + 1
	if offset-start > 4096 {
		start = offset - 4096
	}
	line := strings.ToLower(text[start:offset])
	return strings.Contains(line, "powershell") || strings.Contains(line, "pwsh")
}

// windowsHookImageEncodedScripts returns the scripts (base64 of UTF-16LE)
// of every -EncodedCommand argument of a PowerShell command line in text
// and, to depth, in those scripts, and whether any such value could not be
// decoded.
func windowsHookImageEncodedScripts(text string, depth int) (scripts []string, undecodable bool) {
	if depth <= 0 {
		return nil, false
	}
	for _, match := range windowsHookImageEncodedArgument.FindAllStringSubmatchIndex(text, -1) {
		name := text[match[2]:match[3]]
		if match[3] >= len(text) || (text[match[3]] != ' ' && text[match[3]] != '\t' && text[match[3]] != ':') ||
			!windowsHookImageEncodedSwitch(name) || !windowsHookImagePowerShellLine(text, match[2]) {
			continue
		}
		start := match[3]
		if text[start] == ':' {
			// -EncodedCommand:<value>
			start++
		}
		value := windowsHookImageSwitchValue(text, start)
		// A JSON writer may escape the slash.
		value = strings.ReplaceAll(value, `\/`, "/")
		if len(value) > windowsHookImageEncodedScriptLimit {
			undecodable = true
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded)%2 != 0 {
			undecodable = true
			continue
		}
		units := make([]uint16, len(decoded)/2)
		for i := range units {
			units[i] = uint16(decoded[2*i]) | uint16(decoded[2*i+1])<<8
		}
		script := string(utf16.Decode(units))
		scripts = append(scripts, script)
		nested, unknown := windowsHookImageEncodedScripts(script, depth-1)
		scripts = append(scripts, nested...)
		undecodable = undecodable || unknown
	}
	return scripts, undecodable
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
	// An account file that could not be read or verified (a signed-out
	// Hermes account, a moved agent home, a link, a timeout) may name any
	// folder, so no superseded folder goes while one is left (rel-1-0-10
	// GAP-0891: such an account became one unread entry, and prune removed
	// the folders its Hermes files still named).
	if len(policy.Scan.Unverified) > 0 {
		return "unverified_account_file:" + policy.Scan.Unverified[0].File.Path
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
