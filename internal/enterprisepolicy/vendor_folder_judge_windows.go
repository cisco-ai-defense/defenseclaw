// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// vendorFolderVerdict is the one judgement of a vendor folder under
// ProgramData that holds a file DefenseClaw recorded (E3 case c, GAP-0756,
// GAP-0760). The publish and repair walk (reclaimPolicyDirsFor), the removal
// walk, machine-policy verify (VerifyAll) and the lifecycle's status, verify
// and refusals (InspectRecordedVendorFolders) all ask it, so they cannot
// disagree about the same folder.
type vendorFolderVerdict struct {
	// caseC is true when DefenseClaw did not create the folder and a file
	// DefenseClaw recorded lies under it. Every other folder is case a
	// (DefenseClaw created it: the repair may re-stamp it) or case b (the
	// documented takeover), and gets no verdict here.
	caseC bool
	// file is the recorded file under the folder.
	file string
	// refused is set when the folder does not protect that file: another
	// account can delete or replace it, or, for a vendor that loads more than
	// that one file name from the folder, add a file the vendor loads beside
	// it. Nil means the folder is left as it is. A refused folder is put back
	// to DefenseClaw's protected form only by the safe transaction below.
	refused *recordedVendorFolderError
}

// judgeRecordedVendorFolder decides one existing component cur of a vendor
// policy path whose own check failed with trustErr. last marks the folder
// that holds the policy file itself. The recorded file keeps its own
// administrator-only access list, which every read and publish judges. That
// protects it only while no other account can delete or replace an entry of
// the folder (the ancestor rule), and, in the folder that holds the policy
// file, while no other account can add a file the vendor loads beside it
// (Copilot's policy.d, OpenCode's opencode.jsonc: g582 review 7 M1). A vendor
// that reads one file name (Devin, in both of its folders: hooks.json) is not opened by
// an added file, so the inherited ProgramData default (Users may create
// files) passes there.
func judgeRecordedVendorFolder(recorded *recordedPolicyPaths, cur string, last bool, use policyFolderUse, trustErr error) vendorFolderVerdict {
	file := recorded.heldFile(cur)
	if file == "" || recorded.createdFolder(cur) {
		return vendorFolderVerdict{}
	}
	verdict := vendorFolderVerdict{caseC: true, file: file}
	switch {
	case !last:
		verdict.refused = &recordedVendorFolderError{dir: cur, file: file, err: trustErr}
	default:
		if replaceErr := validateTrustedDir(cur); replaceErr != nil {
			verdict.refused = &recordedVendorFolderError{dir: cur, file: file, err: replaceErr}
		} else if use.siblings != "" {
			verdict.refused = &recordedVendorFolderError{dir: cur, file: file, err: trustErr, siblings: use.siblings}
		}
	}
	return verdict
}

// The safe transaction (GAP-0756, GAP-0760, GAP-0763; lead ruling of
// 2026-11-07). A case c folder that does not protect DefenseClaw's recorded
// file is put back to DefenseClaw's owner and protected access list only
// after all of this holds, on handles that stay open until the stamp is done:
//
//  1. the folder opens without delete sharing, so no other handle can hold
//     it with delete access, and it is a plain folder;
//  2. every file DefenseClaw recorded under it opens for reading without
//     write or delete sharing (no other handle can write or delete it, and
//     none denies reading), is a regular file with one link, is
//     administrator-only, and still has the bytes DefenseClaw recorded;
//  3. a vendor that loads every file in the folder finds nothing in it that
//     DefenseClaw did not write.
//
// Anything else is refused by name and nothing is changed.
type reprotectTx struct {
	dir   windows.Handle
	files []windows.Handle
}

func (tx *reprotectTx) close() {
	for _, handle := range tx.files {
		_ = windows.CloseHandle(handle)
	}
	tx.files = nil
	if tx.dir != 0 && tx.dir != windows.InvalidHandle {
		_ = windows.CloseHandle(tx.dir)
		tx.dir = 0
	}
}

// openNoDeleteShare opens path itself (never a reparse target) with share
// mode share, which never includes delete sharing.
func openNoDeleteShare(path string, access, share uint32, flags uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func heldOrOpenError(path string, err error, what string) error {
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return fmt.Errorf("another program holds %s open (%s)", path, what)
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return fmt.Errorf("%s is not there", path)
	}
	return fmt.Errorf("could not open %s: %v", path, err)
}

func readHandleBounded(handle windows.Handle, limit int64) ([]byte, error) {
	var data []byte
	buffer := make([]byte, 64<<10)
	for {
		var read uint32
		if err := windows.ReadFile(handle, buffer, &read, nil); err != nil {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return nil, err
		}
		if read == 0 {
			break
		}
		data = append(data, buffer[:read]...)
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("it exceeds %d bytes", limit)
		}
	}
	return data, nil
}

// beginReprotect runs steps 1 to 3 of the safe transaction for cur and returns
// the open handles, or the reason the folder cannot be re-protected. last
// marks the folder that holds the policy file. forStamp asks for the access
// the stamp needs.
func beginReprotect(recorded *recordedPolicyPaths, cur string, last bool, use policyFolderUse, forStamp bool) (*reprotectTx, error) {
	// Listing access is data access: an open that asks for none is not
	// checked against other handles' share modes at all, so without it a
	// handle that holds the folder with delete access would not be seen.
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY)
	if forStamp {
		access |= windows.WRITE_DAC | windows.WRITE_OWNER
	}
	dir, err := openNoDeleteShare(cur, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		return nil, heldOrOpenError(cur, err, "with delete access, so it could be renamed or removed while it is being protected")
	}
	tx := &reprotectTx{dir: dir}
	ok := false
	defer func() {
		if !ok {
			tx.close()
		}
	}()
	if err := requirePlainDirectory(dir, cur); err != nil {
		return nil, err
	}
	for _, file := range recorded.filesUnder(cur) {
		digest := recorded.digests[strings.ToLower(file)]
		info, err := os.Lstat(file)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("DefenseClaw's recorded file %s is not there (it was renamed or removed)", file)
		}
		if err != nil {
			return nil, fmt.Errorf("could not inspect DefenseClaw's recorded file %s: %v", file, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("DefenseClaw's recorded file %s is not a regular file", file)
		}
		handle, err := openNoDeleteShare(file, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, 0)
		if err != nil {
			return nil, heldOrOpenError(file, err, "so that it can be written or deleted, or it does not let others read it")
		}
		tx.files = append(tx.files, handle)
		var fileInfo windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &fileInfo); err != nil {
			return nil, fmt.Errorf("could not inspect DefenseClaw's recorded file %s: %v", file, err)
		}
		if fileInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
			return nil, fmt.Errorf("DefenseClaw's recorded file %s is not a regular file", file)
		}
		if fileInfo.NumberOfLinks != 1 {
			return nil, fmt.Errorf("DefenseClaw's recorded file %s has %d hard links", file, fileInfo.NumberOfLinks)
		}
		if err := validateTrustedFileItself(file); err != nil {
			return nil, fmt.Errorf("DefenseClaw's recorded file %s is not administrator-only: %v", file, err)
		}
		if digest == "" {
			return nil, fmt.Errorf("DefenseClaw's record of %s holds no digest to check it against", file)
		}
		data, err := readHandleBounded(handle, policyFileLimit)
		if err != nil {
			return nil, fmt.Errorf("could not read DefenseClaw's recorded file %s: %v", file, err)
		}
		if sha256Hex(data) != digest {
			return nil, fmt.Errorf("DefenseClaw's recorded file %s was changed after DefenseClaw wrote it (it no longer matches DefenseClaw's record)", file)
		}
	}
	if last && use.siblings != "" {
		entries, err := os.ReadDir(cur)
		if err != nil {
			return nil, fmt.Errorf("could not list %s: %v", cur, err)
		}
		for _, entry := range entries {
			if !recorded.namesFileIn(cur, entry.Name()) {
				return nil, fmt.Errorf("%s holds %s, which DefenseClaw did not write and the vendor would load beside DefenseClaw's file", cur, filepath.Join(cur, entry.Name()))
			}
		}
	}
	ok = true
	return tx, nil
}

// stamp puts the folder back to DefenseClaw's owner and protected access list
// through the open handle and returns the descriptor before and after.
func (tx *reprotectTx) stamp() (string, string, error) {
	before := handleDescriptorSDDL(tx.dir)
	sd, err := protectedDirDescriptor()
	if err != nil {
		return before, "", err
	}
	// SetKernelObjectSecurity sets exactly this object's descriptor; unlike
	// SetNamedSecurityInfo it never walks the children.
	if err := windows.SetKernelObjectSecurity(tx.dir,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd); err != nil {
		return before, "", err
	}
	return before, handleDescriptorSDDL(tx.dir), nil
}

func handleDescriptorSDDL(handle windows.Handle) string {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	return sd.String()
}

// reprotectBeforeStamp runs after the safe transaction's checks and before
// its stamp, while the handles are open; tests replace it to change the
// folder in between.
var reprotectBeforeStamp = func(string) {}

// reprotectRecordedVendorFolder runs the safe transaction for the weak case c
// folder cur: it checks, then stamps, on the same handles. It returns the
// reason it refused, or the folder it re-protected. A refusal found after the
// stamp (a file added in between that cannot be moved aside, a folder that
// still fails its check) also returns the re-protected folder, so the change
// that was made is reported and audited.
func reprotectRecordedVendorFolder(opts Options, recorded *recordedPolicyPaths, cur string, last bool, use policyFolderUse, refused *recordedVendorFolderError, validate func(string) error) (ReprotectedFolder, error) {
	var out ReprotectedFolder
	err := reclaimDirHandle(cur, func() error {
		tx, err := beginReprotect(recorded, cur, last, use, true)
		if err != nil {
			return err
		}
		defer tx.close()
		reprotectBeforeStamp(cur)
		before, after, err := tx.stamp()
		if err != nil {
			return fmt.Errorf("DefenseClaw could not apply its access list to %s: %v", cur, err)
		}
		out = ReprotectedFolder{Dir: cur, File: refused.file, Why: refused.reason(), Before: before, After: after}
		return nil
	})
	if err != nil {
		return ReprotectedFolder{}, err
	}
	if last && use.siblings != "" {
		displaced, err := displaceAddedDuringReprotect(opts, recorded, cur)
		out.Displaced = displaced
		if err != nil {
			return out, err
		}
	}
	if validateErr := validate(cur); validateErr != nil {
		return out, fmt.Errorf("%s still does not protect DefenseClaw's file after DefenseClaw applied its access list: %v", cur, validateErr)
	}
	return out, nil
}

// displaceAddedDuringReprotect lists cur again once the stamp is done. The
// transaction's folder handle shares writing, so an account that could add a
// file before the stamp may have added one between the transaction's listing
// and the stamp; after the stamp no such account can add one, so this listing
// is final. Each entry DefenseClaw did not write is moved aside, as the
// publish moves aside a file a standard user left in the folder
// (displaceUntrustedPolicyFiles, and OpenCode's displaceUntrustedPolicyFile).
// One DefenseClaw cannot move aside (an administrator's, which DefenseClaw
// never removes) refuses the transaction by name. It returns what it moved.
func displaceAddedDuringReprotect(opts Options, recorded *recordedPolicyPaths, cur string) ([]string, error) {
	entries, err := os.ReadDir(cur)
	if err != nil {
		return nil, fmt.Errorf("could not list %s again after DefenseClaw applied its access list: %v", cur, err)
	}
	var notes []string
	for _, entry := range entries {
		if recorded.namesFileIn(cur, entry.Name()) {
			continue
		}
		path := filepath.Join(cur, entry.Name())
		note, err := displacePlanted(opts, path)
		if err != nil {
			return notes, fmt.Errorf("%s appeared in %s while DefenseClaw put the folder back to its protected form, and "+
				"DefenseClaw could not move it aside (%v); the vendor would load it beside DefenseClaw's file: check it and "+
				"remove it, then run `%s`. %s", path, cur, err, managed.WindowsSetupCommand("/ensure"), managed.WindowsSetupSource)
		}
		notes = append(notes, note)
	}
	return notes, nil
}

// weakVendorFolder is a case c folder that does not protect DefenseClaw's
// recorded file, as the inspection finds it.
type weakVendorFolder struct {
	connector string
	last      bool
	use       policyFolderUse
	validate  func(string) error
	refused   *recordedVendorFolderError
}

// VendorFolderProblem is a vendor folder DefenseClaw did not create that
// holds a file DefenseClaw recorded and does not protect it. Message names
// the folder, the unsafe access entry and what happens next.
type VendorFolderProblem struct {
	Connector string
	Dir       string
	File      string
	Message   string
	// Reprotectable is true when nothing blocks the safe transaction: the
	// next reconcile (the guardian pass, Setup /ensure, /repair or
	// /reconcile) puts the folder back to DefenseClaw's protected form and
	// reports it. Otherwise Message names what blocks it and the
	// administrator's fix.
	Reprotectable bool
	Blocker       string
	// UnrecordedFile marks a problem that is a file, not a folder: File is a
	// vendor policy file DefenseClaw has no record of writing, that another
	// account can change and that the publish cannot move aside, so it cannot
	// publish through it (GAP-0930). Dir is the folder that holds it.
	UnrecordedFile bool
	// PendingMoveAside is set for such a file that a standard user owns: the
	// next reconcile (the guardian pass, or Setup /ensure) moves it aside to a
	// hidden name, so nothing blocks the action, but the connector is not
	// covered until it has (machine-policy verify says the same).
	PendingMoveAside bool
	// Conflict marks a machine-policy verify conflict that is neither of the
	// above (an administrator's file that is not valid JSON, a missing
	// managed plugin): Message is the conflict text.
	Conflict bool
}

// goOwnedVendorTarget is one Go-owned Windows machine policy target among the
// connectors and the vendor policy paths it publishes into.
type goOwnedVendorTarget struct {
	name  string
	paths []string
}

// goOwnedVendorTargets lists the Go-owned Windows targets among connectors,
// with their paths, as the publish walks them: a target publishes into the
// first path only, except Devin with its pre-rename companion folder.
func goOwnedVendorTargets(opts Options, connectors []string) []goOwnedVendorTarget {
	var out []goOwnedVendorTarget
	for _, name := range withCompanions(normalizeConnectors(connectors)) {
		if !windowsGoOwnedTargets[name] {
			continue
		}
		target, ok := TargetFor(name)
		if !ok {
			continue
		}
		paths, err := target.Paths(opts)
		if err != nil {
			continue
		}
		// Devin branches kept on purpose (g877b review S6). A 1.0.9 install writes
		// nothing into the Devin or pre-rename Devin folders (GAP-0787), so these
		// branches are reachable only on a host where a 1.0.5 to 1.0.8 install recorded
		// a Cascade file there: the supported 1.0.5-1.0.8 to 1.0.9 upgrade on the
		// Windows standalone profile. 1.0.0 to 1.0.4 never wrote it and a fresh 1.0.9
		// install has no record, so nothing else reaches them. They go with the
		// Cascade withdrawal in 1.1 (devin_cascade.go), when no upgrade from 1.0.5 to
		// 1.0.8 remains supported.
		if name != ConnectorDevinCascade && len(paths) > 1 {
			paths = paths[:1]
		}
		out = append(out, goOwnedVendorTarget{name: name, paths: paths})
	}
	return out
}

// vendorFolderInspectable is false off the standalone profile (Secure Client
// keeps the takeover of 1.0.8), on a test tree that skips the trust checks
// and off Windows: the inspection judges nothing there.
func vendorFolderInspectable(opts Options) bool {
	return opts.goos() == "windows" && !opts.SkipTrustChecks && reclaimRefusesContentDrift()
}

// weakVendorFolders walks the policy folders of the Go-owned Windows
// targets among connectors, as reclaimPolicyDirsFor does, and returns each
// case c folder that does not protect DefenseClaw's recorded file. It takes
// nothing over and writes nothing.
func weakVendorFolders(opts Options, connectors []string) (*recordedPolicyPaths, []weakVendorFolder) {
	if !vendorFolderInspectable(opts) {
		return nil, nil
	}
	recorded := loadRecordedPolicyPaths(opts)
	var weak []weakVendorFolder
	seen := map[string]bool{}
	for _, target := range goOwnedVendorTargets(opts, connectors) {
		use := windowsGoOwnedFolderUse(target.name)
		for _, path := range target.paths {
			found := inspectRecordedVendorFolder(opts, &recorded, platformPath(opts, dirFor(opts, path)), use)
			if found == nil || seen[strings.ToLower(found.refused.dir)] {
				continue
			}
			seen[strings.ToLower(found.refused.dir)] = true
			found.connector = target.name
			weak = append(weak, *found)
		}
	}
	return &recorded, weak
}

// The unrecorded policy file (GAP-0930). A vendor folder that holds no file
// DefenseClaw recorded is case b: the first publish takes it over, and an
// empty one passes. The publish then reads the file it writes to and moves
// aside a file a standard user left in the folder, but a file an
// administrator owns is never moved (displacePlanted), and a file another
// account can change is never read or merged into (readPolicyFile). Such a
// file is what a purge leaves behind when it keeps a recorded policy file
// another account can change (keepUntrustedRecordedFile, GAP-0761): the next
// install has no record of it, so the folder looks like case b, and the
// publish fails on the file while the lifecycle, which only judged recorded
// files, reported the connector covered and machine-policy verify reported it
// uncovered. The same verdict is now asked of every vendor policy file the
// vendor loads from a folder DefenseClaw publishes into, so they agree.

// unrecordedPolicyFileCandidates says, for a Go-owned target that publishes
// into path, the folder and which files in it the vendor loads as machine
// policy. Devin is not asked: since GAP-0787 it publishes nothing into its
// ProgramData folders, so no hooks.json there is a coverage claim. OpenCode on
// the per-user route and a connector whose ownership is off publish nothing
// either.
func unrecordedPolicyFileCandidates(opts Options, name, path string) (dir string, files []string, use policyFolderUse) {
	dir = platformPath(opts, dirFor(opts, path))
	switch name {
	case ConnectorCopilot:
		if opts.PolicyFor(name).Ownership == config.MachinePolicyOwnershipOff {
			return "", nil, policyFolderUse{}
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", nil, policyFolderUse{}
		}
		for _, entry := range entries {
			// DefenseClaw's own drop-in name is replaced by the publish
			// whatever its access list says (replaceUntrustedPolicyFile).
			if effectivePolicyDropIn(entry) && !strings.EqualFold(entry.Name(), DefenseClawDropInName) {
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
		return dir, files, copilotFolderUse
	case ConnectorOpenCode:
		if openCodePerUserFallback(opts, opts.PolicyFor(name), &State{}) {
			return "", nil, policyFolderUse{}
		}
		return dir, []string{filepath.Join(dir, "opencode.jsonc"), filepath.Join(dir, "opencode.json")}, opencodeFolderUse
	}
	return "", nil, policyFolderUse{}
}

// policyFileWouldBeMovedAside reports whether the publish moves path aside
// instead of failing on it: an account other than SYSTEM, Administrators and
// TrustedInstaller owns it (displacePlanted). It only reads the owner, through
// a handle that does not follow a reparse point and asks for no data access,
// so no other handle's sharing mode can stop it.
func policyFileWouldBeMovedAside(path string) (bool, error) {
	handle, err := openDirNoFollow(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return false, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	privileged, err := ownedByPrivilegedPrincipal(handle, path)
	return !privileged, err
}

// unrecordedPolicyFileProblems returns, for each Go-owned target among
// connectors, each vendor policy file (or other entry) in its folder that
// DefenseClaw has no record of and that the publish cannot use:
//   - a regular file that an account other than SYSTEM, Administrators and
//     TrustedInstaller can change, and that an administrator owns (the
//     publish never moves such a file aside, and never reads it);
//   - the same file owned by a standard user: the publish moves it aside, so
//     it is PendingMoveAside under ownership merge, and a plain problem under
//     verify_only, where nothing moves it;
//   - a link or other entry that is not a regular file (the publish removes
//     one a standard user owns, and fails on one an administrator owns).
//
// A trusted file (administrator-only), DefenseClaw's own drop-in name and an
// empty folder give none, as before. It writes nothing.
func unrecordedPolicyFileProblems(opts Options, connectors []string) []VendorFolderProblem {
	if !vendorFolderInspectable(opts) {
		return nil
	}
	recorded := loadRecordedPolicyPaths(opts)
	var problems []VendorFolderProblem
	seen := map[string]bool{}
	for _, target := range goOwnedVendorTargets(opts, connectors) {
		if len(target.paths) == 0 {
			continue
		}
		dir, files, use := unrecordedPolicyFileCandidates(opts, target.name, target.paths[0])
		// A link on the folder itself is the folder walk's matter (the
		// publish replaces it), not a file's.
		if len(files) == 0 || programDataPathHasLink(opts, dir) {
			continue
		}
		merge := opts.PolicyFor(target.name).Ownership == config.MachinePolicyOwnershipMerge
		for _, file := range files {
			key := strings.ToLower(file)
			if seen[key] || recorded.namesFileIn(dir, filepath.Base(file)) {
				continue
			}
			info, err := os.Lstat(file)
			if err != nil {
				continue
			}
			var trustErr error
			if info.Mode().IsRegular() {
				if trustErr = validateTrustedFileItself(file); trustErr == nil {
					continue
				}
			} else {
				trustErr = fmt.Errorf("%s is not a regular file", file)
			}
			userOwned, ownerErr := policyFileWouldBeMovedAside(file)
			problem := VendorFolderProblem{
				Connector: target.name, Dir: dir, File: file, Blocker: trustErr.Error(), UnrecordedFile: true,
				PendingMoveAside: userOwned && ownerErr == nil && merge,
			}
			problem.Message = unrecordedPolicyFileMessage(file, info.Mode().IsRegular(), trustErr, ownerErr, userOwned && ownerErr == nil, problem.PendingMoveAside, use)
			seen[key] = true
			problems = append(problems, problem)
		}
	}
	return problems
}

// UnrecordedPolicyFileProblems is the unrecorded-file part of
// InspectRecordedVendorFolders, for the guardian pass to alert on once its
// publish has had its chance to move a file aside.
func UnrecordedPolicyFileProblems(opts Options, connectors []string) []VendorFolderProblem {
	return unrecordedPolicyFileProblems(opts, connectors)
}

// unrecordedFileFix is the one recovery that works for every cause of an
// untrusted policy file: an explicit or an inherited entry, any number of
// accounts, a null access list, an entry type the check does not understand,
// a file a standard user owns. It gives the file to Administrators, replaces
// its access list with the inherited default, then replaces that with the
// access list DefenseClaw gives its own vendor policy files (SYSTEM and
// Administrators full control, Users read and execute). A link or other
// entry that is not a regular file is moved aside instead.
func unrecordedFileFix(path string, regular bool) string {
	if !regular {
		return `Move-Item -LiteralPath "` + path + `" -Destination "` + path + `.moved-aside"`
	}
	commands := [][]string{
		{"icacls", path, "/setowner", "*" + adminOwnerSIDStr},
		{"icacls", path, "/reset"},
		{"icacls", path, "/inheritance:r", "/grant:r", "*" + systemSIDStr + ":F", "*" + adminOwnerSIDStr + ":F", "*" + usersSIDStr + ":RX"},
	}
	rendered := make([]string, 0, len(commands))
	for _, command := range commands {
		rendered = append(rendered, renderWindowsCommand(command))
	}
	return strings.Join(rendered, ", then ")
}

// unrecordedPolicyFileMessage names the file, why DefenseClaw cannot publish
// through it and the administrator's recovery, in the words of the vendor
// folder refusal (recordedVendorFolderError) and the purge's kept-file warning.
func unrecordedPolicyFileMessage(file string, regular bool, trustErr, ownerErr error, userOwned, pending bool, use policyFolderUse) string {
	loads := ""
	if use.siblings != "" {
		loads = ", and " + use.siblings
	}
	owner := ""
	if ownerErr != nil {
		owner = fmt.Sprintf(" (DefenseClaw could not read who owns it either: %v)", ownerErr)
	}
	if pending {
		return fmt.Sprintf("%s is not covered yet: DefenseClaw has no record of writing it and a standard account owns it and can change it (%v)%s%s; "+
			"DefenseClaw moves such a file aside to a hidden name at its next reconcile (the guardian pass, or `%s`), and this connector is covered once it has. %s",
			file, trustErr, owner, loads, managed.WindowsSetupCommand("/ensure"), managed.WindowsSetupSource)
	}
	why := "an administrator owns it, so DefenseClaw cannot read it, merge into it or move it aside"
	if userOwned {
		why = "ownership: verify_only keeps DefenseClaw from moving a standard account's file aside"
	}
	if !regular {
		why = "DefenseClaw does not remove or replace an entry an administrator owns"
		if userOwned {
			why = "ownership: verify_only keeps DefenseClaw from removing a standard account's entry"
		}
	}
	return fmt.Sprintf("%s is not covered: DefenseClaw has no record of writing it and %v%s%s; %s, so it cannot publish its hooks through it; "+
		"this connector is not protected until an administrator fixes the file: from an elevated PowerShell prompt run %s, check the file, then run `%s`. %s",
		file, unrecordedCause(regular, trustErr), owner, loads, why, unrecordedFileFix(file, regular), managed.WindowsSetupCommand("/ensure"), managed.WindowsSetupSource)
}

func unrecordedCause(regular bool, trustErr error) string {
	if regular {
		return fmt.Sprintf("an account other than SYSTEM, Administrators and TrustedInstaller can change it (%v)", trustErr)
	}
	return "it is a link or other entry, not a regular file"
}

// GoOwnedPolicyProblems is what Setup's status and verify say about the
// Go-owned Windows machine policy (Copilot's policy.d, OpenCode's managed
// config, Devin's withdrawn files): the vendor folder and unrecorded file
// problems of InspectRecordedVendorFolders, then every other conflict or
// error that machine-policy verify raises for those connectors, from the
// same function (verifyConnector), so status never claims coverage that
// machine-policy verify denies (GAP-0930). A connector on the per-user route
// or with ownership off has none. Standalone Windows only.
func GoOwnedPolicyProblems(opts Options, connectors []string) []VendorFolderProblem {
	if !vendorFolderInspectable(opts) || opts.Validate() != nil {
		return nil
	}
	problems := InspectRecordedVendorFolders(opts, connectors)
	known := map[string]bool{}
	var mentioned []string
	for _, problem := range problems {
		known[problem.Message] = true
		for _, name := range []string{problem.File, problem.Dir} {
			if name != "" {
				mentioned = append(mentioned, strings.ToLower(name))
			}
		}
	}
	covered := func(text string) bool {
		text = strings.ToLower(text)
		for _, name := range mentioned {
			if strings.Contains(text, name) {
				return true
			}
		}
		return false
	}
	for _, target := range goOwnedVendorTargets(opts, connectors) {
		state, err := verifyConnector(opts, target.name)
		if state.Route != RouteMachinePolicy {
			continue
		}
		texts := slices.Clone(state.Conflicts)
		if err != nil {
			texts = append(texts, err.Error())
		}
		for _, text := range texts {
			if known[text] || covered(text) {
				continue
			}
			known[text] = true
			problems = append(problems, VendorFolderProblem{Connector: target.name, Message: text, Conflict: true})
		}
	}
	return problems
}

// InspectRecordedVendorFolders judges, without writing, the vendor folders of
// the Go-owned Windows machine policy targets among connectors (Copilot,
// OpenCode, and Devin with its pre-rename companion folder) with the verdict a
// publish, a repair and the removal reach. It returns one problem per folder
// that is case c and does not protect DefenseClaw's recorded file, and says
// whether the safe transaction would put it right. It reports nothing off the
// standalone profile, where a vendor folder keeps the takeover (Secure
// Client), and nothing for a folder DefenseClaw created or that holds no
// recorded file, which the next publish takes over. It also returns a problem
// (UnrecordedFile) for each vendor policy file DefenseClaw has no record of
// that another account can change and the publish cannot move aside, in a
// folder of either kind (GAP-0930).
func InspectRecordedVendorFolders(opts Options, connectors []string) []VendorFolderProblem {
	recorded, weak := weakVendorFolders(opts, connectors)
	var problems []VendorFolderProblem
	for _, folder := range weak {
		problem := VendorFolderProblem{Connector: folder.connector, Dir: folder.refused.dir, File: folder.refused.file}
		// The same checks as the transaction, on the same opens: the
		// recorded files share reading only, so the verdict cannot differ
		// from the one Setup or the guardian reaches. For the instant these
		// read handles are open, a guardian write of a recorded file fails
		// with a sharing violation and is made again at the next pass. Only
		// a weak folder is inspected this way, and the guardian rewrites a
		// recorded file only when it changed, so the window is negligible.
		tx, err := beginReprotect(recorded, folder.refused.dir, folder.last, folder.use, false)
		if err == nil {
			tx.close()
			problem.Reprotectable = true
			problem.Message = fmt.Sprintf("%s; DefenseClaw did not create this folder and will put it back to its protected form at the next "+
				"reconcile (the guardian pass, or `%s`): nothing holds it open, DefenseClaw's recorded files in it match "+
				"their records and it holds nothing else DefenseClaw did not account for", folder.refused.reason(), managed.WindowsSetupCommand("/ensure"))
		} else {
			problem.Blocker = err.Error()
			blocked := *folder.refused
			blocked.blocker = problem.Blocker
			problem.Message = blocked.Error()
		}
		problems = append(problems, problem)
	}
	return append(problems, unrecordedOutsideWeakFolders(unrecordedPolicyFileProblems(opts, connectors), problems)...)
}

// unrecordedOutsideWeakFolders drops the unrecorded-file problems of a folder
// that is already reported as weak: that folder's message names the foreign
// file ("which DefenseClaw did not write"), and its own fix covers it.
func unrecordedOutsideWeakFolders(unrecorded, folders []VendorFolderProblem) []VendorFolderProblem {
	var out []VendorFolderProblem
	for _, problem := range unrecorded {
		inWeakFolder := false
		for _, folder := range folders {
			if strings.EqualFold(folder.Dir, problem.Dir) {
				inWeakFolder = true
			}
		}
		if !inWeakFolder {
			out = append(out, problem)
		}
	}
	return out
}

// reprotectWalks bounds the walks of one ReprotectRecordedVendorFolders call.
// Every walk but the last heals at least one folder of a vendor path, and no
// vendor path has more folders below ProgramData than this.
const reprotectWalks = 8

// ReprotectRecordedVendorFolders is InspectRecordedVendorFolders that also
// runs the safe transaction for each folder it can put right: it returns the
// folders it re-protected, and the problems it could not (with what blocks
// them). Setup calls it before an install-like action or a reconcile, so a
// weak but clean folder is healed and reported instead of left to the next
// guardian pass. The inspection stops at the first folder of a path that
// fails its check, and the check of a folder includes the folders above it,
// so a heal can uncover the next weak folder of the same path (a weak
// GitHub\Copilot hides a weak policy.d). It walks again until nothing is weak
// or a walk heals nothing, so one call heals the whole path, as the publish
// walk does.
func ReprotectRecordedVendorFolders(opts Options, connectors []string) ([]ReprotectedFolder, []VendorFolderProblem) {
	var healed []ReprotectedFolder
	// stuck are the refusals found after a stamp. Such a folder is reported
	// once and not tried again in a later walk.
	var stuck, blocked []VendorFolderProblem
	stuckDirs := map[string]bool{}
	for walk := 0; walk < reprotectWalks; walk++ {
		recorded, weak := weakVendorFolders(opts, connectors)
		blocked = nil
		progress := false
		for _, folder := range weak {
			key := strings.ToLower(filepath.Clean(folder.refused.dir))
			if stuckDirs[key] {
				continue
			}
			done, err := reprotectRecordedVendorFolder(opts, recorded, folder.refused.dir, folder.last, folder.use, folder.refused, folder.validate)
			if done.Dir != "" {
				done.Connector = folder.connector
				healed = append(healed, done)
				progress = true
			}
			if err == nil {
				continue
			}
			refusal := *folder.refused
			refusal.blocker = err.Error()
			problem := VendorFolderProblem{
				Connector: folder.connector, Dir: refusal.dir, File: refusal.file, Message: refusal.Error(), Blocker: refusal.blocker,
			}
			if done.Dir != "" {
				stuckDirs[key] = true
				stuck = append(stuck, problem)
			} else {
				blocked = append(blocked, problem)
			}
		}
		if !progress {
			break
		}
	}
	// An unrecorded file another account can change is not something the safe
	// transaction heals: it is refused with the administrator's recovery.
	// A file a standard user owns is moved aside by the publish that follows,
	// so it blocks nothing.
	folders := append(slices.Clone(stuck), blocked...)
	for _, problem := range unrecordedOutsideWeakFolders(unrecordedPolicyFileProblems(opts, connectors), folders) {
		if !problem.PendingMoveAside {
			blocked = append(blocked, problem)
		}
	}
	return healed, append(stuck, blocked...)
}

// VendorFolderRefusal is one vendor folder a publish refused because it does
// not protect DefenseClaw's recorded file: the folder and the refusal text.
type VendorFolderRefusal struct {
	Dir     string
	Message string
}

// VendorFolderRefusals returns the refusal of each vendor folder that err
// carries (a publish joins the errors of its connectors), once per folder, in
// order; nil when there is none.
func VendorFolderRefusals(err error) []VendorFolderRefusal {
	var out []VendorFolderRefusal
	seen := map[string]bool{}
	var walk func(error)
	walk = func(err error) {
		switch typed := err.(type) {
		case nil:
		case *recordedVendorFolderError:
			if key := strings.ToLower(filepath.Clean(typed.dir)); !seen[key] {
				seen[key] = true
				out = append(out, VendorFolderRefusal{Dir: typed.dir, Message: typed.Error()})
			}
		case interface{ Unwrap() []error }:
			for _, inner := range typed.Unwrap() {
				walk(inner)
			}
		case interface{ Unwrap() error }:
			walk(typed.Unwrap())
		}
	}
	walk(err)
	return out
}

// inspectRecordedVendorFolder walks dir from ProgramData as
// reclaimPolicyDirsFor does and stops at the first component that fails its
// check; it takes nothing over.
func inspectRecordedVendorFolder(opts Options, recorded *recordedPolicyPaths, dir string, use policyFolderUse) *weakVendorFolder {
	root, rel, ok := programDataRelative(opts, dir)
	if !ok || validateTrustedDir(root) != nil {
		return nil
	}
	cur := root
	parts := strings.Split(rel, `\`)
	for index, part := range parts {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return nil
		}
		last := index == len(parts)-1
		validate := validateTrustedDir
		if last {
			validate = validateTrustedLeafDir
		}
		trustErr := validate(cur)
		if trustErr == nil {
			continue
		}
		if !plainDirectory(info) {
			// A planted file or link: the publish replaces it, and the
			// machine policy verify reports the path.
			return nil
		}
		verdict := judgeRecordedVendorFolder(recorded, cur, last, use, trustErr)
		if verdict.refused == nil {
			continue
		}
		return &weakVendorFolder{last: last, use: use, validate: validate, refused: verdict.refused}
	}
	return nil
}
