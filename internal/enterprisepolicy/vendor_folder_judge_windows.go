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
	"strings"

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
// that reads one file name (Devin and Windsurf: hooks.json) is not opened by
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

// reprotectRecordedVendorFolder runs the safe transaction for the weak case c
// folder cur: it checks, then stamps, on the same handles. It returns the
// reason it refused, or the folder it re-protected.
func reprotectRecordedVendorFolder(recorded *recordedPolicyPaths, cur string, last bool, use policyFolderUse, refused *recordedVendorFolderError, validate func(string) error) (ReprotectedFolder, error) {
	var out ReprotectedFolder
	err := reclaimDirHandle(cur, func() error {
		tx, err := beginReprotect(recorded, cur, last, use, true)
		if err != nil {
			return err
		}
		defer tx.close()
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
	if validateErr := validate(cur); validateErr != nil {
		return ReprotectedFolder{}, fmt.Errorf("%s still does not protect DefenseClaw's file after DefenseClaw applied its access list: %v", cur, validateErr)
	}
	return out, nil
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
}

// weakVendorFolders walks the policy folders of the Go-owned Windows
// targets among connectors, as reclaimPolicyDirsFor does, and returns each
// case c folder that does not protect DefenseClaw's recorded file. It takes
// nothing over and writes nothing.
func weakVendorFolders(opts Options, connectors []string) (*recordedPolicyPaths, []weakVendorFolder) {
	if opts.goos() != "windows" || opts.SkipTrustChecks || !reclaimRefusesContentDrift() {
		return nil, nil
	}
	recorded := loadRecordedPolicyPaths(opts)
	var weak []weakVendorFolder
	seen := map[string]bool{}
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
		if name != ConnectorDevinCascade && len(paths) > 1 {
			paths = paths[:1]
		}
		use := windowsGoOwnedFolderUse(name)
		for _, path := range paths {
			found := inspectRecordedVendorFolder(opts, &recorded, platformPath(opts, dirFor(opts, path)), use)
			if found == nil || seen[strings.ToLower(found.refused.dir)] {
				continue
			}
			seen[strings.ToLower(found.refused.dir)] = true
			found.connector = name
			weak = append(weak, *found)
		}
	}
	return &recorded, weak
}

// InspectRecordedVendorFolders judges, without writing, the vendor folders of
// the Go-owned Windows machine policy targets among connectors (Copilot,
// OpenCode, and Devin with its Windsurf companion) with the verdict a
// publish, a repair and the removal reach. It returns one problem per folder
// that is case c and does not protect DefenseClaw's recorded file, and says
// whether the safe transaction would put it right. It reports nothing off the
// standalone profile, where a vendor folder keeps the takeover (Secure
// Client), and nothing for a folder DefenseClaw created or that holds no
// recorded file, which the next publish takes over.
func InspectRecordedVendorFolders(opts Options, connectors []string) []VendorFolderProblem {
	recorded, weak := weakVendorFolders(opts, connectors)
	var problems []VendorFolderProblem
	for _, folder := range weak {
		problem := VendorFolderProblem{Connector: folder.connector, Dir: folder.refused.dir, File: folder.refused.file}
		tx, err := beginReprotect(recorded, folder.refused.dir, folder.last, folder.use, false)
		if err == nil {
			tx.close()
			problem.Reprotectable = true
			problem.Message = fmt.Sprintf("%s; DefenseClaw did not create this folder and will put it back to its protected form at the next "+
				"reconcile (the guardian pass, or Setup /ensure): nothing holds it open, DefenseClaw's recorded files in it match "+
				"their records and it holds nothing else DefenseClaw did not account for", folder.refused.reason())
		} else {
			problem.Blocker = err.Error()
			blocked := *folder.refused
			blocked.blocker = problem.Blocker
			problem.Message = blocked.Error()
		}
		problems = append(problems, problem)
	}
	return problems
}

// ReprotectRecordedVendorFolders is InspectRecordedVendorFolders that also
// runs the safe transaction for each folder it can put right: it returns the
// folders it re-protected, and the problems it could not (with what blocks
// them). Setup calls it before an install-like action or a reconcile, so a
// weak but clean folder is healed and reported instead of left to the next
// guardian pass.
func ReprotectRecordedVendorFolders(opts Options, connectors []string) ([]ReprotectedFolder, []VendorFolderProblem) {
	recorded, weak := weakVendorFolders(opts, connectors)
	var healed []ReprotectedFolder
	var blocked []VendorFolderProblem
	for _, folder := range weak {
		done, err := reprotectRecordedVendorFolder(recorded, folder.refused.dir, folder.last, folder.use, folder.refused, folder.validate)
		if err == nil {
			done.Connector = folder.connector
			healed = append(healed, done)
			continue
		}
		refusal := *folder.refused
		refusal.blocker = err.Error()
		blocked = append(blocked, VendorFolderProblem{
			Connector: folder.connector, Dir: refusal.dir, File: refusal.file, Message: refusal.Error(), Blocker: refusal.blocker,
		})
	}
	return healed, blocked
}

// VendorFolderProblemFor is the problem InspectRecordedVendorFolders reports
// for one connector, or nil.
func VendorFolderProblemFor(opts Options, connector string) *VendorFolderProblem {
	if problems := InspectRecordedVendorFolders(opts, []string{connector}); len(problems) > 0 {
		return &problems[0]
	}
	return nil
}

// IsVendorFolderRefusal reports whether err is, or wraps, the refusal of a
// vendor folder that does not protect DefenseClaw's recorded file.
func IsVendorFolderRefusal(err error) bool {
	var refusal *recordedVendorFolderError
	return errors.As(err, &refusal)
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
