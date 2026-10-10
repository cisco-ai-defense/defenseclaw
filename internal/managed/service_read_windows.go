//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// serviceReadTreeMaxEntries bounds the folder walk of a rule-pack tree.
const serviceReadTreeMaxEntries = 4096

// serviceReadTokenSIDs are the well-known groups every NT SERVICE virtual
// account's token carries, besides its own service SID.
var serviceReadTokenSIDs = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinServiceSid,
	windows.WinAuthenticatedUserSid,
	windows.WinBuiltinUsersSid,
	windows.WinWorldSid,
	windows.WinLocalSid,
}

// allServicesSID is NT SERVICE\ALL SERVICES, in every service SID's token.
const allServicesSID = "S-1-5-80-0"

// ValidateServiceCanReadTree reports a folder, or a file in it, that the
// gateway's NT SERVICE virtual account cannot read, and a parent folder it
// cannot list or read the permissions of. Setup's preflight runs as
// LocalSystem, which reads everything, so without this check a policy
// folder only administrators can read passed preflight and the gateway
// service then failed to start. The gateway inspects the security
// descriptor of every parent folder (the administrator-controlled check)
// and resolves the path through each of them, so a parent needs Read &
// execute too. It checks the allow and deny entries for the service SID and
// the well-known groups its token carries; an entry whose DACL this process
// cannot read is skipped.
func ValidateServiceCanReadTree(root, label, serviceAccount string) error {
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return &serviceAccountUnresolvedError{err: err}
	}
	if serviceSID == nil {
		return nil
	}
	// The gateway itself reads the tree directly; the DACL check is for a
	// preflight that runs as another account.
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user.User.Sid.Equals(serviceSID) {
		return nil
	}
	sids, err := serviceTokenSIDs(serviceSID)
	if err != nil {
		return err
	}
	for _, parent := range serviceReadParents(root) {
		if !serviceHasAccess(parent, sids, serviceParentAccess) {
			return fmt.Errorf(
				"%s %s: the gateway service account %s cannot list or read the permissions of the parent folder %s; "+
					"grant it Read & execute on that folder, for example: icacls \"%s\" /grant \"%s:RX\", or move the rule pack out of %s to a folder whose parents it can read",
				label, root, serviceAccount, parent, parent, serviceAccount, parent)
		}
	}
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entries++; entries > serviceReadTreeMaxEntries {
			return filepath.SkipAll
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return nil
		}
		if serviceHasAccess(path, sids, serviceTreeAccess) {
			return nil
		}
		// A grant with /T does not reach a file whose permissions do not
		// inherit (an (OI)(CI) entry does not apply to a file), so the old
		// remedy left a pack that icacls /inheritance:r /T had emptied
		// unreadable and Setup refused it again (GAP-1112): grant the pack
		// folder, then let everything in it inherit again.
		return fmt.Errorf(
			"%s %s: the gateway service account %s cannot read %s; grant it Read & execute on the folder and let everything in it inherit that, "+
				"for example: icacls \"%s\" /grant \"%s:(OI)(CI)RX\" and then icacls \"%s\\*\" /reset /T /C",
			label, root, serviceAccount, path, root, serviceAccount, root)
	})
}

// ValidateServiceCanWriteFile reports a file the gateway NT SERVICE virtual
// account could not write: a folder it cannot create files in, list or read
// the permissions of or rotate and prune files in, or an existing file it
// cannot append to or rotate. Setup runs its preflight as LocalSystem or an
// administrator, who write everywhere, so a kind: jsonl destination in a
// folder only administrators can write passed it; the gateway then could not
// open the file and did not start, and the install failed after the
// readiness wait and rolled back (GAP-1118). For a missing folder, the
// nearest existing parent must permit the service to create a subfolder, and
// pass on to the folders it creates the rights to create the rest of the
// path and the file (GAP-1328).
func ValidateServiceCanWriteFile(path, serviceAccount string) error {
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return &serviceAccountUnresolvedError{err: err}
	}
	if serviceSID == nil {
		return nil
	}
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user.User.Sid.Equals(serviceSID) {
		return nil
	}
	folder := filepath.Dir(filepath.Clean(path))
	missing := 0
	for {
		info, statErr := os.Lstat(folder)
		if statErr == nil {
			if !info.IsDir() {
				return fmt.Errorf("JSONL destination parent %s is not a folder", folder)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect JSONL destination parent %s: %w", folder, statErr)
		}
		parent := filepath.Dir(folder)
		if parent == folder {
			return fmt.Errorf("JSONL destination has no existing parent folder: %s", path)
		}
		folder = parent
		missing++
	}
	sids, err := serviceTokenSIDs(serviceSID)
	if err != nil {
		return err
	}
	if missing > 0 {
		if !serviceHasAccess(folder, sids, serviceFolderCreateChildAccess) {
			return fmt.Errorf("the gateway service account %s cannot create a folder in %s", serviceAccount, folder)
		}
		// The gateway creates the missing folders with MkdirAll, so each
		// one has only what it inherits from folder: its container-inherit
		// entries, with CREATOR OWNER standing for the service, which owns
		// what it creates. Below the first new folder an entry that does
		// not propagate is gone. A this-folder-only grant let the service
		// create the first folder and nothing in it.
		creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
		if err != nil {
			return err
		}
		want, skip := serviceFolderWriteAccess, uint8(0)
		if missing > 1 {
			want, skip = want|serviceFolderCreateChildAccess, windows.NO_PROPAGATE_INHERIT_ACE
		}
		if !serviceDACLGrants(folder, append(sids, creatorOwner), want, windows.CONTAINER_INHERIT_ACE, skip) {
			return fmt.Errorf("the gateway service account %s can create a folder in %s, but the folders it creates there "+
				"would not let it create the rest of %s; grant it Modify on %s for its subfolders too, "+
				"for example: icacls \"%s\" /grant \"%s:(OI)(CI)M\"", serviceAccount, folder, path, folder, folder, serviceAccount)
		}
		return nil
	}
	if !serviceHasAccess(folder, sids, serviceFolderWriteAccess) {
		return fmt.Errorf("the gateway service account %s cannot create files in %s", serviceAccount, folder)
	}
	info, statErr := os.Lstat(path)
	existing := statErr == nil && info.Mode().IsRegular()
	// Rotation renames the active file and pruning removes old backups:
	// Windows permits both with FILE_DELETE_CHILD on the folder or DELETE on
	// the file. The documented grant, Modify with (OI)(CI), gives DELETE on
	// every file in the folder and not FILE_DELETE_CHILD, so requiring the
	// folder right refused it (GAP-1123). The gateway creates the next active
	// file after each rotation, so the folder must pass DELETE on to new
	// files, and an existing file must grant it as well.
	if !serviceHasAccess(folder, sids, serviceFolderDeleteChildAccess) {
		if !serviceDACLGrants(folder, sids, windows.DELETE, windows.OBJECT_INHERIT_ACE, 0) {
			return fmt.Errorf("the gateway service account %s cannot rotate or prune files in %s", serviceAccount, folder)
		}
		if existing && !serviceHasAccess(path, sids, windows.DELETE) {
			return fmt.Errorf("the gateway service account %s cannot rotate %s, which does not grant it Delete; "+
				"let the file inherit the folder permissions, for example: icacls \"%s\" /reset", serviceAccount, path, path)
		}
	}
	if existing && !serviceHasAccess(path, sids, serviceFileAppendAccess) {
		return fmt.Errorf("the gateway service account %s cannot write %s", serviceAccount, path)
	}
	return nil
}

// serviceTokenSIDs is serviceSID with the groups every NT SERVICE virtual
// account token carries.
func serviceTokenSIDs(serviceSID *windows.SID) ([]*windows.SID, error) {
	allServices, err := windows.StringToSid(allServicesSID)
	if err != nil {
		return nil, err
	}
	sids := []*windows.SID{serviceSID, allServices}
	for _, kind := range serviceReadTokenSIDs {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, err
		}
		sids = append(sids, sid)
	}
	return sids, nil
}

// serviceAccountUnresolvedError is a service account whose SID could not be
// resolved, for example before Setup has created the service.
type serviceAccountUnresolvedError struct{ err error }

func (e *serviceAccountUnresolvedError) Error() string { return e.err.Error() }
func (e *serviceAccountUnresolvedError) Unwrap() error { return e.err }

// IsServiceAccountUnresolved reports whether ValidateServiceCanReadTree
// failed only because the service account could not be resolved. Setup's
// preflight before a first install has no service yet and leaves the check
// to the install.
func IsServiceAccountUnresolved(err error) bool {
	var unresolved *serviceAccountUnresolvedError
	return errors.As(err, &unresolved)
}

// serviceReadParents lists the parent folders of root up to its volume
// root; tests replace it to stay inside their temporary folder.
var serviceReadParents = func(root string) []string {
	var parents []string
	clean := filepath.Clean(root)
	for parent := filepath.Dir(clean); parent != clean; clean, parent = parent, filepath.Dir(parent) {
		parents = append(parents, parent)
	}
	return parents
}

const (
	// serviceTreeAccess is FILE_READ_DATA (FILE_LIST_DIRECTORY on a folder).
	serviceTreeAccess = windows.ACCESS_MASK(0x0001)
	// serviceParentAccess adds READ_CONTROL: the gateway reads each parent's
	// security descriptor.
	serviceParentAccess = serviceTreeAccess | windows.READ_CONTROL
	// serviceFolderWriteAccess is what a jsonl destination needs on its
	// folder: create its file and the rotated copies (FILE_ADD_FILE), list
	// them to prune, and read the attributes and permissions the gateway
	// checks before every open.
	serviceFolderWriteAccess = serviceTreeAccess | windows.ACCESS_MASK(0x0002|0x0080) | windows.READ_CONTROL
	// FILE_ADD_SUBDIRECTORY lets MkdirAll create the first missing folder.
	serviceFolderCreateChildAccess = serviceTreeAccess | windows.ACCESS_MASK(0x0004|0x0080) | windows.READ_CONTROL
	// FILE_DELETE_CHILD permits renaming the active file and removing old
	// backups even when a file does not grant DELETE.
	serviceFolderDeleteChildAccess = windows.ACCESS_MASK(0x0040)
	// serviceFileAppendAccess is what the gateway opens an existing
	// destination file with (FILE_APPEND_DATA).
	serviceFileAppendAccess = windows.ACCESS_MASK(0x0004|0x0080) | windows.READ_CONTROL
)

// serviceFileGenericMapping maps generic rights to file rights.
var serviceFileGenericMapping = [...]struct{ generic, specific windows.ACCESS_MASK }{
	{windows.GENERIC_READ, 0x120089},
	{windows.GENERIC_WRITE, 0x120116},
	{windows.GENERIC_EXECUTE, 0x1200a0},
	{windows.GENERIC_ALL, 0x1f01ff},
}

// serviceHasAccess reports whether the DACL of path grants every right in
// want to one of sids, evaluating allow and deny entries in order as
// Windows does.
func serviceHasAccess(path string, sids []*windows.SID, want windows.ACCESS_MASK) bool {
	return serviceDACLGrants(path, sids, want, 0, windows.INHERIT_ONLY_ACE)
}

// serviceDACLGrants is serviceHasAccess over the entries of the DACL of path
// that carry every flag in require and none in skip: skip INHERIT_ONLY_ACE
// for path itself, require OBJECT_INHERIT_ACE for a file created in it.
func serviceDACLGrants(path string, sids []*windows.SID, want windows.ACCESS_MASK, require, skip uint8) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return true
	}
	if dacl == nil {
		return true // a NULL DACL grants everyone access
	}
	var allowed, denied windows.ACCESS_MASK
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil ||
			ace.Header.AceFlags&require != require || ace.Header.AceFlags&skip != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matches := false
		for _, candidate := range sids {
			if sid.Equals(candidate) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		mask := ace.Mask
		for _, mapping := range serviceFileGenericMapping {
			if mask&mapping.generic != 0 {
				mask = mask&^mapping.generic | mapping.specific
			}
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			denied |= mask &^ allowed
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allowed |= mask &^ denied
		}
	}
	return allowed&want == want
}
