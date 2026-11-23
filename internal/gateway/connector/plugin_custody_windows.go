// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// pluginCustodyQuote writes p for a PowerShell command line as the repair
// does (managed.PowerShellLiteral), and only when it needs it.
func pluginCustodyQuote(p string) string {
	if p != "" && strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./\\-") == "" {
		return p
	}
	return managed.PowerShellLiteral(p)
}

// explainPluginArtifactRefusal turns a refusal of the plugin destination into
// one that names what to fix: every refused folder and file, the one command
// that repairs what a command can repair, and the steps only a person can take
// (GAP-0730, GAP-0731). It is a custody refusal, so Setup stops only this
// connector, before any change (GAP-1887, the Windows form of GAP-0798).
//
// A safefile refusal of the plugin folder DACL that places each of its entries
// keeps its repair: each account is removed at each folder that holds the entry.
// Any other refusal (the directory walk, or a safefile refusal it cannot use)
// is explained by judging the walk's own chain again, outermost first, with the
// same rules (hookAPIDirectoryChain, trustedOwnerSID included), and then the
// plugin file. The walk stops at the first element it refuses, the leaf
// first, so its refusal alone sends the user to a fix that does not clear it.
// Here every refused verdict of every element counts (GAP-1889): a write entry
// of another account is removed at each folder that grants it, which is not
// the folder the walk met it at when that one inherits it; an entry whose
// granting folder cannot be found gets a step by hand and no command. A
// junction, link or other reparse point, an element of the wrong type, a
// foreign owner, a missing DACL and an entry the walk cannot read get a step by
// hand (GAP-1888). A structural refusal stops the judgement there: what lies
// below depends on what the user puts in its place. When nothing is refused (a
// change made since) or an element cannot be judged, cause is returned
// unchanged, and the gateway refuses the start as before.
//
// A command only ever names a folder or file of this account's own tree
// (windowsCustodyUserTree): an entry granted at a drive root, an operating
// system or installer folder, or any folder another account owns gets a step
// by hand and no command, since removing it there changes every folder that
// inherits from it (GAP-1899). A folder Administrators owns is this account's
// only below its own profile folder (GAP-1910, GAP-1911; for a run that
// verifies another account, the profile Windows records for that account,
// GAP-1916). One left out although it is in the profile gets a step to take it
// back, never one to move the plugin folder (GAP-1917).
func explainPluginArtifactRefusal(path, trustedOwnerSID string, cause error) error {
	if cause == nil {
		return nil
	}
	extra := hookAPIParseTrustedOwnerSID(trustedOwnerSID)
	var clean string
	var chain []hookAPIDirectoryElement
	if filepath.IsAbs(path) {
		clean = filepath.Clean(path)
		chain = hookAPIDirectoryChain(filepath.Dir(clean), extra)
	}
	tree, profile := windowsCustodyUserTree(chain, clean, extra)
	var refusal *safefile.UnsafePrivateDACLError
	if errors.As(cause, &refusal) {
		placed := windowsCustodyJudge{tree: tree, profile: profile}
		if explained := placed.unsafePrivateDACL(cause, refusal); explained != nil {
			return explained
		}
	}
	if clean == "" {
		return cause
	}
	judge := windowsCustodyJudge{tree: tree, profile: profile}
	whole := true
	for i := len(chain) - 1; i >= 0 && whole; i-- {
		element := chain[i]
		var ok bool
		whole, ok = judge.element(element.path, true, element.protectChildren, element.advisory, element.mode, extra)
		if !ok {
			return cause
		}
	}
	if whole {
		// The plugin file, when there is one, as checkPluginArtifactDestination
		// judges it (hookAPIValidateOwnerFor).
		if _, err := os.Lstat(clean); err == nil {
			if _, ok := judge.element(clean, false, true, false, hookAPIDriftStrict, extra); !ok {
				return cause
			}
		} else if !os.IsNotExist(err) {
			return cause
		}
	}
	return judge.refusal(cause)
}

// unsafePrivateDACL is the safefile refusal with its repair, or nil when one of
// its entries names no account or no folder (a repair that leaves one refused
// entry in place is not offered).
func (j *windowsCustodyJudge) unsafePrivateDACL(cause error, refusal *safefile.UnsafePrivateDACLError) error {
	if len(refusal.Entries) == 0 {
		return nil
	}
	for _, entry := range refusal.Entries {
		if entry.Trustee == "" || len(entry.Carriers) == 0 {
			return nil
		}
	}
	for _, entry := range refusal.Entries {
		j.place(refusal.Path, entry.Trustee, entry.Deny, entry.Carriers)
	}
	return j.refusal(cause)
}

// windowsCustodyUserTree is the part of the plugin destination this account
// may be told to change by command: the elements of chain, and the plugin file
// clean, that windowsCustodyOwnElement accepts. A folder outside it is shared
// with other accounts or belongs to Windows or an installer (GAP-1899).
// profile is the account's profile folder as read, for the steps by hand
// (windowsCustodyAdministratorsScope).
func windowsCustodyUserTree(chain []hookAPIDirectoryElement, clean string, extra *windows.SID) (tree []string, profile string) {
	scope, profile := windowsCustodyAdministratorsScope(extra)
	for _, element := range chain {
		if windowsCustodyOwnElement(element.path, extra, scope) {
			tree = append(tree, element.path)
		}
	}
	if clean != "" && windowsCustodyOwnElement(clean, extra, scope) {
		tree = append(tree, clean)
	}
	return tree, profile
}

// windowsCustodyAdministratorsScope is the folder below which a folder or file
// BUILTIN\Administrators owns is still this account's own (scope): the profile
// folder of the account this run verifies, the effective user's, or for a run
// that verifies another account (extra) the one Windows records for it
// (windowsCustodyProfileImagePath, GAP-1916). An elevated run of the account
// makes its new folders there Administrators-owned, and the profile's
// inherited full control lets the account change them whether or not the next
// run is elevated (GAP-1911). Outside the profile an Administrators-owned
// folder is shared by every administrator (another administrator's C:\src, an
// installer's folder, a vendor's ProgramData folder), so a command there would
// change other accounts' access, elevated or not (GAP-1910). scope is empty,
// and Administrators is never the account, when the profile cannot be read or
// is not spelled as a plain drive path already in clean form. profile is the
// folder as read, cleaned, whatever its spelling (empty when it cannot be
// read): it only chooses the words of a step by hand (GAP-1917).
func windowsCustodyAdministratorsScope(extra *windows.SID) (scope, profile string) {
	var err error
	if extra != nil {
		profile, err = windowsCustodyProfileImagePath(extra)
	} else {
		profile, err = windowsEffectiveUserProfile()
	}
	if err != nil || !filepath.IsAbs(profile) {
		return "", ""
	}
	if profile == filepath.Clean(profile) && len(filepath.VolumeName(profile)) == 2 {
		scope = profile
	}
	return scope, filepath.Clean(profile)
}

// windowsCustodyProfileList is the machine's list of user profiles; only
// administrators and LocalSystem can change it. It is a variable only as a
// test seam: the Windows tests point it at a throwaway key of their own
// (GAP-1921). Nothing in production assigns it, and it is never taken from
// config or the environment.
var windowsCustodyProfileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// windowsCustodyProfileImagePath is the profile folder Windows records for sid
// (ProfileList\<SID>\ProfileImagePath). Only a %SystemDrive% prefix is
// expanded, as the enterprise profile walk does; a value with any other
// expansion is not read.
func windowsCustodyProfileImagePath(sid *windows.SID) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsCustodyProfileList+`\`+sid.String(), registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer key.Close()
	value, kind, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	const systemDrive = "%SystemDrive%"
	if kind == registry.EXPAND_SZ && len(value) >= len(systemDrive) && strings.EqualFold(value[:len(systemDrive)], systemDrive) {
		windowsDir, err := windows.GetSystemWindowsDirectory()
		if err != nil {
			return "", err
		}
		value = filepath.VolumeName(windowsDir) + value[len(systemDrive):]
	}
	if strings.Contains(value, "%") {
		return "", fmt.Errorf("the profile folder of %s is recorded with an expansion this check does not make", sid)
	}
	return value, nil
}

// windowsCustodyOwnElement reports whether path is a folder or file of this
// account's own tree: a plain element (windowsCustodyPlainElementOwner) owned
// by this account (the effective user, or the per-user target a privileged
// guardian verifies), or by Administrators strictly below scope
// (windowsCustodyAdministratorsScope) and reached from it through plain
// folders only (a junction inside the profile may lead to a shared folder).
// LocalSystem and TrustedInstaller own Windows' folders, never the user's. Any
// read that fails is outside the tree.
func windowsCustodyOwnElement(path string, extra *windows.SID, scope string) bool {
	owner := windowsCustodyPlainElementOwner(path)
	if owner == nil {
		return false
	}
	if managed.IsWindowsTrustedAdminOwner(owner) {
		return scope != "" && owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) &&
			winpath.RejectReparseBelow(scope, path) == nil
	}
	if extra != nil {
		return owner.Equals(extra)
	}
	current, err := windowsEffectiveUserSID()
	return err == nil && current != nil && owner.Equals(current)
}

// windowsCustodyPlainElementOwner is the owner of path when path can be in an
// account's own tree at all: not a volume root, not an operating system or
// installer folder (managed.AdvisoryAncestorPath), not a reparse point. It is
// nil otherwise and when a read fails.
func windowsCustodyPlainElementOwner(path string) *windows.SID {
	if path == "" || !filepath.IsAbs(path) || filepath.Dir(path) == path || managed.AdvisoryAncestorPath(path) {
		return nil
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return nil
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil
	}
	owner, err = owner.Copy()
	if err != nil {
		return nil
	}
	return owner
}

// windowsCustodyAdministratorsLeftOut reports whether path, a folder or file
// outside the account's tree, is a plain one Administrators owns (leftOut),
// and whether it is shown to be below the account's profile (inProfile): an
// elevated run made it there, and the check left it out because the profile
// is not plainly spelled, is a junction-redirected profile, or path is an 8.3
// or subst spelling. The user then takes it back or has an administrator
// remove the entry; moving the plugin folder is no fix (GAP-1917). path is
// compared with profile as spelled and once both resolve to their final
// paths. With the profile unread (empty) path may be in it or a shared folder
// such as C:\tools, so inProfile is false (GAP-1920). This only chooses the
// words of a step by hand; it never puts path in the tree.
func windowsCustodyAdministratorsLeftOut(path, profile string) (leftOut, inProfile bool) {
	owner := windowsCustodyPlainElementOwner(path)
	if owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return false, false
	}
	if profile == "" {
		return true, false
	}
	if windowsCustodyStrictlyBelow(profile, path) {
		return true, true
	}
	finalProfile, err := atomicTransformResolveDirectoryPathPlatform(profile)
	if err != nil {
		return false, false
	}
	finalPath, err := atomicTransformResolveDirectoryPathPlatform(path)
	below := err == nil && windowsCustodyStrictlyBelow(finalProfile, finalPath)
	return below, below
}

// windowsCustodyStrictlyBelow reports whether path names an element strictly
// below root, compared case-insensitively as spelled.
func windowsCustodyStrictlyBelow(root, path string) bool {
	prefix := strings.TrimSuffix(filepath.Clean(root), `\`) + `\`
	path = filepath.Clean(path)
	return len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix)
}

// windowsCustodyJudge collects what the refused elements of one plugin
// destination need.
type windowsCustodyJudge struct {
	removals  []icaclsRefusedEntry
	removed   map[string]bool
	manual    []string
	failing   []string
	inherited bool
	// tree is windowsCustodyUserTree: the only folders and files a command
	// may name.
	tree []string
	// profile is the account's profile folder as read, empty when it could
	// not be read (windowsCustodyAdministratorsScope).
	profile string
	// outside holds the entries already given a step by hand because a
	// folder that grants them is outside tree (once where the entry is the
	// folder's own, once where a folder inherits it).
	outside map[string]bool
}

// element judges one element. whole is false after a structural refusal (the
// judgement stops there); ok is false when the element cannot be judged.
func (j *windowsCustodyJudge) element(
	path string, wantDir, protectChildren, advisory bool, mode hookAPIDriftMode, extra *windows.SID,
) (whole, ok bool) {
	var verdicts []error
	err := hookAPIJudgeWindowsPathElement(path, wantDir, protectChildren, advisory, mode, extra,
		func(verdict error) { verdicts = append(verdicts, verdict) })
	for _, verdict := range verdicts {
		if !j.verdict(path, verdict) {
			return false, false
		}
	}
	var structure *hookAPIStructureError
	var unsupported *hookAPIUnsupportedACEError
	switch {
	case err == nil:
		return true, true
	case os.IsNotExist(err):
		// Nothing there to fix; the walk refuses it on its own terms.
		return true, true
	case errors.As(err, &structure):
		kind := "folder"
		if !wantDir {
			kind = "file"
		}
		j.step(structure.path, "replace "+pluginCustodyQuote(structure.path)+" with a real "+kind+
			" owned by this account (a junction, link or other reparse point is refused whatever it points to, and changing permissions does not clear it)")
		return false, true
	case errors.As(err, &unsupported):
		j.step(unsupported.path, fmt.Sprintf("remove the allow entry of type 0x%x from %s (this check cannot read whose entry it is)",
			unsupported.aceType, pluginCustodyQuote(unsupported.path)))
		return true, true
	default:
		return false, false
	}
}

// verdict records one refused permission verdict on path; false when it is
// not one this judgement knows.
func (j *windowsCustodyJudge) verdict(path string, verdict error) bool {
	var write *hookAPIUntrustedWriteError
	var owner *hookAPIUntrustedOwnerError
	var null *hookAPINullDACLError
	switch {
	case errors.As(verdict, &write) && write.sid != "":
		j.write(path, write)
	case errors.As(verdict, &owner):
		j.step(path, "have an administrator give "+pluginCustodyQuote(path)+" back to this account")
	case errors.As(verdict, &null):
		j.step(path, "give "+pluginCustodyQuote(path)+" an access list (it has none, so every account can write to it)")
	default:
		return false
	}
	return true
}

// write records a refused write entry: the account is removed at every folder
// that holds the entry as its own (path itself when the entry is not
// inherited). When the walk up the parents cannot place it, no command is
// printed for it, since one that removes nothing would leave the refusal.
func (j *windowsCustodyJudge) write(path string, write *hookAPIUntrustedWriteError) {
	trustee := "*" + write.sid
	carriers := []string{path}
	if write.inherited {
		j.inherited = true
		carriers = nil
		if sid, err := windows.StringToSid(write.sid); err == nil {
			protectChildren := write.protectChildren
			carriers = safefile.AllowEntryCarriers(path, sid, func(mask windows.ACCESS_MASK) bool {
				return hookAPIWindowsWriteLikeAccess(mask, protectChildren)
			})
		}
		if len(carriers) == 0 {
			j.step(path, "remove the write entry of "+trustee+" that "+pluginCustodyQuote(path)+
				" inherits, at the folder above it that grants it (this check could not find that folder)")
			return
		}
	}
	j.place(path, trustee, false, carriers)
}

// place records the removal of trustee's entry, refused on path, at every
// carrier, the folders and files that grant it. When one of them is outside
// this account's own tree, no command is printed for the entry (removing it
// at the others alone would leave the refusal, and a command on a drive root or
// a shared folder changes every folder that inherits from it): the step by
// hand names the folder that grants it, once per entry (GAP-1899). When every
// such folder is one Administrators owns in the account's profile, the step
// says to take it back or have an administrator remove the entry (GAP-1917);
// when the profile could not be read, the step says so only for a folder in
// the profile and otherwise to move the plugin folder (GAP-1920).
func (j *windowsCustodyJudge) place(path, trustee string, deny bool, carriers []string) {
	var outside []string
	administrators, inProfile := true, true
	for _, carrier := range carriers {
		if !j.inTree(carrier) {
			outside = append(outside, pluginCustodyQuote(carrier))
			leftOut, in := windowsCustodyAdministratorsLeftOut(carrier, j.profile)
			administrators = administrators && leftOut
			inProfile = inProfile && in
		}
	}
	if len(outside) > 0 {
		kind := "write"
		if deny {
			kind = "deny"
		}
		own := len(carriers) == 1 && carriers[0] == path
		key := fmt.Sprint(own) + "\x00" + kind + "\x00" + trustee + "\x00" + strings.Join(outside, "\x00")
		if j.outside == nil {
			j.outside = map[string]bool{}
		}
		if j.outside[key] {
			j.addFailing(path)
			return
		}
		j.outside[key] = true
		granted := strings.Join(outside, ", ")
		is, it := "is", "it"
		if len(outside) > 1 {
			is, it = "are", "them"
		}
		switch {
		case administrators && !inProfile && own:
			j.step(path, "Administrators owns "+granted+", so no command is printed for the "+kind+" entry of "+trustee+
				" on it: if "+granted+" "+is+" inside this account's own profile, take ownership of "+it+" and remove the entry"+
				" or have an administrator remove it, and if not, move the plugin folder under a folder this account owns"+
				" (removing the entry there changes every folder that inherits from it)")
			return
		case administrators && !inProfile:
			j.step(path, "the "+kind+" entry of "+trustee+" that "+pluginCustodyQuote(path)+" inherits is granted at "+granted+
				", which Administrators owns, so no command is printed for it (a change there reaches every folder that inherits from it):"+
				" if "+granted+" "+is+" inside this account's own profile, take ownership of "+it+" and remove the entry there"+
				" or have an administrator remove it, and if not, have "+pluginCustodyQuote(path)+
				" stop inheriting the entry or move the plugin folder under a folder this account owns")
			return
		case administrators && own:
			j.step(path, "Administrators owns "+granted+", so no command is printed for the "+kind+" entry of "+trustee+
				" on it: take ownership of "+granted+" and remove the entry, or have an administrator remove it")
			return
		case administrators:
			j.step(path, "the "+kind+" entry of "+trustee+" that "+pluginCustodyQuote(path)+" inherits is granted at "+granted+
				", which Administrators owns, so no command is printed for it: take ownership of "+granted+
				" and remove the entry there, or have an administrator remove it")
			return
		}
		if own {
			j.step(path, "the "+kind+" entry of "+trustee+" on "+granted+
				" is outside the folders this account owns, so no command is printed for it: move the plugin folder under a folder this account owns"+
				" (removing the entry there changes every folder that inherits from it)")
			return
		}
		j.step(path, "the "+kind+" entry of "+trustee+" that "+pluginCustodyQuote(path)+" inherits is granted at "+granted+
			", outside the folders this account owns, so no command is printed for it (a change there reaches every folder that inherits from it):"+
			" have "+pluginCustodyQuote(path)+" stop inheriting the entry, or move the plugin folder under a folder this account owns")
		return
	}
	if j.removed == nil {
		j.removed = map[string]bool{}
	}
	var fresh []string
	for _, carrier := range carriers {
		if key := fmt.Sprint(deny) + "\x00" + trustee + "\x00" + carrier; !j.removed[key] {
			j.removed[key] = true
			fresh = append(fresh, carrier)
		}
	}
	if len(fresh) > 0 {
		j.removals = append(j.removals, icaclsRefusedEntry{trustee: trustee, deny: deny, carriers: fresh})
	}
}

// inTree reports whether path is one of the folders or files a command may
// name.
func (j *windowsCustodyJudge) inTree(path string) bool {
	clean := filepath.Clean(path)
	for _, own := range j.tree {
		if strings.EqualFold(clean, own) {
			return true
		}
	}
	return false
}

// step records a step by hand for path, once.
func (j *windowsCustodyJudge) step(path, text string) {
	j.addFailing(path)
	for _, known := range j.manual {
		if known == text {
			return
		}
	}
	j.manual = append(j.manual, text)
}

func (j *windowsCustodyJudge) addFailing(path string) {
	for _, known := range j.failing {
		if known == path {
			return
		}
	}
	j.failing = append(j.failing, path)
}

// refusal is cause with everything recorded, or cause when nothing was.
func (j *windowsCustodyJudge) refusal(cause error) error {
	fix, carriers := icaclsRemovalFix(j.removals)
	for _, carrier := range carriers {
		j.addFailing(carrier)
	}
	if len(j.failing) == 0 {
		return cause
	}
	sort.SliceStable(j.failing, func(a, b int) bool { return len(j.failing[a]) < len(j.failing[b]) })
	return &pluginCustodyError{
		cause: cause, failing: j.failing, fix: fix, manual: strings.Join(j.manual, "; "), listFailing: j.inherited,
	}
}
