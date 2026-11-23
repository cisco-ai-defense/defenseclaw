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
	"golang.org/x/sys/windows"
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
func explainPluginArtifactRefusal(path, trustedOwnerSID string, cause error) error {
	if cause == nil {
		return nil
	}
	var refusal *safefile.UnsafePrivateDACLError
	if errors.As(cause, &refusal) {
		if explained := explainUnsafePrivateDACL(cause, refusal); explained != nil {
			return explained
		}
	}
	if !filepath.IsAbs(path) {
		return cause
	}
	clean := filepath.Clean(path)
	extra := hookAPIParseTrustedOwnerSID(trustedOwnerSID)
	var judge windowsCustodyJudge
	chain := hookAPIDirectoryChain(filepath.Dir(clean), extra)
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

// explainUnsafePrivateDACL is the safefile refusal with its repair, or nil when
// one of its entries names no account or no folder (a repair that leaves one
// refused entry in place is not offered).
func explainUnsafePrivateDACL(cause error, refusal *safefile.UnsafePrivateDACLError) error {
	if len(refusal.Entries) == 0 {
		return nil
	}
	entries := make([]icaclsRefusedEntry, 0, len(refusal.Entries))
	for _, entry := range refusal.Entries {
		if entry.Trustee == "" || len(entry.Carriers) == 0 {
			return nil
		}
		entries = append(entries, icaclsRefusedEntry{trustee: entry.Trustee, deny: entry.Deny, carriers: entry.Carriers})
	}
	fix, failing := icaclsRemovalFix(entries)
	return &pluginCustodyError{cause: cause, failing: failing, fix: fix}
}

// windowsCustodyJudge collects what the refused elements of one plugin
// destination need.
type windowsCustodyJudge struct {
	removals  []icaclsRefusedEntry
	removed   map[string]bool
	manual    []string
	failing   []string
	inherited bool
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
	if j.removed == nil {
		j.removed = map[string]bool{}
	}
	var fresh []string
	for _, carrier := range carriers {
		if key := trustee + "\x00" + carrier; !j.removed[key] {
			j.removed[key] = true
			fresh = append(fresh, carrier)
		}
	}
	if len(fresh) > 0 {
		j.removals = append(j.removals, icaclsRefusedEntry{trustee: trustee, carriers: fresh})
	}
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
