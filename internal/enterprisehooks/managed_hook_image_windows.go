// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// sameWindowsManagedHookImage reports that a recorded hook executable and a
// hook executable name the same managed hook (GAP-0751): the same file, or
// two images of one kind (transition bin\defenseclaw-hook.exe or a launch
// image bin\hooks\<16 hex>\defenseclaw-hook.exe) in the same install bin.
// Hook-side admission and ownership use it: an agent session that read its
// command before an upgrade runs the older launch image (or the transition
// image) while the policy already names the new one, and an upgrade must
// recognise the older release's entry as its own. Checks that decide whether
// a policy is current keep exact equality, which is what makes the guardian
// switch a stale policy to the current launch image.
func sameWindowsManagedHookImage(recorded, hook string) bool {
	return sameWindowsEnterprisePath(recorded, hook) || winpath.SameEnterpriseHookImageFamily(recorded, hook)
}

// sameWindowsManagedHookImageExact is sameWindowsManagedHookImage for the
// checks that also require the recorded spelling byte for byte: the same
// string, or two images of the same kind whose bin and name are spelled the
// same.
func sameWindowsManagedHookImageExact(recorded, hook string) bool {
	if recorded == hook {
		return sameWindowsEnterprisePath(recorded, hook)
	}
	return winpath.SameEnterpriseHookImageFamilyExact(recorded, hook)
}

// windowsPriorReleaseTargetHookImage is the hook image a read-only
// verification that accepts an earlier release render
// (InstallOptions.AcceptPriorReleaseRender) checks the records of one target
// against: its runtime selector entry, its runtime bundle, the per-user
// enrollment and its own agent configs. That is the image the protected
// runtime selector records for the SID when it is another image of this
// install (sameWindowsManagedHookImageExact), is a regular file and passes
// the hook trust check; otherwise, and in every other verification, it is
// current. Releases up to 1.0.9 named the transition image
// bin\defenseclaw-hook.exe, which Setup replaces in place with this release
// hook, and the hook admits it (GAP-0751). An account with no active Windows
// session through the upgrade keeps those records until the guardian rewrites
// them in its own session, so the exact check against the launch image failed
// it, and with it the upgrade, although this install hook still guards it
// (GAP-1096). Machine-wide files (the Claude Code policy, the Codex
// requirements) are still checked against current.
func windowsPriorReleaseTargetHookImage(opts InstallOptions, connectorName string, targetSID *windows.SID, current string) string {
	if !opts.AcceptPriorReleaseRender || targetSID == nil {
		return current
	}
	selector, _, exists, err := readWindowsManagedRuntimeSelector(strings.ToLower(strings.TrimSpace(connectorName)), true)
	if err != nil || !exists {
		return current
	}
	entry, selected := windowsManagedRuntimeSelectorTargetForSID(selector, targetSID.String())
	if !selected {
		return current
	}
	recorded := entry.HookExecutable
	if recorded == current || !sameWindowsManagedHookImageExact(recorded, current) {
		return current
	}
	if info, err := os.Lstat(recorded); err != nil || !info.Mode().IsRegular() {
		return current
	}
	if err := windowsEnterpriseHookTrustCheck(recorded); err != nil {
		return current
	}
	return recorded
}
