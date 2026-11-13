// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/winpath"

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
