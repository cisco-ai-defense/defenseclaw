// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import "os"

// SkillFolderRefs lists the skill folders a tool input reaches for the calling
// account (SkillFolderRefsAndCut without the cut report).
func SkillFolderRefs(tool string, input any, home, cwd string, caller ...string) []FolderRef {
	return skillRefsFor(tool, input, home, cwd, false, caller)
}

// SkillFolderRefsStrict is SkillFolderRefs for the strict policy tier.
func SkillFolderRefsStrict(tool string, input any, home, cwd string, caller ...string) []FolderRef {
	return skillRefsFor(tool, input, home, cwd, true, caller)
}

func skillRefsFor(tool string, input any, home, cwd string, strict bool, caller []string) []FolderRef {
	account := ""
	if len(caller) > 0 {
		account = caller[0]
	}
	refs, _ := SkillFolderRefsAndCut(tool, input, home, cwd, account, os.Geteuid(), os.Getegid(), strict)
	return refs
}
