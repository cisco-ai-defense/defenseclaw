// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "github.com/defenseclaw/defenseclaw/internal/assetfacts"

// The link walk of the skill folder check (assetfacts.ResolveLinks) reads the
// attributes of every part of a path, so it asks a network share as every
// other read below one does: once, for every call that names it, within the
// wait the hook call has for shares. A share that answers is followed, links
// on it included, so a link on a responsive share to a held skill folder is
// shown like one on a local disk. A share that does not answer reads as
// unknown, as an unreadable path does, and the walk stops there (the path
// stays as spelled); that is final for a share that did not answer within its
// own wait (the owner-accepted bound), but when only the budget of the call
// ended the wait the share might have answered, and the call records it
// (SkillLinksUnproven) for the caller to judge by the policy tier. The
// gateway holds the skill folder check to that: a skill held or denied is
// refused unproven in the strict tier and allowed with a visible alert in the
// others, as a script body the budget kept unread is (ShareBodyUnread).
func init() {
	assetfacts.ShareGate = shareAnswersForLinks
	assetfacts.UnprovenLinkNote = noteSkillLinksUnproven
}

// noteSkillLinksUnproven records, for the hook call on the calling goroutine,
// that a path of the request could not be placed (SkillLinksUnproven).
func noteSkillLinksUnproven() {
	if call := currentHookCall(); call != nil {
		call.linksUnproven = true
	}
}

// shareAnswersForLinks reports whether the walk may read path: it is local, or
// on a network share that has answered.
func shareAnswersForLinks(path string) bool {
	root := networkShareRootOf(path)
	if root == "" {
		return true
	}
	unanswered, budgetCut := askNetworkShare(root)
	if !unanswered {
		return true
	}
	if call := currentHookCall(); call != nil && budgetCut {
		call.linksUnproven = true
	}
	return false
}

// SkillLinksUnproven reports that the hook call on the calling goroutine could
// not follow the links of a path to a skill folder because the call's wait
// for network shares was spent before a share answered. The skill folder that
// path leads to is unknown, not shown to be an ordinary one.
func SkillLinksUnproven() bool {
	call := currentHookCall()
	return call != nil && call.linksUnproven
}
