// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// ShareBodyUnreadKey carries, in the hook client evidence, that the user-side
// hook call could not read the body of a script the command runs: the call
// budget cut the read short, or the path to the script passes more links than
// the system or the walk follows (ShareBodyUnreadCauses). A managed gateway
// cannot open the user home, so the client is the only reader of those bodies
// and the only one that can tell the gateway one went unread; without this
// fact a body past the link bound reads as a call with nothing to judge. The
// gateway judges the fact by the policy tier of the request, as it judges the
// same cause recorded by its own reads (rel-1-0-9:GAP-0950).
const ShareBodyUnreadKey = "\x00share-body-unread"

const (
	shareBodyUnreadBudget = "budget"
	shareBodyUnreadLinks  = "links"
	shareBodyUnreadBoth   = "budget,links"
)

// shareBodyUnreadFact is the value of ShareBodyUnreadKey for the hook call on
// the calling goroutine: "" when no body went unread.
func shareBodyUnreadFact() string {
	return shareBodyUnreadValue(ShareBodyUnreadCauses())
}

func shareBodyUnreadValue(budget, linkBound bool) string {
	switch {
	case budget && linkBound:
		return shareBodyUnreadBoth
	case budget:
		return shareBodyUnreadBudget
	case linkBound:
		return shareBodyUnreadLinks
	}
	return ""
}

// ClientShareBodyUnread reads ShareBodyUnreadKey from decoded client
// evidence: why the hook client left a script body unread (the same causes as
// ShareBodyUnreadCauses). Both are false when the client reports none.
func ClientShareBodyUnread(targets map[string]string) (budget, linkBound bool) {
	value := targets[ShareBodyUnreadKey]
	return strings.Contains(value, shareBodyUnreadBudget), strings.Contains(value, shareBodyUnreadLinks)
}

func validShareBodyUnreadFact(value string) bool {
	return value == "" || value == shareBodyUnreadBudget || value == shareBodyUnreadLinks || value == shareBodyUnreadBoth
}

// mergeShareBodyUnread is the fact of two readings of one call: every cause
// either one reports.
func mergeShareBodyUnread(a, b string) string {
	budgetA, linksA := ClientShareBodyUnread(map[string]string{ShareBodyUnreadKey: a})
	budgetB, linksB := ClientShareBodyUnread(map[string]string{ShareBodyUnreadKey: b})
	return shareBodyUnreadValue(budgetA || budgetB, linksA || linksB)
}
