// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

// ordinaryNoAnswerPayloadInHome is the strict (PreToolUse, no cd) reader for
// one home; only tests ask it directly. Production code asks
// noAnswerPayloadInHomes through OrdinaryNoAnswerPayload or the late use. The
// list-of-homes reader sits beside its only (!windows) caller in
// late_ordinary_parent_variants_test.go (rel-1-0-10:GAP-0105).
func ordinaryNoAnswerPayloadInHome(body []byte, home string) bool {
	return noAnswerPayloadInHome(body, home, false)
}
