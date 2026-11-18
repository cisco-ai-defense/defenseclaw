// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

// ordinaryNoAnswerPayloadInHome is the strict (PreToolUse, no cd) reader for
// one home; only the GAP-0641 tests ask it directly. Production code asks
// noAnswerPayloadInHomes through OrdinaryNoAnswerPayload or the late use.
func ordinaryNoAnswerPayloadInHome(body []byte, home string) bool {
	return noAnswerPayloadInHome(body, home, false)
}
