// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

// ordinaryNoAnswerPayloadInHome and ordinaryNoAnswerPayloadInHomes are the
// strict (PreToolUse, no cd) reader for one home and for a list of homes;
// only tests ask them directly. Production code asks
// noAnswerPayloadInHomes through OrdinaryNoAnswerPayload or the late use.
func ordinaryNoAnswerPayloadInHome(body []byte, home string) bool {
	return noAnswerPayloadInHome(body, home, false)
}

func ordinaryNoAnswerPayloadInHomes(body []byte, homes []string) bool {
	return noAnswerPayloadInHomes(body, homes, false)
}
