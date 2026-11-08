// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "errors"

// errPerUserListenerUnanswered ends a per-user try whose connection sat in
// the accept queue of a listener that the OS proves belongs to this account
// and that took no accept() for the whole wait: this account's own gateway
// is stopped, frozen or wedged. Nothing was sent. It is not a listener of
// another account (errPerUserPeerUnverified, closed in every fail mode) and
// not a gateway that took the call (errGatewayTookCallNoAnswer); the call
// follows the account's outage mode (failPerUserListenerUnanswered).
var errPerUserListenerUnanswered = errors.New("this account's gateway listener accepted no connection")

// PerUserPostListenerUnanswered reports whether err, from PostPerUserHook, is
// a connection that waited in the accept queue of this account's own listener
// and was never accepted. The call was not sent.
func PerUserPostListenerUnanswered(err error) bool {
	return errors.Is(err, errPerUserListenerUnanswered) && !errors.Is(err, errPerUserPeerUnverified)
}

// failPerUserListenerUnanswered ends a call whose gateway listener is this
// account's own and accepts nothing. It is an outage, so the account's outage
// mode decides: open with the visible warning in the default tiers, closed in
// strict and managed ones. A tool call that does not plainly name nothing a
// protected file could be reached through stays closed in every tier, as a
// gateway that is up and late does (GAP-0518, failNoAnswer).
func failPerUserListenerUnanswered(opts Options, sp spec, failMode string) int {
	if opts.lateOrdinary != nil && !opts.lateOrdinary() {
		return failNoAnswer(opts, sp, failMode)
	}
	return failUnreachable(withPerUserOutage(opts), sp, failMode, perUserGatewayNoAnswerReason)
}
