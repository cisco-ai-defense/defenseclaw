// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// defenseClawInspectUserRejectedTTL is how long an endpoint that rejected
// the identity fields is sent requests without them before they are tried
// again, so an AI Defense upgrade that accepts them is picked up.
const defenseClawInspectUserRejectedTTL = time.Hour

// defenseClawInspectUserRejected maps an endpoint to the time it last
// rejected a request that carried the identity fields.
var defenseClawInspectUserRejected sync.Map

func defenseClawInspectUserRejectedRecently(endpoint string, now time.Time) bool {
	value, ok := defenseClawInspectUserRejected.Load(endpoint)
	if !ok {
		return false
	}
	at, ok := value.(time.Time)
	if !ok || now.Sub(at) >= defenseClawInspectUserRejectedTTL {
		defenseClawInspectUserRejected.Delete(endpoint)
		return false
	}
	return true
}

// attachDefenseClawInspectUser adds metadata.user and dc_metadata.user to a
// defense_claw inspection payload when the request carries a Secure Client
// identity block, and reports whether it did. metadata.user is the one
// string AI Defense keys on: the UPN, otherwise the SID or uid. The full
// block, with how far each value is proven, goes in dc_metadata.user. A
// panic leaves the payload as it was.
func attachDefenseClawInspectUser(ctx context.Context, payload map[string]interface{}, endpoint string) (sent bool) {
	if payload == nil {
		return false
	}
	user, ok := secureClientUserFromContext(ctx)
	if !ok || defenseClawInspectUserRejectedRecently(endpoint, time.Now()) {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			delete(payload, "metadata")
			delete(payload, "dc_metadata")
			sent = false
			secureClientUserWarnf("inspection sent without its end user after a panic: %v", r)
		}
	}()
	block := map[string]interface{}{
		"id":           user.ID,
		"id_kind":      user.IDKind,
		"id_assurance": string(user.Assurance),
	}
	if user.Name != "" {
		block["name"] = user.Name
	}
	if user.UPN != "" {
		block["upn"] = user.UPN
	}
	key := user.UPN
	if key == "" {
		key = user.ID
	}
	payload["metadata"] = map[string]interface{}{"user": key}
	payload["dc_metadata"] = map[string]interface{}{"user": block}
	return true
}

// defenseClawInspectUserFallback is the validation-error handler of a
// request that carried the identity fields: it removes them, so the
// request is sent once more exactly as before this feature, and sets
// *retried. A request without them has no handler, which keeps the 400/422
// handling it had.
func defenseClawInspectUserFallback(sent bool, payload map[string]interface{}, retried *bool) func() *ScanVerdict {
	if !sent {
		return nil
	}
	return func() *ScanVerdict {
		delete(payload, "metadata")
		delete(payload, "dc_metadata")
		*retried = true
		fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] HTTP 400/422 with the end-user fields, retrying without them\n")
		return nil
	}
}

// recordDefenseClawInspectUserRejection stops sending the identity fields
// to the endpoint for defenseClawInspectUserRejectedTTL, but only when the
// request without them got a verdict: that proves the fields were what AI
// Defense refused. A retry that also fails was refused for another reason,
// which must not turn attribution off.
func recordDefenseClawInspectUserRejection(retried bool, verdict *ScanVerdict, endpoint string) {
	if retried && verdict != nil {
		defenseClawInspectUserRejected.Store(endpoint, time.Now())
	}
}
