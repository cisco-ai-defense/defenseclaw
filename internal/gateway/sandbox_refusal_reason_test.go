// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// Every 429 on a sandbox request names the limit that refused it: the stable
// reason and a message that is true for that limit. The account budget text
// is only for the account bucket (rel-1-0-6 GAP-0490).
func TestSandboxHookRefusalNamesTheLimitThatRefused(t *testing.T) {
	account := sandboxHookBudgetMessage()
	for _, tc := range []struct {
		name       string
		err        error
		reason     string
		wantInText string
		account    bool
	}{
		{"binding rate", sandboxauth.ErrRateLimited, sandboxReasonBindingRate, "this one sandbox", false},
		{"binding rate wrapped", fmt.Errorf("charge: %w", sandboxauth.ErrRateLimited), sandboxReasonBindingRate, "this one sandbox", false},
		{"binding in flight", sandboxauth.ErrTooManyInFlight, sandboxReasonBindingInFlight, "waiting for DefenseClaw's answer", false},
		{"gateway overload", errors.New(managedHookReasonOverloaded), managedHookReasonOverloaded, "handling as many hook requests", false},
		{"account budget", errors.New(managedHookReasonRateLimited), managedHookReasonRateLimited, account, true},
		{"unknown cause", errors.New("something else"), managedHookReasonRateLimited, "limiting the hook requests", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, message := sandboxHookRefusal(tc.err)
			if reason != tc.reason || !strings.Contains(message, tc.wantInText) {
				t.Fatalf("refusal = %q %q, want reason %q containing %q", reason, message, tc.reason, tc.wantInText)
			}
			if (message == account) != tc.account {
				t.Fatalf("account budget text for %q = %v, want %v: %q", tc.name, message == account, tc.account, message)
			}
		})
	}
}

// The hook handler's body charge answers with the same cause: a sandbox over
// its own 25/s limit is told so, and the account budget is not named for it.
func TestSandboxHookBodyChargeRefusalCarriesItsCause(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		reason  string
		account bool
	}{
		{"binding rate", sandboxauth.ErrRateLimited, sandboxReasonBindingRate, false},
		{"account budget", errors.New(managedHookReasonRateLimited), managedHookReasonRateLimited, true},
		{"gateway overload", errors.New(managedHookReasonOverloaded), managedHookReasonOverloaded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/claude-code/hook", nil)
			err := tc.err
			r = r.WithContext(withSandboxHookBudgetCharge(r.Context(), func(bool) error { return err }))
			(&APIServer{}).handleAgentHook("claudecode")(w, r)
			var body struct{ Error, Reason, Message string }
			if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatalf("refusal %d %q", w.Code, w.Body.String())
			}
			if body.Error != "rate_limited" || body.Reason != tc.reason || (body.Message == sandboxHookBudgetMessage()) != tc.account {
				t.Fatalf("refusal body = %+v, want reason %q (account text %v)", body, tc.reason, tc.account)
			}
		})
	}
}
