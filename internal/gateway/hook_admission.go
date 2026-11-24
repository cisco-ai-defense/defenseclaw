// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"runtime"
)

// GAP-0011 part 2. At 35 hook calls per second on dc-win2 the per-user
// gateway worked on every call at once (447 goroutines, PROF-0011B). The
// calls slowed each other down until none finished inside the hook's
// deadline, and calls whose hook had already given up kept running. Hook
// calls now take one of a bounded number of admission slots before the
// gateway authenticates and evaluates them. A call waits for a slot only
// while its request lasts: once its hook gives up (the request context
// ends) it is dropped before any work, answered 503 and recorded as a
// rejection (abandoned_before_admission). A call that is admitted runs as
// before. The bound is well above a normal load: with the trusted
// machine-root cache, a call takes a few milliseconds of gateway work.
const hookAdmissionFloor = 32

// gatewayHookAdmission is the process-wide bound; tests replace it.
var gatewayHookAdmission = newHookAdmission(hookAdmissionLimit())

// hookAdmissionLimit is four calls per CPU the gateway may use, and at
// least hookAdmissionFloor.
func hookAdmissionLimit() int {
	limit := 4 * runtime.GOMAXPROCS(0)
	if limit < hookAdmissionFloor {
		limit = hookAdmissionFloor
	}
	return limit
}

type hookAdmission struct{ slots chan struct{} }

func newHookAdmission(limit int) *hookAdmission {
	if limit < 1 {
		limit = 1
	}
	return &hookAdmission{slots: make(chan struct{}, limit)}
}

// admit takes a slot, waiting while ctx lasts. It returns the release and
// true, or false once ctx is done.
func (h *hookAdmission) admit(ctx context.Context) (func(), bool) {
	release := func() { <-h.slots }
	select {
	case h.slots <- struct{}{}:
		return release, true
	default:
	}
	select {
	case h.slots <- struct{}{}:
		return release, true
	case <-ctx.Done():
		return nil, false
	}
}

// admitHookCall admits the hook call r for connector scope. When its request
// ends first, it records the rejection, answers 503 and returns false; the
// caller then returns without further work.
func (a *APIServer) admitHookCall(w http.ResponseWriter, r *http.Request, scope string) (func(), bool) {
	release, ok := gatewayHookAdmission.admit(r.Context())
	if ok {
		return release, true
	}
	a.recordConnectorHookRejection(context.WithoutCancel(r.Context()), scope, "unknown", "abandoned_before_admission", 0)
	http.Error(w, "hook call abandoned before the gateway admitted it", http.StatusServiceUnavailable)
	return nil, false
}
