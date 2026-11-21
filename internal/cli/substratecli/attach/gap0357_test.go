// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// GAP-0357: the relay answers 410 for an agent its hook-folder integrity
// guard stopped. The launcher says that, and what to do, instead of "you are
// not allowed to attach (it belongs to someone else)", and does not retry.
func TestStoppedAgentIsReportedWithTheGuardsReason(t *testing.T) {
	tg := Target{Atespace: "eng", Name: "agy-1"}
	re := routeError(http.StatusGone, nil, tg)
	if !errors.Is(re, ErrAgentStopped) || !re.final() || re.waits() {
		t.Fatalf("410: kind %v final %v", re.Kind, re.final())
	}
	msg := re.Error()
	for _, want := range []string{"integrity guard", "~/.gemini", "delete it and start a new one", "defenseclaw substrate delete agy-1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "belongs to someone else") {
		t.Errorf("message still blames ownership: %q", msg)
	}
	// The status probe after a refused WebSocket gets 410 too: final, so no
	// long-poll fallback and no "not allowed" from the poll route.
	l := &link{o: Options{Target: tg}}
	if k, err := l.statusOutcome(http.StatusGone, errors.New("relay status 410")); k != outFatal || !errors.Is(err, ErrAgentStopped) {
		t.Fatalf("statusOutcome(410) = %v %v", k, err)
	}
}
