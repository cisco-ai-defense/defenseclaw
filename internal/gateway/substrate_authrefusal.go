// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// Refused tokens on the Substrate listeners (GAP-0407, GAP-0408). The actor
// listener (an actor token on a hook, model or relay call) and the admin
// listener (a person token from the launcher) refuse a missing, forged,
// tampered, foreign or expired token with 401 and a closed reason. Each
// refusal is now visible to the operator three ways, none of which carries
// token bytes, a claim value or the verifier's message (a header alg or an
// issuer is attacker text):
//
//   - the metric defenseclaw.substrate.auth_refused, every refusal, labelled
//     by listener and reason (both closed sets);
//   - one gateway log line per listener and reason per window, with the
//     count since the last line and the client address class;
//   - one substrate audit row per listener and reason per window, with the
//     same fields.
//
// A flood of bad tokens therefore costs at most one row and one line per
// listener and reason per window on each replica, so it cannot fill the
// audit store (GAP-0402) or the pod log.

// Listener names, the metric's listener label.
const (
	substrateListenerActor = "actor"
	substrateListenerAdmin = "admin"
)

// substrateAuthRefusalWindow is how often one listener and reason writes a
// log line and an audit row.
const substrateAuthRefusalWindow = time.Minute

// substrateAuthReasons is the closed reason set of the metric label and the
// row. Anything else (a future verifier reason) counts as "other", so the
// label and the window map stay bounded.
var substrateAuthReasons = map[identity.Reason]bool{
	identity.ReasonMissing: true, identity.ReasonMalformed: true, identity.ReasonAlgorithm: true,
	identity.ReasonType: true, identity.ReasonUnknownKey: true, identity.ReasonSignature: true,
	identity.ReasonIssuer: true, identity.ReasonAudience: true, identity.ReasonExpired: true,
	identity.ReasonNotYetValid: true, identity.ReasonLifetime: true, identity.ReasonWorkerToken: true,
	identity.ReasonSubject: true, identity.ReasonClaims: true, identity.ReasonActorGone: true,
	identity.ReasonActorUID: true, identity.ReasonActorState: true, identity.ReasonUnavailable: true,
	identity.ReasonKeysetFailed: true,
}

func substrateAuthReason(r identity.Reason) string {
	if substrateAuthReasons[r] {
		return string(r)
	}
	return "other"
}

// substrateAuthForgery are the reasons only a made or altered token gets;
// their row is MEDIUM so the alert views list it. The rest (no token, an
// expired or stale one, a verifier outage) are routine and INFO.
func substrateAuthForgery(reason string) bool {
	switch identity.Reason(reason) {
	case identity.ReasonMalformed, identity.ReasonAlgorithm, identity.ReasonType, identity.ReasonUnknownKey,
		identity.ReasonSignature, identity.ReasonIssuer, identity.ReasonAudience, identity.ReasonWorkerToken,
		identity.ReasonSubject, identity.ReasonClaims, identity.ReasonLifetime:
		return true
	}
	return false
}

// substrateClientClass is the address class of a caller, never the address.
func substrateClientClass(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast():
		return "link_local"
	case ip.IsGlobalUnicast():
		return "public"
	}
	return "unknown"
}

type substrateAuthKey struct{ listener, reason string }

type substrateAuthWindow struct {
	since time.Time // the last row
	count int       // refusals since that row, the one that writes the next row included
}

// substrateAuthRefusals bounds the log lines and audit rows of refused
// tokens: one per listener and reason per window.
type substrateAuthRefusals struct {
	mu      sync.Mutex
	windows map[substrateAuthKey]*substrateAuthWindow
}

// note counts one refusal and reports whether it writes a row, and how many
// refusals that row stands for.
func (s *substrateAuthRefusals) note(listener, reason string, now time.Time) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windows == nil {
		s.windows = map[substrateAuthKey]*substrateAuthWindow{}
	}
	k := substrateAuthKey{listener, reason}
	w := s.windows[k]
	if w == nil {
		w = &substrateAuthWindow{}
		s.windows[k] = w
	}
	w.count++
	if !w.since.IsZero() && now.Sub(w.since) < substrateAuthRefusalWindow {
		return 0, false
	}
	n := w.count
	w.since, w.count = now, 0
	return n, true
}

func (st *substrateState) clock() time.Time {
	if st.now != nil {
		return st.now()
	}
	return time.Now()
}

// logLine writes one gateway log line (the caller bounds it).
func (st *substrateState) logLine(format string, args ...any) {
	out := st.logOut
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "[substrate] "+format+"\n", args...)
}

// authRefused records one refused token on listener: the metric always,
// the log line and the audit row at most once per window.
func (st *substrateState) authRefused(r *http.Request, listener string, why identity.Reason) {
	if st == nil {
		return
	}
	reason := substrateAuthReason(why)
	if st.cfg.OnAuthRefused != nil {
		st.cfg.OnAuthRefused(listener, reason)
	}
	n, write := st.authRefusals.note(listener, reason, st.clock())
	if !write {
		return
	}
	client := substrateClientClass(r.RemoteAddr)
	st.logLine("%s listener refused a token: %s (client %s, %d since the last line)", listener, reason, client, n)
	if st.audit == nil {
		return
	}
	severity := "INFO"
	if substrateAuthForgery(reason) {
		severity = "MEDIUM"
	}
	details := map[string]any{
		"event": "auth_refused", "listener": listener, "reason": reason, "client": client,
		"count": n, "window_seconds": int(substrateAuthRefusalWindow / time.Second),
	}
	// The actor route is a closed name; the admin path is caller text and
	// stays out.
	if listener == substrateListenerActor {
		details["route"] = substrateRouteName(substrateRouteFrom(r.Context()))
	}
	st.audit(context.WithoutCancel(r.Context()), severity,
		fmt.Sprintf("%s listener refused %d token(s): %s", listener, n, reason), details)
}
