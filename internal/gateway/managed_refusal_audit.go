// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

// managedRefusalAuditPath is the hook-socket route a standard user CLI
// reports a refused policy write on. A standard user holds no gateway token,
// so the token-authenticated CLI ingress (cliObservabilityV8Path) is closed
// to it; the kernel-verified peer of this socket is its credential instead.
const managedRefusalAuditPath = "/api/v1/managed/refusal"

const (
	managedRefusalMaxBodyBytes    = 4 << 10
	managedRefusalMaxTargetBytes  = 256
	managedRefusalMaxDetailsBytes = 512
	// One account adds at most managedRefusalBurst rows at once and one
	// every managedRefusalInterval after that (GAP-0206): a person refuses
	// a few writes a minute; a loop must not fill the audit store.
	managedRefusalBurst       = 20
	managedRefusalInterval    = 3 * time.Second
	managedRefusalMaxAccounts = 4096
)

// managedRefusalTypes are the asset types a block/allow/unblock refusal
// names (TARGET_TYPES in cli/defenseclaw/enforce/asset_lists.py).
var managedRefusalTypes = map[string]bool{"skill": true, "mcp": true, "plugin": true, "tool": true}

// managedRefusalActions are the audit actions a refused local writer reports:
// the per-type block/allow/unblock rows and the generic "action" row for a
// refused config or guardrail write. Mirrors _REFUSAL_ACTIONS and ACTION_ACTION
// in cli/defenseclaw/enforce/asset_lists.py. Anything else is refused, so a
// local account can not write any other audit row through this route.
var managedRefusalActions = map[string]bool{
	"action":      true,
	"skill-block": true, "skill-allow": true, "skill-unblock": true,
	"plugin-block": true, "plugin-allow": true, "plugin-unblock": true,
	"block-mcp": true, "allow-mcp": true, "mcp-unblock": true,
	"tool-block": true, "tool-allow": true, "tool-unblock": true,
}

// managedRefusalLimiter keeps one token bucket per kernel-verified account.
type managedRefusalLimiter struct {
	mu       sync.Mutex
	accounts map[int]*rate.Limiter
}

func (l *managedRefusalLimiter) allow(uid int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.accounts == nil || len(l.accounts) >= managedRefusalMaxAccounts {
		l.accounts = map[int]*rate.Limiter{}
	}
	limiter := l.accounts[uid]
	if limiter == nil {
		limiter = rate.NewLimiter(rate.Every(managedRefusalInterval), managedRefusalBurst)
		l.accounts[uid] = limiter
	}
	return limiter.Allow()
}

// managedRefusalField turns the request details into the one field the row
// may carry: type=<asset type> or command=<the refused CLI words>. The
// gateway writes outcome, reason, actor and user itself, so the command text
// loses every "=" and can not add a key of its own.
func managedRefusalField(details string) (string, bool) {
	details = strings.Join(strings.Fields(stripLogInjectionRunes(details)), " ")
	switch key, value, _ := strings.Cut(details, "="); {
	case details == "":
		return "", true
	case key == "type" && managedRefusalTypes[value]:
		return "type=" + value, true
	case key == "command" && strings.TrimSpace(value) != "":
		return "command=" + strings.ReplaceAll(strings.TrimSpace(value), "=", "_"), true
	}
	return "", false
}

type managedRefusalRequest struct {
	Action  string `json:"action"`
	Target  string `json:"target"`
	Details string `json:"details,omitempty"`
}

// handleManagedRefusalAudit records, in the managed audit store, a policy
// write that a local account attempted on a managed device and the CLI
// refused. The caller is the kernel-verified peer of the hook socket, never
// a name the request carries, and the row always reads outcome=refused
// reason=managed_device plus one type= or command= field, so the route can
// not be used to record anything else. Each account is rate limited.
func (a *APIServer) handleManagedRefusalAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, ok := managedHookPeerFromContext(r.Context())
	if !ok {
		writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified)
		return
	}
	if a.logger == nil {
		http.Error(w, "{\"error\":\"audit unavailable\"}", http.StatusServiceUnavailable)
		return
	}
	var request managedRefusalRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, managedRefusalMaxBodyBytes))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&request)
	field, fieldOK := managedRefusalField(request.Details)
	if err != nil || !fieldOK || !managedRefusalActions[request.Action] ||
		strings.TrimSpace(request.Target) == "" || len(request.Target) > managedRefusalMaxTargetBytes ||
		len(request.Details) > managedRefusalMaxDetailsBytes ||
		!utf8.ValidString(request.Target) || !utf8.ValidString(request.Details) {
		http.Error(w, "{\"error\":\"invalid refusal record\"}", http.StatusBadRequest)
		return
	}
	if !a.managedRefusalLimits.allow(peer.UID) {
		http.Error(w, "{\"error\":\"too many refusal records\"}", http.StatusTooManyRequests)
		return
	}
	details := fmt.Sprintf("outcome=refused reason=managed_device actor=uid:%d", peer.UID)
	if name := strings.TrimSpace(stripLogInjectionRunes(peer.Name)); name != "" {
		details += " user=" + strings.ReplaceAll(name, " ", "_")
	}
	if field != "" {
		details += " " + field
	}
	if err := a.logger.LogCLIAction(r.Context(), request.Action, strings.TrimSpace(stripLogInjectionRunes(request.Target)), details); err != nil {
		fmt.Fprintf(os.Stderr, "[api] managed refusal by uid=%d was not recorded: %v\n", peer.UID, err)
		http.Error(w, "{\"error\":\"audit emission failed\"}", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
