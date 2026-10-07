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
	"unicode/utf8"
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
)

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

type managedRefusalRequest struct {
	Action  string `json:"action"`
	Target  string `json:"target"`
	Details string `json:"details,omitempty"`
}

// handleManagedRefusalAudit records, in the managed audit store, a policy
// write that a local account attempted on a managed device and the CLI
// refused. The caller is the kernel-verified peer of the hook socket, never
// a name the request carries, and the row always reads outcome=refused
// reason=managed_device, so the route can not be used to record anything else.
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
	if err := decoder.Decode(&request); err != nil || !managedRefusalActions[request.Action] ||
		strings.TrimSpace(request.Target) == "" || len(request.Target) > managedRefusalMaxTargetBytes ||
		len(request.Details) > managedRefusalMaxDetailsBytes ||
		!utf8.ValidString(request.Target) || !utf8.ValidString(request.Details) {
		http.Error(w, "{\"error\":\"invalid refusal record\"}", http.StatusBadRequest)
		return
	}
	details := fmt.Sprintf("outcome=refused reason=managed_device actor=uid:%d", peer.UID)
	if name := strings.TrimSpace(stripLogInjectionRunes(peer.Name)); name != "" {
		details += " user=" + strings.ReplaceAll(name, " ", "_")
	}
	if extra := strings.TrimSpace(stripLogInjectionRunes(request.Details)); extra != "" {
		details += " " + extra
	}
	if err := a.logger.LogCLIAction(r.Context(), request.Action, strings.TrimSpace(stripLogInjectionRunes(request.Target)), details); err != nil {
		fmt.Fprintf(os.Stderr, "[api] managed refusal by uid=%d was not recorded: %v\n", peer.UID, err)
		http.Error(w, "{\"error\":\"audit emission failed\"}", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
