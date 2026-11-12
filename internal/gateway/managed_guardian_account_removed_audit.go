// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

const managedGuardianAccountRemovedAuditPath = "/api/v1/managed/guardian-account-removed"

type managedGuardianAccountRemovedRequest struct {
	User      string `json:"user"`
	UID       *int   `json:"uid,omitempty"`
	Connector string `json:"connector"`
}

// Only the root guardian can report this transition over the verified hook
// socket. A missing uid is valid when the directory no longer resolves it.
func (a *APIServer) handleManagedGuardianAccountRemovedAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, ok := managedHookPeerFromContext(r.Context())
	if !ok || peer.UID != 0 {
		writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified)
		return
	}
	if a.logger == nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	var report managedGuardianAccountRemovedRequest
	var extra any
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&extra) != io.EOF ||
		!utf8.ValidString(report.User) || !utf8.ValidString(report.Connector) ||
		len(report.User) > 256 || len(report.Connector) > 64 ||
		strings.TrimSpace(report.User) == "" || strings.TrimSpace(report.Connector) == "" ||
		(report.UID != nil && (*report.UID <= 0 || *report.UID > 1<<31-1)) {
		http.Error(w, "invalid removal report", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(stripLogInjectionRunes(report.User))
	connectorName := strings.ToLower(strings.TrimSpace(stripLogInjectionRunes(report.Connector)))
	if user == "" || connectorName == "" {
		http.Error(w, "invalid removal report", http.StatusBadRequest)
		return
	}
	caller := auditCaller{Name: auditUserName(user)}
	if report.UID != nil {
		caller.ID = strconv.Itoa(*report.UID)
		caller.IDKind = useridentity.KindPOSIXUID
	}
	structured := map[string]any{}
	caller.addTo(structured)
	if err := a.logger.LogEvent(audit.Event{
		Action: string(audit.ActionConnectorHookAccountRemoved), Target: connectorName,
		Actor: "defenseclaw", Details: fmt.Sprintf("retired hook target after account removal for user %s", user),
		Severity: "INFO", Connector: connectorName, Structured: structured,
	}); err != nil {
		http.Error(w, "audit emission failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
