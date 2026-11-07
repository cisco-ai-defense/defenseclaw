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

// The root guardian has no audit database writer. It reports a successful
// per-user hook repair to the gateway over the kernel-verified hook socket.
const managedGuardianRepairAuditPath = "/api/v1/managed/guardian-repair"

type managedGuardianRepairRequest struct {
	User      string `json:"user"`
	UID       *int   `json:"uid"`
	Connector string `json:"connector"`
	// Element names the protected element the guardian put back (for example
	// the Hermes hook script). Optional: a report of a repaired target as a
	// whole, such as a hook file the foreign-hook pass rewrote, has none.
	Element string `json:"element,omitempty"`
}

func (a *APIServer) handleManagedGuardianRepairAudit(w http.ResponseWriter, r *http.Request) {
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
	var report managedGuardianRepairRequest
	var extra any
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&extra) != io.EOF ||
		!utf8.ValidString(report.User) || !utf8.ValidString(report.Connector) ||
		!utf8.ValidString(report.Element) || len(report.User) > 256 || len(report.Connector) > 64 || len(report.Element) > 256 ||
		report.UID == nil || *report.UID < 0 || *report.UID > 1<<31-1 ||
		strings.TrimSpace(report.User) == "" || strings.TrimSpace(report.Connector) == "" {
		http.Error(w, "invalid repair report", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(stripLogInjectionRunes(report.User))
	connectorName := strings.ToLower(strings.TrimSpace(stripLogInjectionRunes(report.Connector)))
	if user == "" || connectorName == "" {
		http.Error(w, "invalid repair report", http.StatusBadRequest)
		return
	}
	element := strings.TrimSpace(stripLogInjectionRunes(report.Element))
	if report.Element != "" && element == "" {
		http.Error(w, "invalid repair report", http.StatusBadRequest)
		return
	}
	details := fmt.Sprintf("re-installed hook entries after deletion for user %s", user)
	structured := map[string]any{}
	if element != "" {
		details = fmt.Sprintf("restored %s for user %s", element, user)
		structured["hook_element"] = element
	}
	(auditCaller{ID: strconv.Itoa(*report.UID), IDKind: useridentity.KindPOSIXUID, Name: auditUserName(user)}).addTo(structured)
	if err := a.logger.LogEvent(audit.Event{
		Action: string(audit.ActionConnectorHookRepaired), Target: connectorName,
		Actor: "defenseclaw", Details: details,
		Severity: "HIGH", Connector: connectorName, Structured: structured,
	}); err != nil {
		http.Error(w, "audit emission failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
