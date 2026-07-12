// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const alertAcknowledgementV8Path = "/api/v1/alerts/disposition"
const alertAcknowledgementV8Actor = "cli:operator"

type alertAcknowledgementV8Runtime interface {
	ApplyAlertAcknowledgement(
		context.Context,
		audit.AlertAcknowledgementCommand,
	) (audit.AlertAcknowledgementResult, error)
}

type alertAcknowledgementV8Request struct {
	OperationID string `json:"operation_id"`
	Disposition string `json:"disposition"`
	Severity    string `json:"severity"`
}

type alertAcknowledgementV8Response struct {
	Matched  int `json:"matched"`
	Applied  int `json:"applied"`
	NoChange int `json:"no_change"`
	Rejected int `json:"rejected"`
}

func (a *APIServer) handleAlertAcknowledgementV8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.store == nil {
		http.Error(w, `{"error":"canonical alert runtime unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(alertAcknowledgementV8Runtime)
	if !ok || runtime == nil {
		http.Error(w, `{"error":"canonical alert runtime unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	request, err := decodeAlertAcknowledgementV8Request(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid alert disposition request"}`, http.StatusBadRequest)
		return
	}
	targets, err := a.store.ListAlertAcknowledgementTargets(r.Context(), request.Severity)
	if err != nil {
		http.Error(w, `{"error":"alert disposition unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	disposition := audit.AlertDisposition(request.Disposition)
	response := alertAcknowledgementV8Response{Matched: len(targets)}
	for _, target := range targets {
		result, applyErr := runtime.ApplyAlertAcknowledgement(r.Context(), audit.AlertAcknowledgementCommand{
			OperationID: derivedAlertOperationID(request.OperationID, target.AlertID),
			AlertID:     target.AlertID, Actor: alertAcknowledgementV8Actor, Disposition: disposition,
			ExpectedProjectionVersion: target.ProjectionVersion,
		})
		if applyErr != nil {
			http.Error(w, `{"error":"alert disposition unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		switch result.Outcome {
		case audit.AlertAcknowledgementApplied:
			response.Applied++
		case audit.AlertAcknowledgementNoChange:
			response.NoChange++
		case audit.AlertAcknowledgementRejected:
			response.Rejected++
		}
	}
	a.writeJSON(w, http.StatusOK, response)
}

func decodeAlertAcknowledgementV8Request(body io.Reader) (alertAcknowledgementV8Request, error) {
	if body == nil {
		return alertAcknowledgementV8Request{}, errors.New("missing body")
	}
	raw, err := io.ReadAll(io.LimitReader(body, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 || !cliObservabilityV8JSONHasUniqueKeys(raw) {
		return alertAcknowledgementV8Request{}, errors.New("invalid body")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request alertAcknowledgementV8Request
	if err := decoder.Decode(&request); err != nil {
		return alertAcknowledgementV8Request{}, errors.New("invalid body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return alertAcknowledgementV8Request{}, errors.New("trailing body")
	}
	if !observability.IsStableToken(request.OperationID) || len(request.OperationID) > 192 {
		return alertAcknowledgementV8Request{}, errors.New("invalid identifiers")
	}
	if request.Disposition != string(audit.AlertDispositionAcknowledged) &&
		request.Disposition != string(audit.AlertDispositionDismissed) {
		return alertAcknowledgementV8Request{}, errors.New("invalid disposition")
	}
	switch request.Severity {
	case "all", "CRITICAL", "HIGH", "MEDIUM", "LOW":
	default:
		return alertAcknowledgementV8Request{}, errors.New("invalid severity")
	}
	return request, nil
}

func derivedAlertOperationID(base, alertID string) string {
	digest := sha256.Sum256([]byte(alertID))
	return base + "-" + hex.EncodeToString(digest[:8])
}
