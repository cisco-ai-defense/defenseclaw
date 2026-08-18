// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestAlertAcknowledgementV8UsesCanonicalCASAndPreservesEventSeverity(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{store: fixture.store, logger: fixture.logger}
	fixture.sidecar.setAPIServer(api)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	)
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil {
		t.Fatalf("bootstrap bound=%t runtime=%T error=%v", bound, api.observabilityV8RuntimeEmitter(), err)
	}
	event := audit.Event{
		ID: "alert-target-1", Timestamp: time.Now().UTC(), Action: "scan-finding",
		Target: "skill://demo", Actor: "scanner", Details: "unsafe instruction", Severity: "HIGH",
	}
	if err := api.store.LogEvent(event); err != nil {
		t.Fatal(err)
	}
	if err := api.store.LogEvent(audit.Event{
		ID: "platform-event-1", Timestamp: time.Now().UTC(), Action: "sidecar-start",
		Target: "gateway", Actor: "system", Details: "not an alert", Severity: "HIGH",
	}); err != nil {
		t.Fatal(err)
	}
	identity, err := alertAuditDatabaseIdentity(api.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	command := alertAcknowledgementV8Request{
		OperationID: "alert-review-test", AuditDBIdentity: identity,
		Disposition: "acknowledged", Selector: alertAcknowledgementV8Selector{IDs: []string{event.ID}},
		Preview: true,
	}
	status, preview := performAlertAcknowledgementV8Request(t, api, command)
	if status != http.StatusOK || preview.Matched != 1 || preview.Applied != 0 || preview.SelectionDigest == "" {
		t.Fatalf("preview status=%d response=%+v", status, preview)
	}
	command.Preview = false
	command.SelectionDigest = preview.SelectionDigest
	status, applied := performAlertAcknowledgementV8Request(t, api, command)
	if status != http.StatusOK || applied.Matched != 1 || applied.Applied != 1 {
		t.Fatalf("apply status=%d response=%+v", status, applied)
	}
	alerts, err := api.store.ListAlerts(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("active finding-scoped alerts after acknowledgement = %+v", alerts)
	}
	events, err := api.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	foundOriginal, foundCompliance := false, false
	for _, stored := range events {
		if stored.ID == event.ID {
			foundOriginal = stored.Severity == "HIGH"
		}
		if stored.Action == "alert.acknowledgement.requested" {
			foundCompliance = true
		}
	}
	if !foundOriginal || !foundCompliance {
		t.Fatalf("original severity/compliance preserved=%t/%t", foundOriginal, foundCompliance)
	}

	command.OperationID = "alert-review-repeat"
	command.Preview = true
	command.SelectionDigest = ""
	status, preview = performAlertAcknowledgementV8Request(t, api, command)
	if status != http.StatusOK || preview.Matched != 1 || preview.Targets[0].ProjectionVersion != 1 {
		t.Fatalf("repeat preview status=%d response=%+v", status, preview)
	}
	command.Preview = false
	command.SelectionDigest = preview.SelectionDigest
	status, repeated := performAlertAcknowledgementV8Request(t, api, command)
	if status != http.StatusOK || repeated.NoChange != 1 || repeated.Applied != 0 {
		t.Fatalf("repeat status=%d response=%+v", status, repeated)
	}
}

func TestDerivedAlertOperationIDRemainsBoundedAndStable(t *testing.T) {
	base := strings.Repeat("a", 192)
	first := derivedAlertOperationID(base, "alert-1")
	second := derivedAlertOperationID(base, "alert-1")
	if first != second || len(first) > 256 || !strings.HasPrefix(first, base+"-") {
		t.Fatalf("derived operation id length=%d stable=%t", len(first), first == second)
	}
}

func TestAlertAcknowledgementV8RejectsClientSuppliedActor(t *testing.T) {
	_, err := decodeAlertAcknowledgementV8Request(strings.NewReader(
		`{"operation_id":"alert-review-test","actor":"forged:admin","disposition":"dismissed","severity":"HIGH"}`,
	))
	if err == nil {
		t.Fatal("client-controlled compliance actor was accepted")
	}
}

func TestAlertAcknowledgementV8NormalizesAndDomainSeparatesSelectionDigest(t *testing.T) {
	request := alertAcknowledgementV8Request{
		OperationID:     "alert-review-test",
		AuditDBIdentity: alertDigestPrefix + strings.Repeat("0", 64),
		Disposition:     "dismissed", Preview: true,
		Selector: alertAcknowledgementV8Selector{IDs: []string{"alert-b", "alert-a", "alert-a"}},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAlertAcknowledgementV8Request(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Selector.IDs) != 2 || decoded.Selector.IDs[0] != "alert-a" || decoded.Selector.IDs[1] != "alert-b" {
		t.Fatalf("normalized selector=%+v", decoded.Selector)
	}
	first, err := alertSelectionDigest(decoded.Selector, []audit.AlertAcknowledgementTarget{
		{AlertID: "alert-a", ProjectionVersion: 1}, {AlertID: "alert-b", ProjectionVersion: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := alertDigestPrefix + "6e25dbe1df374e7330fc81c4db3ab80ead27ae43b6d1f5ff0f9e90e7eeda1cda"
	if first != want {
		t.Fatalf("selection digest=%q want=%q", first, want)
	}
	second, err := alertSelectionDigest(decoded.Selector, []audit.AlertAcknowledgementTarget{
		{AlertID: "alert-a", ProjectionVersion: 1}, {AlertID: "alert-b", ProjectionVersion: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !validAlertDigest(first) || first == decoded.AuditDBIdentity {
		t.Fatalf("selection digests first=%q second=%q identity=%q", first, second, decoded.AuditDBIdentity)
	}
}

func TestAlertAuditDatabaseIdentityMatchesCrossLanguageVector(t *testing.T) {
	path := "/__defenseclaw_identity_vector__/audit.db"
	want := alertDigestPrefix + "edf22eb16e6d1bf09331b1581c9a33b4694ced26bf3f6c6085a7b06f83291c60"
	if runtime.GOOS == "windows" {
		path = `D:\__defenseclaw_identity_vector__\audit.db`
		want = alertDigestPrefix + "1991f13803f4111a45620ecb5426c7c2363444d9b961a312eacc86d851aed03f"
	}
	got, err := alertAuditDatabaseIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		normalized, normalizeErr := normalizeAlertAuditDatabasePath(path)
		t.Fatalf("identity=%q want=%q normalized=%q normalize_error=%v", got, want, normalized, normalizeErr)
	}
}

func TestAlertAcknowledgementV8RejectsDifferentAuditDatabaseIdentity(t *testing.T) {
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store}
	otherIdentity, err := alertAuditDatabaseIdentity(filepath.Join(t.TempDir(), "other-audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	status, response := performAlertAcknowledgementV8Request(t, api, alertAcknowledgementV8Request{
		OperationID: "alert-review-wrong-db", AuditDBIdentity: otherIdentity,
		Disposition: "dismissed", Selector: alertAcknowledgementV8Selector{Severity: "HIGH"},
		Preview: true,
	})
	if status != http.StatusConflict || response.Error != "audit database identity mismatch" {
		t.Fatalf("status=%d response=%+v", status, response)
	}
}

type alertAcknowledgementV8RuntimeFunc func(
	context.Context,
	audit.AlertAcknowledgementCommand,
) (audit.AlertAcknowledgementResult, error)

func (function alertAcknowledgementV8RuntimeFunc) ApplyAlertAcknowledgement(
	ctx context.Context,
	command audit.AlertAcknowledgementCommand,
) (audit.AlertAcknowledgementResult, error) {
	return function(ctx, command)
}

func TestAlertAcknowledgementV8ReportsPartialAndCASFailuresTruthfully(t *testing.T) {
	runtime := alertAcknowledgementV8RuntimeFunc(func(
		_ context.Context,
		command audit.AlertAcknowledgementCommand,
	) (audit.AlertAcknowledgementResult, error) {
		switch command.AlertID {
		case "alert-applied":
			return audit.AlertAcknowledgementResult{Outcome: audit.AlertAcknowledgementApplied}, nil
		case "alert-rejected":
			return audit.AlertAcknowledgementResult{
				Outcome:         audit.AlertAcknowledgementRejected,
				RejectionReason: audit.AlertAcknowledgementStaleVersion,
			}, nil
		default:
			return audit.AlertAcknowledgementResult{}, errors.New("synthetic unavailable")
		}
	})
	targets := []audit.AlertAcknowledgementTarget{
		{AlertID: "alert-applied"}, {AlertID: "alert-rejected"}, {AlertID: "alert-failed"},
	}
	response := applyAlertAcknowledgementV8Targets(
		t.Context(), runtime,
		alertAcknowledgementV8Request{OperationID: "partial", Disposition: "dismissed"},
		targets, alertAcknowledgementV8Response{Matched: len(targets)},
		audit.AlertDispositionDismissed,
	)
	if response.Applied != 1 || response.Rejected != 1 || response.Failed != 1 ||
		len(response.Failures) != 2 || alertAcknowledgementV8Status(response) != http.StatusServiceUnavailable {
		t.Fatalf("partial response=%+v status=%d", response, alertAcknowledgementV8Status(response))
	}
	if response.Failures[0].Code != string(audit.AlertAcknowledgementStaleVersion) ||
		response.Failures[1].Code != "unavailable" {
		t.Fatalf("failure details=%+v", response.Failures)
	}
}

func TestAlertAcknowledgementV8RejectsSelectionDriftBeforeMutation(t *testing.T) {
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: store}
	if err := api.store.LogEvent(audit.Event{
		ID: "drift-alert", Timestamp: time.Now().UTC(), Action: "scan-finding",
		Target: "skill://drift", Severity: "HIGH",
	}); err != nil {
		t.Fatal(err)
	}
	identity, err := alertAuditDatabaseIdentity(api.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	request := alertAcknowledgementV8Request{
		OperationID: "drift-client", AuditDBIdentity: identity, Disposition: "dismissed",
		Selector: alertAcknowledgementV8Selector{Severity: "HIGH"}, Preview: true,
	}
	status, preview := performAlertAcknowledgementV8Request(t, api, request)
	if status != http.StatusOK {
		t.Fatalf("preview status=%d response=%+v", status, preview)
	}
	if err := store.LogEvent(audit.Event{
		ID: "drift-alert-2", Timestamp: time.Now().UTC(), Action: "scan-finding",
		Target: "skill://drift-2", Severity: "HIGH",
	}); err != nil {
		t.Fatal(err)
	}
	request.Preview = false
	request.SelectionDigest = preview.SelectionDigest
	status, drifted := performAlertAcknowledgementV8Request(t, api, request)
	if status != http.StatusConflict || !drifted.Drift || drifted.Applied != 0 {
		t.Fatalf("drift status=%d response=%+v", status, drifted)
	}
}

func TestAlertAcknowledgementV8UnavailableServerFailsClosed(t *testing.T) {
	var api *APIServer
	request := httptest.NewRequest(http.MethodPost, alertAcknowledgementV8Path, strings.NewReader(
		`{"operation_id":"alert-review-test","disposition":"dismissed","severity":"HIGH"}`,
	))
	response := httptest.NewRecorder()
	api.handleAlertAcknowledgementV8(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func performAlertAcknowledgementV8Request(
	t *testing.T,
	api *APIServer,
	request alertAcknowledgementV8Request,
) (int, alertAcknowledgementV8Response) {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(
		http.MethodPost, alertAcknowledgementV8Path, strings.NewReader(string(encoded)),
	)
	recorder := httptest.NewRecorder()
	api.handleAlertAcknowledgementV8(recorder, httpRequest)
	var response alertAcknowledgementV8Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, response
}
