// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identityTestRequest runs one forged hook request through the correlation
// middleware and the hook-socket subject attachment for verified uid 1201.
func identityTestRequest(t *testing.T) (got map[string]any) {
	t.Helper()
	original := managedHookPeerDirectory
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if uid != 1201 {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Principal: "dcad-alice@dclab.test", UPN: "dcad-alice@dclab.test", Domain: "dclab.test",
			Realm: "DCLAB.TEST", Directory: useridentity.DirectoryActiveDirectory,
			Groups: []string{"dc-ml-team@dclab.test"}, Source: useridentity.SourceSSSDInfoPipe,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, true
	}
	t.Cleanup(func() { managedHookPeerDirectory = original })

	request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	request.RemoteAddr = "127.0.0.1:40000"
	request.Header.Set(useridentity.SessionFactsHeader,
		"v1;k=ssh;ca=203.0.113.9;krb=mallory@EVIL.TEST;upn=mallory@evil.test")
	request.Header.Set(llmEventUserIDHeader, "0")
	got = map[string]any{}
	handler := CorrelationMiddleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx := (&APIServer{}).attachVerifiedSubject(r.Context(), "1201", "dcad-alice", subjectSourcePeerCredentials)
		subject, ok := verifiedSubjectFromContext(ctx)
		got["subject_ok"], got["subject"] = ok, subject
		got["verified"] = requestIdentityFor(ctx, "1201")
		got["forged"] = requestIdentityFor(ctx, "0")
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	return got
}

func TestSessionFactsHeaderCannotChangeVerifiedFacts(t *testing.T) {
	setIdentityFactsEnabled(true)
	SetUserPrincipalCollectionEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false); SetUserPrincipalCollectionEnabled(false) })

	got := identityTestRequest(t)
	subject := got["subject"].(VerifiedSubject)
	if !got["subject_ok"].(bool) || subject.Directory.Principal != "dcad-alice@dclab.test" ||
		subject.Source != subjectSourcePeerCredentials || len(subject.Directory.Groups) != 1 {
		t.Fatalf("verified subject = %+v", subject)
	}
	verified := got["verified"].(*llmEventIdentity)
	attrs := verified.v8()
	if principal, _ := attrs.Principal.Get(); principal != "dcad-alice@dclab.test" {
		t.Fatalf("principal = %q, want the verified UPN", principal)
	}
	if assurance, _ := attrs.Assurance.Get(); assurance != "verified" {
		t.Fatalf("assurance = %q", assurance)
	}
	// The claimed SSH session is not presented under the verified record,
	// and the claimed Kerberos principal is reported only as itself.
	if attrs.SessionKind.IsPresent() || attrs.ClientAddress.IsPresent() {
		t.Fatalf("claimed session reported as verified: %+v", attrs)
	}
	if krb, _ := attrs.KerberosPrincipal.Get(); krb != "mallory@EVIL.TEST" {
		t.Fatalf("kerberos principal = %q", krb)
	}
	// A record naming another account never receives the verified facts.
	forged := got["forged"].(*llmEventIdentity)
	if forged.Directory.Assurance != useridentity.AssuranceClaimed || forged.Directory.Principal != "mallory@evil.test" {
		t.Fatalf("forged record facts = %+v", forged.Directory)
	}
}

func TestSecureClientIgnoresIdentityFacts(t *testing.T) {
	applyIdentityPosture(&config.Config{DeploymentMode: "managed_enterprise"})
	t.Cleanup(func() { setIdentityFactsEnabled(false); SetUserPrincipalCollectionEnabled(false) })
	if identityFactsEnabled.Load() {
		t.Fatal("identity facts enabled under the Secure Client integration")
	}
	got := identityTestRequest(t)
	if got["subject_ok"].(bool) || got["verified"].(*llmEventIdentity) != nil || got["forged"].(*llmEventIdentity) != nil {
		t.Fatalf("Secure Client attached identity: %+v", got)
	}
	input := observability.LogCompatHookDecisionInput{}
	(&llmEventIdentity{Directory: useridentity.DirectoryFacts{Principal: "a@B", Assurance: useridentity.AssuranceVerified}}).applyTo(&input)
	if !reflect.DeepEqual(input, observability.LogCompatHookDecisionInput{}) {
		t.Fatal("Secure Client record gained identity attributes")
	}
}

// A verified subject with resolved directory facts emits one
// identity.observed record carrying the group count (GAP-0060).
func TestVerifiedSubjectEmitsIdentityObserved(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	capture := &endpointInventoryCapture{}
	(&APIServer{observabilityV8: capture}).observeIdentity(context.Background(), VerifiedSubject{
		UserID: "1291", IDKind: useridentity.KindPOSIXUID, UserName: "dcad-alice",
		Directory: useridentity.DirectoryFacts{
			Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Groups: []string{"dc-ml-team@dclab.test", "dc-devs@dclab.test"}, Source: useridentity.SourceSSSDInfoPipe,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		},
	}, useridentity.SessionFacts{})
	records := capture.snapshot()
	if len(records) != 1 || string(records[0].EventName()) != observability.TelemetryEventIdentityObserved {
		t.Fatalf("records = %d, want one identity.observed", len(records))
	}
	if got := fmt.Sprint(canonicalBody(t, records[0])[observability.TelemetryAttributeDefenseClawUserGroupCount]); got != "2" {
		t.Fatalf("group_count = %s, want 2", got)
	}
}

// Discovery records carry the scanned account's directory facts and the
// agent identity the hook path derives for that account's connector install,
// so inventory joins the agent's decisions (GAP-0016).
func TestDiscoverySignalCarriesInventoryIdentity(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	self := strconv.Itoa(os.Getuid())
	original := managedHookPeerDirectory
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if strconv.Itoa(uid) != self {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: time.Now(),
		}, true
	}
	t.Cleanup(func() { managedHookPeerDirectory = original })
	capture := &endpointInventoryCapture{}
	report := inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: "scan-identity", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 1, ActiveSignals: 1, NewSignals: 1,
		},
		Signals: []inventory.AISignal{{
			SignalID: "model-identity", SignatureID: "local-model", Category: inventory.SignalLocalModel,
			Confidence: .9, State: inventory.AIStateNew, SupportedConnector: "claudecode", UserID: self,
		}},
	}
	if err := (&aiDiscoveryV8Adapter{runtime: capture}).EmitReport(t.Context(), report, nil); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	for _, record := range capture.snapshot() {
		if record.EventName() == "ai_component.discovered" {
			body = canonicalBody(t, record)
		}
	}
	if body == nil || body["defenseclaw.user.directory"] != "active_directory" ||
		body["defenseclaw.user.domain"] != "dclab.test" || body["defenseclaw.user.principal.assurance"] != "verified" {
		t.Fatalf("ai_component.discovered identity = %v", body)
	}
	if want := resolveHookAgentIdentity(t.Context(), agentHookRequest{ConnectorName: "claudecode"}).ID; want != "" &&
		body["defenseclaw.agent.identity.id"] != want {
		t.Fatalf("agent.identity.id = %v, want the hook path's %q", body["defenseclaw.agent.identity.id"], want)
	}
}

func TestParseUtmp(t *testing.T) {
	record := make([]byte, utmpRecordSize)
	binary.LittleEndian.PutUint16(record[0:2], utmpUserProcess)
	binary.LittleEndian.PutUint32(record[4:8], 4242)
	copy(record[utmpLineOffset:], "pts/3")
	copy(record[utmpUserOffset:], "dcad-alice@dclab.test")
	copy(record[utmpHostOffset:], "192.0.2.10")
	copy(record[utmpAddrOffset:], []byte{192, 0, 2, 10})
	dead := make([]byte, utmpRecordSize) // DEAD_PROCESS records are skipped
	binary.LittleEndian.PutUint16(dead[0:2], 8)
	entries := parseUtmp(append(record, dead...), binary.LittleEndian)
	if len(entries) != 1 || entries[0].Line != "pts/3" || entries[0].User != "dcad-alice@dclab.test" ||
		entries[0].PID != 4242 || entries[0].Addr.String() != "192.0.2.10" {
		t.Fatalf("utmp entries = %+v", entries)
	}
}
