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
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
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
		ctx := attachVerifiedSubject(r.Context(), nil, "1201", "dcad-alice", subjectSourcePeerCredentials)
		subject, ok := verifiedSubjectFromContext(ctx)
		got["subject_ok"], got["subject"] = ok, subject
		got["verified"] = requestIdentityFor(ctx, "1201")
		got["forged"] = requestIdentityFor(ctx, "0")
		got["hook_user"] = resolveHookUser(ctx, map[string]interface{}{"user_id": "1202"}).ID
		got["http_user"] = resolveHTTPUserIdentity(r.WithContext(ctx), nil).ID
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
	// The forged user header and payload user never re-attribute the record.
	if got["hook_user"] != "1201" || got["http_user"] != "1201" {
		t.Fatalf("hook user = %v, http user = %v, want the verified uid 1201", got["hook_user"], got["http_user"])
	}
}

// An SSH peer address that starts with a colon (the loopback ::1, an
// IPv4-mapped ::ffff:a.b.c.d) stays on the record: the registry's
// client.address pattern admits the compressed IPv6 forms (GAP-0127).
func TestIdentityKeepsCompressedIPv6ClientAddress(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	for _, addr := range []string{"10.0.1.81", "::1", "::ffff:10.0.1.5"} {
		id := &llmEventIdentity{Session: useridentity.SessionFacts{
			Kind: useridentity.SessionSSH, ClientAddr: addr, Assurance: useridentity.AssuranceClaimed,
		}}
		if got, _ := id.v8().ClientAddress.Get(); got != addr {
			t.Fatalf("client.address for %q = %q", addr, got)
		}
	}
	if v8IdentityToken(":1", 256, false, true).IsPresent() {
		t.Fatal("a single leading colon is not an address token")
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
// identity.observed record carrying the group count (GAP-0060). The same
// facts again within the cache lifetime emit nothing, but changed facts (a
// group added in the directory) emit at once, not up to 15 minutes later.
func TestVerifiedSubjectEmitsIdentityObserved(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	capture := &endpointInventoryCapture{}
	observe := func(groups ...string) {
		observeIdentity(context.Background(), capture, VerifiedSubject{
			UserID: "1291", IDKind: useridentity.KindPOSIXUID, UserName: "dcad-alice",
			Directory: useridentity.DirectoryFacts{
				Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
				Groups: groups, Source: useridentity.SourceSSSDInfoPipe,
				Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
			},
		}, useridentity.SessionFacts{})
	}
	observe("dc-ml-team@dclab.test", "dc-devs@dclab.test")
	observe("dc-devs@dclab.test", "dc-ml-team@dclab.test")
	observe("dc-ml-team@dclab.test", "dc-devs@dclab.test", "dc-sre@dclab.test")
	records := capture.snapshot()
	if len(records) != 2 || string(records[0].EventName()) != observability.TelemetryEventIdentityObserved {
		t.Fatalf("records = %d, want two identity.observed", len(records))
	}
	for i, want := range []string{"2", "3"} {
		if got := fmt.Sprint(canonicalBody(t, records[i])[observability.TelemetryAttributeDefenseClawUserGroupCount]); got != want {
			t.Fatalf("record %d group_count = %s, want %s", i, got, want)
		}
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

// Sandbox traffic is verified as the binding's host user, the gateway's own
// account: its records carry that account's directory facts, which come
// from the refreshed directory cache like host traffic's (GAP-0150). A
// binding that names another account gets no subject.
func TestSandboxHostUserIsVerifiedSubject(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	self, _ := localProcessUser()
	if self == "" {
		t.Skip("no process owner")
	}
	original := managedHookPeerDirectory
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		return useridentity.DirectoryFacts{
			Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Groups: []string{"dc-ml-team@dclab.test"}, ResolvedAt: time.Now(),
		}, strconv.Itoa(uid) == self
	}
	t.Cleanup(func() { managedHookPeerDirectory = original })

	f := newSandboxIngressFixture(t)
	st := f.api.sandboxIngressState()
	_, exact := f.api.sandboxIngressMux()
	next := &recordingHandler{}
	h := f.api.sandboxIngressAuthenticate(st, f.api.sandboxIngressAuthorize(st, exact, next))
	other, _ := strconv.Atoi(self)
	for _, uid := range []string{self, strconv.Itoa(other + 1)} {
		_, token, err := f.store.Mint(sandboxauth.Spec{
			SandboxName: "dc-host-" + uid, Connector: "claudecode", HookContractID: "claudecode-hooks-v1",
			Routes: []sandboxauth.Route{sandboxauth.RouteHook}, Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
			HostUser: sandboxauth.HostUser{UID: uid},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if len(next.reqs) != 2 {
		t.Fatalf("reached mux %d times, want 2", len(next.reqs))
	}
	owner, stranger := next.reqs[0].Context(), next.reqs[1].Context()
	subject, ok := verifiedSubjectFromContext(owner)
	if !ok || subject.UserID != self || len(subject.Directory.Groups) != 1 {
		t.Fatalf("host user subject = %+v, %v", subject, ok)
	}
	identity := resolveHookUserIdentity(owner, "claudecode", nil).Identity
	if identity == nil || identity.Directory.Assurance != useridentity.AssuranceVerified || identity.Directory.Domain != "dclab.test" {
		t.Fatalf("sandbox record identity = %+v, want the verified directory facts", identity)
	}
	if _, ok := verifiedSubjectFromContext(stranger); ok {
		t.Fatal("a binding naming another account got a verified subject")
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

// GAP-0147: the LLM proxy and the ACP routes bind the per-user gateway's own
// account as the verified subject, as the hook routes do, so a loopback
// X-DefenseClaw-User-* pair never names the user there. The proxy, which no
// hook helper calls, drops the pair.
func TestProxyAndACPBindProcessOwnerOverClaimedUser(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	owner, _ := localProcessUser()
	if owner == "" {
		t.Skip("the test account has no passwd entry")
	}
	correlate := CorrelationMiddleware(NewAgentRegistry("", ""))
	forged := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set(llmEventUserIDHeader, "4242")
			r.Header.Set(llmEventUserNameHeader, "forged")
			next.ServeHTTP(w, r)
		})
	}

	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	api := &APIServer{scannerCfg: acpGatewayTestConfig(writePrivateACPToken(t, token), "")}
	acpUser := make(chan string, 1)
	server := httptest.NewServer(forged(correlate(api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/acp/evaluate" {
			acpUser <- AgentIdentityFromContext(r.Context()).UserID
			api.handleACPEvaluate(w, r)
			return
		}
		api.handleACPChallenge(w, r)
	}))))))
	defer server.Close()
	evaluator, err := acp.NewHTTPEvaluator(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evaluator.Evaluate(t.Context(), deniedACPTestEvaluation()); err != nil {
		t.Fatal(err)
	}
	if got := <-acpUser; got != owner {
		t.Fatalf("ACP user.id = %q, want the gateway owner %q", got, owner)
	}

	proxyUser := func(p *GuardrailProxy, dcAuth string) (user string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		if dcAuth != "" {
			req.Header.Set("X-DC-Auth", "Bearer "+dcAuth)
		}
		forged(dropProxyUserClaims(correlate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if authenticated, ok := p.authenticateRequest(r); ok {
				user = AgentIdentityFromContext(authenticated.Context()).UserID
			}
		})))).ServeHTTP(httptest.NewRecorder(), req)
		return user
	}
	if got := proxyUser(&GuardrailProxy{gatewayToken: "gateway-token"}, "gateway-token"); got != owner {
		t.Fatalf("proxy user.id = %q, want the gateway owner %q", got, owner)
	}
	// A request admitted without an owner credential proves nothing about
	// who sent it: it keeps neither the claim nor a verified owner.
	if got := proxyUser(&GuardrailProxy{skipAuthForTest: true}, ""); got != "" {
		t.Fatalf("credential-less proxy user.id = %q, want none", got)
	}
}

// TestVerifiedSubjectIsNamedFromTheGuardianRecordWhenItsLookupFails pins
// GAP-0231: with the domain controller down and a cold SSSD the uid of a hook
// caller has no name, and the audit rows carried none. The uid is always on
// the row; the name the guardian recorded for it (while it was current)
// attributes the row too, and the name used for authorization is unchanged.
func TestVerifiedSubjectIsNamedFromTheGuardianRecordWhenItsLookupFails(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	dir := t.TempDir()
	for uid, record := range map[string]enterprisehooks.IdentitySpoolRecord{
		"94401115": {User: "dcad-frank@dclab.test", UpdatedAt: time.Now().UTC()},
		"94401116": {User: "dcad-old@dclab.test", UpdatedAt: time.Now().UTC().Add(-2 * time.Hour)},
	} {
		record.Key = uid
		data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, uid+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	restoreValidate, restoreDirectory := validateManagedGuardianAuthorization, managedHookPeerDirectory
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	managedHookPeerDirectory = func(int, bool) (useridentity.DirectoryFacts, bool) { return useridentity.DirectoryFacts{}, false }
	t.Cleanup(func() {
		validateManagedGuardianAuthorization, managedHookPeerDirectory = restoreValidate, restoreDirectory
		setIdentitySpoolDir("")
	})
	setIdentitySpoolDir(dir)
	for uid, want := range map[string]string{"94401115": "dcad-frank", "94401116": "", "94401117": ""} {
		ctx := attachVerifiedSubject(context.Background(), nil, uid, "", subjectSourcePeerCredentials)
		pid, _ := strconv.Atoi(uid)
		caller := auditCallerIdentity(withManagedHookPeer(ctx, managedHookPeer{UID: pid}))
		if id := AgentIdentityFromContext(ctx); id.UserID != uid || id.UserName != want || caller.ID != uid || caller.Name != want {
			t.Errorf("uid %s: agent identity %+v, audit caller %+v, want the uid and the name %q", uid, id, caller, want)
		}
	}
}
