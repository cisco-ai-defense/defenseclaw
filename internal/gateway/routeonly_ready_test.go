// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func readinessConfig(up config.RoutingUpstreamConfig) *config.Config {
	cfg := &config.Config{DataDir: "/nonexistent"}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}, Upstreams: map[string]config.RoutingUpstreamConfig{"claudecode": up}}
	return cfg
}

func useRoutingCredentials(t *testing.T, values map[string]string) {
	t.Helper()
	prev := routingCredentialValue
	routingCredentialValue = func(_ *config.Config, name string) string { return values[name] }
	t.Cleanup(func() { routingCredentialValue = prev })
}

func onlyReadiness(t *testing.T, got []routeOnlyReadiness) routeOnlyReadiness {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("readiness rows: %+v", got)
	}
	return got[0]
}

func TestRouteOnlyReadinessCredentialClasses(t *testing.T) {
	anthropic := config.RoutingUpstreamConfig{BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages}
	cfg := readinessConfig(anthropic)
	var signers bedrockSigners
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "darwin", &signers, true)); !r.Ready || r.Credential != routeCredentialAgent || r.Custody || r.Provider != "anthropic" || r.Upstream != "https://api.anthropic.com" {
		t.Fatalf("OSS passthrough: %+v", r)
	}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, false)); r.Ready || !strings.Contains(r.Fix, "restart the gateway") {
		t.Fatalf("listener not mounted: %+v", r)
	}
	cfg.Routing.Enabled = false
	if got := routeOnlyReadinessFor(cfg, "linux", &signers, true); got != nil {
		t.Fatalf("routing off reports nothing: %+v", got)
	}

	// Managed macOS (custody): no agent credential is forwarded, so a
	// gateway-held key of the upstream provider and origin is required.
	cfg = readinessConfig(anthropic)
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	useRoutingCredentials(t, map[string]string{"anthropic-key": "sk-ant-held", "openai-key": "sk-held"})
	r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "darwin", &signers, true))
	if r.Ready || !r.Custody || r.Credential != routeCredentialMissing || r.Fix != "set routing.models[].credential for anthropic (base_url https://api.anthropic.com) in the policy bundle" {
		t.Fatalf("custody without a gateway key: %+v", r)
	}
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "gpt", Provider: "openai", Model: "gpt-5", Credential: "openai-key"}}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "darwin", &signers, true)); r.Ready || r.Credential != routeCredentialMissing {
		t.Fatalf("a key of another provider does not cover the upstream: %+v", r)
	}
	cfg.Routing.Models = append(cfg.Routing.Models, config.RoutingModelBackend{Name: "sonnet", Provider: "anthropic", Model: "claude-sonnet", Credential: "anthropic-key"})
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "darwin", &signers, true)); !r.Ready || r.Credential != routeCredentialHeld {
		t.Fatalf("custody with a gateway key: %+v", r)
	}
	cfg.Routing.Models[1].Credential = "unreadable"
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "windows", &signers, true)); r.Ready || r.Credential != routeCredentialMissing {
		t.Fatalf("a credential ref that does not resolve: %+v", r)
	}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, true)); !r.Ready || r.Custody || r.Credential != routeCredentialAgent {
		t.Fatalf("managed Linux passes the agent credential through: %+v", r)
	}

	delete(cfg.Routing.RouteOnly.Upstreams, "claudecode")
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, true)); r.Ready || !strings.Contains(r.Fix, "policy bundle") {
		t.Fatalf("missing upstream on a managed host: %+v", r)
	}
}

func TestRouteOnlyReadinessBedrockSigning(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("DC_READY_AK", "AKIDREADY")
	t.Setenv("DC_READY_SK", "ready-secret")
	base := "https://bedrock-runtime.us-west-2.amazonaws.com"
	iam := &config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthIAMCredentials, AccessKeyEnv: "DC_READY_AK", SecretKeyEnv: "DC_READY_SK"}
	check := func(b *config.RoutingBedrockAuthConfig, baseURL, goos string) routeOnlyReadiness {
		t.Helper()
		cfg := readinessConfig(config.RoutingUpstreamConfig{BaseURL: baseURL, API: config.RoutingAPIInvoke, Bedrock: b})
		if goos != "linux" {
			cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
		}
		var signers bedrockSigners
		return onlyReadiness(t, routeOnlyReadinessFor(cfg, goos, &signers, true))
	}
	r := check(iam, base, "linux")
	if !r.Ready || r.Credential != routeCredentialSigning || r.Signing == nil || !r.Signing.Signer || !r.Signing.Credential || r.Signing.Region != "us-west-2" {
		t.Fatalf("signing ready: %+v %+v", r, r.Signing)
	}
	mismatch := *iam
	mismatch.Region = "us-east-1"
	if r := check(&mismatch, base, "linux"); r.Ready || r.Signing.RegionOK || !strings.Contains(r.Signing.RegionError, "does not match") {
		t.Fatalf("region mismatch: %+v", r.Signing)
	}
	unset := *iam
	unset.AccessKeyEnv, unset.SecretKeyEnv = "DC_READY_UNSET_AK", "DC_READY_UNSET_SK"
	if r := check(&unset, base, "linux"); r.Ready || !r.Signing.Signer || r.Signing.Credential || r.Signing.CredentialError == "" {
		t.Fatalf("no credential: %+v", r.Signing)
	}
	corp := *iam
	corp.Region = "us-west-2"
	if r := check(&corp, "https://bedrock.example.corp", "linux"); r.Ready || !r.Signing.RegionOK || r.Signing.Signer || r.Signing.SignerError == "" {
		t.Fatalf("a non-AWS host gets no credential: %+v", r.Signing)
	}

	// Profiles: the gateway reads the AWS files of its own account.
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(creds, []byte("[bedrock-dev]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = profile-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	found := check(&config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthProfile, Profile: "bedrock-dev"}, base, "linux")
	if !found.Ready || found.Signing.ProfileFound == nil || !*found.Signing.ProfileFound || found.Signing.Profile != "bedrock-dev" {
		t.Fatalf("profile present: %+v", found.Signing)
	}
	missing := check(&config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthProfile, Profile: "gone"}, base, "linux")
	if missing.Ready || missing.Signing.ProfileFound == nil || *missing.Signing.ProfileFound {
		t.Fatalf("profile missing: %+v", missing.Signing)
	}

	// Managed macOS: gateway signing is the gateway credential (custody).
	useRoutingCredentials(t, map[string]string{"ak": "AKIDMANAGED", "sk": "managed-secret"})
	managedIAM := &config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthIAMCredentials, AccessKeyCredential: "ak", SecretKeyCredential: "sk"}
	if r := check(managedIAM, base, "darwin"); !r.Ready || !r.Custody || r.Credential != routeCredentialSigning {
		t.Fatalf("managed signing covers custody: %+v %+v", r, r.Signing)
	}
}

func TestHealthSnapshotCarriesRouteOnlyReadiness(t *testing.T) {
	h := NewSidecarHealth()
	details := map[string]interface{}{"enabled": true, "classifier": "rules"}
	h.SetRouting(StateRunning, "", details)
	h.SetRouteOnlyReadiness([]routeOnlyReadiness{{Connector: "codex", Mounted: true, Credential: routeCredentialMissing, Custody: true, Fix: "set it"}})
	snap := h.Snapshot()
	if _, ok := details["route_only"]; ok {
		t.Fatal("the stored routing details must not be written")
	}
	raw, err := json.Marshal(snap.Routing)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Details struct {
			Classifier string `json:"classifier"`
			RouteOnly  []struct {
				Connector, Credential, Fix string
				Custody                    bool
			} `json:"route_only"`
		} `json:"details"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Details.Classifier != "rules" || len(out.Details.RouteOnly) != 1 ||
		out.Details.RouteOnly[0].Credential != "missing" || !out.Details.RouteOnly[0].Custody || out.Details.RouteOnly[0].Fix != "set it" {
		t.Fatalf("health JSON: %s %v", raw, err)
	}
	h.SetRouteOnlyReadiness(nil)
	if _, ok := h.Snapshot().Routing.Details["route_only"]; ok {
		t.Fatal("no route-only connectors, no route_only key")
	}
}

// Managed macOS custody with gateway Bedrock signing: the signature is the
// gateway credential, so the call goes out signed without a held key, and
// no agent AWS header reaches the upstream.
func TestManagedCustodyGatewaySigningNeedsNoHeldKey(t *testing.T) {
	f := newSigV4Fixture(t)
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "claudecode", OK: true})
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice"})
	api.managedHookAuthz.Store(routeCallerTestAuthz(config.EnterpriseEnrollmentConfig{}, &ledger.ledger, nil))
	f.cfg.DeploymentMode, f.cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	up := f.cfg.Routing.RouteOnly.Upstreams["claudecode"]
	up.Bedrock = &config.RoutingBedrockAuthConfig{Region: "us-east-1", Auth: config.RoutingBedrockAuthIAMCredentials, AccessKeyCredential: "ak", SecretKeyCredential: "sk", SessionTokenCredential: "st"}
	f.cfg.Routing.RouteOnly.Upstreams["claudecode"] = up
	useRoutingCredentials(t, map[string]string{"ak": "AKIDGATEWAY", "sk": "gateway-secret", "st": "gateway-session"})
	api.SetRouteOnly(f.srv)
	f.srv.goos = "darwin"
	prevWin, prevPeer, prevUID := routeCallerWindows, routeCallerPeer, acpLoopbackPeerUID
	routeCallerWindows = false
	routeCallerPeer = func(uid int) managedHookPeer { return managedHookPeer{UID: uid, Name: "alice"} }
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return 1001, nil }
	t.Cleanup(func() { routeCallerWindows, routeCallerPeer, acpLoopbackPeerUID = prevWin, prevPeer, prevUID })
	f.token, _ = connector.UserScopedRouteToken(userScopedTestKey, "claudecode", "1001")

	rec := f.post(t, "/r/claudecode"+sigv4FlowARN, "hello there", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "agent-stale") })
	if rec.Code != http.StatusOK || len(f.orig) != 1 {
		t.Fatalf("custody signed call = %d %s (orig %d)", rec.Code, rec.Body.String(), len(f.orig))
	}
	mustVerify(t, f.orig[0])
}
