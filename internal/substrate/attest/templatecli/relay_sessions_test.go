// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// These tests render the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package templatecli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/kitspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// gatewaySigner is the session signer the gateway runs for an install
// (substrate_serve.go): its issuer comes from the install's config.
func gatewaySigner(t *testing.T, cfg *config.Config) (*identity.SessionSigner, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := identity.NewSessionSigner(key, cfg.Substrate.RelaySessionIssuer())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(p, s.PublicKeyPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	return s, p
}

// substrate-1 GAP-0147: an image built with the product command for an
// install starts its relay, and the relay accepts the session tokens that
// install's gateway issues. The kit file the build bakes is loaded the way
// the relay loads it at start.
func TestBuiltRelayAcceptsTheInstallsSessionTokens(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"defaults":       {},
		"custom service": {Substrate: config.SubstrateConfig{Services: config.SubstrateServicesConfig{Admin: "defenseclaw-admin.dc.svc.cluster.local"}}},
	} {
		t.Run(name, func(t *testing.T) {
			signer, pub := gatewaySigner(t, cfg)
			gw := cfg.Substrate.ActorGatewayURL()
			keys, rs, err := relaySessions(cfg, []string{pub}, "", "", "", gw)
			if err != nil {
				t.Fatal(err)
			}
			if rs.Issuer != signer.Issuer() || !slices.Equal(rs.KeyIDs, []string{signer.KeyID()}) || rs.Audience != identity.SessionAudience {
				t.Fatalf("relay sessions %+v, gateway issuer %q kid %q", rs, signer.Issuer(), signer.KeyID())
			}
			// Every built relay also asks the gateway (GAP-0435).
			if rs.VerifyURL != gw+kit.RelayVerifyPath {
				t.Fatalf("verify URL %q, want %q", rs.VerifyURL, gw+kit.RelayVerifyPath)
			}
			spec, _, err := kitspec.Spec(kitspec.Options{Connector: "claudecode", KitVersion: "t", HookBinary: []byte("h"), GatewayURL: gw,
				RelayBinary: []byte("r"), MetadataOnly: true, SessionKeys: keys, SessionIssuer: rs.Issuer, Audience: rs.Audience, VerifyURL: rs.VerifyURL})
			if err != nil {
				t.Fatal(err)
			}
			files := map[string][]byte{}
			for _, f := range spec.Files {
				files[f.Path] = f.Data
			}
			raw, ok := files[kit.ConfigPath]
			if !ok {
				t.Fatalf("no %s in the kit layer", kit.ConfigPath)
			}
			kc := kit.DefaultConfig()
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&kc); err != nil {
				t.Fatal(err)
			}
			if err := kc.Validate(); err != nil {
				t.Fatal(err)
			}
			if kc.Relay.VerifyURL != rs.VerifyURL {
				t.Fatalf("baked verify_url %q, want %q", kc.Relay.VerifyURL, rs.VerifyURL)
			}
			// The relay reads the baked key files and its identity files; point
			// both at a temporary directory.
			dir := t.TempDir()
			for kid, p := range kc.Relay.SessionKeys {
				local := filepath.Join(dir, kid+".pem")
				if err := os.WriteFile(local, files[p], 0o644); err != nil {
					t.Fatal(err)
				}
				kc.Relay.SessionKeys[kid] = local
			}
			actor := identity.SessionActor{Atespace: "dc-eng", Name: "alice-1", UID: "11111111-2222-3333-4444-555555555555"}
			for f, v := range map[string]string{"atespace": actor.Atespace, "name": actor.Name, "uid": actor.UID} {
				if err := os.WriteFile(filepath.Join(dir, f), []byte(v+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			kc.Relay.IdentityDir = dir
			v, err := relay.NewVerifier(kc)
			if err != nil {
				t.Fatalf("the relay of the built image does not start: %v", err)
			}
			cv, ok := v.(*relay.CheckedVerifier)
			if !ok || cv == nil || cv.Keys == nil || cv.Gateway == nil || cv.Gateway.URL != rs.VerifyURL {
				t.Fatalf("verifier %T, want the keys then the gateway at %s", v, rs.VerifyURL)
			}
			kv := cv.Keys
			tok, _, err := signer.Issue(identity.SessionSignIn{Person: "alice", TokenKey: "jti:a"}, actor, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := kv.VerifyToken(tok); err != nil {
				t.Fatalf("the relay refused the gateway's session token: %v", err)
			}
			// A token of another install (another issuer) is refused.
			other, err := identity.NewSessionSigner(mustKey(t), "https://defenseclaw-admin.elsewhere.svc")
			if err != nil {
				t.Fatal(err)
			}
			tok2, _, _ := other.Issue(identity.SessionSignIn{Person: "alice", TokenKey: "jti:a"}, actor, 5*time.Minute)
			if _, err := kv.VerifyToken(tok2); err == nil {
				t.Fatal("a token of another issuer and key was accepted")
			}
		})
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRelaySessionsRules(t *testing.T) {
	cfg := &config.Config{}
	signer, pub := gatewaySigner(t, cfg)
	const gw = "http://defenseclaw-actor.dc.svc.cluster.local"
	const custom = "http://defenseclaw-actor.other.svc.cluster.local/api/v1/substrate/relay/verify"
	cases := []struct {
		name        string
		keys        []string
		issuer, url string
		wantErr     string
		wantIssuer  string
		wantURL     string
	}{
		{name: "kid matches", keys: []string{signer.KeyID() + "=" + pub}, wantIssuer: signer.Issuer(), wantURL: gw + kit.RelayVerifyPath},
		{name: "explicit issuer wins", keys: []string{pub}, issuer: "https://admin.example.test", wantIssuer: "https://admin.example.test", wantURL: gw + kit.RelayVerifyPath},
		{name: "wrong kid", keys: []string{"k1=" + pub}, wantErr: "is not the key's id"},
		{name: "keys and verify url", keys: []string{pub}, url: custom, wantIssuer: signer.Issuer(), wantURL: custom},
		{name: "nothing: the gateway check", wantURL: gw + kit.RelayVerifyPath},
		{name: "verify url only", url: custom, wantURL: custom},
		{name: "issuer without keys", issuer: "https://admin.example.test", url: "http://x.test/v", wantErr: "goes with --session-key"},
		{name: "not a key", keys: []string{pub + ".missing"}, wantErr: "no such file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rs, err := relaySessions(cfg, c.keys, c.issuer, "", c.url, gw)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rs.Issuer != c.wantIssuer || rs.VerifyURL != c.wantURL {
				t.Fatalf("issuer %q url %q, want %q %q", rs.Issuer, rs.VerifyURL, c.wantIssuer, c.wantURL)
			}
		})
	}
}

// kitspec refuses what the relay would refuse at start, so a direct caller
// (not only the CLI) never bakes a relay that cannot start.
func TestKitSpecRefusesARelayThatWouldNotStart(t *testing.T) {
	signer, pub := gatewaySigner(t, &config.Config{})
	b, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	base := kitspec.Options{Connector: "claudecode", KitVersion: "t", HookBinary: []byte("h"), RelayBinary: []byte("r"), MetadataOnly: true}
	o := base
	o.SessionKeys = map[string][]byte{signer.KeyID(): b}
	if _, _, err := kitspec.Spec(o); err == nil || !strings.Contains(err.Error(), "session_issuer") {
		t.Fatalf("keys without an issuer: %v", err)
	}
	o.SessionKeys = map[string][]byte{"k1": b}
	o.SessionIssuer = signer.Issuer()
	if _, _, err := kitspec.Spec(o); err == nil || !strings.Contains(err.Error(), "not the key's id") {
		t.Fatalf("a kid that is not the key's: %v", err)
	}
	o = base
	o.VerifyURL = "ftp://x"
	if _, _, err := kitspec.Spec(o); err == nil {
		t.Fatal("a verify URL that is not http(s) was accepted")
	}
}

// The install's actor URL without a config is the kit's default, so a build
// with and without --config agree for the default namespace (GAP-0023).
func TestActorGatewayURLDefaultIsTheKitDefault(t *testing.T) {
	if got := (config.SubstrateConfig{}).ActorGatewayURL(); got != kit.DefaultGatewayURL {
		t.Fatalf("config default %q, kit default %q", got, kit.DefaultGatewayURL)
	}
	c := config.SubstrateConfig{Services: config.SubstrateServicesConfig{Actor: "defenseclaw-actor.dc.svc.cluster.local"}}
	if got := c.ActorGatewayURL(); got != "http://defenseclaw-actor.dc.svc.cluster.local" {
		t.Fatalf("custom %q", got)
	}
}

// template build and scan take exactly the kit's connectors (all 10): a
// listed one passes the connector check (the next refusal is the missing
// --from), anything else is a usage error that names the list.
func TestTemplateCommandsTakeTheKitConnectors(t *testing.T) {
	ctx := context.Background()
	for _, name := range kit.Connectors() {
		var out, errb strings.Builder
		if code := Run(ctx, []string{"build", "--connector", name}, &out, &errb); code != ExitUsageError || !strings.Contains(errb.String(), "build needs --from") {
			t.Errorf("build --connector %s: %d %q", name, code, errb.String())
		}
	}
	for _, bad := range []string{"openclaw", "cursor-agent", "claude"} {
		var out, errb strings.Builder
		if code := Run(ctx, []string{"build", "--connector", bad}, &out, &errb); code != ExitUsageError ||
			!strings.Contains(errb.String(), "is not a connector the kit builds") || !strings.Contains(errb.String(), "or devin") {
			t.Errorf("build --connector %s: %d %q", bad, code, errb.String())
		}
		errb.Reset()
		if code := Run(ctx, []string{"scan", "registry.example/x@sha256:" + strings.Repeat("0", 64), "--connector", bad}, &out, &errb); code != ExitUsageError ||
			!strings.Contains(errb.String(), "is not a connector the kit builds") {
			t.Errorf("scan --connector %s: %d %q", bad, code, errb.String())
		}
	}
}

// GAP-0435: every kit a template build renders sets verify_url, so the
// relay asks the gateway, which checks that a token's person owns the
// agent. A build given only --session-key (the documented command) gets
// the actor listener's check by default, and a direct kitspec caller does
// too.
func TestTemplateBuildAlwaysSetsVerifyURLGAP0435(t *testing.T) {
	cfg := &config.Config{}
	signer, pub := gatewaySigner(t, cfg)
	gw := cfg.Substrate.ActorGatewayURL()
	keys, rs, err := relaySessions(cfg, []string{pub}, "", "", "", gw)
	if err != nil {
		t.Fatal(err)
	}
	if rs.VerifyURL != kit.RelayVerifyURL(gw) {
		t.Fatalf("--session-key alone: verify URL %q, want %q", rs.VerifyURL, kit.RelayVerifyURL(gw))
	}
	// kitspec without a verify URL (a direct caller) bakes the default.
	spec, _, err := kitspec.Spec(kitspec.Options{Connector: "claudecode", KitVersion: "t", HookBinary: []byte("h"),
		RelayBinary: []byte("r"), MetadataOnly: true, SessionKeys: keys, SessionIssuer: signer.Issuer()})
	if err != nil {
		t.Fatal(err)
	}
	var kc kit.Config
	for _, f := range spec.Files {
		if f.Path == kit.ConfigPath {
			if err := json.Unmarshal(f.Data, &kc); err != nil {
				t.Fatal(err)
			}
		}
	}
	if want := kit.RelayVerifyURL(kit.DefaultGatewayURL); kc.Relay.VerifyURL != want || len(kc.Relay.SessionKeys) != 1 {
		t.Fatalf("baked relay verify_url %q keys %d, want %q and the key", kc.Relay.VerifyURL, len(kc.Relay.SessionKeys), want)
	}
}
