// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// These tests render the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package templatecli

import (
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
			keys, rs, err := relaySessions(cfg, []string{pub}, "", "", "", true)
			if err != nil {
				t.Fatal(err)
			}
			if rs.Issuer != signer.Issuer() || !slices.Equal(rs.KeyIDs, []string{signer.KeyID()}) || rs.Audience != identity.SessionAudience {
				t.Fatalf("relay sessions %+v, gateway issuer %q kid %q", rs, signer.Issuer(), signer.KeyID())
			}
			spec, _, _, err := kitspec.Spec(kitspec.Options{Connector: "claudecode", KitVersion: "t", HookBinary: []byte("h"),
				RelayBinary: []byte("r"), MetadataOnly: true, SessionKeys: keys, SessionIssuer: rs.Issuer, Audience: rs.Audience})
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
			kv, ok := v.(*relay.KeyVerifier)
			if !ok || kv == nil {
				t.Fatalf("verifier %T", v)
			}
			tok, _, err := signer.Issue("alice", actor, 5*time.Minute)
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
			tok2, _, _ := other.Issue("alice", actor, 5*time.Minute)
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
	cases := []struct {
		name        string
		keys        []string
		issuer, url string
		startsRelay bool
		wantErr     string
		wantIssuer  string
	}{
		{name: "kid matches", keys: []string{signer.KeyID() + "=" + pub}, startsRelay: true, wantIssuer: signer.Issuer()},
		{name: "explicit issuer wins", keys: []string{pub}, issuer: "https://admin.example.test", startsRelay: true, wantIssuer: "https://admin.example.test"},
		{name: "wrong kid", keys: []string{"k1=" + pub}, startsRelay: true, wantErr: "is not the key's id"},
		{name: "keys and verify url", keys: []string{pub}, url: "http://defenseclaw-actor.dc.svc.cluster.local/api/v1/substrate/relay/verify", startsRelay: true, wantErr: "give one"},
		{name: "nothing, relay starts", startsRelay: true, wantErr: "nobody could attach"},
		{name: "nothing, keep entrypoint", startsRelay: false},
		{name: "verify url only", url: "http://defenseclaw-actor.dc.svc.cluster.local/api/v1/substrate/relay/verify", startsRelay: true},
		{name: "issuer without keys", issuer: "https://admin.example.test", url: "http://x.test/v", startsRelay: true, wantErr: "goes with --session-key"},
		{name: "not a key", keys: []string{pub + ".missing"}, startsRelay: true, wantErr: "no such file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rs, err := relaySessions(cfg, c.keys, c.issuer, "", c.url, c.startsRelay)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rs.Issuer != c.wantIssuer {
				t.Fatalf("issuer %q, want %q", rs.Issuer, c.wantIssuer)
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
	if _, _, _, err := kitspec.Spec(o); err == nil || !strings.Contains(err.Error(), "session_issuer") {
		t.Fatalf("keys without an issuer: %v", err)
	}
	o.SessionKeys = map[string][]byte{"k1": b}
	o.SessionIssuer = signer.Issuer()
	if _, _, _, err := kitspec.Spec(o); err == nil || !strings.Contains(err.Error(), "not the key's id") {
		t.Fatalf("a kid that is not the key's: %v", err)
	}
	o = base
	o.VerifyURL = "ftp://x"
	if _, _, _, err := kitspec.Spec(o); err == nil {
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
