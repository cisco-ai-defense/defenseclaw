// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package kitspec turns a connector's actor kit (internal/substrate/kit)
// into the attest.KitSpec the template build adds to a base image. It is a
// separate package so the controller, which only verifies attestations,
// does not link the harness and image packages.
package kitspec

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// Image identity of the actor, as in deploy/images/actor-kit/kitgen.
const (
	Home    = "/sandbox"
	Workdir = "/work"
	KeyDir  = "/etc/defenseclaw/relay-keys"
)

// Options select and parameterize one connector's kit.
type Options struct {
	Connector  string
	KitVersion string
	GatewayURL string // default kit.DefaultGatewayURL
	// FailMode is the interactive outage mode, "open" or "closed".
	FailMode string
	Provider string
	Model    string
	UID, GID int // default 1000

	// HookBinary and RelayBinary are the static binaries of the kit.
	HookBinary, RelayBinary []byte
	// AgentBinary is the connector's pinned agent build when the kit pins
	// one (kit.AgentReleases, fetched with kit.FetchAgent); it replaces the
	// harness's agent. Arch is its architecture ("amd64" default).
	AgentBinary []byte
	Arch        string
	// MetadataOnly builds the spec for its metadata (phone-home switches,
	// config switches) without the agent binary: never an image.
	MetadataOnly bool

	// Relay session verification (A2/A5): public keys by kid (PEM), the
	// issuer and audience their tokens carry, or the gateway check URL.
	// Every kid must be the key's own id (kit.SessionKeyID), the one the
	// gateway writes in each token; keys need the issuer (GAP-0147).
	SessionKeys   map[string][]byte
	SessionIssuer string
	Audience      string
	VerifyURL     string
	RelayListen   string
	// Providers recorded in the attestation.
	Providers []string
}

// Spec returns the kit layer, the template facts and the harness version of
// a connector.
func Spec(o Options) (attest.KitSpec, attest.TemplateInfo, string, error) {
	var zero attest.KitSpec
	if len(o.HookBinary) == 0 || len(o.RelayBinary) == 0 {
		return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: the hook and relay binaries are required")
	}
	if o.UID == 0 {
		o.UID = 1000
	}
	if o.GID == 0 {
		o.GID = 1000
	}
	h, ok := harness.Get(o.Connector)
	if !ok {
		return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: unknown connector %q", o.Connector)
	}
	ictx, err := image.NewContext(image.BuildSpec{Harness: h, UID: o.UID, GID: o.GID, IngressPort: 18970,
		DefenseClawVersion: o.KitVersion, Owner: "0000000000000000"})
	if err != nil {
		return zero, attest.TemplateInfo{}, "", err
	}
	cfg := kit.DefaultConfig()
	if o.GatewayURL != "" {
		cfg.GatewayURL = o.GatewayURL
	}
	if o.FailMode != "" {
		cfg.FailMode = o.FailMode
	}
	cfg.KitVersion = o.KitVersion
	if o.RelayListen != "" {
		cfg.Relay.Listen = o.RelayListen
	}
	if o.Audience != "" {
		cfg.Relay.SessionAudience = o.Audience
	}
	cfg.Relay.VerifyURL = o.VerifyURL
	cfg.Relay.SessionIssuer = strings.TrimSpace(o.SessionIssuer)
	keyFiles := map[string][]byte{}
	if len(o.SessionKeys) > 0 {
		cfg.Relay.SessionKeys = map[string]string{}
		for kid, pem := range o.SessionKeys {
			id, err := kit.SessionKeyID(pem)
			if err != nil {
				return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: %s: %w", kid, err)
			}
			if kid != id {
				return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: session key id %q is not the key's id %q (the gateway signs with that kid)", kid, id)
			}
			p := path.Join(KeyDir, kid+".pem")
			cfg.Relay.SessionKeys[kid] = p
			keyFiles[p] = pem
		}
	}
	// The rules the hook and the relay apply when they load the file: a
	// configuration they would refuse is never baked into an image.
	if err := cfg.Validate(); err != nil {
		return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: %w", err)
	}
	if err := cfg.Relay.CheckSessions(); err != nil {
		return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: %w", err)
	}
	// The kit may install a newer agent than the harness pins (GAP-0114).
	agentVersion := kit.AgentVersion(o.Connector, ictx.HarnessVersion)
	if _, pinned := kit.AgentReleases[o.Connector]; pinned && !o.MetadataOnly {
		arch := o.Arch
		if arch == "" {
			arch = "amd64"
		}
		if err := kit.CheckAgent(o.Connector, arch, o.AgentBinary); err != nil {
			return zero, attest.TemplateInfo{}, "", fmt.Errorf("kit spec: the pinned agent binary (kit.FetchAgent): %w", err)
		}
	}
	art, err := kit.SubstrateArtifacts(h.Provider, agentVersion, cfg)
	if err != nil {
		return zero, attest.TemplateInfo{}, "", err
	}
	ov, err := kit.ActorOverlay(art, kit.OverlayOptions{Config: cfg, Home: Home, Workdir: Workdir, Provider: o.Provider, Model: o.Model, HarnessVersion: agentVersion})
	if err != nil {
		return zero, attest.TemplateInfo{}, "", err
	}
	for p, b := range keyFiles {
		ov.Files = append(ov.Files, kit.ImageFile{Path: p, Mode: 0o644, Data: b})
	}

	spec := attest.KitSpec{
		Version: o.KitVersion, HookContract: ov.HookContract, Remove: ov.Remove, Env: ov.Env,
		User: fmt.Sprintf("%d:%d", o.UID, o.GID), Workdir: Workdir,
		Entrypoint: []string{kit.RelayBinary, "serve"},
		HomeOwners: map[string][2]int{Home: {o.UID, o.GID}},
		UserFiles:  map[string]bool{},
		PhoneHome:  map[string]string{},
	}
	// Golden-snapshot rule (E5): no machine id in the image.
	spec.Remove = append(spec.Remove, "/var/lib/dbus/machine-id")
	spec.Files = append(spec.Files, attest.LayerFile{Path: "/etc/machine-id", Mode: 0o444})
	spec.Files = append(spec.Files,
		attest.LayerFile{Path: kit.HookBinary, Mode: 0o755, Data: o.HookBinary},
		attest.LayerFile{Path: kit.RelayBinary, Mode: 0o755, Data: o.RelayBinary})
	if r, pinned := kit.AgentReleases[o.Connector]; pinned && !o.MetadataOnly {
		spec.Files = append(spec.Files, attest.LayerFile{Path: r.Path, Mode: 0o755, Data: o.AgentBinary})
	}
	sort.Slice(ov.Files, func(i, j int) bool { return ov.Files[i].Path < ov.Files[j].Path })
	rootDirs := map[string]bool{"/etc/defenseclaw": true, kit.KitDir: true, kit.HookDir: true, kit.LibDir: true}
	for _, f := range ov.Files {
		lf := attest.LayerFile{Path: f.Path, Mode: int64(f.Mode.Perm()), Data: f.Data}
		if f.User {
			lf.UID, lf.GID = o.UID, o.GID
			spec.UserFiles[f.Path] = true
		} else {
			rootDirs[path.Dir(f.Path)] = true
		}
		spec.Files = append(spec.Files, lf)
	}
	// Folders the kit owns are root 0755; the user's folders are the user's.
	var dl []string
	for d := range rootDirs {
		if !strings.HasPrefix(d, Home) && d != "/etc" && d != "/usr/local/etc" {
			dl = append(dl, d)
		}
	}
	sort.Strings(dl)
	for _, d := range dl {
		spec.Files = append(spec.Files, attest.LayerFile{Path: d, Mode: 0o755, Dir: true})
	}
	for _, d := range []struct {
		p    string
		mode int64
	}{{Home, 0o755}, {Home + "/.cache", 0o700}, {Home + "/.cache/tmp", 0o700}, {Home + "/.defenseclaw", 0o700}, {Workdir, 0o755}} {
		spec.Files = append(spec.Files, attest.LayerFile{Path: d.p, Mode: d.mode, UID: o.UID, GID: o.GID, Dir: true})
	}

	// The switches the image must carry (E7).
	for _, set := range []string{o.Connector, "npm"} {
		for k, v := range kit.PhoneHomeOff[set] {
			spec.PhoneHome[k] = v
		}
	}
	if o.Connector == "codex" {
		spec.ConfigSwitches = map[string][]string{
			connector.CodexSandboxManagedConfigPath: {"[feedback]\nenabled = false", "[analytics]\nenabled = false"},
		}
	}
	tpl := attest.TemplateInfo{Connector: o.Connector, AgentVersion: agentVersion, Name: o.Connector, Providers: o.Providers}
	return spec, tpl, agentVersion, nil
}
