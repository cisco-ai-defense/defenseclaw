// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// kitgen renders the build context of a wave-1 actor image: the connector's
// OpenShell harness overlay (internal/openshell/image, unchanged) as the
// first stage, and the actor kit layer (internal/substrate/kit) on top. The
// template build (A9) does the same through the kit package; this tool is
// for building and testing the images by hand.
//
//	go run ./deploy/images/actor-kit/kitgen --connector claudecode --out /tmp/ctx
//	cp defenseclaw-actor-hook defenseclaw-actor-relay /tmp/ctx/kit/bin/
//	docker buildx build -t <registry>/<repo>:<tag> --push /tmp/ctx
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

type keyFlag map[string]string

func (k keyFlag) String() string { return fmt.Sprint(map[string]string(k)) }
func (k keyFlag) Set(v string) error {
	kid, file, ok := strings.Cut(v, "=")
	if !ok || kid == "" || file == "" {
		return fmt.Errorf("want kid=path")
	}
	k[kid] = file
	return nil
}

func main() {
	connectorName := flag.String("connector", "claudecode", kit.ConnectorList())
	out := flag.String("out", "", "output directory (created; must not exist)")
	uid := flag.Int("uid", 1000, "image USER uid")
	gid := flag.Int("gid", 1000, "image USER gid")
	gateway := flag.String("gateway-url", kit.DefaultGatewayURL, "actor listener base URL")
	failMode := flag.String("fail-mode", "closed", "interactive outage mode (open or closed)")
	provider := flag.String("provider", "", "model route (claudecode: bedrock|anthropic; codex: openai|bedrock-mantle)")
	model := flag.String("model", "", "default model id")
	version := flag.String("kit-version", "dev", "kit version (also the DefenseClaw version label)")
	listen := flag.String("relay-listen", ":8080", "relay listen address")
	keys := keyFlag{}
	flag.Var(keys, "session-key", "launcher session-token public key, kid=PEM file (repeatable)")
	audience := flag.String("session-audience", "dcrelay", "session token audience")
	issuer := flag.String("session-issuer", "", "session token issuer (required with --session-key)")
	verifyURL := flag.String("verify-url", "", "gateway session-token check URL (instead of keys)")
	interactive := flag.String("interactive", "", "relay interactive argv, space-separated (test variants; default: the connector)")
	managedFlag := flag.Bool("managed", false, "managed_enterprise image: the relay refuses an agent that signs in to a vendor account (E9)")
	flag.Parse()
	managedImage = *managedFlag
	if *interactive != "" {
		interactiveArgv = strings.Fields(*interactive)
	}
	sessionIssuer = *issuer
	if err := run(*connectorName, *out, *uid, *gid, *gateway, *failMode, *provider, *model, *version, *listen, keys, *audience, *verifyURL); err != nil {
		fmt.Fprintln(os.Stderr, "kitgen:", err)
		os.Exit(1)
	}
}

var (
	interactiveArgv []string
	sessionIssuer   string
	managedImage    bool
)

const (
	home    = "/sandbox"
	workdir = "/work"
	keyDir  = "/etc/defenseclaw/relay-keys"
)

func run(name, out string, uid, gid int, gateway, failMode, provider, model, version, listen string, keys keyFlag, audience, verifyURL string) error {
	if out == "" {
		return fmt.Errorf("--out is required")
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%s exists", out)
	}
	h, ok := harness.Get(name)
	if !ok {
		return fmt.Errorf("unknown connector %q", name)
	}
	ctx, err := image.NewContext(image.BuildSpec{Harness: h, HarnessVersion: kit.HarnessRelease(name), UID: uid, GID: gid, IngressPort: 18970,
		DefenseClawVersion: version, Owner: "0000000000000000"})
	if err != nil {
		return err
	}
	cfg := kit.DefaultConfig()
	cfg.GatewayURL, cfg.FailMode, cfg.KitVersion = gateway, failMode, version
	cfg.Managed = managedImage
	cfg.Relay.Listen, cfg.Relay.SessionAudience, cfg.Relay.VerifyURL = listen, audience, verifyURL
	cfg.Relay.Interactive = interactiveArgv
	cfg.Relay.SessionIssuer = sessionIssuer
	if len(keys) > 0 && sessionIssuer == "" {
		return fmt.Errorf("--session-key needs --session-issuer")
	}
	keyFiles := map[string][]byte{}
	if len(keys) > 0 {
		cfg.Relay.SessionKeys = map[string]string{}
		for kid, file := range keys {
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			p := path.Join(keyDir, kid+".pem")
			cfg.Relay.SessionKeys[kid] = p
			keyFiles[p] = b
		}
	}
	// The kit may install a newer agent than the harness pins (GAP-0114):
	// the settings are rendered for the agent the image runs.
	agentVersion := kit.AgentVersion(name, ctx.HarnessVersion)
	art, err := kit.SubstrateArtifacts(h.Provider, agentVersion, cfg)
	if err != nil {
		return err
	}
	ov, err := kit.ActorOverlay(art, kit.OverlayOptions{Config: cfg, Home: home, Workdir: workdir, Provider: provider, Model: model, HarnessVersion: agentVersion})
	if err != nil {
		return err
	}
	for p, b := range keyFiles {
		ov.Files = append(ov.Files, kit.ImageFile{Path: p, Mode: 0o644, Data: b})
	}
	sort.Slice(ov.Files, func(i, j int) bool { return ov.Files[i].Path < ov.Files[j].Path })

	write := func(rel string, data []byte) error {
		p := filepath.Join(out, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, data, 0o644)
	}
	var harnessDockerfile []byte
	for _, f := range ctx.Files {
		if f.Name == "Dockerfile" {
			harnessDockerfile = f.Data
			continue
		}
		if err := write(f.Name, f.Data); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(out, "kit", "bin"), 0o755); err != nil {
		return err
	}
	var df strings.Builder
	df.WriteString("# DefenseClaw actor image for Agent Substrate: " + h.DisplayName + " " + kit.AgentVersion(name, ctx.HarnessVersion) + ", kit " + version + ".\n")
	df.WriteString("# Generated by deploy/images/actor-kit/kitgen. Stage 1 is the OpenShell harness overlay, unchanged.\n")
	first := true
	for _, line := range strings.Split(strings.TrimRight(string(harnessDockerfile), "\n"), "\n") {
		if first && strings.HasPrefix(line, "FROM ") {
			line += " AS harness"
			first = false
		}
		df.WriteString(line + "\n")
	}
	df.WriteString("\n# Stage 2: the actor kit layer (internal/substrate/kit).\nFROM harness\nUSER root\n")
	df.WriteString("# OpenShell-only pieces are removed: an actor has no supervisor, launcher or shell hooks. The relay holds the agent's terminal itself.\n")
	df.WriteString("RUN set -eu; rm -rf")
	for _, r := range ov.Remove {
		df.WriteString(" '" + r + "'")
	}
	df.WriteString("; rm -f /var/lib/dbus/machine-id; if [ -s /etc/machine-id ]; then : > /etc/machine-id; fi\n")
	if script := kit.AgentInstallScript(name); script != "" {
		fmt.Fprintf(&df, "# %s %s over the harness build (version and checksum pinned in internal/substrate/kit/agentpin.go).\nRUN %s\n",
			h.DisplayName, agentVersion, script)
	}
	fmt.Fprintf(&df, "COPY --chown=0:0 --chmod=0755 kit/bin/defenseclaw-actor-hook %s\n", kit.HookBinary)
	fmt.Fprintf(&df, "COPY --chown=0:0 --chmod=0755 kit/bin/defenseclaw-actor-relay %s\n", kit.RelayBinary)
	dirs := map[string]bool{"/etc/defenseclaw": true, kit.KitDir: true, kit.HookDir: true, kit.LibDir: true}
	// Directories of user-owned files: COPY would create them root-owned, and
	// the agent could not write its own state there (~/.codex).
	userDirs := map[string]bool{}
	for _, f := range ov.Files {
		if d := path.Dir(f.Path); f.User && d != home && strings.HasPrefix(d, home+"/") {
			userDirs[d] = true
		}
	}
	if len(userDirs) > 0 {
		var ud []string
		for d := range userDirs {
			ud = append(ud, d)
		}
		sort.Strings(ud)
		fmt.Fprintf(&df, "RUN install -d -o %d -g %d -m 0700 %s\n", uid, gid, strings.Join(ud, " "))
	}
	if len(ov.UserDirs) > 0 {
		fmt.Fprintf(&df, "RUN install -d -o %d -g %d -m 0755 %s\n", uid, gid, strings.Join(ov.UserDirs, " "))
	}
	for _, f := range ov.Files {
		rel := path.Join("kit/files", f.Path)
		if err := write(rel, f.Data); err != nil {
			return err
		}
		owner := "0:0"
		if f.User {
			owner = fmt.Sprintf("%d:%d", uid, gid)
		} else {
			dirs[path.Dir(f.Path)] = true
		}
		fmt.Fprintf(&df, "COPY --chown=%s --chmod=%04o %s %s\n", owner, uint32(f.Mode.Perm()), rel, f.Path)
	}
	for _, d := range ov.RootDirs {
		fmt.Fprintf(&df, "RUN chown root:root %s && chmod 0755 %s\n", d, d)
	}
	var dl []string
	for d := range dirs {
		if !strings.HasPrefix(d, home) && d != "/etc" && d != "/usr/local/etc" {
			dl = append(dl, d)
		}
	}
	sort.Strings(dl)
	fmt.Fprintf(&df, "RUN set -eu; for d in %s; do chown root:root \"$d\"; chmod 0755 \"$d\"; done; "+
		"install -d -o %d -g %d -m 0700 %s/.cache %s/.cache/tmp %s/.defenseclaw; install -d -o %d -g %d -m 0755 %s; chown %d:%d %s\n",
		strings.Join(dl, " "), uid, gid, home, home, home, uid, gid, workdir, uid, gid, workdir)
	envKeys := make([]string, 0, len(ov.Env))
	for k := range ov.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		v, _ := json.Marshal(ov.Env[k])
		fmt.Fprintf(&df, "ENV %s=%s\n", k, v)
	}
	fmt.Fprintf(&df, "LABEL io.defenseclaw.actor-kit=%q io.defenseclaw.connector=%q io.defenseclaw.hook-contract=%q io.defenseclaw.harness-version=%q\n",
		version, name, ov.HookContract, agentVersion)
	fmt.Fprintf(&df, "USER %d:%d\nWORKDIR %s\nEXPOSE %s\nENTRYPOINT [%q, \"serve\"]\n", uid, gid, workdir, strings.TrimPrefix(listen, ":"), kit.RelayBinary)
	if err := write("Dockerfile", []byte(df.String())); err != nil {
		return err
	}
	fmt.Printf("%s: %s %s (harness %s), hook contract %s, %d kit files -> %s\n", name, h.DisplayName, agentVersion, ctx.HarnessVersion, ov.HookContract, len(ov.Files), out)
	return nil
}
