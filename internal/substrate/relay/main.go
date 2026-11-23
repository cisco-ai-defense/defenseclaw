// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// NewVerifier builds the session verifier the configuration names: the
// gateway check (verify_url), preceded by the public keys when the kit
// carries them. Keys without verify_url are refused (GAP-0435): they check
// the signature and the actor, not that the token's person owns the agent.
// With neither, it is nil and the relay refuses every attachment.
func NewVerifier(cfg kit.Config) (Verifier, error) {
	rc := cfg.Relay
	if err := rc.CheckSessions(); err != nil {
		return nil, err
	}
	if rc.VerifyURL == "" {
		return nil, nil
	}
	t, err := kit.NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	gw := &GatewayVerifier{URL: rc.VerifyURL, Client: t.Client()}
	if len(rc.SessionKeys) == 0 {
		return gw, nil
	}
	keys := map[string]crypto.PublicKey{}
	for kid, path := range rc.SessionKeys {
		k, err := LoadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("relay session key %s: %w", kid, err)
		}
		keys[kid] = k
	}
	return &CheckedVerifier{Keys: &KeyVerifier{Keys: keys, Audience: rc.SessionAudience, Issuer: rc.SessionIssuer,
		Self: IdentityFiles(rc.IdentityDir)}, Gateway: gw}, nil
}

// Main is the defenseclaw-actor-relay entrypoint.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	// The file copies a separated relay runs as the agent's user.
	if IsChildCommand(args) {
		return runChild(args, os.Stdin, stdout, stderr)
	}
	fs := flag.NewFlagSet("defenseclaw-actor-relay "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "listen address (default: the configuration's relay.listen)")
	prompt := fs.String("prompt", "", "task: the task text")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "mcp-stdio":
		// The agent's side of a laptop MCP bridge (B3.3, mcp.go).
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: defenseclaw-actor-relay mcp-stdio NAME")
			return 2
		}
		return MCPStdio(fs.Arg(0), os.Stdin, stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "defenseclaw-actor-relay %s (%s)\n", kit.Version, Version)
		return 0
	case "serve", "task":
	default:
		fmt.Fprintf(stderr, "defenseclaw-actor-relay: unknown command %q (serve, task, mcp-stdio, version)\n", args[0])
		return 2
	}
	cfg, err := kit.LoadConfig(kit.ConfigPath)
	if err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	// The port is bound before the relay gives up its capabilities
	// (GAP-0376): a port below 1024 needs CAP_NET_BIND_SERVICE.
	var ln net.Listener
	if args[0] == "serve" {
		addr := cfg.Relay.Listen
		if *listen != "" {
			addr = *listen
		}
		if ln, err = net.Listen("tcp", addr); err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
			return 1
		}
	}
	// The agent runs as its own user when the image says so (GAP-0116);
	// a root relay that cannot change user refuses to run the agent at all,
	// and a separated relay keeps only the capabilities it needs (GAP-0376).
	sep, warn, err := separate(cfg.Relay)
	if err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	if warn != "" {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay: warning:", warn)
	}
	if args[0] == "task" {
		enc := json.NewEncoder(stdout)
		t, err := kit.NewTransport(cfg)
		if err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
			return 1
		}
		end := RunHeadless(context.Background(), cfg, TaskRequest{Prompt: *prompt}, HeadlessOptions{Warm: t.Warm, sep: sep},
			func(e TaskEvent) { e.TS = time.Now().UTC().Format(time.RFC3339Nano); _ = enc.Encode(e) })
		if err := ReportTaskEnd(context.Background(), GatewayReport(t), end); err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-relay: task-end report:", err)
		}
		return end.ExitCode
	}
	// No process of the agent's user may trace the relay or open its
	// descriptors, the agent's PTY master among them (GAP-0048).
	if err := hardenProcess(); err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay: harden:", err)
		return 1
	}
	if !holdSignals() && sep == nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay: warning: not PID 1, so a process of the agent's user can stop the relay; in an actor the relay is the entrypoint")
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	var certs *CertSource
	if cfg.Relay.ServesTLS() {
		t, err := kit.NewTransport(cfg)
		if err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
			return 1
		}
		certs = &CertSource{URL: cfg.Relay.CertURL(), Client: t.Client(), Self: IdentityFiles(cfg.Relay.IdentityDir)}
		// Best effort: in a template snapshot the actor has no egress yet,
		// and the first handshake asks again.
		go func() {
			if err := certs.Warm(context.Background()); err != nil {
				log.Info("relay.tls_cert", "state", "deferred", "reason", err.Error())
			}
		}()
	}
	h := NewServer(Options{Config: cfg, Verifier: v, sep: sep, Log: log, Certs: certs}).Handler()
	if err := serveListeners(ln, h, certs); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	return 0
}
