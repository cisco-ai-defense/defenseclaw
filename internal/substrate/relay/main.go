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
	"net/http"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// NewVerifier builds the session verifier the configuration names: the
// gateway check when verify_url is set, else the public keys. With neither,
// it is nil and the relay refuses every attachment.
func NewVerifier(cfg kit.Config) (Verifier, error) {
	rc := cfg.Relay
	if rc.VerifyURL != "" {
		t, err := kit.NewTransport(cfg)
		if err != nil {
			return nil, err
		}
		return &GatewayVerifier{URL: rc.VerifyURL, Client: t.Client()}, nil
	}
	if len(rc.SessionKeys) == 0 {
		return nil, nil
	}
	keys := map[string]crypto.PublicKey{}
	for kid, path := range rc.SessionKeys {
		k, err := LoadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("relay session key %s: %w", kid, err)
		}
		keys[kid] = k
	}
	return &KeyVerifier{Keys: keys, Audience: rc.SessionAudience, Issuer: rc.SessionIssuer,
		Self: IdentityFiles(rc.IdentityDir)}, nil
}

// Main is the defenseclaw-actor-relay entrypoint.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	fs := flag.NewFlagSet("defenseclaw-actor-relay "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", kit.ConfigPath, "kit configuration")
	listen := fs.String("listen", "", "listen address (default: the configuration's relay.listen)")
	prompt := fs.String("prompt", "", "task: the task text")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *configPath != kit.ConfigPath && os.Getenv("DEFENSECLAW_ACTOR_KIT_TEST") != "1" {
		*configPath = kit.ConfigPath
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "defenseclaw-actor-relay %s (%s)\n", kit.Version, Version)
		return 0
	case "serve", "task":
	default:
		fmt.Fprintf(stderr, "defenseclaw-actor-relay: unknown command %q (serve, task, version)\n", args[0])
		return 2
	}
	cfg, err := kit.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	if args[0] == "task" {
		enc := json.NewEncoder(stdout)
		code := RunHeadless(context.Background(), cfg, TaskRequest{Prompt: *prompt, Args: fs.Args()},
			func(ctx context.Context) error { return kit.SetUnattended(ctx, warmBudget) },
			func(ctx context.Context, c string) error { return kit.Warm(ctx, c, warmBudget) },
			func(e TaskEvent) { e.TS = time.Now().UTC().Format(time.RFC3339Nano); _ = enc.Encode(e) })
		return code
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	addr := cfg.Relay.Listen
	if *listen != "" {
		addr = *listen
	}
	srv := &http.Server{Addr: addr, Handler: NewServer(Options{Config: cfg, Verifier: v,
		Log: slog.New(slog.NewJSONHandler(stderr, nil))}).Handler(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay:", err)
		return 1
	}
	return 0
}
