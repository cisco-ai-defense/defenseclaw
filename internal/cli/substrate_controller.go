// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

var (
	substrateControllerConfig string
	substrateControllerOnce   bool
	substrateControllerCheck  bool
	substrateControllerUsage  string
)

var substrateControllerCmd = &cobra.Command{
	Use:   "substrate-controller",
	Short: "Run the DefenseClaw Agent Substrate controller (in the cluster)",
	Long: `Run the DefenseClaw controller for Agent Substrate actors: it writes each
actor's egress policy before its first resume, re-checks it on resume,
reverts foreign policy changes (three reverts in ten minutes mark the actor
policy_conflict: it keeps only the DefenseClaw rule until its policy is
DefenseClaw's again), admits only attested, digest-pinned templates, adopts forks, suspends idle actors and reports inventory.
It reads substrate: from config.yaml and runs as one replica in the
DefenseClaw namespace; events go to stdout as JSON lines.

  --check   connect to ate-api-server, print what it sees as JSON and exit
  --once    run one reconcile pass and exit`,
	Hidden:      true,
	Args:        cobra.NoArgs,
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE:        runSubstrateController,
}

func init() {
	substrateControllerCmd.Flags().StringVar(&substrateControllerConfig, "config", "", "config.yaml (default: the DefenseClaw config path)")
	substrateControllerCmd.Flags().BoolVar(&substrateControllerOnce, "once", false, "run one reconcile pass and exit")
	substrateControllerCmd.Flags().BoolVar(&substrateControllerCheck, "check", false, "check access to ate-api-server and exit")
	substrateControllerCmd.Flags().StringVar(&substrateControllerUsage, "usage-listen", "",
		"address for Substrate's per-actor usage records (OTLP/HTTP POST /v1/logs or ndjson), the CPU source of idle suspend; empty turns idle suspend off")
	rootCmd.AddCommand(substrateControllerCmd)
}

func runSubstrateController(cmd *cobra.Command, _ []string) error {
	path := substrateControllerConfig
	if path == "" {
		path = config.ConfigPath()
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return err
	}
	sub := cfg.Substrate
	if !sub.Enabled {
		return errors.New("substrate.enabled is false in " + path)
	}
	auth, err := ateapi.ParseAuth(sub.API.Auth)
	if err != nil {
		return err
	}
	client, err := ateapi.New(ateapi.Options{
		Address: sub.API.Address, ServerName: sub.API.ServerName, CAFile: orDefaultString(sub.API.CAFile, ateapi.DefaultCAFile),
		Auth: auth, TokenFile: sub.API.TokenFile, CredentialBundle: sub.API.CredentialBundle,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if substrateControllerCheck {
		return substrateControllerReport(ctx, cmd, client)
	}
	attestor := controller.Attestor(controller.NoAttestor{})
	if sub.AttestationRequired() {
		// Anchors come from the admin-only Secret mount and are re-read on
		// change; a missing file refuses every template (fail closed).
		ver, anchors := controller.VerifierFromConfig(sub.Templates)
		if _, err := anchors.Get(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v: every template is refused until the trust anchors are mounted\n", err)
		}
		attestor = &controller.TemplateAttestor{Verifier: ver, VolumeImages: sub.Templates.VolumeImages}
	}
	var cpu controller.CPUSource
	idleAfter := sub.EffectiveIdleSuspendAfter()
	if substrateControllerUsage != "" {
		usage := controller.NewUsageCPU(nil)
		mux := http.NewServeMux()
		mux.Handle("/v1/logs", usage.Handler())
		srv := &http.Server{Addr: substrateControllerUsage, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.ListenAndServe() }()
		defer srv.Close()
		cpu = usage
	} else {
		idleAfter = 0 // no CPU source: never suspend on silence alone (E4)
	}
	ctl, err := controller.New(controller.Options{
		Client: client, Attestor: attestor, Activity: controller.NoActivity{}, CPU: cpu,
		Registry: controller.NewMemoryRegistry(), Resolver: &controller.ConfigResolver{Config: cfg},
		Sink:     &controller.JSONSink{W: cmd.OutOrStdout()},
		Settings: controller.SettingsFromConfig(cfg), Secrets: controller.SecretsFromConfig(cfg),
		LauncherAtespaces: controller.LauncherSet(cfg), RequireAttestation: sub.AttestationRequired(), Templates: sub.Templates,
		KitVersion: appVersion, IdleSuspendAfter: idleAfter,
	})
	if err != nil {
		return err
	}
	if substrateControllerOnce {
		return ctl.Reconcile(ctx)
	}
	if err := ctl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func substrateControllerReport(ctx context.Context, cmd *cobra.Command, client ateapi.Client) error {
	spaces, err := ateapi.AllAtespaces(ctx, client, 0)
	if err != nil {
		return fmt.Errorf("list atespaces: %w", err)
	}
	actors, err := ateapi.AllActors(ctx, client, "", 0)
	if err != nil {
		return fmt.Errorf("list actors: %w", err)
	}
	names := make([]string, 0, len(spaces))
	for _, s := range spaces {
		names = append(names, s.GetMetadata().GetName())
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"atespaces": names, "actors": len(actors)})
}

func orDefaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
