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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
)

var substrateExtprocOpts struct {
	config            string
	listen            string
	healthListen      string
	tlsBundle         string
	clientCA          string
	insecurePlaintext bool
}

// substrateExtprocCmd runs the Agent Substrate egress callout: the Envoy
// ext_proc processor atenet-egress calls for every actor request (PLAN
// §6.3). The chart runs it as its own Deployment; it is hidden because no
// person runs it by hand.
var substrateExtprocCmd = &cobra.Command{
	Use:               "substrate-extproc",
	Short:             "Run the Agent Substrate egress callout (Envoy ext_proc)",
	Hidden:            true,
	Args:              cobra.NoArgs,
	SilenceUsage:      true,
	Annotations:       map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	PersistentPostRun: func(*cobra.Command, []string) {},
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return runSubstrateExtproc(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr())
	},
}

func init() {
	f := substrateExtprocCmd.Flags()
	f.StringVar(&substrateExtprocOpts.config, "config", "", "callout configuration file (rendered by the chart)")
	f.StringVar(&substrateExtprocOpts.listen, "listen", ":9443", "gRPC ext_proc listen address")
	f.StringVar(&substrateExtprocOpts.healthListen, "health-listen", ":9444", "plain HTTP /healthz and /readyz address; empty turns it off")
	f.StringVar(&substrateExtprocOpts.tlsBundle, "tls-bundle", "", "PEM credential bundle (key and chain), the servicedns podCertificate")
	f.StringVar(&substrateExtprocOpts.clientCA, "client-ca", "", "CA bundle that verifies the egress gateway's client certificate (required with --tls-bundle)")
	f.BoolVar(&substrateExtprocOpts.insecurePlaintext, "insecure-plaintext", false, "serve gRPC without TLS (local development only)")
	rootCmd.AddCommand(substrateExtprocCmd)
}

func runSubstrateExtproc(ctx context.Context, stdout, stderr io.Writer) error {
	o := substrateExtprocOpts
	cfg, err := extproc.ParseConfig(nil)
	if o.config != "" {
		cfg, err = extproc.LoadConfig(o.config)
	}
	if err != nil {
		return err
	}
	opts := extproc.Options{Config: cfg, Events: extproc.NewJSONLogSink(stdout)}
	judge, err := extproc.NewVerdictClient(cfg.Judge)
	if err != nil {
		return err
	}
	if judge != nil {
		opts.Judge = judge
	}
	eng, err := extproc.NewEngine(opts)
	if err != nil {
		return err
	}
	defer eng.Close()

	var tlsCfg *tls.Config
	switch {
	case o.insecurePlaintext:
		fmt.Fprintln(stderr, "substrate-extproc: serving gRPC without TLS (--insecure-plaintext); never in a cluster")
	case o.tlsBundle == "":
		return errors.New("substrate-extproc: --tls-bundle is required (or --insecure-plaintext for local development)")
	default:
		if tlsCfg, err = extproc.ServerTLS(extproc.TLSOptions{Bundle: o.tlsBundle, ClientCA: o.clientCA, Peers: cfg.EgressPeers}); err != nil {
			return err
		}
	}
	lis, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	g := extproc.NewGRPCServer(eng, tlsCfg)
	errc := make(chan error, 2)
	go func() { errc <- g.Serve(lis) }()

	var health *http.Server
	if o.healthListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ready": true, "body_mode": eng.BodyModeStatus(), "chain_dropped": eng.ChainDropped(),
			})
		})
		health = &http.Server{Addr: o.healthListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	fmt.Fprintf(stderr, "substrate-extproc: listening on %s (body_inspection=%s, failure_mode=%s)\n",
		lis.Addr(), cfg.BodyInspection, cfg.FailureMode)

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	if health != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = health.Shutdown(sctx)
		cancel()
	}
	done := make(chan struct{})
	go func() { g.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		g.Stop()
	}
	return err
}
