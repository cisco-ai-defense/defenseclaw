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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/podcert"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

var (
	substrateControllerConfig string
	substrateControllerOnce   bool
	substrateControllerCheck  bool
	substrateControllerUsage  string
	// The gateway leader that holds registrations (GAP-0125), reached
	// over mTLS with this pod's identity.
	substrateControllerLeader, substrateControllerPeerBundle, substrateControllerPeerTrust string
	substrateControllerLeaderIDs                                                           []string
	// mTLS for a non-loopback usage listener (GAP-0105).
	substrateControllerUsageCert, substrateControllerUsageKey, substrateControllerUsageCA string
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
		"address for Substrate's per-actor usage records (OTLP/HTTP POST /v1/logs or ndjson), the CPU source of idle suspend; empty turns idle suspend off. "+
			"Loopback only, unless --usage-tls-cert, --usage-tls-key and --usage-client-ca make it mutual TLS")
	substrateControllerCmd.Flags().StringVar(&substrateControllerLeader, "leader-address", "",
		"gateway leader host:port: the registrations the launcher writes (required)")
	substrateControllerCmd.Flags().StringSliceVar(&substrateControllerLeaderIDs, "leader-id", nil, "SPIFFE IDs the leader may present")
	substrateControllerCmd.Flags().StringVar(&substrateControllerPeerBundle, "peer-bundle", "/var/run/ate/credential-bundle.pem", "this pod's identity bundle (leader mTLS)")
	substrateControllerCmd.Flags().StringVar(&substrateControllerPeerTrust, "peer-trust", "/var/run/ate/podidentity-ca.crt", "pod identity trust bundle")
	substrateControllerCmd.Flags().StringVar(&substrateControllerUsageCert, "usage-tls-cert", "", "usage listener certificate (PEM)")
	substrateControllerCmd.Flags().StringVar(&substrateControllerUsageKey, "usage-tls-key", "", "usage listener key (PEM)")
	substrateControllerCmd.Flags().StringVar(&substrateControllerUsageCA, "usage-client-ca", "", "CA bundle the usage clients' certificates must chain to")
	rootCmd.AddCommand(substrateControllerCmd)
}

func substrateControllerLeaderClient() (*leader.Client, error) {
	if substrateControllerLeader == "" {
		return nil, errors.New("substrate-controller: --leader-address is required (the gateway leader holds the actor registrations, GAP-0125)")
	}
	if len(substrateControllerLeaderIDs) == 0 {
		return nil, errors.New("substrate-controller: --leader-id names the leader's SPIFFE ID")
	}
	files, err := podcert.NewFiles(substrateControllerPeerBundle, substrateControllerPeerTrust)
	if err != nil {
		return nil, fmt.Errorf("substrate-controller: pod identity: %w", err)
	}
	tr := &http.Transport{TLSClientConfig: files.ClientConfig(substrateControllerLeaderIDs), Proxy: nil, MaxIdleConnsPerHost: 16}
	// Short retries: while the leader is unreachable the controller holds
	// (no policy change) and tries again next pass.
	return &leader.Client{BaseURL: "https://" + substrateControllerLeader, HTTP: &http.Client{Transport: tr, Timeout: 10 * time.Second},
		Retry: 5 * time.Second}, nil
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
	var cpu controller.CPUSource
	if substrateControllerUsage != "" {
		usage := controller.NewUsageCPU(nil)
		mux := http.NewServeMux()
		mux.Handle("/v1/logs", usage.Handler())
		srv := &http.Server{Addr: substrateControllerUsage, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		tlsCfg, err := substrateUsageTLS(substrateControllerUsage, substrateControllerUsageCert, substrateControllerUsageKey, substrateControllerUsageCA)
		if err != nil {
			return err
		}
		srv.TLSConfig = tlsCfg
		go func() {
			if tlsCfg != nil {
				_ = srv.ListenAndServeTLS("", "")
			} else {
				_ = srv.ListenAndServe()
			}
		}()
		defer srv.Close()
		cpu = usage
	}
	// Registrations and activity come from the gateway leader: the
	// launcher's registration attributes a launcher actor (without it the
	// actor is foreign and gets no policy, GAP-0125), and idle suspend
	// reads the gateways' hook, model and relay activity.
	toLeader, err := substrateControllerLeaderClient()
	if err != nil {
		return err
	}
	reg := &controller.LeaderRegistry{Store: &registry.Remote{Client: toLeader}}
	act := &activity.Source{Leader: toLeader}
	// Admin policy_conflict resets arrive through a ConfigMap in our own
	// namespace (the gateway's admin route writes them).
	var resets controller.ResetStore
	ns := os.Getenv("POD_NAMESPACE")
	if ns != "" && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if kube, err := setup.NewInClusterKube(setup.InClusterDir); err == nil {
			resets = kube
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: policy resets are off: %v\n", err)
		}
	}
	ctl, err := newSubstrateController(cfg, client, reg, act, cpu, cmd.OutOrStdout(), true, resets, ns)
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

// substrateUsageTLS decides how the usage listener is protected: forged
// usage records would keep a busy actor from idle suspend or suspend a
// working one (GAP-0105). A loopback address (a collector sidecar) needs
// nothing; any other address needs mutual TLS with a client CA.
func substrateUsageTLS(addr, cert, key, clientCA string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("--usage-listen %q: %w", addr, err)
	}
	if cert == "" && key == "" && clientCA == "" {
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil, nil
		}
		return nil, fmt.Errorf("--usage-listen %q is not loopback: set --usage-tls-cert, --usage-tls-key and --usage-client-ca (mutual TLS), or listen on 127.0.0.1 for a collector sidecar", addr)
	}
	if cert == "" || key == "" || clientCA == "" {
		return nil, errors.New("--usage-tls-cert, --usage-tls-key and --usage-client-ca go together")
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("usage listener key pair: %w", err)
	}
	pem, err := os.ReadFile(clientCA)
	if err != nil {
		return nil, fmt.Errorf("usage client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("usage client CA: no certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

func orDefaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
