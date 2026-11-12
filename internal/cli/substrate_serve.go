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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity/ateactors"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/podcert"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// serve --substrate runs DefenseClaw in an Agent Substrate cluster
// (deploy/helm/defenseclaw-substrate):
//
//   - --substrate-role=gateway: the stateless replicas. The sidecar runs
//     with no connector of its own and its API server also serves the actor
//     listener (Service defenseclaw-actor) and the admin listener (Service
//     defenseclaw-admin); stateful calls go to the leader.
//   - --substrate-role=leader: the one replica that holds the Lease and the
//     store volume and answers the leader RPCs over mutual TLS.

var serveFlags struct {
	substrate        bool
	role             string
	actorListen      string
	adminListen      string
	metricsListen    string
	leaderAddress    string
	leaderListen     string
	lease            string
	storeDir         string
	storeStateCM     string
	tlsBundle        string
	tlsTrust         string
	peerBundle       string
	peerTrust        string
	peerIDs          []string
	leaderIDs        []string
	issuerCA         string
	sessionKeyFile   string
	calloutTokenFile string
	llmCredDir       string
	bedrockRegion    string
	kubeTokenFile    string
	kubeCAFile       string
	adminGroups      []string
	plainHTTP        bool
}

// sidecarSubstrateBuild, when set, makes runSidecar serve the Substrate
// listeners with the API server.
var sidecarSubstrateBuild gateway.SubstrateBuilder

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run DefenseClaw on Agent Substrate (gateway or leader role)",
	Long: `Run DefenseClaw in an Agent Substrate cluster. The Helm chart starts it;
it is not a command for a laptop or a server.

  --substrate-role=gateway  the actor and admin listeners (stateless, several replicas)
  --substrate-role=leader   the lease holder with the store volume (one replica)`,
	Hidden: true,
	RunE:   runServe,
}

func init() {
	f := serveCmd.Flags()
	f.BoolVar(&serveFlags.substrate, "substrate", false, "run on Agent Substrate (required)")
	f.StringVar(&serveFlags.role, "substrate-role", "gateway", "gateway or leader")
	f.StringVar(&serveFlags.actorListen, "actor-listen", ":8443", "actor listener address (gateway)")
	f.StringVar(&serveFlags.adminListen, "admin-listen", ":9443", "admin listener address (gateway)")
	f.StringVar(&serveFlags.metricsListen, "metrics-listen", ":9464", "health and metrics address")
	f.StringVar(&serveFlags.leaderAddress, "leader-address", "", "leader host:port (gateway)")
	f.StringVar(&serveFlags.leaderListen, "leader-listen", ":7443", "leader RPC address (leader)")
	f.StringVar(&serveFlags.lease, "lease", "defenseclaw-leader", "Lease name (leader)")
	f.StringVar(&serveFlags.storeDir, "store-dir", "/var/lib/defenseclaw/store", "store volume (leader)")
	f.StringVar(&serveFlags.storeStateCM, "store-state-configmap", "", "ConfigMap that records the store schema (leader)")
	f.StringVar(&serveFlags.tlsBundle, "tls-bundle", "/run/servicedns.podcert.ate.dev/credential-bundle.pem", "serving credential bundle")
	f.StringVar(&serveFlags.tlsTrust, "tls-trust", "/run/servicedns.podcert.ate.dev/trust-bundle.pem", "serving trust bundle")
	f.StringVar(&serveFlags.peerBundle, "peer-bundle", "/run/podidentity.podcert.ate.dev/credential-bundle.pem", "pod identity bundle (leader RPC)")
	f.StringVar(&serveFlags.peerTrust, "peer-trust", "/run/podidentity.podcert.ate.dev/trust-bundle.pem", "pod identity trust bundle")
	f.StringSliceVar(&serveFlags.peerIDs, "peer-id", nil, "SPIFFE IDs allowed to call the leader")
	f.StringSliceVar(&serveFlags.leaderIDs, "leader-id", nil, "SPIFFE IDs the leader may present")
	f.StringVar(&serveFlags.issuerCA, "issuer-ca", "/run/servicedns.podcert.ate.dev/trust-bundle.pem", "trust bundle of the actor JWT issuer")
	f.StringVar(&serveFlags.sessionKeyFile, "session-key-file", "/var/run/secrets/defenseclaw-relay-session/private.pem", "relay session signing key")
	f.StringVar(&serveFlags.calloutTokenFile, "callout-token-file", "/var/run/secrets/defenseclaw-callout-judge/token", "callout service token")
	f.StringVar(&serveFlags.llmCredDir, "llm-credentials-dir", "/var/run/secrets/defenseclaw-llm", "provider keys, one file per provider")
	f.StringVar(&serveFlags.bedrockRegion, "bedrock-region", "us-east-1", "Bedrock runtime region")
	f.StringVar(&serveFlags.kubeTokenFile, "kube-token-file", leader.DefaultKubeTokenFile, "Kubernetes API token (leader Lease)")
	f.StringVar(&serveFlags.kubeCAFile, "kube-ca-file", leader.DefaultKubeCAFile, "Kubernetes API CA (leader Lease)")
	f.StringSliceVar(&serveFlags.adminGroups, "admin-groups", nil, "OIDC groups whose members are administrators")
	f.BoolVar(&serveFlags.plainHTTP, "plain-http", false, "serve without TLS (tests only)")
	rootCmd.AddCommand(serveCmd)
}

// substrateRateLimited is defenseclaw.substrate.rate_limited.
var substrateRateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "defenseclaw_substrate_rate_limited_total",
	Help: "Actor requests refused by the fair-share limits (defenseclaw.substrate.rate_limited).",
}, []string{"scope", "route"})

func runServe(cmd *cobra.Command, args []string) error {
	if !serveFlags.substrate {
		return errors.New("serve runs only on Agent Substrate: pass --substrate")
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(substrateRateLimited)
	var ready atomic.Bool
	go serveSubstrateMetrics(reg, &ready)
	switch serveFlags.role {
	case "leader":
		return runSubstrateLeader(cmd.Context(), &ready)
	case "gateway":
		if cfg == nil {
			return errors.New("serve: no configuration loaded")
		}
		if !cfg.Substrate.Enabled {
			return errors.New("serve: substrate.enabled is false in the configuration")
		}
		if err := seedSubstratePolicies(cfg.PolicyDir); err != nil {
			return err
		}
		sidecarSubstrateBuild = substrateGatewayBuilder(cfg, &ready)
		return runSidecar(cmd, args)
	}
	return fmt.Errorf("serve: unknown --substrate-role %q (gateway or leader)", serveFlags.role)
}

func serveSubstrateMetrics(reg *prometheus.Registry, ready *atomic.Bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: serveFlags.metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "[substrate] metrics listener: %v\n", err)
	}
}

// seedSubstratePolicies writes the vendor policies (the rule packs, presets
// and Rego the binary embeds) into policyDir. A container has no
// `defenseclaw init`; its data directory starts empty on every pod start,
// so the packs come from the binary that runs, never from an older copy.
// Files are written read-only to the gateway account.
func seedSubstratePolicies(policyDir string) error {
	if strings.TrimSpace(policyDir) == "" {
		return errors.New("serve: policy_dir is empty")
	}
	files, err := policyassets.Files()
	if err != nil {
		return fmt.Errorf("serve: embedded policies: %w", err)
	}
	for _, f := range files {
		dst := filepath.Join(policyDir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fmt.Errorf("serve: seed policies: %w", err)
		}
		_ = os.Remove(dst + ".tmp")
		if err := os.WriteFile(dst+".tmp", f.Data, 0o400); err != nil {
			return fmt.Errorf("serve: seed policies: %w", err)
		}
		if err := os.Rename(dst+".tmp", dst); err != nil {
			return fmt.Errorf("serve: seed policies: %w", err)
		}
	}
	return nil
}

// substratePeerClient is the gateway's mTLS client to the leader.
func substratePeerClient() (*http.Client, string, error) {
	if serveFlags.leaderAddress == "" {
		return nil, "", errors.New("serve: --leader-address is required for the gateway role")
	}
	if serveFlags.plainHTTP {
		return &http.Client{Timeout: 30 * time.Second}, "http://" + serveFlags.leaderAddress, nil
	}
	files, err := podcert.NewFiles(serveFlags.peerBundle, serveFlags.peerTrust)
	if err != nil {
		return nil, "", err
	}
	if len(serveFlags.leaderIDs) == 0 {
		return nil, "", errors.New("serve: --leader-id names the leader's SPIFFE ID")
	}
	tr := &http.Transport{TLSClientConfig: files.ClientConfig(serveFlags.leaderIDs), Proxy: nil,
		MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, "https://" + serveFlags.leaderAddress, nil
}

func substrateServingTLS() (*tls.Config, error) {
	if serveFlags.plainHTTP {
		return nil, nil
	}
	files, err := podcert.NewFiles(serveFlags.tlsBundle, "")
	if err != nil {
		return nil, err
	}
	return files.ServerConfig(nil), nil
}

func readSecretFile(path string) func() (string, error) {
	return func() (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}

func substrateATEClient(c *config.Config) (ateapi.Client, error) {
	api := c.Substrate.API
	return ateapi.New(ateapi.Options{
		Address: api.Address, ServerName: api.ServerName, CAFile: api.CAFile,
		Auth: ateapi.Auth(api.Auth), TokenFile: api.TokenFile, CredentialBundle: api.CredentialBundle,
	})
}

func substratePeople(c *config.Config) (*identity.PersonVerifier, error) {
	var issuers []identity.PersonIssuer
	id := c.Substrate.Identity
	if id.OIDC.Issuer != "" {
		ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: id.OIDC.Issuer})
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, identity.PersonIssuer{KeySet: ks, Audience: id.OIDC.ClientID, GroupsClaim: id.OIDC.GroupsClaim})
	}
	for _, w := range id.WorkloadOIDC {
		ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: w.Issuer})
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, identity.PersonIssuer{KeySet: ks, Audience: w.Audience, Kind: identity.PersonWorkload})
	}
	if len(issuers) == 0 {
		return nil, nil
	}
	return identity.NewPersonVerifier(issuers, nil)
}

func substrateGatewayBuilder(c *config.Config, ready *atomic.Bool) gateway.SubstrateBuilder {
	return func(api *gateway.APIServer, llmProxy http.Handler) (gateway.SubstrateConfig, error) {
		var out gateway.SubstrateConfig
		ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: c.Substrate.Identity.Issuer, CAFile: serveFlags.issuerCA})
		if err != nil {
			return out, err
		}
		ate, err := substrateATEClient(c)
		if err != nil {
			return out, fmt.Errorf("serve: control API client: %w", err)
		}
		lookup := ateactors.ATEAPILookup(ate)
		actors, err := identity.NewActorVerifier(identity.ActorVerifierOptions{
			KeySet: ks, Audience: c.Substrate.Identity.Audience, Lookup: lookup,
		})
		if err != nil {
			return out, err
		}
		hc, base, err := substratePeerClient()
		if err != nil {
			return out, err
		}
		people, err := substratePeople(c)
		if err != nil {
			return out, err
		}
		servingTLS, err := substrateServingTLS()
		if err != nil {
			return out, err
		}
		llm, err := gateway.NewSubstrateLLMHandler(gateway.SubstrateLLMConfig{
			Providers: gateway.DefaultSubstrateLLMProviders(serveFlags.llmCredDir, serveFlags.bedrockRegion),
			Proxy:     llmProxy,
		})
		if err != nil {
			return out, err
		}
		out = gateway.SubstrateConfig{
			ActorAddr: serveFlags.actorListen, ActorTLS: servingTLS,
			Actors: actors, Registrations: &registry.Remote{Client: &leader.Client{BaseURL: base, HTTP: hc}},
			Limiter: ratelimit.New(ratelimit.Config{
				PerActorRPS: c.Substrate.RateLimits.PerActorRPS, PerAtespaceRPS: c.Substrate.RateLimits.PerAtespaceRPS,
			}),
			Lookup: lookup, LLM: llm,
			// D8: interactive actors fail as hosts do (managed closed, OSS
			// open with a warning); unattended actors always closed.
			FailOpenInteractive: !managed.IsManagedEnterprise(c.DeploymentMode),
			OnRateLimited: func(scope ratelimit.Scope, route string) {
				substrateRateLimited.WithLabelValues(string(scope), route).Inc()
			},
		}
		if people != nil {
			out.AdminAddr, out.AdminTLS, out.People = serveFlags.adminListen, servingTLS, people
			admins := slices.Clone(serveFlags.adminGroups)
			out.IsAdmin = func(p identity.Person) bool {
				for _, g := range p.Groups {
					if slices.Contains(admins, g) {
						return true
					}
				}
				return false
			}
			out.Profiles = launcherProfiles(c)
			if _, err := os.Stat(serveFlags.calloutTokenFile); err == nil {
				out.CalloutToken = readSecretFile(serveFlags.calloutTokenFile)
			}
		} else {
			fmt.Fprintln(os.Stderr, "[substrate] no substrate.identity.oidc issuer: the admin listener does not run")
		}
		if _, err := os.Stat(serveFlags.sessionKeyFile); err == nil {
			issuer := "https://" + strings.TrimSpace(c.Substrate.Services.Admin)
			s, err := identity.LoadSessionSigner(serveFlags.sessionKeyFile, issuer)
			if err != nil {
				return out, err
			}
			out.Sessions = s
		}
		ready.Store(true)
		return out, nil
	}
}

// launcherProfiles allows a create for a profile listed in
// substrate.launcher_atespaces, in its first atespace.
func launcherProfiles(c *config.Config) gateway.SubstrateProfileResolver {
	spaces := c.Substrate.LauncherAtespaces
	return func(_ identity.Person, requested string) (string, string, error) {
		list := spaces[requested]
		if len(list) == 0 {
			return "", "", fmt.Errorf("profile %q has no launcher atespace", requested)
		}
		return requested, list[0], nil
	}
}

func runSubstrateLeader(parent context.Context, ready *atomic.Bool) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := registry.OpenFileStore(filepath.Join(serveFlags.storeDir, "registrations"))
	if err != nil {
		return err
	}
	pod := strings.TrimSpace(os.Getenv("POD_NAME"))
	ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	if pod == "" || ns == "" {
		return errors.New("serve: the leader needs POD_NAME and POD_NAMESPACE")
	}
	kube, err := kubeHTTPClient()
	if err != nil {
		return err
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return errors.New("serve: the leader runs in a cluster (KUBERNETES_SERVICE_HOST is unset)")
	}
	el := &leader.Elector{
		API: &leader.KubeLeaseAPI{Server: "https://" + net.JoinHostPort(host, port), Namespace: ns, Name: serveFlags.lease,
			TokenFile: serveFlags.kubeTokenFile, HTTP: kube},
		Name: serveFlags.lease, Ns: ns, Identity: pod,
		OnStarted: func(context.Context) {
			fmt.Fprintf(os.Stderr, "[substrate] %s is the leader\n", pod)
			ready.Store(true)
		},
		OnStopped: func() { ready.Store(false) },
	}
	srv := &leader.Server{IsLeader: el.IsLeader}
	registry.Serve(srv, store)
	hs := &http.Server{Addr: serveFlags.leaderListen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	if !serveFlags.plainHTTP {
		files, err := podcert.NewFiles(serveFlags.peerBundle, serveFlags.peerTrust)
		if err != nil {
			return err
		}
		if len(serveFlags.peerIDs) == 0 {
			return errors.New("serve: --peer-id names the gateway SPIFFE IDs allowed to call the leader")
		}
		hs.TLSConfig = files.ServerConfig(serveFlags.peerIDs)
	}
	errCh := make(chan error, 2)
	go func() {
		var err error
		if hs.TLSConfig != nil {
			err = hs.ListenAndServeTLS("", "")
		} else {
			err = hs.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() { errCh <- el.Run(ctx) }()
	err = <-errCh
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func kubeHTTPClient() (*http.Client, error) {
	pem, err := os.ReadFile(serveFlags.kubeCAFile)
	if err != nil {
		return nil, fmt.Errorf("serve: Kubernetes CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("serve: Kubernetes CA has no certificate")
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, Proxy: nil,
	}}, nil
}
