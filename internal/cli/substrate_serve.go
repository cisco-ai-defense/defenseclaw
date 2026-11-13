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
	"crypto/hmac"
	"crypto/sha256"
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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
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
	actorPlainHTTP   bool
	// oidcCAFile is the trust bundle of a private OIDC issuer (a lab or
	// in-house Keycloak); noKubeSignIn turns the Kubernetes sign-in off.
	oidcCAFile   string
	noKubeSignIn bool
	// The atenet router for attach (GAP-0085): its CONNECT-TLS address,
	// TLS name and CA, and the relay port inside actors.
	routerAddress    string
	routerServerName string
	routerCAFile     string
	relayPort        int
	// Leader RPC permissions by peer (GAP-0094).
	calloutPeerIDs    []string
	controllerPeerIDs []string
	// Chain state (lane A13).
	chainKeyFile      string
	chainEgressAction string
	chainRetention    time.Duration
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
	f.StringSliceVar(&serveFlags.peerIDs, "peer-id", nil, "SPIFFE IDs of the gateway replicas (every leader method)")
	f.StringSliceVar(&serveFlags.calloutPeerIDs, "callout-peer-id", nil, "SPIFFE IDs of the callout (the egress chain check only)")
	f.StringSliceVar(&serveFlags.controllerPeerIDs, "controller-peer-id", nil, "SPIFFE IDs of the controller (registrations, lifecycle and activity)")
	f.StringSliceVar(&serveFlags.leaderIDs, "leader-id", nil, "SPIFFE IDs the leader may present")
	f.StringVar(&serveFlags.issuerCA, "issuer-ca", "/run/servicedns.podcert.ate.dev/trust-bundle.pem", "trust bundle of the actor JWT issuer")
	f.StringVar(&serveFlags.sessionKeyFile, "session-key-file", "/var/run/secrets/defenseclaw-relay-session/private.pem", "relay session signing key")
	f.StringVar(&serveFlags.calloutTokenFile, "callout-token-file", "/var/run/secrets/defenseclaw-callout-judge/token", "callout service token")
	f.StringVar(&serveFlags.llmCredDir, "llm-credentials-dir", "/var/run/secrets/defenseclaw-llm", "provider keys, one file per provider")
	f.StringVar(&serveFlags.bedrockRegion, "bedrock-region", "us-east-1", "Bedrock runtime region")
	f.StringVar(&serveFlags.kubeTokenFile, "kube-token-file", leader.DefaultKubeTokenFile, "Kubernetes API token (leader Lease)")
	f.StringVar(&serveFlags.kubeCAFile, "kube-ca-file", leader.DefaultKubeCAFile, "Kubernetes API CA (leader Lease)")
	f.StringSliceVar(&serveFlags.adminGroups, "admin-groups", nil, "OIDC groups whose members are administrators")
	f.BoolVar(&serveFlags.plainHTTP, "plain-http", false, "serve every listener and the leader RPC without TLS (tests outside a cluster only)")
	f.StringVar(&serveFlags.oidcCAFile, "oidc-ca-file", "", "PEM trust bundle of the OIDC issuer (empty: the system roots)")
	f.StringVar(&serveFlags.routerAddress, "router-address", "", "atenet router CONNECT-TLS host:port, for attach through the admin listener (empty: attach is off)")
	f.StringVar(&serveFlags.routerServerName, "router-server-name", "", "TLS name of the router certificate (default: the address host)")
	f.StringVar(&serveFlags.routerCAFile, "router-ca-file", "", "PEM trust bundle of the router certificate (empty: the system roots)")
	f.IntVar(&serveFlags.relayPort, "relay-port", 8080, "the actor relay's port")
	f.BoolVar(&serveFlags.noKubeSignIn, "no-kube-sign-in", false, "with no OIDC issuer, do not accept Kubernetes credentials on the admin listener")
	f.BoolVar(&serveFlags.actorPlainHTTP, "actor-plain-http", false,
		"serve the actor listener as plain HTTP (egress reaches it on an http rule; the actor JWT authenticates); the admin listener and the leader RPC keep TLS")
	f.StringVar(&serveFlags.chainKeyFile, "chain-key-file", "/var/run/secrets/defenseclaw-chain-key/key", "value lineage key every gateway replica shares (gateway)")
	f.StringVar(&serveFlags.chainEgressAction, "chain-egress-action", chainstate.EgressBlock, "block or alert a secret read followed by egress at the callout (leader)")
	f.DurationVar(&serveFlags.chainRetention, "chain-retention", chainstate.DefaultRetention, "how long a suspended actor's chain windows count as live (leader)")
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
	// In a cluster the admin listener always serves TLS and the leader RPC
	// always uses mTLS; only the actor listener may be plain HTTP, on its
	// own flag (GAP-0042, GAP-0023).
	if serveFlags.plainHTTP && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return errors.New("serve: --plain-http is for tests outside a cluster; use --actor-plain-http to serve only the actor listener without TLS")
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
		// Managed: policy_dir is the root-owned vendor folder the chart's
		// init container seeds (substrate-datadir --policies) and mounts
		// read-only; the gateway account must not write its own policy.
		if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
			if err := seedSubstratePolicies(cfg.PolicyDir); err != nil {
				return err
			}
		}
		substrateStartupChecks(cfg)
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
	return writeSubstratePolicies(policyDir, 0o700, 0o400)
}

// writeSubstratePolicies writes the embedded policies into policyDir with
// the given folder and file modes.
func writeSubstratePolicies(policyDir string, dirMode, fileMode os.FileMode) error {
	if strings.TrimSpace(policyDir) == "" {
		return errors.New("serve: policy_dir is empty")
	}
	files, err := policyassets.Files()
	if err != nil {
		return fmt.Errorf("serve: embedded policies: %w", err)
	}
	for _, f := range files {
		dst := filepath.Join(policyDir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), dirMode); err != nil {
			return fmt.Errorf("serve: seed policies: %w", err)
		}
		_ = os.Remove(dst + ".tmp")
		if err := os.WriteFile(dst+".tmp", f.Data, fileMode); err != nil {
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

// substratePeople is the admin listener's sign-in: the OIDC issuer and the
// workload issuers, and, for an open source cluster with no OIDC issuer,
// the person's Kubernetes token (TokenReview). Managed installs require
// OIDC (STEER 11-12 22:55Z). Nil when nothing is configured.
func substratePeople(c *config.Config) (gateway.SubstratePersonVerifier, error) {
	oidc, err := substrateOIDCPeople(c)
	if err != nil {
		return nil, err
	}
	var kube *identity.KubeTokenVerifier
	if substrateKubeSignIn(c) {
		kube = substrateKubePeople()
	}
	switch {
	case kube != nil && oidc != nil:
		return identity.PersonVerifiers{OIDC: oidc, Kube: kube}, nil
	case kube != nil:
		fmt.Fprintln(os.Stderr, "[substrate] no substrate.identity.oidc issuer: people sign in with their Kubernetes credentials")
		return identity.PersonVerifiers{Kube: kube}, nil
	case oidc != nil:
		return oidc, nil
	}
	return nil, nil
}

// substrateKubeSignIn reports whether people sign in with Kubernetes
// credentials: no OIDC issuer, not a managed install, not turned off.
func substrateKubeSignIn(c *config.Config) bool {
	return c.Substrate.Identity.OIDC.Issuer == "" && !managed.IsManagedEnterprise(c.DeploymentMode) && !serveFlags.noKubeSignIn
}

func substrateKubePeople() *identity.KubeTokenVerifier {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil
	}
	hc, err := kubeHTTPClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] Kubernetes sign-in: %v\n", err)
		return nil
	}
	return &identity.KubeTokenVerifier{Server: "https://" + net.JoinHostPort(host, port), TokenFile: serveFlags.kubeTokenFile, HTTP: hc}
}

func substrateOIDCPeople(c *config.Config) (*identity.PersonVerifier, error) {
	var issuers []identity.PersonIssuer
	id := c.Substrate.Identity
	if id.OIDC.Issuer != "" {
		ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: id.OIDC.Issuer, CAFile: serveFlags.oidcCAFile})
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, identity.PersonIssuer{KeySet: ks, Audience: id.OIDC.ClientID, GroupsClaim: id.OIDC.GroupsClaim,
			APIAudience: c.Substrate.EffectiveAudience()})
	}
	for _, w := range id.WorkloadOIDC {
		ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: w.Issuer})
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, identity.PersonIssuer{KeySet: ks, Audience: w.Audience, Kind: identity.PersonWorkload,
			Binding: identity.WorkloadBinding{Subject: w.Subject, Claims: w.Claims}})
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
			Providers:     gateway.DefaultSubstrateLLMProviders(serveFlags.llmCredDir, serveFlags.bedrockRegion),
			Proxy:         llmProxy,
			BedrockModels: c.Substrate.LLM.BedrockModels,
		})
		if err != nil {
			return out, err
		}
		actorTLS := servingTLS
		if serveFlags.actorPlainHTTP {
			actorTLS = nil
		}
		chainKey, err := loadChainKey(serveFlags.chainKeyFile)
		if err != nil {
			return out, err
		}
		toLeader := &leader.Client{BaseURL: base, HTTP: hc}
		regs := &registry.Remote{Client: toLeader}
		// The idle feed: last hook, model call and relay byte per actor,
		// sent to the leader every few seconds (A3's ActivitySource reads it).
		recorder := &activity.Recorder{Leader: toLeader}
		go recorder.Run(context.Background())
		// The create path's policy writer: the controller's own admission,
		// profiles and render, run before the first resume.
		ctl, err := newSubstrateController(c, ate, &controller.LeaderRegistry{Store: regs}, nil, nil, &controller.JSONSink{W: os.Stderr}, false, nil, "", nil)
		if err != nil {
			return out, fmt.Errorf("serve: controller for the create path: %w", err)
		}
		out = gateway.SubstrateConfig{
			ActorAddr: serveFlags.actorListen, ActorTLS: actorTLS,
			Actors: actors, Registrations: regs, Activity: recorder,
			Chains: &chainstate.Client{Leader: toLeader},
			Asks:   &asks.Client{Leader: toLeader}, Policies: ate,
			Secrets: c.Substrate.Secrets, SecretStore: substrateKubeSecrets(),
			Relays: substrateRelays(),
			Skills: newRuntimeSkillScanner(c),
			// GAP-0039: an unscanned skill folder is refused where hooks fail
			// closed (managed, strict tier) and alerted on elsewhere; scan
			// receipts hold on every replica that shares the chain key.
			BlockUnscannedSkills: substrateBlocksUnscannedSkills(c),
			SkillReceiptKey:      substrateSkillReceiptKey(chainKey),
			Info:                 substrateInfo(c),
			// E23: the workspace cap of an upload through attach.
			WorkspaceMaxBytes: c.Substrate.EffectiveWorkspaceMaxBytes(),
			Doctor: func(ctx context.Context) []gateway.SubstrateCheck {
				return []gateway.SubstrateCheck{gateway.SubstrateUpstreamCheck(ctx,
					gateway.DefaultSubstrateLLMProviders(serveFlags.llmCredDir, serveFlags.bedrockRegion), c.Guardrail.AllowPrivateUpstreams, nil)}
			},
			Actions: &gateway.SubstrateATEActions{Client: ate, Ensure: substrateEnsurer(ctl)},
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
		out.PolicyReset = substratePolicyResetter()
		if people != nil {
			adminTLS := servingTLS
			if !serveFlags.plainHTTP {
				if adminTLS, err = substrateAdminTLS(servingTLS); err != nil {
					return out, err
				}
			}
			out.AdminAddr, out.AdminTLS, out.People = serveFlags.adminListen, adminTLS, people
			admins := slices.Clone(serveFlags.adminGroups)
			out.IsAdmin = func(p identity.Person) bool {
				for _, g := range p.Groups {
					if slices.Contains(admins, g) {
						return true
					}
				}
				return false
			}
			out.Profiles = gateway.SubstrateLauncherProfiles(c)
			if out.Bundles, err = substrateBundleStore(c); err != nil {
				return out, err
			}
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

func runSubstrateLeader(parent context.Context, ready *atomic.Bool) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The store volume's root is 0777 or 2777 (Kubernetes), which the audit
	// store refuses as an ancestor; the leader alone mounts it (RWO) and
	// keeps its stores in 0700 directories under it (A8 item).
	audit.TrustVolumeRoot(serveFlags.storeDir)
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
	if err := substrateRecordStoreState(ctx, ns); err != nil {
		return err
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
	askStore, err := asks.Open(filepath.Join(serveFlags.storeDir, "asks"))
	if err != nil {
		return err
	}
	defer askStore.Close()
	if cfg != nil {
		askStore.Expiry = cfg.Substrate.EffectiveAskTimeout()
	}
	// An approved host joins the actor's registration; the controller adds
	// it to the policy on its next pass.
	askStore.OnApprove = func(ctx context.Context, a asks.Ask) error {
		if a.Host == "" {
			return nil
		}
		reg, ok, err := store.Get(ctx, a.Atespace, a.UID)
		if err != nil || !ok {
			return fmt.Errorf("approve: registration of %s/%s: %v", a.Atespace, a.Actor, err)
		}
		if !slices.Contains(reg.Approved, a.Host) {
			reg.Approved = append(reg.Approved, a.Host)
		}
		return store.Put(ctx, reg)
	}
	asks.Serve(srv, askStore)
	activity.Serve(srv, &activity.Store{Pending: askStore.Pending})
	chains, err := chainstate.New(chainstate.Options{Dir: serveFlags.storeDir,
		EgressAction: serveFlags.chainEgressAction, Retention: serveFlags.chainRetention,
		// A fork starts from its parent windows the first time the leader
		// sees it; the parent comes from the verified registration (GAP-0091).
		ParentOf: func(ctx context.Context, atespace, uid string) (string, error) {
			reg, ok, err := store.Get(ctx, atespace, uid)
			if err != nil || !ok {
				return "", err
			}
			return reg.ParentUID, nil
		}})
	if err != nil {
		return err
	}
	defer chains.Close()
	chains.Register(srv)
	// A crashed or deleted actor asks nothing any more (E16): its open asks
	// close when the controller reports the lifecycle event.
	srv.Handle(chainstate.MethodChainLifecycle, leader.Typed(substrateLifecycleClosesAsks(chains.Lifecycle, askStore)))
	go func() { _ = chains.Run(ctx) }()
	hs := &http.Server{Addr: serveFlags.leaderListen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	if !serveFlags.plainHTTP {
		files, err := podcert.NewFiles(serveFlags.peerBundle, serveFlags.peerTrust)
		if err != nil {
			return err
		}
		if len(serveFlags.peerIDs) == 0 {
			return errors.New("serve: --peer-id names the gateway SPIFFE IDs allowed to call the leader")
		}
		srv.Permit = substrateLeaderPermissions(serveFlags.peerIDs, serveFlags.calloutPeerIDs, serveFlags.controllerPeerIDs)
		hs.TLSConfig = files.ServerConfig(srv.Permit.Peers())
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

// substrateLeaderPermissions is who may call what on the leader
// (GAP-0094): gateway replicas every method; the callout only the egress
// chain check; the controller the registrations, the chain lifecycle and
// the activity feed. An identity listed in two roles gets both sets.
func substrateLeaderPermissions(gateways, callouts, controllers []string) leader.Permissions {
	p := leader.Permissions{}
	add := func(ids []string, methods ...string) {
		for _, id := range ids {
			if id = strings.TrimSpace(id); id != "" {
				p[id] = append(p[id], methods...)
			}
		}
	}
	add(gateways, "*")
	add(callouts, chainstate.MethodChainEgress)
	add(controllers, leader.MethodRegistrationGet, leader.MethodRegistrationList, leader.MethodRegistrationWrite,
		chainstate.MethodChainLifecycle, leader.MethodActivitySnapshot)
	return p
}

// substrateKubeSecrets is the secrets admin API's writer over the
// Kubernetes API (nil outside a cluster: the list still answers).
func substrateKubeSecrets() gateway.SubstrateSecretStore {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil
	}
	hc, err := kubeHTTPClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] secrets admin API: no Kubernetes client: %v\n", err)
		return nil
	}
	return &kubeSecrets{server: "https://" + net.JoinHostPort(host, port), tokenFile: serveFlags.kubeTokenFile, http: hc}
}

// substrateRelays is attach's way to the relays (nil when no router is
// configured or the pod identity bundle is missing).
func substrateRelays() gateway.SubstrateRelayDialer {
	if serveFlags.routerAddress == "" {
		return nil
	}
	files, err := podcert.NewFiles(serveFlags.peerBundle, serveFlags.peerTrust)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] attach is off: pod identity: %v\n", err)
		return nil
	}
	d, err := newRouterDialer(serveFlags.routerAddress, serveFlags.routerServerName, serveFlags.routerCAFile, serveFlags.relayPort, files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] attach is off: %v\n", err)
		return nil
	}
	return d
}

// substrateInfo is the admin listener's unauthenticated sign-in
// information (A6's `login --admin-url`).
func substrateInfo(c *config.Config) map[string]any {
	info := map[string]any{"sign_in": "none"}
	switch {
	case c.Substrate.Identity.OIDC.Issuer != "":
		info["sign_in"] = "oidc"
		info["issuer"], info["client_id"] = c.Substrate.Identity.OIDC.Issuer, c.Substrate.Identity.OIDC.ClientID
	case substrateKubeSignIn(c):
		info["sign_in"] = "kubernetes"
	}
	return info
}

// substrateStartupChecks logs the gateway-side doctor checks that fail at
// start (GAP-0040), so an operator sees them in the pod log too.
func substrateStartupChecks(c *config.Config) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		chk := gateway.SubstrateUpstreamCheck(ctx, gateway.DefaultSubstrateLLMProviders(serveFlags.llmCredDir, serveFlags.bedrockRegion),
			c.Guardrail.AllowPrivateUpstreams, nil)
		if chk.Status == "fail" {
			fmt.Fprintf(os.Stderr, "[substrate] %s: %s; fix: %s\n", chk.ID, chk.Detail, chk.Fix)
		}
	}()
}

// loadChainKey sets the value lineage key every gateway replica shares
// (Secret defenseclaw-chain-key). Without it each replica keeps its own
// random key and value joins only match on the replica that saw both calls.
func loadChainKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "[substrate] warning: no chain key at %s: value-lineage chains match only within one replica\n", path)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("serve: chain key: %w", err)
	}
	key := []byte(strings.TrimSpace(string(raw)))
	return key, gateway.SetToolValueLineageKey(key)
}

// substrateSkillReceiptKey derives the skill scan receipt key from the
// shared chain key, so a receipt one replica gives holds on all of them
// (GAP-0039). No chain key: nil, and each replica uses its own.
func substrateSkillReceiptKey(chainKey []byte) []byte {
	if len(chainKey) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, chainKey)
	m.Write([]byte("defenseclaw substrate skill receipt key v1"))
	return m.Sum(nil)
}

// substrateBlocksUnscannedSkills refuses an unscanned skill folder where a
// hook fails closed: managed installs and the strict tier of a connector.
func substrateBlocksUnscannedSkills(c *config.Config) func(connector string) bool {
	return func(connector string) bool {
		return managed.IsManagedEnterprise(c.DeploymentMode) || c.HookPolicyTierForConnector(connector) == config.HookPolicyTierStrict
	}
}

// substrateLifecycleClosesAsks wraps the chain lifecycle handler: after a
// crashed or deleted event the actor's pending asks are closed.
func substrateLifecycleClosesAsks(next func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error),
	asksStore interface{ CloseActor(uid, reason string) int }) func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
	return func(ctx context.Context, ev chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
		res, err := next(ctx, ev)
		if err != nil {
			return res, err
		}
		switch ev.Event {
		case chainstate.LifecycleCrashed:
			asksStore.CloseActor(ev.Actor.UID, "the actor crashed")
		case chainstate.LifecycleDeleted:
			asksStore.CloseActor(ev.Actor.UID, "the actor was deleted")
		}
		return res, nil
	}
}
