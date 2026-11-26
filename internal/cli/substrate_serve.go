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
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity/ateactors"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/podcert"
	"github.com/defenseclaw/defenseclaw/internal/substrate/pushgrant"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
	"github.com/defenseclaw/defenseclaw/internal/substrate/spendleader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
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
	relayCADir       string
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
	chainKeyFile   string
	chainRetention time.Duration
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
	f.StringVar(&serveFlags.metricsListen, "metrics-listen", ":9464", "liveness and readiness probe address (/healthz, /readyz); the metrics go over OTLP")
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
	// Deprecated: substrate.identity.keys_ca_file. Kept until CERT-110 for
	// the lab manifests that still pass it; set, it wins over the config.
	f.StringVar(&serveFlags.issuerCA, "issuer-ca", "", "deprecated: use substrate.identity.keys_ca_file")
	_ = f.MarkDeprecated("issuer-ca", "use substrate.identity.keys_ca_file")
	f.StringVar(&serveFlags.sessionKeyFile, "session-key-file", "/var/run/secrets/defenseclaw-relay-session/private.pem", "relay session signing key")
	f.StringVar(&serveFlags.relayCADir, "relay-ca-dir", "/var/run/secrets/defenseclaw-relay-ca", "relay CA (ca.pem, ca-key.pem) that signs and verifies relay TLS certificates")
	f.StringVar(&serveFlags.calloutTokenFile, "callout-token-file", "/var/run/secrets/defenseclaw-callout-judge/token", "callout service token")
	f.StringVar(&serveFlags.llmCredDir, "llm-credentials-dir", "/var/run/secrets/defenseclaw-llm", "provider keys, one file per provider")
	f.StringVar(&serveFlags.bedrockRegion, "bedrock-region", "us-east-1", "Bedrock runtime region")
	f.StringVar(&serveFlags.kubeTokenFile, "kube-token-file", leader.DefaultKubeTokenFile, "Kubernetes API token (leader Lease)")
	f.StringVar(&serveFlags.kubeCAFile, "kube-ca-file", leader.DefaultKubeCAFile, "Kubernetes API CA (leader Lease)")
	f.StringSliceVar(&serveFlags.adminGroups, "admin-groups", nil, "groups whose members are administrators, added to substrate.identity.admin_groups")
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
	f.DurationVar(&serveFlags.chainRetention, "chain-retention", chainstate.DefaultRetention, "how long a suspended actor's chain windows count as live (leader)")
	rootCmd.AddCommand(serveCmd)
}

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
	var ready atomic.Bool
	go serveSubstrateProbes(&ready)
	switch serveFlags.role {
	case "leader":
		return runSubstrateLeader(cmd.Context(), &ready)
	case "gateway":
		if cfg == nil {
			return errors.New("serve: no configuration loaded")
		}
		// The chart's LLM credentials Secret is where a managed cluster
		// keeps the keys its enterprise.inspection.llm.credential names (the
		// LLM judge's, GAP-0560), as the /llm route reads its provider keys.
		managed.UseClusterCredentialDir(serveFlags.llmCredDir)
		if !cfg.Substrate.Enabled {
			return errors.New("serve: substrate.enabled is false in the configuration")
		}
		// Before anything reads the issuers (startup checks, routing.admin
		// warnings and matching): pin whether this gateway lets Kubernetes
		// people sign in. substrate.identity is restart-only, so a live
		// reload must not move the issuers away from the verifiers built now
		// (GAP-0939, GAP-0968).
		config.PinKubeSignIn(substrateKubeSignIn(cfg))
		// Managed: policy_dir is the root-owned vendor folder the chart's
		// init container seeds (substrate-datadir --policies) and mounts
		// read-only; the gateway account must not write its own policy.
		if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
			if err := seedSubstratePolicies(cfg.PolicyDir); err != nil {
				return err
			}
		}
		substrateStartupChecks(cfg)
		// A managed gateway in a pod has no laptop lifecycle: the chart's
		// read-only mounted config is the activated one, or, in bundle
		// mode, a verified signed Substrate bundle (GAP-0135).
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			sources := []func(string, []byte) error{gateway.SubstrateMountedConfigActivation(gateway.SubstrateFileOwner)}
			if cfg.Substrate.Bundles.Enabled {
				sources = append(sources, substrateBundleActivation(cfg))
			}
			gateway.SetSubstrateClusterActivation(gateway.SubstrateActivationSources(sources...))
		}
		// A verified actor's hook refuses egress after a secret read by the
		// same setting as the callout: config substrate.chain_egress_action,
		// which the gateway and the leader read from the same ConfigMap
		// (owner decision 2026-11-13; GAP-0250).
		if err := applyGatewayChainEgress(cfg); err != nil {
			return err
		}
		// config.yaml changes reach this pod without a restart (GAP-0276):
		// the chain egress action here, and the create path's policy
		// writer, profiles and unattended asks through the same watcher.
		src, err := substrateConfigWatcher("", cfg)
		if err != nil {
			return err
		}
		followCtx, stopFollow := substrateContext(cmd)
		defer stopFollow()
		go newSubstrateFollower(src, "gateway", os.Stderr, applyGatewayChainEgress).run(followCtx)
		sidecarSubstrateBuild = substrateGatewayBuilder(cfg, src, &ready)
		return runSidecar(cmd, args)
	}
	return fmt.Errorf("serve: unknown --substrate-role %q (gateway or leader)", serveFlags.role)
}

// serveSubstrateProbes serves the liveness and readiness probes on the
// metrics port. The Substrate metrics go through the gateway's telemetry
// runtime to the OTLP destinations (GAP-0401); the Prometheus /metrics page
// this port served before held counters nothing read.
func serveSubstrateProbes(ready *atomic.Bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Addr: serveFlags.metricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "[substrate] probe listener: %v\n", err)
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

// substrateNoPeople refuses every sign-in: the admin listener of a
// cluster with no sign-in configured serves the callout route only.
type substrateNoPeople struct{}

func (substrateNoPeople) Verify(context.Context, string) (identity.Person, error) {
	return identity.Person{}, &identity.Error{Reason: identity.ReasonIssuer, Message: "no sign-in is configured on this cluster"}
}

// substrateKubeSignIn reports whether people sign in with Kubernetes
// credentials: no OIDC issuer, not a managed install, not turned off by
// substrate.identity.kube_sign_in or --no-kube-sign-in. runServe pins the
// answer at start (config.PinKubeSignIn), so the routing.admin issuers agree
// with the verifiers for the life of the process (GAP-0939, GAP-0968).
func substrateKubeSignIn(c *config.Config) bool {
	return c.SubstrateKubeSignIn() && !serveFlags.noKubeSignIn
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

// substrateAdminGroups are the administrator groups:
// substrate.identity.admin_groups plus the --admin-groups flag (GAP-0191).
func substrateAdminGroups(id config.SubstrateIdentityConfig, flag []string) []string {
	var out []string
	for _, g := range slices.Concat(id.AdminGroups, flag) {
		if g = strings.TrimSpace(g); g != "" && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
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

func substrateGatewayBuilder(c *config.Config, src *configwatch.Watcher, ready *atomic.Bool) gateway.SubstrateBuilder {
	// live is config.yaml in force (GAP-0276); c is the boot config, which
	// the restart-only parts keep (substrateRestartOnly).
	live := func() *config.Config {
		cur, _ := src.Current()
		return cur
	}
	return func(api *gateway.APIServer, llmProxy http.Handler) (gateway.SubstrateConfig, error) {
		var out gateway.SubstrateConfig
		ks, err := substrateActorKeySet(c)
		if err != nil {
			return out, err
		}
		// A keys URL that does not answer refuses every actor token: say so
		// in the pod log at start, not only per request.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if chk := substrateActorKeysCheck(ctx, ks); chk.Status == "fail" {
				fmt.Fprintf(os.Stderr, "[substrate] %s: %s; fix: %s\n", chk.ID, chk.Detail, chk.Fix)
			}
		}()
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
		if people == nil && !managed.IsManagedEnterprise(c.DeploymentMode) {
			if _, err := os.Stat(serveFlags.calloutTokenFile); err == nil {
				// GAP-0015: with no sign-in at all, the admin listener still
				// runs for the callout's tool verdict route (its own bearer
				// token); every person route refuses.
				fmt.Fprintln(os.Stderr, "[substrate] no sign-in is configured: the admin listener serves the callout verdict route only")
				people = substrateNoPeople{}
			}
		}
		servingTLS, err := substrateServingTLS()
		if err != nil {
			return out, err
		}
		llm, err := gateway.NewSubstrateLLMHandler(gateway.SubstrateLLMConfig{
			Providers:     gateway.DefaultSubstrateLLMProviders(serveFlags.llmCredDir, serveFlags.bedrockRegion),
			Proxy:         llmProxy,
			BedrockModels: c.Substrate.LLM.BedrockModels,
			// actor_secrets: exact-value DLP on prompts (PLAN §7.2), from
			// the callout's actor-secrets Secret mounted in the gateway; the
			// hook route masks the same values before any audit row
			// (GAP-0504).
			ExposedValues: gateway.SubstrateExposedValues(c, c.Substrate.Extproc.ActorSecretsDir),
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
		// Replica (the pod name) adds a heartbeat to every flush, so the leader
		// can tell a replica that stopped reporting (substrate-1:GAP-0578 e).
		replicaName, _ := os.Hostname()
		recorder := &activity.Recorder{Leader: toLeader, Replica: replicaName}
		go recorder.Run(context.Background())
		// The create path's policy writer: the controller's own admission,
		// profiles and render, run before the first resume.
		ctl, err := newSubstrateController(c, ate, &controller.LeaderRegistry{Store: regs}, nil, nil, &controller.JSONSink{W: os.Stderr}, false, nil, "", nil, src)
		if err != nil {
			return out, fmt.Errorf("serve: controller for the create path: %w", err)
		}
		// The create path writes the same policy as the controller while
		// another callout holds Substrate's egress slot (GAP-0505). The
		// gateway may not read the slot: it reads the controller's latest
		// report from the leader; none, or one older than three reads, is
		// unknown.
		ctl.SetCallout(&controller.LeaderCallout{Leader: toLeader})
		router, routerErr := substrateRouter()
		runtimeScan := newRuntimeSkillScanner(c)
		bindingStore := substrateBindingStore(c)
		// B5.1: the ended sign-ins list, pulled from the leader (nil: off).
		revs := newSubstrateRevocation(context.Background(), c.Substrate.Identity.Revocation, &revocation.Client{Leader: toLeader})
		runtimeScan.enabled = func() bool { return live().Substrate.SkillScanEnabled() }
		go runtimeScan.checkSidecar(context.Background(), os.Stderr, 12, 5*time.Second)
		out = gateway.SubstrateConfig{
			ActorAddr: serveFlags.actorListen, ActorTLS: actorTLS,
			Actors: actors, Registrations: regs, Activity: recorder,
			ActivityFeed: &activity.Reader{Leader: toLeader},
			ActivityConfig: func() config.SubstrateActivityConfig {
				if cur := live(); cur != nil {
					return cur.Substrate.Activity
				}
				return c.Substrate.Activity
			},
			Chains: &chainstate.Client{Leader: toLeader},
			// The controller's, the callout's and the leader's records reach
			// the OTLP destinations through this replica (GAP-0450, GAP-0453).
			Relay: &telemetryrelay.Taker{Leader: toLeader},
			// Last use of a secret: the leader's host-use map (S6b).
			SecretUses: &telemetryrelay.UseReader{Leader: toLeader},
			Asks:       &asks.Client{Leader: toLeader}, Policies: ate,
			UnattendedAsk: func(profile string) gateway.SubstrateUnattendedAsk {
				return gateway.SubstrateUnattendedAskFor(live(), profile)
			},
			Secrets: c.Substrate.Secrets, SecretStore: substrateKubeSecrets(),
			Bindings: bindingStore, SelfService: c.Substrate.SelfServiceSecrets,
			SecretTemplates: c.Substrate.SecretTemplates, NoSwapHosts: c.Substrate.Egress.NoSwapHosts,
			LiveSelfService: func() (config.SubstrateSelfServiceSecretsConfig, []config.SubstrateSecretTemplate) {
				l := live()
				return l.Substrate.SelfServiceSecrets, l.Substrate.SecretTemplates
			},
			LiveNoSwapHosts: func() []string { return live().Substrate.Egress.NoSwapHosts },
			Relays:          relayDialer(router),
			Skills:          runtimeScan,
			// E20, GAP-0185: the runtime MCP scan of hook events.
			MCP: gateway.AttestMCPScanner{RT: runtimeScan.rt},
			// GAP-0039: an unscanned skill folder is refused where hooks fail
			// closed (managed, strict tier) and alerted on elsewhere; scan
			// receipts hold on every replica that shares the chain key.
			BlockUnscannedSkills: func(connector string) bool { return substrateBlocksUnscannedSkills(live())(connector) },
			SkillReceiptKey:      substrateSkillReceiptKey(chainKey),
			TemplateSkills:       substrateTemplateSkills(ctl),
			SkillScanLimits: func() (time.Duration, time.Duration) {
				s := live().Substrate
				return s.EffectiveSkillScanTimeout(), s.EffectiveSkillPendingWait()
			},
			Info: substrateInfo(c),
			// GAP-0497: /info says when another callout holds Substrate's
			// egress slot and which checks are off; launchers print it.
			EgressCallout: ctl.CalloutStatus,
			// GAP-0262: the gateway checks the sign-in server it verifies
			// people with, from its own network.
			SignInServer: substrateSignInServer(people),
			// E23: the workspace cap of an upload through attach.
			WorkspaceMaxBytes: c.Substrate.EffectiveWorkspaceMaxBytes(),
			// B3.1: read live, so the admin-off switch applies to the next attach.
			KeyReplay: func() string { return live().Substrate.Launcher.EffectiveKeyReplay() },
			// B1: the upload scan, read live; hold_back is its admin-off switch.
			UploadScan: func() config.SubstrateUploadScanConfig { return live().Substrate.Launcher.UploadScan },
			// B2: the admin-off switches of push and sync, read live.
			FilesPush:   func() bool { return live().Substrate.Files.PushAllowed() },
			FilesSync:   func() bool { return live().Substrate.Files.SyncAllowed() },
			Revocations: revs.snap, RevocationSource: revs.src, Streams: revs.streams,
			// B2 2.5: the https rewrite map, submodules and LFS, read live.
			Git: func() config.SubstrateGitConfig { return live().Substrate.Git },
			// B2 2.4: git_push and substrate.git.push_branch, read live.
			GitPush: func(profile string) string { return gateway.SubstrateGitPushFor(live())(profile) },
			// GAP-1073: an allowed push opens a grant the callout enforces.
			PushGrants: &pushgrant.Client{Leader: toLeader},
			Doctor: func(ctx context.Context) []gateway.SubstrateCheck {
				return []gateway.SubstrateCheck{gateway.SubstrateUpstreamCheck(ctx,
					gateway.DefaultSubstrateLLMProviders(serveFlags.llmCredDir, serveFlags.bedrockRegion), c.Guardrail.AllowPrivateUpstreams, nil),
					substrateRouterCheck(ctx, router, routerErr), substrateActorKeysCheck(ctx, ks),
					substrateTemplateAllowlistCheck(ctx, ate, ctl.LiveAttestor()), substrateRelaySeparationCheck(ctx, ate, ctl.LiveAttestor()),
					gateway.SubstrateSecretEchoHostCheck(live().Substrate.Secrets, live().Substrate.Egress.NoSwapHosts),
					gateway.SubstrateSecretBindingStoreCheck(bindingStore),
					gateway.SubstrateRevocationCheck(revs.snap, time.Now()),
					gateway.SubstrateRelayCertReissueCheck(c.Substrate.EffectiveRelayCertReissue(), c.Substrate.RelayCertReissueFor(managed.IsManagedEnterprise(c.DeploymentMode))),
					gateway.SubstrateSecretBindingFormCheck(bindingStore, live().Substrate.SecretTemplates)}
			},
			Actions: &gateway.SubstrateATEActions{Client: ate, Ensure: substrateEnsurer(ctl), TemplateKit: substrateTemplateKit(ctl.LiveAttestor())},
			// PLAN 7.3: the profile sandbox_class picks the class at create.
			SandboxClass: func(profile string) string { return gateway.SubstrateSandboxClassFor(live())(profile) },
			Limiter: ratelimit.New(ratelimit.Config{
				PerActorRPS: c.Substrate.RateLimits.PerActorRPS, PerAtespaceRPS: c.Substrate.RateLimits.PerAtespaceRPS,
			}),
			Lookup: lookup, LLM: llm,
			// D8: interactive actors fail as hosts do (managed closed, OSS
			// open with a warning); unattended actors always closed.
			FailOpenInteractive: !managed.IsManagedEnterprise(c.DeploymentMode),
			// E9: a managed deployment refuses a vendor sign-in held in an actor.
			Managed:            managed.IsManagedEnterprise(c.DeploymentMode),
			SecretPlaceholders: substrateSecretPlaceholders(c.Substrate.Secrets),
		}
		out.PolicyReset = substratePolicyResetter()
		// T-COST: spend and usage live on the leader. substrate.usage.enabled
		// false leaves both unset: no counter swap, no usage sink, no push
		// loop, and the usage API answers usage_disabled.
		if c.Substrate.Usage.UsageEnabled() {
			spend := &spendleader.Client{Leader: toLeader}
			out.SpendLeader = spend
			out.UsageSyncInterval = c.Substrate.Usage.EffectiveSyncInterval()
			out.Usage = gateway.NewSubstrateLeaderUsage(spend, live, regs)
		} else {
			out.UsageDisabled = true
		}
		if people != nil {
			adminTLS := servingTLS
			if !serveFlags.plainHTTP {
				if adminTLS, err = substrateAdminTLS(servingTLS); err != nil {
					return out, err
				}
			}
			out.AdminAddr, out.AdminTLS, out.People = serveFlags.adminListen, adminTLS, people
			admins := substrateAdminGroups(c.Substrate.Identity, serveFlags.adminGroups)
			out.IsAdmin = func(p identity.Person) bool {
				for _, g := range p.Groups {
					if slices.Contains(admins, g) {
						return true
					}
				}
				return false
			}
			out.Profiles = func(p identity.Person, requested, connector string, admin bool) (string, string, error) {
				return gateway.SubstrateLauncherProfiles(live())(p, requested, connector, admin)
			}
			out.ProfileWhy = func(p identity.Person, admin bool) gateway.SubstrateProfileWhy {
				return gateway.SubstrateProfileWhyFor(live())(p, admin)
			}
			out.WorkloadEntry = func(subject string) (string, string) {
				return gateway.SubstrateWorkloadEntry(live(), subject)
			}
			if out.Bundles, err = substrateBundleStore(c, live); err != nil {
				return out, err
			}
			if _, err := os.Stat(serveFlags.calloutTokenFile); err == nil {
				out.CalloutToken = readSecretFile(serveFlags.calloutTokenFile)
			}
		} else {
			fmt.Fprintln(os.Stderr, "[substrate] no sign-in and no callout token: the admin listener does not run")
		}
		if _, err := os.Stat(serveFlags.sessionKeyFile); err == nil {
			s, err := identity.LoadSessionSigner(serveFlags.sessionKeyFile, c.Substrate.RelaySessionIssuer())
			if err != nil {
				return out, err
			}
			out.Sessions = s
		}
		if out.RelayCA, err = loadRelayCA(serveFlags.relayCADir); err != nil {
			return out, err
		}
		out.RelayTLS = relaytls.Mode(c.Substrate.EffectiveRelayTLS())
		// GAP-0861: the live relay certificate per actor is on the leader.
		out.RelayCerts = regs
		out.RelayCertReissue = c.Substrate.RelayCertReissueFor(managed.IsManagedEnterprise(c.DeploymentMode))
		out.Interactive = func() config.SubstrateInteractiveConfig {
			if cur := live(); cur != nil {
				return cur.Substrate.Interactive
			}
			return c.Substrate.Interactive
		}
		ready.Store(true)
		return out, nil
	}
}

// loadRelayCA reads the relay CA Secret mount (substrate setup,
// gateway.relayCASecret). A missing folder is no CA: TLS relays then
// answer relay_ca_missing and doctor fails substrate.relay_tls.
func loadRelayCA(dir string) (*relaytls.CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, setup.RelayCACertKey))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "[substrate] no relay CA at", dir+": actors on templates with relay TLS cannot be attached")
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("serve: relay CA: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, setup.RelayCAKeyKey))
	if err != nil {
		return nil, fmt.Errorf("serve: relay CA key: %w", err)
	}
	ca, err := relaytls.LoadCA(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("serve: relay CA: %w", err)
	}
	return ca, nil
}

// substrateSecretPlaceholders resolves bound secret names to the environment
// variable names the actor carries in their place. E9 looks there for a
// vendor API key (CURSOR_API_KEY, AMP_API_KEY, KIRO_API_KEY, GEMINI_API_KEY).
func substrateSecretPlaceholders(secrets []config.SubstrateSecret) func([]string) []string {
	byName := make(map[string]string, len(secrets))
	for _, s := range secrets {
		if s.Inject.Placeholder != "" {
			byName[s.Name] = s.Inject.Placeholder
		}
	}
	return func(names []string) []string {
		var out []string
		for _, n := range names {
			if p, ok := byName[n]; ok {
				out = append(out, p)
			}
		}
		return out
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
	// chains is the leader's chain state, opened below before the elector
	// runs; becoming the leader starts its start grace term (GAP-0601).
	var chains *chainstate.Service
	el := &leader.Elector{
		API: &leader.KubeLeaseAPI{Server: "https://" + net.JoinHostPort(host, port), Namespace: ns, Name: serveFlags.lease,
			TokenFile: serveFlags.kubeTokenFile, HTTP: kube},
		Name: serveFlags.lease, Ns: ns, Identity: pod,
		OnStarted: func(context.Context) { substrateLeaderStarted(os.Stderr, pod, chains, ready) },
		OnStopped: func() { ready.Store(false) },
	}
	srv := &leader.Server{IsLeader: el.IsLeader}
	registry.Serve(srv, store)
	if err := serveSubstrateRevocations(srv, cfg, serveFlags.storeDir); err != nil {
		return err
	}
	askStore, err := asks.Open(filepath.Join(serveFlags.storeDir, "asks"))
	if err != nil {
		return err
	}
	defer askStore.Close()
	if cfg != nil {
		askStore.Expiry = cfg.Substrate.EffectiveAskTimeout()
	}
	// A host approved always joins the actor's registration; the controller
	// adds it to the policy on its next pass. The store never runs this for
	// a once approval, which lets one request through (GAP-0484).
	askStore.OnApprove = func(ctx context.Context, a asks.Ask) error {
		// Only a host-wide approval joins the registration (and so the
		// policy); a url_rules approval covers its rule only (GAP-0177).
		if a.Host == "" || !asks.HostWide(a.Rule) {
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
	// A revoked always approval leaves the registration, and so the policy
	// on the controller's next pass (GAP-0492).
	askStore.OnRevoke = func(ctx context.Context, in asks.RevokeRequest) (bool, error) {
		return registry.RemoveApproved(ctx, store, in.Atespace, in.UID, in.Host, in.CallerID, in.Admin)
	}
	asks.Serve(srv, askStore)
	activity.Serve(srv, &activity.Store{Pending: askStore.Pending})
	// The records the gateway replicas export for the components that have
	// no telemetry runtime: the controller's counts, the callout's egress
	// decisions and the lifecycle events below (GAP-0450, GAP-0453).
	relay := &telemetryrelay.Store{Registrations: store}
	telemetryrelay.Serve(srv, relay)
	// The controller's egress callout slot reads, for the gateways
	// (GAP-0505).
	controller.ServeCallout(srv, &controller.CalloutBoard{})
	// The pull --push-branch push grants the callout enforces (GAP-1073).
	pushgrant.Serve(srv, pushgrant.NewStore())
	chainOpts, source := leaderChainOptions(cfg, store, serveFlags.storeDir, serveFlags.chainRetention)
	fmt.Fprintf(os.Stderr, "[substrate] leader: chain egress action %s (%s): a request after a secret read is %s at the egress callout\n",
		chainOpts.EgressAction, source, map[string]string{chainstate.EgressBlock: "refused", chainstate.EgressAlert: "allowed with an alert"}[chainOpts.EgressAction])
	chains, err = chainstate.New(chainOpts)
	if err != nil {
		return err
	}
	defer chains.Close()
	if cfg != nil {
		// The chain egress action follows config.yaml (GAP-0276).
		src, err := substrateConfigWatcher("", cfg)
		if err != nil {
			return err
		}
		go newSubstrateFollower(src, "leader", os.Stderr, func(c *config.Config) error {
			action, _ := leaderChainEgressAction(c)
			return chains.SetEgressAction(action)
		}).run(ctx)
	}
	chains.Register(srv)
	// Cluster spend and usage of the gateway replicas (T-COST): on the store
	// volume, only for the gateway peer, off with substrate.usage.enabled.
	closeSpend, err := serveSpendUsage(srv, cfg, serveFlags.storeDir)
	if err != nil {
		return err
	}
	defer closeSpend()
	// A crashed or deleted actor asks nothing any more (E16): its open asks
	// close when the controller reports the lifecycle event.
	srv.Handle(chainstate.MethodChainLifecycle, leader.Typed(substrateLifecycleRelays(substrateLifecycleClosesAsks(chains.Lifecycle, askStore, os.Stderr, relay), store, relay)))
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

// substrateLeaderStarted runs when this replica becomes the leader: the
// chain start grace term begins (its 30 s cap runs from here, not from when
// the chain state was opened, which can be a lease duration earlier), then
// ready (GAP-0601).
func substrateLeaderStarted(w io.Writer, pod string, chains *chainstate.Service, ready *atomic.Bool) {
	fmt.Fprintf(w, "[substrate] %s is the leader\n", pod)
	chains.Leading()
	ready.Store(true)
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
// (GAP-0094): gateway replicas every method but the controller's own
// (leader.NamedOnly, GAP-0553); the callout only the egress chain check,
// the name lookup of a registration (GAP-0090), its egress decisions for
// the telemetry relay and the check of a git push against the open push
// grants (GAP-1073, never their opening or closing); the controller the registrations, the chain
// lifecycle, the activity feed, its counts for the relay (GAP-0450) and
// publishing its egress callout slot read (GAP-0505). Each relay method
// accepts only its poster's kinds of record.
// An identity listed in two roles gets both sets.
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
	add(callouts, chainstate.MethodChainEgress, leader.MethodRegistrationLookup, telemetryrelay.MethodPostEgress, pushgrant.MethodCheck)
	add(controllers, leader.MethodRegistrationGet, leader.MethodRegistrationList, leader.MethodRegistrationWrite,
		chainstate.MethodChainLifecycle, chainstate.MethodChainRunning, leader.MethodActivitySnapshot, telemetryrelay.MethodPostCounts,
		leader.MethodCalloutPublish)
	return p
}

// substrateBindingsConfigMap is the chart's binding store ConfigMap in the
// release namespace.
const substrateBindingsConfigMap = "defenseclaw-secret-bindings"

// substrateBindingStore is the self-service binding store, watched every
// 2 s. It is nil, and nothing reads the ConfigMap, when
// self_service_secrets.mode is off or outside a cluster (M-PERF-1).
func substrateBindingStore(c *config.Config) *secretbind.Store {
	if c.Substrate.SelfServiceSecrets.EffectiveMode() == config.SelfServiceOff {
		return nil
	}
	return substrateBindingsWatched()
}

// substrateBindingsWatched is the one store and watcher of this process
// (gateway or controller).
var substrateBindingsWatched = sync.OnceValue(func() *secretbind.Store {
	ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	k, ok := substrateKubeSecrets().(*kubeSecrets)
	if ns == "" || !ok || k == nil {
		return nil
	}
	st := secretbind.New(kubeBindings{k: k, ns: ns, name: substrateBindingsConfigMap})
	go st.Watch(context.Background(), 2*time.Second)
	return st
})

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

// substrateRouter builds attach's way to the relays: nil, nil when no router
// address is set; nil and the reason when it cannot be built. The doctor
// row substrate.attach_router names either (GAP-0157).
func substrateRouter() (*routerDialer, error) {
	if serveFlags.routerAddress == "" {
		fmt.Fprintln(os.Stderr, "[substrate] attach is off: no --router-address (run, connect, pull, logs and checkpoint answer attach_unavailable)")
		return nil, nil
	}
	files, err := podcert.NewFiles(serveFlags.peerBundle, serveFlags.peerTrust)
	if err != nil {
		err = fmt.Errorf("pod identity: %w", err)
		fmt.Fprintf(os.Stderr, "[substrate] attach is off: %v\n", err)
		return nil, err
	}
	d, err := newRouterDialer(serveFlags.routerAddress, serveFlags.routerServerName, serveFlags.routerCAFile, serveFlags.relayPort, files.Certificate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] attach is off: %v\n", err)
		return nil, err
	}
	return d, nil
}

// relayDialer is d as the attach route's dialer (a nil *routerDialer must be
// a nil interface, so attach answers attach_unavailable).
func relayDialer(d *routerDialer) gateway.SubstrateRelayDialer {
	if d == nil {
		return nil
	}
	return d
}

// substrateActorKeySet is the actor token key set: iss must equal
// substrate.identity.issuer, and the keys come from the keys URL (the idp
// Service by default), never from the issuer's own host, so a per-cluster
// issuer need not resolve (GAP-0194).
func substrateActorKeySet(c *config.Config) (*identity.KeySet, error) {
	ca := c.Substrate.EffectiveKeysCAFile()
	if serveFlags.issuerCA != "" {
		ca = serveFlags.issuerCA
	}
	return identity.NewKeySet(identity.KeySetOptions{
		Issuer: c.Substrate.Identity.Issuer, KeysURL: c.Substrate.EffectiveKeysURL(), CAFile: ca,
	})
}

// substrateActorKeysCheck is the gateway doctor row (GET /api/v1/substrate/doctor) for the actor token key
// set: the keys URL answers with signing keys, and the issuer the idp
// serves (what ate-api-server puts in iss) is substrate.identity.issuer.
func substrateActorKeysCheck(ctx context.Context, ks *identity.KeySet) gateway.SubstrateCheck {
	const id = "substrate.actor_keys"
	if ks == nil {
		return gateway.SubstrateCheck{ID: id, Status: "fail", Detail: "the actor token key set is not configured"}
	}
	n, err := ks.Probe(ctx)
	if err != nil {
		return gateway.SubstrateCheck{ID: id, Status: "fail",
			Detail: "the keys URL " + ks.KeysURL() + " does not answer: " + err.Error() + "; every actor token is refused",
			Fix:    "set substrate.identity.keys_url to the idp Service key set (chart value substrate.actorKeys.url) and keys_ca_file to the CA that signed it"}
	}
	served, err := ks.ServedIssuer(ctx)
	switch {
	case err != nil:
		return gateway.SubstrateCheck{ID: id, Status: "warn",
			Detail: fmt.Sprintf("the keys URL answers (%d keys), but the idp discovery document could not be read to compare the issuer: %v", n, err)}
	case served != ks.Issuer():
		return gateway.SubstrateCheck{ID: id, Status: "fail",
			Detail: fmt.Sprintf("Substrate signs actor tokens with issuer %q, but substrate.identity.issuer is %q: every actor token is refused", served, ks.Issuer()),
			Fix:    "set substrate.identity.issuer to the issuer given to setup --issuer and ate-setup deploy"}
	}
	return gateway.SubstrateCheck{ID: id, Status: "pass",
		Detail: fmt.Sprintf("the keys URL answers (%d keys) and Substrate's issuer matches substrate.identity.issuer", n)}
}

// substrateTemplateAllowlistCheck names every template the actor allowlist of
// 1.0.10 refuses (GAP-0354, GAP-0355): after an upgrade its new actors are
// refused, while running ones keep running with a warning in 1.0.10.
func substrateTemplateAllowlistCheck(ctx context.Context, ate ateapi.Client, a controller.Attestor) gateway.SubstrateCheck {
	ts, err := controller.TemplatesFailingAllowlist(ctx, ate, a)
	status, detail, fix := controller.AllowlistCheck(ts, err)
	return gateway.SubstrateCheck{ID: controller.AllowlistCheckID, Status: status, Detail: detail, Fix: fix}
}

// substrateRelaySeparationCheck names every template whose relay runs as
// the agent's own user (GAP-0372): images built before 1.0.10 are admitted,
// but the agent can stop their relay until they are rebuilt.
func substrateRelaySeparationCheck(ctx context.Context, ate ateapi.Client, a controller.Attestor) gateway.SubstrateCheck {
	ts, err := controller.UnseparatedTemplates(ctx, ate, a)
	status, detail, fix := controller.SeparationCheck(ts, err)
	return gateway.SubstrateCheck{ID: controller.SeparationCheckID, Status: status, Detail: detail, Fix: fix}
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
	if line := substrateAuditExportWarning(c); line != "" {
		fmt.Fprintln(os.Stderr, line)
	}
	for _, line := range substrateEchoHostWarnings(c.Substrate.Secrets, c.Substrate.Egress.NoSwapHosts) {
		fmt.Fprintln(os.Stderr, line)
	}
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

// substrateEchoHostWarnings says, once at start, which secrets an
// administrator let be added on a host that echoes or publishes requests
// (inject.allow_echo; GAP-0405): egress injects the real value there, and
// the answer hands it back to the agent and its model. Every other echo
// binding is dropped by the controller (secret_echo_host) and failed by
// the doctor row substrate.secret_echo_host, so it needs no start line.
func substrateEchoHostWarnings(secrets []config.SubstrateSecret, noSwap []string) []string {
	var out []string
	for _, sec := range secrets {
		if !sec.Inject.AllowEcho {
			continue
		}
		if hits := gateway.SubstrateSecretEchoHits(sec, noSwap); len(hits) > 0 {
			out = append(out, fmt.Sprintf("[substrate] warning: secret %s is injected on %s, which return the request they get, "+
				"because its entry sets inject.allow_echo: the real value comes back to the agent and its model.",
				sec.Name, strings.Join(hits, ", ")))
		}
	}
	return out
}

// substrateAuditExportWarning says, once at start, that a gateway pod keeps
// its audit store in a pod volume (the chart's emptyDir): it is lost when the
// pod restarts, and each replica holds only the records it handled. The
// durable record on Substrate is an export destination (GAP-0275). "" when
// the config has an enabled push destination, or cannot be read here (the
// observability bootstrap reports that).
func substrateAuditExportWarning(c *config.Config) string {
	if c == nil || c.ConfigFilePath == "" {
		return ""
	}
	raw, err := os.ReadFile(c.ConfigFilePath)
	if err != nil {
		return ""
	}
	return substrateAuditExportWarningFor(c.ConfigFilePath, raw, c.DataDir)
}

// substrateChartCollectorDestination is the destination the chart adds for
// observability.local.enabled (templates/_helpers.tpl, GAP-0272).
const substrateChartCollectorDestination = "chart-collector"

// substrateChartCollector reports whether destination is the one the chart
// adds: named chart-collector and pointing at the chart's collector Service
// (http://defenseclaw-otel-collector.<namespace>.svc:4318). The chart keeps
// an operator's own destination of that name, so the name alone does not
// make it the try-out collector (GAP-0299).
func substrateChartCollector(destination config.ObservabilityV8EffectiveDestination) bool {
	if destination.Name != substrateChartCollectorDestination {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(destination.Transport.Endpoint))
	if err != nil || u.Scheme != "http" || u.Port() != "4318" || strings.Trim(u.Path, "/") != "" {
		return false
	}
	ns, ok := strings.CutPrefix(u.Hostname(), "defenseclaw-otel-collector.")
	if !ok {
		return false
	}
	ns, ok = strings.CutSuffix(ns, ".svc")
	return ok && ns != "" && !strings.Contains(ns, ".")
}

func substrateAuditExportWarningFor(source string, raw []byte, dataDir string) string {
	compiled, err := config.ParseCompileObservabilityV8(source, raw, config.ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
	if err != nil || compiled == nil || compiled.Plan == nil {
		return ""
	}
	tryOut := false
	for _, destination := range compiled.Plan.Destinations() {
		if !destination.Enabled {
			continue
		}
		switch destination.Kind {
		case config.ObservabilityV8DestinationOTLP, config.ObservabilityV8DestinationSplunkHEC,
			config.ObservabilityV8DestinationHTTPJSONL:
			// The chart's try-out collector prints what it gets and keeps
			// nothing, so it is no audit record (GAP-0286).
			if substrateChartCollector(destination) {
				tryOut = true
				continue
			}
			return ""
		}
	}
	if tryOut {
		return "[substrate] warning: the only export destination is " + substrateChartCollectorDestination +
			", the chart's try-out collector, which keeps nothing: this pod keeps its audit records in a pod volume, only those it handled, " +
			"and they are lost when the pod restarts; add a destination that stores them under observability.destinations " +
			"(docs: Agent Substrate reference, Turn on OTLP export)"
	}
	return "[substrate] warning: no export destination: this pod keeps its audit records in a pod volume, only those it handled, " +
		"and they are lost when the pod restarts; add an otlp, splunk_hec or http_jsonl destination under " +
		"observability.destinations for a durable record (docs: Agent Substrate reference, Turn on OTLP export)"
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

// substrateAskCloseReasons is the reason code and the words of an ask a
// lifecycle event closes (GAP-0526).
var substrateAskCloseReasons = map[string][2]string{
	chainstate.LifecycleCrashed:  {telemetryrelay.AskClosedActorCrashed, "the actor crashed"},
	chainstate.LifecycleReverted: {telemetryrelay.AskClosedActorReverted, "the actor was reverted to a snapshot"},
	chainstate.LifecycleDeleted:  {telemetryrelay.AskClosedActorDeleted, "the actor was deleted"},
}

// substrateLifecycleClosesAsks wraps the chain lifecycle handler: after a
// crashed, reverted or deleted event the actor's pending asks are closed
// (a revert drops the held request with the run it belonged to, GAP-0415).
// Each closed ask is a decision with the reason code, as an answer is; a
// log line names the event and every ask it closed; and each closure is a
// relay record, which a gateway replica writes to its audit log and the
// webhooks with the reason code (actor_crashed, actor_reverted,
// actor_deleted): the closure left no record anywhere before (GAP-0526).
// log and relay may be nil.
func substrateLifecycleClosesAsks(next func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error),
	asksStore interface {
		CloseActor(uid, code, reason string) []asks.Ask
	}, log io.Writer, relay *telemetryrelay.Store) func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
	if log == nil {
		log = io.Discard
	}
	return func(ctx context.Context, ev chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
		res, err := next(ctx, ev)
		if err != nil || res.Ignored {
			// An ignored event changed nothing (a delete of an actor whose
			// registration is not marked deleted): its asks stay open too
			// (GAP-0142 residual).
			return res, err
		}
		why, ok := substrateAskCloseReasons[ev.Event]
		if !ok {
			return res, nil
		}
		closed := asksStore.CloseActor(ev.Actor.UID, why[0], why[1]+" ("+why[0]+")")
		fmt.Fprintf(log, "[substrate] lifecycle %s: actor %s/%s; closed %d open ask(s) (%s)\n", ev.Event, ev.Actor.Atespace, ev.Actor.UID, len(closed), why[0])
		now := time.Now().UTC()
		for _, a := range closed {
			fmt.Fprintf(log, "[substrate] ask %s of %s/%s (%s) closed: expired, reason %s (%s)\n", a.ID, a.Atespace, a.Actor, substrateFirst(a.Host, a.Tool), why[0], why[1])
			if relay != nil {
				relay.Add(telemetryrelay.Record{Kind: telemetryrelay.KindAskClosed, At: now, Atespace: a.Atespace, Actor: a.Actor, UID: a.UID,
					AskID: a.ID, Host: substrateFirst(a.Host, a.Tool), Reason: why[0], Unattended: a.Unattended, Severity: a.Severity,
					Profile: a.Profile, UserID: a.OwnerID})
			}
		}
		return res, nil
	}
}

// substrateLifecycleRelays queues each actor lifecycle event the controller
// reports, with the actor's registration, for a gateway replica to export
// as log.sandbox.lifecycle (GAP-0453). An event the chain state ignored or
// refused is not a transition and is not relayed.
func substrateLifecycleRelays(next func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error),
	regs registry.Store, relay *telemetryrelay.Store) func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
	return func(ctx context.Context, ev chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
		res, err := next(ctx, ev)
		if err != nil || res.Ignored {
			return res, err
		}
		at := time.Now().UTC()
		if ev.AtUnixNano > 0 {
			at = time.Unix(0, ev.AtUnixNano).UTC()
		}
		rec := telemetryrelay.Record{Kind: telemetryrelay.KindLifecycle, At: at, Lifecycle: ev.Event,
			Atespace: ev.Actor.Atespace, UID: ev.Actor.UID}
		if reg, ok, rerr := regs.Get(ctx, ev.Actor.Atespace, ev.Actor.UID); rerr == nil && ok {
			rec.Actor, rec.Profile, rec.Template, rec.Connector = reg.Name, reg.Profile, reg.Template, reg.Connector
			rec.BatchID, rec.ParentUID, rec.UserID, rec.UserName = reg.BatchID, reg.ParentUID, reg.Person.Subject, reg.Person.Principal
			rec.Driver = reg.SandboxClass
			rec.RunMode = "interactive"
			if reg.Unattended {
				rec.RunMode = "unattended"
			}
		}
		if ev.Parent != nil && rec.ParentUID == "" {
			rec.ParentUID = ev.Parent.UID
		}
		if rec.Actor != "" {
			relay.Add(rec)
		}
		return res, nil
	}
}

// substrateChainRegistrations is what the leader's chain state reads from
// the registrations.
func substrateChainRegistrations(store registry.Store) chainstate.Options {
	return chainstate.Options{
		// A fork starts from its parent windows the first time the leader
		// sees it; the parent comes from the verified registration (GAP-0091).
		ParentOf: func(ctx context.Context, atespace, uid string) (string, error) {
			reg, ok, err := store.Get(ctx, atespace, uid)
			if err != nil || !ok {
				return "", err
			}
			return reg.ParentUID, nil
		},
		// A delete purges only a registration the controller marked
		// deleted (or an actor never registered) (GAP-0142).
		Deleted: func(ctx context.Context, atespace, uid string) (bool, error) {
			reg, ok, err := store.Get(ctx, atespace, uid)
			if err != nil {
				return false, err
			}
			return !ok || reg.Deleted, nil
		},
		// The callout's egress chain check is answered only for the name's
		// live incarnation, never for a deleted or replaced UID it still
		// caches (GAP-0234).
		Current: func(ctx context.Context, atespace, name, uid string) (bool, error) {
			return registry.Current(ctx, store, atespace, name, uid)
		},
	}
}

// substrateChainEgressAction is the leader's chain egress action and where
// it came from (GAP-0250): config substrate.chain_egress_action, the one
// source, which the gateway and the leader read from the same ConfigMap
// (default block).
func substrateChainEgressAction(c *config.Config) (action, source string) {
	if c == nil || strings.TrimSpace(c.Substrate.ChainEgressAction) == "" {
		return chainstate.EgressBlock, "default"
	}
	return c.Substrate.EffectiveChainEgressAction(), "config substrate.chain_egress_action"
}

// applyGatewayChainEgress is the gateway role's hand-off: it applies the
// role's chain egress action to verified actors' hook calls
// (gateway.SetSubstrateChainEgressAction). leaderChainOptions is the
// leader's: the chainstate options the egress callout runs with. The serve
// paths call exactly these, and TestSubstrateChainEgressActionGatewayAndLeaderAgree
// reads what each role ends up with (gateway.SubstrateChainEgressAction and
// Options.EgressAction), so a hard-coded value at either hand-off fails it
// (GAP-0252).
func applyGatewayChainEgress(cfg *config.Config) error {
	action, source := gatewayRoleChainEgressAction(cfg)
	if err := gateway.SetSubstrateChainEgressAction(action); err != nil {
		return fmt.Errorf("serve: chain egress action (%s): %w", source, err)
	}
	return nil
}

// leaderChainOptions: see applyGatewayChainEgress. It returns the options
// and where the action came from.
func leaderChainOptions(cfg *config.Config, store registry.Store, dir string, retention time.Duration) (chainstate.Options, string) {
	opts := substrateChainRegistrations(store)
	action, source := leaderChainEgressAction(cfg)
	opts.Dir, opts.EgressAction, opts.Retention = dir, action, retention
	opts.StartGrace = leaderChainStartGrace
	return opts, source
}

// leaderChainStartGrace covers a gateway's note of a tool step it could not
// record during a leader outage: retried every 5 s with a 2 s timeout
// (internal/gateway substrateNotes), so 15 s holds two tries of a small
// backlog (GAP-0601).
const leaderChainStartGrace = 15 * time.Second

// gatewayRoleChainEgressAction is the chain egress action the gateway role
// hands to gateway.SetSubstrateChainEgressAction: the verified actor's hook
// disposition after a secret read. leaderChainEgressAction is the one the
// leader puts in chainstate.Options.EgressAction: the egress callout's
// verdict. Each role's serve path calls its own function, and both read
// config substrate.chain_egress_action through substrateChainEgressAction, so
// the hook and the callout cannot disagree on one rendered ConfigMap
// (GAP-0252; TestSubstrateChainEgressActionGatewayAndLeaderAgree calls both).
func gatewayRoleChainEgressAction(c *config.Config) (action, source string) {
	return substrateChainEgressAction(c)
}

// leaderChainEgressAction: see gatewayRoleChainEgressAction.
func leaderChainEgressAction(c *config.Config) (action, source string) {
	return substrateChainEgressAction(c)
}

// substrateSignInServer is the OIDC issuer people sign in with, as the
// person verifier reaches it (its key set, trust bundle and network), or nil
// with no OIDC issuer (GAP-0262).
func substrateSignInServer(people gateway.SubstratePersonVerifier) gateway.SubstrateSignInServer {
	var pv *identity.PersonVerifier
	switch p := people.(type) {
	case *identity.PersonVerifier:
		pv = p
	case identity.PersonVerifiers:
		pv, _ = p.OIDC.(*identity.PersonVerifier)
	}
	if pv == nil {
		return nil
	}
	if ks := pv.SignInKeySet(); ks != nil {
		return ks
	}
	return nil
}
