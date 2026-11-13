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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// substrateExitUnreachable is the exit code of status and verify when the
// cluster or the Substrate API could not be reached (exit-codes.md): retry
// later, there is no document.
const substrateExitUnreachable = 75

// substrateClusterFlags say where an administrator reads the cluster from.
// By default the cluster is read with kubectl; --api reads the documents the
// DefenseClaw gateway builds itself (administrators only).
type substrateClusterFlags struct {
	api         bool
	kubeconfig  string
	kubeContext string
	namespace   string
	substrateNS string
	installFile string
	configFile  string
	timeout     time.Duration
	com         substrateCommon
}

func (f *substrateClusterFlags) add(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.api, "api", false, "read the document from the DefenseClaw gateway (needs an administrator sign-in) instead of with kubectl")
	f.addKube(cmd)
	f.com.add(cmd)
}

// addKube adds the flags that say how to read the cluster with kubectl.
func (f *substrateClusterFlags) addKube(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.kubeconfig, "kubeconfig", "", "kubectl configuration file (default: kubectl's own)")
	fl.StringVar(&f.kubeContext, "kube-context", "", "kubectl context to use")
	fl.StringVar(&f.namespace, "namespace", "defenseclaw-system", "namespace DefenseClaw is installed in")
	fl.StringVar(&f.substrateNS, "substrate-namespace", "ate-system", "namespace Agent Substrate runs in")
	fl.StringVar(&f.installFile, "install-file", "", "the SubstrateInstall file you gave ate-setup (the callout and router settings are read from it)")
	fl.StringVar(&f.configFile, "config", "", "DefenseClaw config.yaml (default: read from the cluster)")
	fl.DurationVar(&f.timeout, "timeout", 30*time.Second, "give up on the cluster after this long")
}

// substrateKubectl runs kubectl; tests replace it.
var substrateKubectl = func(ctx context.Context, f *substrateClusterFlags, args ...string) ([]byte, error) {
	var pre []string
	if f.kubeconfig != "" {
		pre = append(pre, "--kubeconfig", f.kubeconfig)
	}
	if f.kubeContext != "" {
		pre = append(pre, "--context", f.kubeContext)
	}
	cmd := exec.CommandContext(ctx, "kubectl", append(pre, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("kubectl is not installed or not on PATH")
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(firstLineOf(msg))
	}
	return out.Bytes(), nil
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

type kubeList struct {
	Items []kubeItem `json:"items"`
}

type kubeItem struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Replicas       *int   `json:"replicas"`
		HolderIdentity string `json:"holderIdentity"`
		Template       struct {
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas int `json:"readyReplicas"`
	} `json:"status"`
	Data map[string]string `json:"data"`
}

func kubeGetList(ctx context.Context, f *substrateClusterFlags, args ...string) ([]kubeItem, error) {
	raw, err := substrateKubectl(ctx, f, append(args, "-o", "json")...)
	if err != nil {
		return nil, err
	}
	var l kubeList
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("kubectl answered something this version does not read: %w", err)
	}
	return l.Items, nil
}

// collectFleet reads what fleet.Observed and the status report need from
// the cluster with kubectl and from the SubstrateInstall file. A failure to
// reach the cluster is returned as errClusterUnreachable.
type errClusterUnreachable struct{ err error }

func (e *errClusterUnreachable) Error() string {
	return "the cluster could not be reached: " + e.err.Error() + ". Check your kubectl access (kubectl get ns) and retry"
}
func (e *errClusterUnreachable) Unwrap() error { return e.err }

func collectFleet(ctx context.Context, f *substrateClusterFlags) (fleet.Observed, fleet.Report, error) {
	var o fleet.Observed
	var r fleet.Report
	if f.installFile == "" {
		return o, r, withExitCode(errors.New("give the SubstrateInstall file you gave ate-setup with --install-file FILE: the callout and router settings are read from it (or use --api as an administrator)"), 2)
	}
	install, err := os.ReadFile(f.installFile)
	if err != nil {
		return o, r, withExitCode(fmt.Errorf("cannot read the install file: %w", err), 2)
	}
	settings, err := setup.InstallSettings(install)
	if err != nil {
		return o, r, withExitCode(err, 2)
	}
	cctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	name := f.kubeContext
	if name == "" {
		out, err := substrateKubectl(cctx, f, "config", "current-context")
		if err != nil {
			return o, r, &errClusterUnreachable{err}
		}
		name = strings.TrimSpace(string(out))
	}
	o.ClusterName, o.Namespace, o.SubstrateNamespace = name, f.namespace, f.substrateNS
	o.SupportedVersions = config.DefaultSubstrateSupportedVersions

	// The install settings.
	o.ExtprocService = settings[setup.KeyExtprocService]
	o.OpenAPPA = strings.EqualFold(settings[setup.KeyOpenAPPA], "true")
	for _, c := range strings.Split(settings[setup.KeyIngressClients], ",") {
		if c = strings.TrimSpace(c); c != "" {
			o.IngressClients = append(o.IngressClients, c)
		}
	}
	if v, ok := settings[setup.KeyExtprocBodyOptIn]; ok {
		b := strings.EqualFold(v, "true")
		o.BodyOptIn = &b
	}
	o.CalloutPort = 9443
	if i := strings.LastIndexByte(o.ExtprocService, ':'); i >= 0 {
		if p, err := strconv.Atoi(o.ExtprocService[i+1:]); err == nil {
			o.CalloutPort = p
		}
	}

	// The release namespace.
	rawNS, err := substrateKubectl(cctx, f, "get", "namespace", f.namespace, "-o", "json")
	if err != nil {
		return o, r, &errClusterUnreachable{err}
	}
	var nsItem kubeItem
	if json.Unmarshal(rawNS, &nsItem) == nil {
		o.NamespaceLabels = nsItem.Metadata.Labels
		if o.NamespaceLabels == nil {
			o.NamespaceLabels = map[string]string{}
		}
	}

	// Workloads, the lease, the store state and the config.
	loads, err := kubeGetList(cctx, f, "get", "deployments,statefulsets", "-n", f.namespace)
	if err != nil {
		return o, r, &errClusterUnreachable{err}
	}
	for _, it := range loads {
		desired := 1
		if it.Spec.Replicas != nil {
			desired = *it.Spec.Replicas
		}
		rep := fleet.Replicas{Desired: desired, Ready: it.Status.ReadyReplicas}
		n := it.Metadata.Name
		switch {
		case strings.HasSuffix(n, "gateway-leader"):
			r.Health.Leader.Ready = rep.Ready > 0
		case strings.HasSuffix(n, "controller"):
			r.Health.Controller = fleet.Controller{Desired: rep.Desired, Ready: rep.Ready}
		case strings.HasSuffix(n, "callout"):
			r.Health.Callout.Desired, r.Health.Callout.Ready = rep.Desired, rep.Ready
		case strings.HasSuffix(n, "gateway"):
			r.Health.Gateway = rep
		}
	}
	if leases, err := kubeGetList(cctx, f, "get", "leases.coordination.k8s.io", "-n", f.namespace); err == nil {
		for _, l := range leases {
			if strings.Contains(l.Metadata.Name, "gateway-leader") && l.Spec.HolderIdentity != "" {
				r.Health.Leader.LeaseHeld = true
			}
		}
	}
	cms, _ := kubeGetList(cctx, f, "get", "configmaps", "-n", f.namespace)
	for _, c := range cms {
		if strings.HasSuffix(c.Metadata.Name, "store-state") {
			if st, err := setup.ParseStoreState(c.Data); err == nil && st != nil {
				r.Health.Leader.StoreSchema = st.SchemaVersion
			}
		}
	}
	cfgText := ""
	if f.configFile != "" {
		b, err := os.ReadFile(f.configFile)
		if err != nil {
			return o, r, withExitCode(fmt.Errorf("cannot read the config file: %w", err), 2)
		}
		cfgText = string(b)
	} else {
		for _, c := range cms {
			if t := c.Data["config.yaml"]; strings.Contains(t, "substrate:") {
				cfgText = t
				break
			}
		}
	}
	var keysCfg config.SubstrateConfig
	if cfgText != "" {
		var doc struct {
			Substrate struct {
				Supported string `yaml:"supported_versions"`
				Identity  struct {
					Issuer  string `yaml:"issuer"`
					KeysURL string `yaml:"keys_url"`
				} `yaml:"identity"`
				API struct {
					Address string `yaml:"address"`
				} `yaml:"api"`
			} `yaml:"substrate"`
		}
		if err := yaml.Unmarshal([]byte(cfgText), &doc); err == nil {
			o.Issuer = doc.Substrate.Identity.Issuer
			keysCfg.Identity.KeysURL, keysCfg.API.Address = doc.Substrate.Identity.KeysURL, doc.Substrate.API.Address
			if doc.Substrate.Supported != "" {
				o.SupportedVersions = doc.Substrate.Supported
			}
		}
	}
	o.InstallIssuer = settings[setup.KeyActorJWTIssuer]
	if o.InstallIssuer != "" && o.Issuer == "" {
		o.Issuer = o.InstallIssuer
	}
	o.Clusters = 1
	readActorKeys(cctx, f, &o, keysCfg.EffectiveKeysURL())

	// The Substrate release: the tag of the API server image.
	subs, err := kubeGetList(cctx, f, "get", "deployments", "-n", f.substrateNS)
	if err == nil {
		for _, d := range subs {
			for _, c := range d.Spec.Template.Spec.Containers {
				if strings.Contains(c.Image, "ate-api-server") || strings.Contains(d.Metadata.Name, "api-server") ||
					strings.Contains(c.Image, "/substrate") {
					o.SubstrateVersion = imageTag(c.Image)
				}
			}
		}
	}
	// Not read here: the snapshot bucket, the access policies and the actor
	// listener's routes. The checks say so as warnings or skips.
	r.ProductVersion = appVersion
	r.Now = time.Now()
	return o, r, nil
}

// readActorKeys reads the actor token key set the gateway uses, and the
// idp discovery document at the same origin, through the API server's
// Service proxy: the idp Service is not reachable from an administrator's
// machine (GAP-0194). A keys URL that is not a Service of this cluster is
// left to the gateway-side doctor.
func readActorKeys(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed, keysURL string) {
	o.KeysURL = keysURL
	proxy, ok := serviceProxyPath(keysURL)
	if !ok {
		o.KeysNote = "it is not a Service of this cluster"
		return
	}
	raw, err := substrateKubectl(ctx, f, "get", "--raw", proxy.keys)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") || strings.Contains(err.Error(), "Forbidden") {
			o.KeysNote = "this identity may not use the Service proxy"
			return
		}
		zero := 0
		o.Keys, o.KeysErr = &zero, firstLineOf(err.Error())
		return
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	n := 0
	if json.Unmarshal(raw, &set) == nil {
		n = len(set.Keys)
	}
	o.Keys = &n
	if n == 0 {
		o.KeysErr = "the answer holds no keys"
		return
	}
	if raw, err := substrateKubectl(ctx, f, "get", "--raw", proxy.discovery); err == nil {
		var d struct {
			Issuer string `json:"issuer"`
		}
		if json.Unmarshal(raw, &d) == nil {
			o.ServedIssuer = d.Issuer
		}
	}
}

type serviceProxy struct{ keys, discovery string }

// serviceProxyPath maps https://SVC.NS.svc[.cluster.local][:PORT]/PATH to
// the API server's Service proxy paths for PATH and the discovery document.
func serviceProxyPath(raw string) (serviceProxy, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return serviceProxy{}, false
	}
	host := strings.TrimSuffix(u.Hostname(), ".cluster.local")
	parts := strings.Split(host, ".")
	if len(parts) != 3 || parts[2] != "svc" || parts[0] == "" || parts[1] == "" {
		return serviceProxy{}, false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	base := "/api/v1/namespaces/" + parts[1] + "/services/https:" + parts[0] + ":" + port + "/proxy"
	return serviceProxy{keys: base + u.EscapedPath(), discovery: base + "/.well-known/openid-configuration"}, true
}

func imageTag(image string) string {
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndexByte(image, ':'); i >= 0 && !strings.Contains(image[i:], "/") {
		return strings.TrimPrefix(image[i+1:], "v")
	}
	return ""
}

func newSubstrateVerifyCmd() *cobra.Command {
	var (
		out substrateOutput
		cf  substrateClusterFlags
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check the cluster setup: issuer, snapshot bucket, access grants, callout and version",
		Long: `For administrators. Checks that the cluster is set up as DefenseClaw needs it: Substrate's version is
one DefenseClaw is tested on, the cluster has its own sign-in issuer, the snapshot bucket is private and
encrypted, DefenseClaw holds the right access grants, the egress callout is registered and nobody else
can reach agents through the router. By default it reads the cluster with kubectl; --api reads the same
checks from the DefenseClaw gateway.

Exit 0: every check passed or warned. Exit 1: a check failed. Exit 2: wrong arguments. Exit 75: the cluster
could not be reached; there is no document, retry later. With --json it prints the verify document.`,
		Example: "defenseclaw substrate verify --install-file install.yaml\ndefenseclaw substrate verify --api --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSubstrateFleet(cmd, "verify", &out, &cf)
		},
	}
	out.add(cmd)
	cf.add(cmd)
	return cmd
}

// runSubstrateFleet prints the verify or status document of the cluster.
func runSubstrateFleet(cmd *cobra.Command, kind string, out *substrateOutput, cf *substrateClusterFlags) error {
	asJSON, err := out.wantJSON()
	if err != nil {
		return withExitCode(err, 2)
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	var doc any
	var checks []fleet.Check
	var ok = true
	var header string
	if cf.api {
		s, err := substrateOpen(cmd, &cf.com)
		if err != nil {
			return err
		}
		if kind == "verify" {
			d, err := s.Client.FleetVerifyDocument(ctx)
			if err != nil {
				return substrateFleetAPIFail(err)
			}
			doc, checks, ok, header = d, d.Checks, d.OK, d.Cluster.Name
		} else {
			d, err := s.Client.FleetStatusDocument(ctx)
			if err != nil {
				return substrateFleetAPIFail(err)
			}
			doc, checks, header = d, d.Checks, d.Cluster.Name
		}
	} else {
		o, r, err := collectFleet(ctx, cf)
		if err != nil {
			var un *errClusterUnreachable
			if errors.As(err, &un) {
				return withExitCode(err, substrateExitUnreachable)
			}
			return err
		}
		if kind == "verify" {
			d := fleet.BuildVerify(o, r.ProductVersion, r.Now)
			doc, checks, ok, header = d, d.Checks, d.OK, d.Cluster.Name
		} else {
			d := fleet.BuildStatus(o, r)
			doc, checks, header = d, d.Checks, d.Cluster.Name
		}
	}
	w := cmd.OutOrStdout()
	if asJSON {
		if err := writeSubstrateJSON(w, doc); err != nil {
			return err
		}
	} else {
		printSubstrateFleet(w, kind, header, doc, checks, ok)
	}
	if kind == "verify" && !ok {
		return withExitCode(errors.New("a cluster check failed"), 1)
	}
	return nil
}

func substrateFleetAPIFail(err error) error {
	if strings.Contains(err.Error(), "cannot reach") || strings.Contains(err.Error(), "nothing answers") ||
		strings.Contains(err.Error(), "did not answer in time") {
		return withExitCode(err, substrateExitUnreachable)
	}
	return substrateFail(err)
}

func printSubstrateFleet(w io.Writer, kind, cluster string, doc any, checks []fleet.Check, ok bool) {
	fmt.Fprintf(w, "Cluster %s\n", substrateDash(cluster))
	if st, isStatus := doc.(fleet.StatusDocument); isStatus {
		h := st.Health
		fmt.Fprintf(w, "Health:      %s\n", h.State)
		fmt.Fprintf(w, "Gateway:     %d of %d ready\n", h.Gateway.Ready, h.Gateway.Desired)
		fmt.Fprintf(w, "Leader:      ready=%t lease held=%t\n", h.Leader.Ready, h.Leader.LeaseHeld)
		fmt.Fprintf(w, "Controller:  %d of %d ready\n", h.Controller.Ready, h.Controller.Desired)
		fmt.Fprintf(w, "Callout:     %d of %d ready, registered=%t, %s\n", h.Callout.Ready, h.Callout.Desired, h.Callout.Registered, h.Callout.BodyMode)
		fmt.Fprintf(w, "Agents:      %d (%d running, %d suspended)\n", st.Inventory.Actors, st.Inventory.Running, st.Inventory.Suspended)
		fmt.Fprintln(w)
	}
	failed := 0
	for _, c := range checks {
		fmt.Fprintf(w, "  %-5s %-22s %s\n", c.Status, c.ID, c.Message)
		if c.Status == fleet.Fail {
			failed++
		}
	}
	if kind == "verify" {
		if ok {
			fmt.Fprintln(w, "cluster verified")
		} else {
			fmt.Fprintf(w, "not verified: %d check(s) failed\n", failed)
		}
	}
}
