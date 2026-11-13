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

// substrate-bundle is the in-cluster side of signed policy bundles for Agent
// Substrate (internal/substrate/bundle): it runs where the bundle ConfigMaps
// and the anchors Secret are, for example
//
//	kubectl -n defenseclaw-system exec -i deploy/defenseclaw-controller -- \
//	  /defenseclaw-gateway substrate-bundle apply --bundle - --stage canary --atespaces team-a < v3.dcbundle
//
// Administrators normally use "defenseclaw substrate bundle", which goes
// through the admin listener to the same store, or the GitOps inbox. The
// controller's resolver (substrateProfileResolver) applies the result.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/substrate/bundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

type substrateBundleFlags struct {
	config, namespace, anchors   string
	kubeAPI, kubeToken, kubeCA   string
	json                         bool
	bundle, stage                string
	atespaces                    []string
	receipts                     int
	atespace, template, workload string
}

func (f *substrateBundleFlags) common(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.config, "config", "", "config.yaml (default: the DefenseClaw config path)")
	fl.StringVar(&f.namespace, "namespace", "", "the DefenseClaw namespace (default: $POD_NAMESPACE)")
	fl.StringVar(&f.anchors, "anchors", "", "bundle-anchors.json (default: substrate.bundles.anchors_file)")
	fl.StringVar(&f.kubeAPI, "kube-api", "", "Kubernetes API URL (default: in-cluster)")
	fl.StringVar(&f.kubeToken, "kube-token-file", "", "with --kube-api: bearer token file")
	fl.StringVar(&f.kubeCA, "kube-ca", "", "with --kube-api: CA bundle file")
	fl.BoolVar(&f.json, "json", false, "print the result as JSON")
}

var substrateBundleCmd = &cobra.Command{
	Use:   "substrate-bundle",
	Short: "Apply, roll back and show signed policy bundles in an Agent Substrate cluster (in the cluster)",
	Long: `Signed policy bundles for the DefenseClaw Substrate controller. A bundle is
an enterprise bundle (bundle sign --platform linux) whose config.yaml holds
guardrail profiles (sandbox sections) and match.substrate assignments. It
is applied to a stage: named atespaces (--stage canary --atespaces a,b) or
every other atespace (--stage all). The controller layers the stage's
active bundle over config.yaml; substrate.admin still applies. Every apply
and rollback, refused or not, leaves a receipt.

  apply     verify a bundle and make it the stage's active bundle
  rollback  re-activate the stage's previous bundle (verified again)
  status    stages, active and previous bundles, problems, receipts
  test      verify a bundle offline and show what an actor would get`,
	Hidden:      true,
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
}

func init() {
	apply := &substrateBundleFlags{}
	applyCmd := &cobra.Command{
		Use: "apply", Short: "Verify a bundle and make it a stage's active bundle", Args: cobra.NoArgs, SilenceUsage: true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := apply.store()
			if err != nil {
				return err
			}
			archive, err := readSubstrateBundleArchive(cmd, apply.bundle)
			if err != nil {
				return err
			}
			rc, err := s.Apply(cmd.Context(), archive, apply.stage, apply.atespaces, bundle.SourceCLI)
			return printSubstrateBundleReceipt(cmd, apply.json, rc, err)
		},
	}
	apply.common(applyCmd)
	applyCmd.Flags().StringVar(&apply.bundle, "bundle", "", "the signed .dcbundle file (- for stdin)")
	applyCmd.Flags().StringVar(&apply.stage, "stage", "", "the stage: a name for --atespaces, or all")
	applyCmd.Flags().StringSliceVar(&apply.atespaces, "atespaces", nil, "the stage's atespaces (exact names, comma separated)")
	_ = applyCmd.MarkFlagRequired("bundle")
	_ = applyCmd.MarkFlagRequired("stage")

	rb := &substrateBundleFlags{}
	rollbackCmd := &cobra.Command{
		Use: "rollback", Short: "Re-activate a stage's previous bundle", Args: cobra.NoArgs, SilenceUsage: true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := rb.store()
			if err != nil {
				return err
			}
			rc, err := s.Rollback(cmd.Context(), rb.stage, bundle.SourceCLI)
			return printSubstrateBundleReceipt(cmd, rb.json, rc, err)
		},
	}
	rb.common(rollbackCmd)
	rollbackCmd.Flags().StringVar(&rb.stage, "stage", "", "the stage to roll back")
	_ = rollbackCmd.MarkFlagRequired("stage")

	st := &substrateBundleFlags{}
	statusCmd := &cobra.Command{
		Use: "status", Short: "Show stages, bundles, problems and receipts", Args: cobra.NoArgs, SilenceUsage: true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := st.store()
			if err != nil {
				return err
			}
			res, err := s.Status(cmd.Context(), st.receipts)
			if err != nil {
				return err
			}
			if st.json {
				return writeSubstrateBundleJSON(cmd.OutOrStdout(), res)
			}
			printSubstrateBundleStatus(cmd.OutOrStdout(), res)
			return nil
		},
	}
	st.common(statusCmd)
	statusCmd.Flags().IntVar(&st.receipts, "receipts", 20, "how many receipts to show (0: all)")

	tf := &substrateBundleFlags{}
	testCmd := &cobra.Command{
		Use: "test", Short: "Verify a bundle offline and show the profile and egress an actor would get", Args: cobra.NoArgs, SilenceUsage: true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE:        func(cmd *cobra.Command, _ []string) error { return runSubstrateBundleTest(cmd, tf) },
	}
	tf.common(testCmd)
	testCmd.Flags().StringVar(&tf.bundle, "bundle", "", "the signed .dcbundle file (- for stdin)")
	testCmd.Flags().StringVar(&tf.atespace, "atespace", "", "the actor's atespace")
	testCmd.Flags().StringVar(&tf.template, "template", "", "the actor's template, <atespace>/<name>")
	testCmd.Flags().StringVar(&tf.workload, "workload", "", "the actor's verified workload principal")
	_ = testCmd.MarkFlagRequired("bundle")
	_ = testCmd.MarkFlagRequired("atespace")

	substrateBundleCmd.AddCommand(applyCmd, rollbackCmd, statusCmd, testCmd)
	rootCmd.AddCommand(substrateBundleCmd)
}

func (f *substrateBundleFlags) loadConfig() (*config.Config, error) {
	path := f.config
	if path == "" {
		path = config.ConfigPath()
	}
	return config.LoadFromFile(path)
}

func (f *substrateBundleFlags) anchorsLoader(cfg *config.Config) func() (*eb.Anchors, error) {
	path := f.anchors
	if path == "" {
		path = cfg.Substrate.Bundles.EffectiveAnchorsFile()
	}
	return func() (*eb.Anchors, error) { return bundle.LoadAnchorsFile(path) }
}

func (f *substrateBundleFlags) store() (*bundle.Store, error) {
	cfg, err := f.loadConfig()
	if err != nil {
		return nil, err
	}
	ns := f.namespace
	if ns == "" {
		ns = os.Getenv("POD_NAMESPACE")
	}
	var cms bundle.ConfigMaps
	if f.kubeAPI != "" {
		cms, err = bundle.NewKube(f.kubeAPI, ns, f.kubeToken, f.kubeCA)
	} else {
		cms, err = bundle.NewInClusterKube(ns)
	}
	if err != nil {
		return nil, err
	}
	path := f.anchors
	if path == "" {
		path = cfg.Substrate.Bundles.EffectiveAnchorsFile()
	}
	return &bundle.Store{CM: cms, Base: cfg, Anchors: f.anchorsLoader(cfg), AnchorsFile: path}, nil
}

func readSubstrateBundleArchive(cmd *cobra.Command, path string) ([]byte, error) {
	var r io.Reader
	if path == "-" {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, bundle.MaxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func writeSubstrateBundleJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printSubstrateBundleReceipt(cmd *cobra.Command, asJSON bool, rc *bundle.Receipt, err error) error {
	w := cmd.OutOrStdout()
	if rc != nil {
		if asJSON {
			if jerr := writeSubstrateBundleJSON(w, rc); jerr != nil {
				return jerr
			}
		} else {
			fmt.Fprintf(w, "%s %s stage %s: %s", rc.Action, rc.BundleID, rc.Stage, rc.Result)
			if rc.Version > 0 {
				fmt.Fprintf(w, " (version %d", rc.Version)
				if rc.KeyID != "" {
					fmt.Fprintf(w, ", key %s", rc.KeyID)
				}
				fmt.Fprint(w, ")")
			}
			fmt.Fprintln(w)
			if len(rc.Atespaces) > 0 {
				fmt.Fprintf(w, "atespaces: %s\n", strings.Join(rc.Atespaces, ", "))
			}
		}
	}
	if err != nil {
		err = withExitCode(err, 2)
		silenceJSONReportedError(cmd, asJSON, err)
	}
	return err
}

func printSubstrateBundleStatus(w io.Writer, s *bundle.Status) {
	names := make([]string, 0, len(s.Stages))
	for n := range s.Stages {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Fprintln(w, "No bundle is applied: every atespace uses config.yaml.")
	}
	for _, n := range names {
		st := s.Stages[n]
		fmt.Fprintf(w, "stage %s (%s), floor %d\n", n, strings.Join(st.Atespaces, ", "), st.Floor)
		for _, r := range []struct {
			what string
			rec  *bundle.Record
		}{{"active", st.Active}, {"previous", st.Previous}} {
			if r.rec != nil {
				fmt.Fprintf(w, "  %-8s %s version %d key %s applied %s by %s\n", r.what, r.rec.BundleID, r.rec.Version, r.rec.KeyID,
					r.rec.AppliedAt.Format("2006-01-02T15:04:05Z"), r.rec.Source)
			}
		}
	}
	for _, p := range s.Problems {
		fmt.Fprintf(w, "PROBLEM stage %s: %s (its atespaces use config.yaml)\n", p.Stage, p.Error)
	}
	if s.AnchorsError != "" {
		fmt.Fprintf(w, "anchors: %s\n", s.AnchorsError)
	}
	for _, r := range s.Receipts {
		line := fmt.Sprintf("%s %s %s stage %s %s v%d %s", r.Time.Format("2006-01-02T15:04:05Z"), r.Source, r.Action, r.Stage, r.BundleID, r.Version, r.Result)
		if r.Code != "" {
			line += " " + r.Code
		}
		fmt.Fprintln(w, line)
	}
}

func runSubstrateBundleTest(cmd *cobra.Command, f *substrateBundleFlags) error {
	cfg, err := f.loadConfig()
	if err != nil {
		return err
	}
	archive, err := readSubstrateBundleArchive(cmd, f.bundle)
	if err != nil {
		return err
	}
	anchors, err := f.anchorsLoader(cfg)()
	if err != nil {
		return withExitCode(err, 2)
	}
	v, err := bundle.Verify(archive, anchors, cfg, time.Now().UTC(), bundle.Check{Reactivate: true})
	if err != nil {
		return withExitCode(err, 2)
	}
	eff := v.Policy.Overlay(cfg)
	reg := controller.Registration{Atespace: f.atespace, Template: f.template, Workload: f.workload, Source: controller.SourceAtespace}
	launcher := controller.LauncherSet(eff)[f.atespace]
	if launcher {
		reg.Source = controller.SourceLauncher
	}
	res, err := (&controller.ConfigResolver{Config: eff}).Resolve(reg, launcher)
	if err != nil {
		return err
	}
	out := map[string]any{"bundle_id": v.Manifest.BundleID, "version": v.Manifest.Version, "key_id": v.KeyID,
		"atespace": f.atespace, "managed": res.Managed, "warnings": res.Warnings}
	if res.Managed {
		out["profile"], out["egress_block"], out["egress_allow_only"], out["refuse"] = res.Profile.Name, res.Profile.Block, res.Profile.AllowOnly, res.Refuse
		if res.Refuse == "" {
			r, rerr := render.EgressPolicy(render.Input{Settings: controller.SettingsFromConfig(eff), Profile: res.Profile, Secrets: controller.SecretsFromConfig(eff)})
			if rerr != nil {
				return rerr
			}
			var hosts []string
			for _, rule := range r.Policy.GetRules() {
				switch {
				case rule.GetHttps() != nil:
					hosts = append(hosts, rule.GetHttps().GetHostnames()...)
				case rule.GetHttp() != nil:
					hosts = append(hosts, rule.GetHttp().GetHostnames()...)
				case rule.GetTlsPassthrough() != nil:
					hosts = append(hosts, rule.GetTlsPassthrough().GetHostnames()...)
				}
			}
			drops := make([]string, 0, len(r.Dropped))
			for _, d := range r.Dropped {
				drops = append(drops, d.Host+d.Secret+" "+d.Reason)
			}
			out["egress_hosts"], out["dropped"] = hosts, drops
		}
	}
	if f.json {
		return writeSubstrateBundleJSON(cmd.OutOrStdout(), out)
	}
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "bundle %s version %d verifies (key %s)\n", v.Manifest.BundleID, v.Manifest.Version, v.KeyID)
	if !res.Managed {
		fmt.Fprintf(w, "atespace %s: not managed by this bundle or config.yaml (no policy is written)\n", f.atespace)
		return nil
	}
	fmt.Fprintf(w, "atespace %s: profile %s\n", f.atespace, res.Profile.Name)
	if res.Refuse != "" {
		fmt.Fprintf(w, "refused: %s\n", res.Refuse)
		return nil
	}
	if hosts, ok := out["egress_hosts"].([]string); ok {
		fmt.Fprintf(w, "egress: %s\n", strings.Join(hosts, ", "))
	}
	return nil
}

// substrateProfileResolver is the controller's profile resolver: config.yaml
// alone, or in bundle mode the bundle resolver kept current by a manager
// (started here; it ends with ctx). The first refresh must succeed, so the
// controller never writes a config.yaml-only policy for an atespace a
// bundle covers.
func substrateProfileResolver(ctx context.Context, cfg *config.Config, sink controller.Sink) (controller.ProfileResolver, error) {
	b := cfg.Substrate.Bundles
	if !b.Enabled {
		return &controller.ConfigResolver{Config: cfg}, nil
	}
	ns := os.Getenv("POD_NAMESPACE")
	cms, err := bundle.NewInClusterKube(ns)
	if err != nil {
		return nil, fmt.Errorf("substrate.bundles: %w", err)
	}
	path := b.EffectiveAnchorsFile()
	store := &bundle.Store{CM: cms, Base: cfg, Anchors: func() (*eb.Anchors, error) { return bundle.LoadAnchorsFile(path) }}
	res := bundle.NewResolver(cfg)
	res.Managed = managed.IsManagedEnterprise(cfg.DeploymentMode)
	m := &bundle.Manager{Store: store, Resolver: res, Inbox: b.EffectiveInbox(), Interval: b.EffectiveRefreshInterval(), Sink: sink}
	if err := m.Start(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, fmt.Errorf("substrate.bundles: %w", err)
	}
	return res, nil
}
