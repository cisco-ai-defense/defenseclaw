// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// The hook Jobs of the defenseclaw-substrate Helm chart run these steps in
// the gateway image (deploy/helm/defenseclaw-substrate/templates/hooks). Not
// for people: hidden, and every flag comes from the chart.
var (
	substrateChartPlan       string
	substrateChartConfig     string
	substrateChartOwnerToken string
	substrateChartAPIToken   string
	substrateChartAPICA      string
	substrateChartKubeDir    string
)

var substrateChartCmd = &cobra.Command{
	Use:          "substrate-chart",
	Short:        "Steps of the defenseclaw-substrate Helm chart hooks",
	Hidden:       true,
	SilenceUsage: true,
	Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
}

func substrateChartStep(name, short string, run func(ctx context.Context, plan setup.ChartPlan) (setup.StepReport, error)) *cobra.Command {
	return &cobra.Command{
		Use:          name,
		Short:        short,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := setup.LoadPlan(substrateChartPlan)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), setup.StepTimeout)
			defer cancel()
			report, runErr := run(ctx, plan)
			// The Job log is the record: the report goes out on success and
			// on failure, as one JSON line, then each note as plain text.
			enc := json.NewEncoder(cmd.OutOrStdout())
			_ = enc.Encode(report)
			for _, n := range report.Notes {
				fmt.Fprintln(cmd.OutOrStdout(), n)
			}
			return runErr
		},
	}
}

func substrateChartKube() (*setup.Kube, error) { return setup.NewInClusterKube(substrateChartKubeDir) }

func substrateChartAPI(plan setup.ChartPlan, token string) (*setup.API, error) {
	return setup.NewAPI(setup.APIOptions{Address: plan.API.Address, ServerName: plan.API.Audience,
		CAFile: substrateChartAPICA, TokenFile: token})
}

// substrateChartValidateConfig validates the next release's config.yaml as
// `config validate` does.
func substrateChartValidateConfig(raw []byte) error {
	dir, err := os.MkdirTemp("", "defenseclaw-chart-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	loaded, err := checkConfigV8Candidate(path, dir)
	if err != nil {
		return err
	}
	if _, err := loaded.runtime.DeriveGuardrailProfiles(); err != nil {
		return err
	}
	return nil
}

func init() {
	pf := substrateChartCmd.PersistentFlags()
	pf.StringVar(&substrateChartPlan, "plan", "env:DEFENSECLAW_CHART_PLAN", "the chart plan: a file, or env:NAME")
	pf.StringVar(&substrateChartConfig, "config", "env:DEFENSECLAW_CHART_CONFIG", "the release's config.yaml: a file, or env:NAME")
	pf.StringVar(&substrateChartOwnerToken, "owner-token", "", "a Substrate global owner's token (bootstrap)")
	pf.StringVar(&substrateChartAPIToken, "api-token", "/var/run/ate/token", "this pod's ate-api token")
	pf.StringVar(&substrateChartAPICA, "api-ca", "/var/run/ate/ca.crt", "the ate-api serving CA")
	pf.StringVar(&substrateChartKubeDir, "kube-dir", setup.InClusterDir, "the projected Kubernetes API token and CA")

	substrateChartCmd.AddCommand(
		substrateChartStep("bootstrap", "Write DefenseClaw's OpenFGA grants and the credential provider grant",
			func(ctx context.Context, plan setup.ChartPlan) (setup.StepReport, error) {
				if substrateChartOwnerToken == "" {
					return setup.StepReport{Step: "bootstrap"}, fmt.Errorf("--owner-token is required")
				}
				if _, err := os.Stat(substrateChartOwnerToken); errors.Is(err, os.ErrNotExist) {
					// The first bootstrap deleted the owner token Secret; an
					// upgrade without a new one keeps the grants as they are.
					return setup.StepReport{Step: "bootstrap", Notes: []string{"no owner token Secret: the access policies " +
						"were not touched. Doctor checks them; create the Secret again to rewrite them."}}, nil
				}
				kube, err := substrateChartKube()
				if err != nil {
					return setup.StepReport{Step: "bootstrap"}, err
				}
				api, err := substrateChartAPI(plan, substrateChartOwnerToken)
				if err != nil {
					return setup.StepReport{Step: "bootstrap"}, err
				}
				defer api.Close()
				return setup.Bootstrap(ctx, plan, api, kube)
			}),
		substrateChartStep("pre-upgrade", "Check the release about to roll out (config, skew, store schema)",
			func(ctx context.Context, plan setup.ChartPlan) (setup.StepReport, error) {
				raw, err := setup.ReadSource(substrateChartConfig)
				if err != nil {
					return setup.StepReport{Step: "pre-upgrade"}, err
				}
				kube, err := substrateChartKube()
				if err != nil {
					return setup.StepReport{Step: "pre-upgrade"}, err
				}
				return setup.PreUpgrade(ctx, plan, raw, substrateChartValidateConfig, kube)
			}),
		substrateChartStep("pre-rollback", "Refuse a rollback across a store schema change",
			func(ctx context.Context, plan setup.ChartPlan) (setup.StepReport, error) {
				kube, err := substrateChartKube()
				if err != nil {
					return setup.StepReport{Step: "pre-rollback"}, err
				}
				return setup.PreRollback(ctx, plan, kube)
			}),
		substrateChartStep("chain-key", "Create the shared chain key Secret when it does not exist",
			func(ctx context.Context, plan setup.ChartPlan) (setup.StepReport, error) {
				kube, err := substrateChartKube()
				if err != nil {
					return setup.StepReport{Step: "chain-key"}, err
				}
				return setup.EnsureChainKey(ctx, plan, kube)
			}),
		substrateChartStep("pre-delete", "Remove DefenseClaw-written egress policies and grants before uninstall",
			func(ctx context.Context, plan setup.ChartPlan) (setup.StepReport, error) {
				kube, err := substrateChartKube()
				if err != nil {
					return setup.StepReport{Step: "pre-delete"}, err
				}
				api, err := substrateChartAPI(plan, substrateChartAPIToken)
				if err != nil {
					return setup.StepReport{Step: "pre-delete"}, err
				}
				defer api.Close()
				return setup.PreDelete(ctx, plan, api, kube)
			}),
	)
	rootCmd.AddCommand(substrateChartCmd)
}
