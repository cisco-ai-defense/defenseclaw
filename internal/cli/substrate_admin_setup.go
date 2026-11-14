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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// Capabilities a caller may declare with --capability.
const (
	substrateCapBodyMode      = "body-mode"
	substrateCapRouteTimeouts = "route-timeouts"
)

type substrateSetupOptions struct {
	out          substrateOutput
	installFile  string
	namespace    string
	calloutPort  int
	issuer       string
	keysURL      string
	kubeconfig   string
	kubeContext  string
	capabilities []string
	remove       bool
	printPolicy  bool
	plan         string
	dryRun       bool
	yes          bool
}

// substrateSetupResult is `substrate setup --json`.
type substrateSetupResult struct {
	InstallFile string         `json:"install_file,omitempty"`
	Action      string         `json:"action"`
	DryRun      bool           `json:"dry_run"`
	Changes     []setup.Change `json:"changes"`
	Notes       []string       `json:"notes"`
	// Written is the file that now holds the new document ("" when nothing
	// was written); Backup the copy of the original kept when it was replaced.
	Written string `json:"written,omitempty"`
	Backup  string `json:"backup,omitempty"`
	// AccessPolicies is the --print-access-policies text.
	AccessPolicies string `json:"access_policies,omitempty"`
}

func newSubstrateSetupCmd() *cobra.Command {
	o := &substrateSetupOptions{}
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Add DefenseClaw's settings to the SubstrateInstall file (administrators)",
		Long: `Reads the SubstrateInstall document you give to ate-setup and adds the settings DefenseClaw needs: the egress
callout, the router client the gateway attaches launchers through, and, only when you say your Substrate build has them,
the callout body opt-in and the long-stream timeouts. It refuses when Substrate already sends egress to another callout,
and says what to do. Nothing here changes the cluster. With --issuer it reads, with kubectl when it can, the key set the
gateway verifies actor tokens with (--keys-url, the idp Service by default) and warns when it does not answer.

The result is written next to the file as FILE.new (mode 0600) for you to read. With --yes it replaces the file and keeps
the old one as FILE.bak. With --dry-run it only shows the changes. With --remove it takes DefenseClaw's settings out again.

With --print-access-policies and --plan FILE it prints the access policies the install would write, as commands and
manifests a global owner can apply, and reads no install file.

Next: run ate-setup deploy with the new file, then install the chart with helm install.`,
		Example: "defenseclaw substrate setup --install-file install.yaml --namespace defenseclaw --dry-run\n" +
			"defenseclaw substrate setup --install-file install.yaml --capability route-timeouts --yes\n" +
			"defenseclaw substrate setup --print-access-policies --plan plan.json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runSubstrateSetup(cmd, o) },
	}
	o.out.add(cmd)
	f := cmd.Flags()
	f.StringVar(&o.installFile, "install-file", "", "the SubstrateInstall document ate-setup reads")
	f.StringVar(&o.namespace, "namespace", "defenseclaw", "the namespace DefenseClaw is installed in")
	f.IntVar(&o.calloutPort, "callout-port", 9443, "the port of the DefenseClaw callout Service")
	f.StringVar(&o.issuer, "issuer", "", "this cluster's actor token issuer (each cluster needs its own); empty leaves it alone")
	f.StringVar(&o.keysURL, "keys-url", (config.SubstrateConfig{}).EffectiveKeysURL(), "the key set the gateway verifies actor tokens with (substrate.identity.keys_url), checked with --issuer")
	f.StringVar(&o.kubeconfig, "kubeconfig", "", "kubectl configuration file for the --issuer check (default: kubectl's own)")
	f.StringVar(&o.kubeContext, "kube-context", "", "kubectl context for the --issuer check")
	f.StringSliceVar(&o.capabilities, "capability", nil, "a setting your Substrate build has: body-mode or route-timeouts (repeatable; off by default)")
	f.BoolVar(&o.remove, "remove", false, "take DefenseClaw's settings out of the file")
	f.BoolVar(&o.printPolicy, "print-access-policies", false, "print the access policies for --plan and stop")
	f.StringVar(&o.plan, "plan", "", "the chart's plan.json (a file, or env:NAME), for --print-access-policies")
	f.BoolVar(&o.dryRun, "dry-run", false, "show the changes and write nothing")
	f.BoolVarP(&o.yes, "yes", "y", false, "replace the install file (the old one is kept as FILE.bak)")
	return cmd
}

func substrateCapabilities(values []string) (setup.Capabilities, bool, error) {
	caps := setup.Capabilities{Settings: map[string]bool{}}
	bodyMode := false
	for _, v := range values {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case substrateCapBodyMode:
			bodyMode = true
			caps.Settings[setup.KeyExtprocBodyOptIn] = true
			caps.Settings[setup.KeyExtprocTimeout] = true
		case substrateCapRouteTimeouts:
			caps.Settings[setup.KeyRouteTimeout] = true
		default:
			return caps, false, withExitCode(fmt.Errorf("--capability %q is not known; use %s or %s", v, substrateCapBodyMode, substrateCapRouteTimeouts), 2)
		}
	}
	return caps, bodyMode, nil
}

func runSubstrateSetup(cmd *cobra.Command, o *substrateSetupOptions) error {
	asJSON, err := o.out.wantJSON()
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()

	if o.printPolicy {
		if o.plan == "" {
			return withExitCode(errors.New("--print-access-policies needs --plan FILE (the chart's plan.json)"), 2)
		}
		plan, err := setup.LoadPlan(o.plan)
		if err != nil {
			return withExitCode(err, 2)
		}
		text, err := setup.PrintAccessPolicies(plan)
		if err != nil {
			return err
		}
		if asJSON {
			return writeSubstrateJSON(w, substrateSetupResult{Action: "print-access-policies", Changes: []setup.Change{}, Notes: []string{}, AccessPolicies: text})
		}
		_, err = io.WriteString(w, text)
		return err
	}

	if o.installFile == "" {
		return withExitCode(errors.New("give the SubstrateInstall document with --install-file FILE"), 2)
	}
	caps, bodyMode, err := substrateCapabilities(o.capabilities)
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(o.installFile)
	isNew := false
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist) && !o.remove:
		existing, isNew = nil, true
	case errors.Is(err, os.ErrNotExist):
		return withExitCode(fmt.Errorf("the install file %s does not exist, so there is nothing to remove", o.installFile), 2)
	default:
		return withExitCode(fmt.Errorf("the install file cannot be read: %w", err), 2)
	}

	opts := setup.OverlayOptions{
		Namespace:      o.namespace,
		CalloutPort:    o.calloutPort,
		Issuer:         strings.TrimSpace(o.issuer),
		BodyInspection: bodyMode,
		Capabilities:   caps,
	}
	action := "setup"
	var newDoc []byte
	var report setup.OverlayReport
	if o.remove {
		action = "remove"
		newDoc, report, err = setup.RemoveOverlay(existing, opts)
	} else {
		newDoc, report, err = setup.RenderOverlay(existing, opts)
	}
	if err != nil {
		var taken *setup.ErrCalloutTaken
		switch {
		case errors.As(err, &taken):
			return withExitCode(fmt.Errorf("not changed. %w", err), substrateExitRefused)
		case errors.Is(err, setup.ErrDataplane):
			return withExitCode(fmt.Errorf("not changed. %w; change the dataplane or run without the DefenseClaw egress callout (substrate.extproc.enabled: false)", err), substrateExitRefused)
		}
		return withExitCode(err, 2)
	}

	res := substrateSetupResult{InstallFile: o.installFile, Action: action, DryRun: o.dryRun, Changes: report.Changes, Notes: report.Notes}
	if res.Changes == nil {
		res.Changes = []setup.Change{}
	}
	if o.issuer != "" && !o.remove {
		res.Notes = append(res.Notes, substrateSetupKeysNote(cmd.Context(), o))
	}
	if res.Notes == nil {
		res.Notes = []string{}
	}
	if len(report.Changes) > 0 && !o.dryRun {
		target := o.installFile + ".new"
		if o.yes {
			target = o.installFile
			if !isNew {
				res.Backup = o.installFile + ".bak"
				if err := writeSubstrateFile0600(res.Backup, existing); err != nil {
					return fmt.Errorf("the backup cannot be written: %w", err)
				}
			}
		}
		if err := writeSubstrateFile0600(target, newDoc); err != nil {
			return fmt.Errorf("the new document cannot be written: %w", err)
		}
		res.Written = target
	}

	if asJSON {
		return writeSubstrateJSON(w, res)
	}
	printSubstrateSetup(w, res, isNew, o)
	return nil
}

// substrateSetupKeysNote says whether the keys URL answers (GAP-0194): the
// gateway compares iss with the issuer as a string and reads the keys from
// the keys URL, never from the issuer's host, so a unique issuer works only
// when that URL answers. The idp Service does not move with the issuer, so
// it can be read before ate-setup deploy.
func substrateSetupKeysNote(parent context.Context, o *substrateSetupOptions) string {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	same := "Set the same issuer in substrate.identity.issuer (chart config.substrate.identity.issuer)."
	kf := &substrateClusterFlags{kubeconfig: o.kubeconfig, kubeContext: o.kubeContext}
	if _, err := substrateKubectl(ctx, kf, "config", "current-context"); err != nil {
		return fmt.Sprintf("The keys URL %s was not checked (%s). %s After the install, defenseclaw substrate verify checks it.",
			o.keysURL, firstLineOf(err.Error()), same)
	}
	var obs fleet.Observed
	readActorKeys(ctx, kf, &obs, o.keysURL)
	switch {
	case obs.Keys == nil:
		return fmt.Sprintf("The keys URL %s was not checked (%s). %s After the install, defenseclaw substrate verify checks it.",
			o.keysURL, obs.KeysNote, same)
	case *obs.Keys == 0:
		return fmt.Sprintf("WARNING: the keys URL %s does not answer (%s). The gateway reads the actor token keys there, not from "+
			"the issuer's host, so with this issuer it would refuse every actor token. Set substrate.identity.keys_url (chart "+
			"value substrate.actorKeys.url) to the idp Service key set, then run this again.", o.keysURL, obs.KeysErr)
	}
	return fmt.Sprintf("The keys URL %s answers (%d keys): the gateway verifies tokens of this issuer with them, so the issuer "+
		"need not resolve. %s", o.keysURL, *obs.Keys, same)
}

func printSubstrateSetup(w io.Writer, res substrateSetupResult, isNew bool, o *substrateSetupOptions) {
	if isNew {
		fmt.Fprintf(w, "%s does not exist; starting a new SubstrateInstall document.\n", res.InstallFile)
	}
	if len(res.Changes) == 0 {
		if res.Action == "remove" {
			fmt.Fprintln(w, "Nothing to remove: the file has none of DefenseClaw's settings.")
		} else {
			fmt.Fprintln(w, "Nothing to change: the file already has DefenseClaw's settings.")
		}
	} else {
		fmt.Fprintf(w, "Changes to %s:\n", res.InstallFile)
		for _, c := range res.Changes {
			fmt.Fprintf(w, "  %s\n", substrateChangeWords(c))
		}
	}
	if len(res.Notes) > 0 {
		fmt.Fprintln(w, "Please note:")
		for _, n := range res.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
	switch {
	case res.Written != "" && res.Backup != "":
		fmt.Fprintf(w, "Replaced %s; the old file is kept as %s.\n", res.Written, res.Backup)
	case res.Written != "":
		fmt.Fprintf(w, "Wrote %s (mode 0600). Read it, then replace %s with it, or run this again with --yes.\n", res.Written, filepath.Base(res.InstallFile))
	case res.DryRun:
		fmt.Fprintln(w, "Dry run: nothing was written.")
	}
	if len(res.Changes) == 0 && res.Written == "" {
		return
	}
	file := res.InstallFile
	if res.Written != "" {
		file = res.Written
	}
	if res.Action == "remove" {
		fmt.Fprintf(w, "Next: run ate-setup deploy --config %s, then remove the chart with helm uninstall.\n", file)
		return
	}
	fmt.Fprintf(w, "Next: run ate-setup deploy --config %s, then install DefenseClaw with helm install (namespace %s).\n", file, o.namespace)
}

func substrateChangeWords(c setup.Change) string {
	switch {
	case c.Old == "" && c.New != "":
		return fmt.Sprintf("set %s to %s", c.Key, c.New)
	case c.New == "":
		return fmt.Sprintf("removed %s (it was %s)", c.Key, c.Old)
	}
	return fmt.Sprintf("changed %s from %s to %s", c.Key, c.Old, c.New)
}

// writeSubstrateFile0600 writes data to path through a temporary file in the
// same folder, so the file is never half written and is never wider than 0600.
func writeSubstrateFile0600(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := os.Chmod(name, 0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
