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
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

// The status of one doctor check.
const (
	doctorOK   = "ok"
	doctorWarn = "warn"
	doctorFail = "fail"
	doctorSkip = "skip"
)

// substrateCheck is one line of `substrate doctor`.
type substrateCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Fix     string `json:"fix,omitempty"`
}

// substrateDoctorReport is `substrate doctor --json`.
type substrateDoctorReport struct {
	OK       bool             `json:"ok"`
	Context  string           `json:"context,omitempty"`
	Problems int              `json:"problems"`
	Checks   []substrateCheck `json:"checks"`
	// componentsChecked is true when the cluster.components row ran
	// (--install-file): only then does the last line say "ready for agents".
	componentsChecked bool
}

// Seams for tests.
var (
	// substrateDoctorStore opens the token store and says which kind it is.
	substrateDoctorStore = func() (string, error) {
		st, err := auth.OpenStore()
		if err != nil {
			return "", err
		}
		var v any = st
		if d, ok := v.(interface{ Describe() string }); ok {
			return d.Describe(), nil
		}
		return "", nil
	}
	// substrateDoctorDialWait bounds one connection attempt.
	substrateDoctorDialWait = 8 * time.Second
	// substrateDoctorAlertWait is how long the agent entrance probe waits
	// for a TLS alert after the handshake (a refused client certificate
	// shows only then, in TLS 1.3).
	substrateDoctorAlertWait = 300 * time.Millisecond
)

const substrateLoginFix = "defenseclaw substrate login --admin-url https://HOST:PORT (your administrator has the address)"

func newSubstrateDoctorCmd() *cobra.Command {
	var (
		out     substrateOutput
		com     substrateCommon
		kf      substrateClusterFlags
		cluster bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that this computer can run agents in the cluster",
		Long: `Checks, from this computer, everything a run needs: the cluster is set up here, its admin address answers
over TLS, you are signed in and the cluster accepts it, the sign-in server matches, attach through the gateway works and
you have what it asks for, your sign-in can be kept safely, the cluster can check ended sign-ins (for administrators: whether
it ends them at all), and (for administrators, when the cluster uses signed policy bundles) every stage's bundle still verifies. Nothing needs to be installed here, and nothing in the
cluster changes.

Administrators add the cluster's own checks (version, issuer, snapshot bucket, access policies, egress callout, router
clients, routes, API access) with --install-file, the SubstrateInstall file you gave ate-setup: they are read with
kubectl and your own cloud credentials, the same as defenseclaw substrate verify. --cluster without it says what is missing.

The last line is "ready for agents" when no check failed and the cluster components (gateway, leader, controller,
callout) were checked, which needs --install-file. Without it the last line says that the checks on this computer pass
and that the cluster components were not checked. Otherwise it is "not ready" and each failed check says how to fix
it, and the exit code is 1.`,
		Example: "defenseclaw substrate doctor\ndefenseclaw substrate doctor --cluster --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSubstrateDoctor(cmd, &out, &com, &kf, cluster)
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().BoolVar(&cluster, "cluster", false, "also run the cluster checks (administrators); say why they were skipped when they were")
	kf.addKube(cmd)
	return cmd
}

type doctorRun struct {
	checks []substrateCheck
}

func (d *doctorRun) add(id, status, summary, fix string) {
	d.checks = append(d.checks, substrateCheck{ID: id, Status: status, Summary: summary, Fix: fix})
}

func runSubstrateDoctor(cmd *cobra.Command, out *substrateOutput, com *substrateCommon, kf *substrateClusterFlags, clusterFlag bool) error {
	asJSON, err := out.wantJSON()
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()

	d := &doctorRun{}
	storeKind, storeErr := substrateDoctorStore()
	s, openErr := substrateOpen(cmd, com)

	// 1. The context.
	switch {
	case openErr == nil:
		d.add("context", doctorOK, "using "+s.Name+" ("+s.Ctx.AdminURL+")", "")
	case storeErr != nil:
		d.add("context", doctorSkip, "not checked: the token store cannot be used (see token_store)", "")
	default:
		d.add("context", doctorFail, doctorFirstLine(openErr), substrateLoginFix)
	}

	// 2. The token store.
	if storeErr != nil {
		d.add("token_store", doctorFail, doctorFirstLine(storeErr), "set DEFENSECLAW_SUBSTRATE_TOKEN_STORE=file to keep the sign-in in a 0600 file (CI and headless Linux), or fix the system keychain")
	} else if storeKind != "" {
		d.add("token_store", doctorOK, "your sign-in is kept in "+storeKind, "")
	} else {
		d.add("token_store", doctorOK, "your sign-in can be kept safely", "")
	}

	// 3. The optional tools the secret sources run (gh, op, security).
	doctorSecretSources(d)
	// 4. The desktop notifier `watch` uses (off by default; never a failure).
	d.checks = append(d.checks, substrateNotifierCheck())

	name := ""
	if openErr != nil {
		for _, id := range []string{"admin_address", "sign_in", "sign_in_server", "attach", "egress_callout"} {
			d.add(id, doctorSkip, "needs a configured cluster", "")
		}
	} else {
		name = s.Name
		doctorCluster(ctx, d, s)
		if c, ok := doctorPolicyConflicts(ctx, s, clusterFlag); ok {
			d.checks = append(d.checks, c)
		}
	}

	switch {
	case kf.installFile != "":
		var groups []string
		if openErr == nil && s.Source != nil {
			// The signed-in token says which form of groups the sign-in
			// server sends (GAP-0568).
			if tok, err := s.Source.Current(ctx); err == nil {
				groups = tok.Groups
			}
		}
		d.checks = append(d.checks, doctorKubeChecks(ctx, kf, groups...)...)
	case clusterFlag:
		d.add("cluster", doctorSkip, "the cluster checks read the cluster with kubectl: give --install-file FILE (the "+
			"SubstrateInstall file you gave ate-setup)", "")
	}

	rep := substrateDoctorReport{Context: name, Checks: d.checks}
	for _, c := range d.checks {
		if c.Status == doctorFail {
			rep.Problems++
		}
		if c.ID == doctorComponentsID {
			rep.componentsChecked = true
		}
	}
	rep.OK = rep.Problems == 0

	if asJSON {
		if err := writeSubstrateJSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
	} else {
		printSubstrateDoctor(cmd.OutOrStdout(), rep)
	}
	if !rep.OK {
		// The report already says what failed.
		cmd.SilenceErrors = true
		return cliusage.WithExitCode(fmt.Errorf("%d check(s) failed", rep.Problems), 1)
	}
	return nil
}

func printSubstrateDoctor(w io.Writer, rep substrateDoctorReport) {
	if rep.Context != "" {
		fmt.Fprintf(w, "Checking cluster %s\n", rep.Context)
	}
	width := 0
	for _, c := range rep.Checks {
		width = max(width, len(c.ID))
	}
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "  %-4s  %-*s  %s\n", c.Status, width, c.ID, safetext.Line(c.Summary))
		if c.Status == doctorWarn && c.Fix != "" {
			fmt.Fprintf(w, "        %-*s  to fix: %s\n", width, "", safetext.Line(c.Fix))
		}
	}
	if rep.OK {
		if rep.componentsChecked {
			fmt.Fprintln(w, "ready for agents")
			return
		}
		// A user's doctor cannot read the cluster's components: say what
		// it checked instead of "ready for agents" (GAP-0593).
		fmt.Fprintln(w, doctorUserSummary)
		return
	}
	fmt.Fprintf(w, "not ready: %d problem(s)\n", rep.Problems)
	for _, c := range rep.Checks {
		if c.Status != doctorFail {
			continue
		}
		fix := c.Fix
		if fix == "" {
			fix = "read the line above and correct it"
		}
		fmt.Fprintf(w, "  %s: %s\n", c.ID, fix)
	}
}

// doctorPolicyConflicts names the agents in policy_conflict: repeated foreign
// changes to their network policy put them on the DefenseClaw rule only
// (deny-only) until an administrator resets it (GAP-0398).
// It reads your agents, every agent with --cluster (administrators). An
// agent in conflict fails the cluster check and warns a person. ok is false
// when the agents could not be read: the sign_in row already says why.
func doctorPolicyConflicts(ctx context.Context, s *substrateSession, cluster bool) (substrateCheck, bool) {
	const id = "policy_conflict"
	// The gateway narrows a person's all=1 to their own agents: only an
	// answer that says it is everyone's is counted as the cluster's.
	notAdmin := false
	var actors []api.Actor
	var err error
	if cluster {
		actors, err = s.Client.ListEveryone(ctx)
		if errors.Is(err, api.ErrNotAdministrator) {
			notAdmin, cluster = true, false
			actors, err = s.Client.List(ctx, api.ListOptions{})
		}
	} else {
		actors, err = s.Client.List(ctx, api.ListOptions{})
	}
	if err != nil {
		return substrateCheck{}, false
	}
	var names, fixes []string
	for _, a := range actors {
		if a.Deleted || a.PolicyConflict == nil {
			continue
		}
		ref := a.Atespace + "/" + a.Name
		names = append(names, fmt.Sprintf("%s (%d foreign change(s) to its network policy reverted)", ref, a.PolicyConflict.Reverts))
		fixes = append(fixes, "defenseclaw substrate policy reset "+ref)
	}
	whose := "of yours"
	if cluster {
		whose = "in the cluster"
	}
	if len(names) == 0 {
		if notAdmin {
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "no agent of yours is in policy_conflict; the cluster's " +
				"agents were not read: you are not signed in as an administrator",
				Fix: "sign in as an administrator (defenseclaw substrate login) and run doctor --cluster again"}, true
		}
		return substrateCheck{ID: id, Status: doctorOK, Summary: "no agent " + whose + " is in policy_conflict"}, true
	}
	status := doctorWarn
	if cluster {
		status = doctorFail
	}
	summary := fmt.Sprintf("%d agent(s) %s in policy_conflict, so they reach only DefenseClaw: %s", len(names), whose, strings.Join(names, "; "))
	if notAdmin {
		summary += "; the cluster's agents were not read: you are not signed in as an administrator"
	}
	return substrateCheck{ID: id, Status: status, Summary: summary,
		Fix: "stop whatever else writes the agent's egress policy, then an administrator runs: " + strings.Join(fixes, "; ")}, true
}

// doctorCluster runs the checks that need the cluster and the context.
func doctorCluster(ctx context.Context, d *doctorRun, s *substrateSession) {
	c := s.Ctx

	// 3. The admin address answers over TLS.
	adminOK := false
	if info, err := probeTLS(ctx, c.AdminURL, c.AdminCAFile, nil, false); err != nil {
		d.add("admin_address", doctorFail, probeMessage("the admin address", c.AdminURL, err), probeFix(err, "--admin-url", "--admin-ca-file"))
	} else {
		adminOK = true
		d.add("admin_address", doctorOK, "the admin address answers ("+info.Version+")", "")
	}

	// 4. Signed in, and the cluster accepts the token.
	var mine []api.Actor
	signedIn, listStale := false, false
	if !adminOK {
		d.add("sign_in", doctorSkip, "not checked: the admin address does not answer", "")
	} else {
		actors, err := s.Client.List(ctx, api.ListOptions{})
		switch {
		case err == nil:
			signedIn = true
			for _, a := range actors {
				if !a.Deleted {
					mine = append(mine, a)
				}
			}
			d.add("sign_in", doctorOK, fmt.Sprintf("signed in; the cluster accepts the token (%d agent(s) of yours)", len(mine)), "")
		case errors.Is(err, auth.ErrNotSignedIn):
			d.add("sign_in", doctorFail, "you are not signed in", "defenseclaw substrate login")
		default:
			if e, ok := api.AsError(err); ok {
				switch {
				case e.Status == http.StatusServiceUnavailable && e.Reason == revocation.ReasonUnavailable:
					// B5.1: the signin_revocation row says why.
					listStale = true
					d.add("sign_in", doctorFail, "the cluster refused your sign-in because it can't check ended sign-ins right now (see signin_revocation)",
						"run doctor again in a minute; if it stays, ask your administrator")
				case e.Unauthorized():
					d.add("sign_in", doctorFail, "the cluster did not accept your sign-in ("+doctorWord(e.Reason, "token refused")+")", "defenseclaw substrate login")
				case e.NotImplemented():
					signedIn = true
					d.add("sign_in", doctorWarn, "the cluster accepted the token but does not list agents yet", "ask your administrator to upgrade DefenseClaw on the cluster")
				default:
					d.add("sign_in", doctorFail, substrateAPIMessage(e), "ask your administrator, or run doctor again in a minute")
				}
			} else {
				d.add("sign_in", doctorFail, "the cluster could not be asked: "+doctorFirstLine(err), "check the admin address, then run doctor again")
			}
		}
	}

	// 5. The sign-in server.
	d.checks = append(d.checks, doctorSignInServer(ctx, c))

	// 6. Attach through the gateway.
	d.checks = append(d.checks, doctorAttach(ctx, s, mine, signedIn))

	// 7. Ended sign-ins (B5.1).
	if c, ok := doctorSignInRevocation(ctx, s, signedIn, listStale); ok {
		d.checks = append(d.checks, c)
	}

	// 8. Policy bundles (administrators, when the cluster has them on).
	if c, ok := doctorBundles(ctx, s, signedIn); ok {
		d.checks = append(d.checks, c)
	}

	// 8. The egress callout: another one in Substrate's slot turns
	// DefenseClaw's egress checks off (GAP-0497).
	d.checks = append(d.checks, doctorEgressCallout(ctx, s, adminOK))
	// 9. Cluster budgets: the leader, the spend feed and the price table.
	if signedIn {
		u, err := s.Client.Usage(ctx, api.UsageQuery{By: "model", Since: "24h"})
		if c, ok := doctorBudgetsRow(u, err); ok {
			d.checks = append(d.checks, c)
		}
		if err == nil {
			d.checks = append(d.checks, substrateCheck{ID: "usage_person_key", Status: doctorOK, Summary: doctorPersonKeyNotice})
		}
	}
}

// doctorPersonKeyNotice names the one change to how an agent's usage is
// owned: its calls are counted under the person key (issuer and subject), not
// the bare subject, which two sign-in servers can share. Usage rows exported
// before the change keep the old id and are not rewritten (until 1.0.13).
const doctorPersonKeyNotice = "usage of your agents is counted under your person key (issuer and subject), not the bare subject, so " +
	"one subject at two sign-in servers is two people; usage rows exported before this change keep the old id and are not rewritten"

// doctorBudgetsRow is the cluster_budgets row: whether the cluster's leader
// answers usage (the leader), whether every budget has a spend (the feed) and
// whether the calls of the last day had a price (the price table). ok is
// false when the cluster cannot say (an older cluster, no access).
func doctorBudgetsRow(u api.UsageAnswer, err error) (substrateCheck, bool) {
	const id = "cluster_budgets"
	if err != nil {
		e, ok := api.AsError(err)
		if !ok {
			return substrateCheck{}, false
		}
		switch e.Reason {
		case "usage_disabled":
			return substrateCheck{ID: id, Status: doctorSkip, Summary: "usage is turned off on this cluster (substrate.usage.enabled: false), so actor and batch budgets are not counted across its replicas"}, true
		case "usage_unavailable":
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "the cluster's leader did not answer usage, so budget spend cannot be read",
				Fix: "ask your administrator to check the leader pods (kubectl get pods -l app.kubernetes.io/component=leader)"}, true
		}
		return substrateCheck{}, false
	}
	var unpriced int64
	for _, r := range u.Rows {
		if d := r.UsageCalls - r.CostCalls; d > 0 {
			unpriced += d
		}
	}
	unknown := 0
	for _, b := range u.Budgets {
		if b.SpentUSD == nil && !b.Exceeded {
			unknown++
		}
	}
	var problems []string
	if unknown > 0 {
		problems = append(problems, fmt.Sprintf("the spend of %d budget(s) is not known yet (the leader's spend feed has not answered)", unknown))
	}
	if unpriced > 0 {
		problems = append(problems, fmt.Sprintf("%d call(s) in the last day had no known price (the model is not in the price table), so budgets do not count them", unpriced))
	}
	if len(problems) == 0 {
		return substrateCheck{ID: id, Status: doctorOK, Summary: "the leader answers usage, every budget has a spend and the calls of the last day were priced"}, true
	}
	return substrateCheck{ID: id, Status: doctorWarn, Summary: strings.Join(problems, "; "),
		Fix: "ask your administrator to add the model to observability.pricing in the chart values, or to check the leader"}, true
}

const (
	doctorRevocationStaleFix = "run doctor again in a minute; if it stays, ask your administrator to check that the cluster's leader pod " +
		"is running and reachable from the gateway"
	doctorRevocationOldFix = "ask your administrator to upgrade DefenseClaw on the cluster to 1.0.11 or later"
)

// doctorSignInRevocation is the signin_revocation row (B5.1): can the
// cluster end a sign-in, so that signing out (or an administrator's
// revoke) stops a copy of the token? A gateway whose list of ended
// sign-ins is too old refuses every sign-in, its own doctor route
// included, so that case comes from the sign_in answer (listStale).
// Otherwise an administrator gets the gateway's own
// substrate.signin_revocation row; a gateway without that row is older
// than 1.0.11 and does not end sign-ins. A non-administrator gets no row.
func doctorSignInRevocation(ctx context.Context, s *substrateSession, signedIn, listStale bool) (substrateCheck, bool) {
	const id = "signin_revocation"
	stale := substrateCheck{ID: id, Status: doctorFail, Fix: doctorRevocationStaleFix,
		Summary: "the cluster can't read its list of ended sign-ins right now, so it refuses every sign-in until it reads the list again"}
	old := substrateCheck{ID: id, Status: doctorWarn, Fix: doctorRevocationOldFix,
		Summary: "the cluster's gateway does not end sign-ins (it is older than 1.0.11): signing out does not stop a copy of " +
			"your sign-in token, which keeps working until it expires (up to 24 h)"}
	switch {
	case listStale:
		return stale, true
	case !signedIn:
		return substrateCheck{}, false
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rows, err := s.Client.GatewayDoctor(cctx)
	if err != nil {
		if e, ok := api.AsError(err); ok {
			switch {
			case e.Status == http.StatusForbidden:
				return substrateCheck{}, false
			case e.Status == http.StatusNotFound || e.NotImplemented():
				return old, true
			case e.Status == http.StatusServiceUnavailable && e.Reason == revocation.ReasonUnavailable:
				return stale, true
			}
		}
		return substrateCheck{ID: id, Status: doctorWarn, Summary: "whether the cluster ends sign-ins could not be read: " + doctorFirstLine(err),
			Fix: "run doctor again in a minute"}, true
	}
	for _, r := range rows {
		if r.ID != "substrate.signin_revocation" {
			continue
		}
		c := substrateCheck{ID: id, Status: doctorWarn, Summary: "the gateway says: " + safetext.Line(r.Detail), Fix: safetext.Line(r.Fix)}
		switch r.Status {
		case "pass":
			c.Status = doctorOK
		case "fail":
			c.Status = doctorFail
		}
		return c, true
	}
	return old, true
}

const doctorBundleFix = "apply a bundle signed by a key of the bundle-anchors Secret (defenseclaw substrate bundle apply), " +
	"or put the Secret's keys back; defenseclaw substrate bundle status shows each stage"

// doctorBundles is the policy_bundles row (GAP-0429): every stage's active
// bundle verifies now against the anchors the cluster reads. A stage that
// no longer verifies has fallen back to config.yaml (deny-only on a managed
// install), which the controller reports only as an alert event, so the
// row fails. There is no row when the caller is not an administrator, when
// bundles are off or when the cluster predates them.
func doctorBundles(ctx context.Context, s *substrateSession, signedIn bool) (substrateCheck, bool) {
	const id = "policy_bundles"
	if !signedIn {
		return substrateCheck{}, false
	}
	res, err := s.Client.BundleStatus(ctx)
	if err != nil {
		if e, ok := api.AsError(err); ok && (e.Status == http.StatusForbidden || e.Status == http.StatusNotFound || e.NotImplemented()) {
			return substrateCheck{}, false
		}
		return substrateCheck{ID: id, Status: doctorWarn, Summary: "the policy bundle state could not be read: " + doctorFirstLine(err),
			Fix: "run doctor again in a minute; defenseclaw substrate bundle status shows it"}, true
	}
	stages, _ := res["stages"].(map[string]any)
	anchorsErr, _ := res["anchors_error"].(string)
	problems, _ := res["problems"].([]any)
	if len(problems) > 0 {
		names := make([]string, 0, len(problems))
		for _, p := range problems {
			pm, _ := p.(map[string]any)
			stage, _ := pm["stage"].(string)
			code, _ := pm["code"].(string)
			if code = safetext.Line(code); code == "" {
				code = "does not verify"
			}
			names = append(names, safetext.Line(stage)+" ("+code+")")
		}
		return substrateCheck{ID: id, Status: doctorFail, Fix: doctorBundleFix,
			Summary: fmt.Sprintf("%d of %d stage(s) no longer verify, so their atespaces have fallen back to config.yaml (deny-only on a managed install): %s",
				len(problems), len(stages), strings.Join(names, ", "))}, true
	}
	if anchorsErr != "" {
		return substrateCheck{ID: id, Status: doctorWarn, Fix: "create the bundle-anchors Secret before a bundle is applied",
			Summary: "no bundle is applied and the cluster cannot read its bundle trust anchors: " + safetext.Line(anchorsErr)}, true
	}
	if c, ok := doctorBundlesOCI(res); ok {
		return c, true
	}
	if len(stages) == 0 {
		return substrateCheck{ID: id, Status: doctorOK, Summary: "no policy bundle is applied; config.yaml is in force"}, true
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: fmt.Sprintf("the active bundle of each of %d stage(s) verifies", len(stages))}, true
}

// doctorBundlesOCI fails the policy_bundles row when the bundle pulled for an
// OCI stage was refused, and warns while one is not pulled yet (GAP-0437).
func doctorBundlesOCI(res map[string]any) (substrateCheck, bool) {
	const id = "policy_bundles"
	oci, _ := res["oci"].([]any)
	var refused, pending []string
	for _, o := range oci {
		om, _ := o.(map[string]any)
		stage, _ := om["stage"].(string)
		state, _ := om["state"].(string)
		result, _ := om["result"].(string)
		code, _ := om["code"].(string)
		switch {
		case state != "processed":
			pending = append(pending, safetext.Line(stage))
		case result == "refused":
			refused = append(refused, safetext.Line(stage)+" ("+safetext.Line(code)+")")
		}
	}
	if len(refused) > 0 {
		return substrateCheck{ID: id, Status: doctorFail, Fix: "sign the bundle with a key in the bundle anchors, push it and pin the new digest in substrate.bundles.oci.stages",
			Summary: "the bundle pulled from the OCI registry was refused for stage(s) " + strings.Join(refused, ", ") + "; those stages keep their last verified bundle"}, true
	}
	if len(pending) > 0 {
		return substrateCheck{ID: id, Status: doctorWarn, Fix: "check the controller events (sandbox.bundle.*) for the pull error: registry reachable, digest, credentials, CA",
			Summary: "the OCI bundle of stage(s) " + strings.Join(pending, ", ") + " is not pulled yet; the controller retries every refresh"}, true
	}
	return substrateCheck{}, false
}

func doctorSignInServer(ctx context.Context, c auth.Context) substrateCheck {
	const id = "sign_in_server"
	if c.Kube {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "this context signs in with your Kubernetes credentials (no sign-in server)"}
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "this context signs in with a workload token only"}
	}
	cfg, err := substrateTLSConfig(c.IssuerCAFile)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: err.Error(), Fix: "defenseclaw substrate login --issuer-ca-file FILE"}
	}
	hc := &http.Client{
		Timeout:       substrateDoctorDialWait + 2*time.Second,
		Transport:     &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: substrateDoctorDialWait},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	issuer := strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: "the issuer in your context is not a valid URL", Fix: "defenseclaw substrate login --issuer URL"}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: probeMessage("the sign-in server", issuer, &probeFailure{kind: classifyProbe(err), err: err}),
			Fix: probeFix(&probeFailure{kind: classifyProbe(err), err: err}, "--issuer", "--issuer-ca-file")}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return substrateCheck{ID: id, Status: doctorFail, Summary: fmt.Sprintf("the sign-in server answered %d at its discovery address", resp.StatusCode),
			Fix: "check --issuer with your administrator; it is the address that ends before /.well-known"}
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: "the sign-in server's discovery answer is not understood", Fix: "check --issuer with your administrator"}
	}
	if got := strings.TrimRight(doc.Issuer, "/"); got != issuer {
		return substrateCheck{ID: id, Status: doctorFail, Summary: fmt.Sprintf("the sign-in server names itself %q, your context has %q", got, issuer),
			Fix: "defenseclaw substrate login --issuer " + got}
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: "the sign-in server answers and its issuer matches"}
}

func doctorAttach(ctx context.Context, s *substrateSession, mine []api.Actor, signedIn bool) substrateCheck {
	const id = "attach"
	if !signedIn {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "not checked: sign in first"}
	}
	if len(mine) == 0 {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "can be checked once you have an agent; start one with: defenseclaw substrate run claude"}
	}
	// A running agent answers at once; one that is still starting would only
	// show the wait.
	a := mine[0]
	for _, m := range mine {
		if m.State == "running" {
			a = m
			break
		}
	}
	o := attach.Options{
		Target:  attach.Target{Atespace: a.Atespace, Name: a.Name},
		Gateway: attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, Bearer: s.Bearer,
		MaxWait: 5 * time.Second, NoBanner: true, NoAsks: true,
		// The doctor prints its own lines; the wait messages stay out.
		Err: io.Discard,
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := attach.Status(cctx, o); err != nil {
		switch {
		case errors.Is(err, attach.ErrNotOffered):
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "this cluster does not offer attach through the gateway yet", Fix: "ask your administrator to upgrade DefenseClaw on the cluster"}
		case errors.Is(err, attach.ErrAttachOff):
			return substrateCheck{ID: id, Status: doctorFail, Summary: "the cluster gateway has no route to agents (attach is not set up)", Fix: "ask your administrator to give the gateway its router address (the --router-address setting)"}
		case errors.Is(err, attach.ErrNotAllowed), errors.Is(err, attach.ErrNoActor):
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "the cluster would not let you reach " + a.Atespace + "/" + a.Name + ": " + doctorFirstLine(err), Fix: "run doctor again after defenseclaw substrate list shows an agent of yours"}
		case errors.Is(err, attach.ErrNotSignedIn):
			return substrateCheck{ID: id, Status: doctorFail, Summary: "the cluster did not accept your sign-in for attach", Fix: "defenseclaw substrate login"}
		case errors.Is(err, attach.ErrClusterFull), errors.Is(err, attach.ErrStarting):
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "attach is offered; the agent is busy starting or the cluster is full right now"}
		}
		return substrateCheck{ID: id, Status: doctorFail, Summary: "attach through the gateway failed: " + doctorFirstLine(err), Fix: "check the admin address and the cluster's gateway, then run doctor again"}
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: "attach through the gateway works (reached " + a.Atespace + "/" + a.Name + ")"}
}

// doctorConvertFleet turns A8's fleet checks into doctor rows.
func doctorConvertFleet(checks []fleet.Check) []substrateCheck {
	out := make([]substrateCheck, 0, len(checks))
	for _, c := range checks {
		sc := substrateCheck{ID: "cluster." + c.ID, Summary: c.Message}
		switch c.Status {
		case fleet.Pass:
			sc.Status = doctorOK
		case fleet.Warn:
			sc.Status = doctorWarn
		case fleet.Fail:
			sc.Status = doctorFail
		case fleet.Skip:
			sc.Status = doctorSkip
		default:
			sc.Status = doctorWarn
		}
		if sc.Status == doctorWarn || sc.Status == doctorFail {
			sc.Fix = fleetCheckFix(c.ID)
		}
		out = append(out, sc)
	}
	return out
}

// doctorKubeChecks reads the cluster with kubectl and runs the fleet checks.
func doctorKubeChecks(ctx context.Context, kf *substrateClusterFlags, tokenGroups ...string) []substrateCheck {
	o, r, err := collectFleet(ctx, kf)
	if err != nil {
		return []substrateCheck{{ID: "cluster", Status: doctorFail, Summary: doctorFirstLine(err), Fix: "check your kubectl access and the --install-file path, then run doctor again"}}
	}
	// The policy_conflict row is doctor's own (doctorPolicyConflicts), read
	// with the same sign-in: the fleet check would only say "not read".
	checks := fleet.BuildVerify(o, r.ProductVersion, r.Now).Checks
	checks = slices.DeleteFunc(checks, func(c fleet.Check) bool { return c.ID == fleet.CheckPolicyConflicts })
	rows := doctorConvertFleet(checks)
	for _, g := range r.GlobOverlaps {
		rows = append(rows, substrateCheck{ID: "cluster.atespace_globs", Status: doctorWarn, Summary: g,
			Fix: "list the atespace by name in match.substrate.atespaces, or delete it"})
	}
	for _, g := range fleet.GroupFormMismatches(r.AssignmentGroups, tokenGroups) {
		rows = append(rows, substrateCheck{ID: "cluster.group_forms", Status: doctorWarn, Summary: g,
			Fix: "write the profile's match.groups in the form the sign-in server sends (a signed-in token's groups claim shows it)"})
	}
	for i := range rows {
		if rows[i].ID == "cluster."+fleet.CheckCallout && rows[i].Fix != "" {
			// The fix depends on what holds the slot (GAP-0496): setup
			// refuses while another callout is in the install file.
			rows[i].Fix = fleet.CalloutFix(o)
		}
	}
	rows = append(rows, doctorComponents(r.Health, o.Namespace))
	return append(rows, doctorSkillScan(ctx, kf))
}

// doctorComponentsID is the row that reads the components' ready pods.
const doctorComponentsID = "cluster.components"

// doctorUserSummary is the last line of a doctor without --install-file
// when no check failed.
const doctorUserSummary = "your sign-in, token store and attach checks pass; the cluster components were not checked " +
	"(an administrator runs defenseclaw substrate doctor --install-file FILE)"

// doctorComponents fails, naming each component, when one of the four the
// chart always deploys (gateway, leader, controller, callout) has no ready
// pod: scaled to 0, not deployed, or not ready. With the callout down every
// agent's hook and egress is refused, so the cluster is not ready for agents
// (GAP-0593, GAP-0608: kubectl scale --replicas=0 sets desired to 0, so a
// desired > 0 test would miss the J46 shape).
func doctorComponents(h fleet.Health, ns string) substrateCheck {
	comps := []struct {
		name           string
		desired, ready int
	}{
		{"gateway", h.Gateway.Desired, h.Gateway.Ready},
		{"leader", h.Leader.Desired, 0},
		{"controller", h.Controller.Desired, h.Controller.Ready},
		{"callout", h.Callout.Desired, h.Callout.Ready},
	}
	if h.Leader.Ready {
		comps[1].ready = 1
	}
	var down, up []string
	for _, c := range comps {
		switch {
		case c.ready > 0:
			up = append(up, fmt.Sprintf("%s %d/%d", c.name, c.ready, c.desired))
		case c.desired == 0:
			down = append(down, c.name+" has no pod (scaled to 0 or not deployed)")
		default:
			down = append(down, fmt.Sprintf("%s has 0 of %d pods ready", c.name, c.desired))
		}
	}
	if len(down) > 0 {
		return substrateCheck{ID: doctorComponentsID, Status: doctorFail, Summary: strings.Join(down, "; "),
			Fix: "kubectl -n " + ns + " get deployments,statefulsets shows the component (wrong --namespace if none is listed); " +
				"scale it back with kubectl -n " + ns + " scale, or redeploy it with helm upgrade; kubectl -n " + ns +
				" describe pods and logs say why a pod is not ready"}
	}
	return substrateCheck{ID: doctorComponentsID, Status: doctorOK, Summary: "ready pods: " + strings.Join(up, ", ")}
}

// doctorSkillScan is the substrate.skill_scan row (B5.4, GAP-0477): the
// gateway pods' skill-scanner sidecar, from the pods' container status, and
// the gateway config (substrate.skills.scan.enabled, deployment_mode, the
// hook policy tier). A scanner that is not running fails where the gateway
// refuses new skills unscanned (managed installs, the strict tier) and warns
// on the others (new skills are allowed with an alert).
func doctorSkillScan(ctx context.Context, kf *substrateClusterFlags) substrateCheck {
	const id = "substrate.skill_scan"
	gc := doctorSkillScanConfig(ctx, kf)
	if gc.read && !gc.scanOn {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "Skill scanning is turned off (substrate.skills.scan.enabled: false)."}
	}
	raw, err := substrateKubectl(ctx, kf, "get", "pods", "-n", kf.namespace, "-l", "app.kubernetes.io/component=gateway", "-o", "json")
	if err != nil {
		return substrateCheck{ID: id, Status: doctorWarn, Summary: "the skill scanner was not read: " + doctorFirstLine(err), Fix: "check your kubectl access, then run doctor again"}
	}
	var pods struct {
		Items []struct {
			Spec struct {
				Containers []struct{ Name, Image string } `json:"containers"`
			} `json:"spec"`
			Status struct {
				ContainerStatuses []struct {
					Name  string `json:"name"`
					Ready bool   `json:"ready"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &pods); err != nil {
		return substrateCheck{ID: id, Status: doctorWarn, Summary: "the skill scanner was not read: " + doctorFirstLine(err), Fix: "run doctor again"}
	}
	if len(pods.Items) == 0 {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "not checked: no gateway pod runs"}
	}
	version, with, down := "", 0, 0
	for _, p := range pods.Items {
		for _, c := range p.Spec.Containers {
			if c.Name == skillScannerContainer {
				with++
				version = imageTag(c.Image)
			}
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name == skillScannerContainer && !cs.Ready {
				down++
			}
		}
	}
	if with == 0 && !gc.read {
		// No sidecar and no config to say otherwise: the chart renders none
		// when gateway.skillScanner.enabled is false.
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "Skill scanning is turned off (substrate.skills.scan.enabled: false)."}
	}
	if n := down + len(pods.Items) - with; n > 0 {
		status, outcome := doctorWarn, "allowed with an alert"
		switch {
		case !gc.read:
			status, outcome = doctorFail, "refused on managed installs and allowed with an alert on others"
		case gc.refusedAll:
			status, outcome = doctorFail, "refused"
		case len(gc.refused) > 0:
			status, outcome = doctorFail, "refused for "+strings.Join(gc.refused, ", ")+" and allowed with an alert for the other agents"
		}
		return substrateCheck{ID: id, Status: status, Summary: fmt.Sprintf("Skill scanner is not running on %d of %d gateway pods. New skills are %s there.", n, len(pods.Items), outcome),
			Fix: "kubectl -n " + kf.namespace + " logs deploy/defenseclaw-gateway -c " + skillScannerContainer}
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: "Skill scanner ready (skill-scanner image " + doctorWord(version, "untagged") + ")."}
}

// skillScanConfig is what the substrate.skill_scan row reads of the gateway
// config; read is false when there was none to read. refused are the
// connectors whose new skills the gateway refuses unscanned (managed
// installs: every one; else the strict-tier ones).
type skillScanConfig struct {
	read, scanOn, refusedAll bool
	refused                  []string
}

// doctorSkillScanConfig reads the gateway config doctor checks (--config, or
// the cluster's config map, as the fleet checks do).
func doctorSkillScanConfig(ctx context.Context, kf *substrateClusterFlags) skillScanConfig {
	text := ""
	if kf.configFile != "" {
		b, err := os.ReadFile(kf.configFile)
		if err != nil {
			return skillScanConfig{}
		}
		text = string(b)
	} else {
		cms, err := kubeGetList(ctx, kf, "get", "configmaps", "-n", kf.namespace)
		if err != nil {
			return skillScanConfig{}
		}
		for _, c := range cms {
			if t := c.Data["config.yaml"]; strings.Contains(t, "substrate:") {
				text = t
				break
			}
		}
	}
	if text == "" {
		return skillScanConfig{}
	}
	var doc config.Config
	if yaml.Unmarshal([]byte(text), &doc) != nil {
		return skillScanConfig{}
	}
	// GAP-0936: the gateway's own check (managed, or the connector's strict
	// tier), for each connector an actor can run.
	blocks := substrateBlocksUnscannedSkills(&doc)
	var refused []string
	all := slices.Concat(kit.Wave1Connectors, kit.Wave2Connectors, kit.Wave3Connectors)
	for _, c := range all {
		if blocks(c) {
			refused = append(refused, c)
		}
	}
	return skillScanConfig{read: true, scanOn: doc.Substrate.SkillScanEnabled(), refusedAll: len(refused) == len(all), refused: refused}
}

// skillScannerContainer is the chart's scanner sidecar container name.
const skillScannerContainer = "skill-scanner"

func fleetCheckFix(id string) string {
	switch id {
	case fleet.CheckSubstrateVersion:
		return "use a Substrate version this DefenseClaw supports, or upgrade DefenseClaw (the message names the range)"
	case fleet.CheckIssuer:
		return "give this cluster its own actor token issuer: defenseclaw substrate setup --issuer URL, then ate-setup deploy"
	case fleet.CheckSignInServer:
		return "fix the sign-in server address, certificate or trust bundle the line names (kubectl logs deploy/defenseclaw-gateway | grep oidc_issuer shows the detail), then run doctor again"
	case fleet.CheckBucket:
		return "turn on encryption and block public access on the snapshot bucket, and set a retention period"
	case fleet.CheckGrants:
		return "write the access policies as a global owner: defenseclaw substrate setup --print-access-policies --plan FILE"
	case fleet.CheckCallout:
		return "defenseclaw substrate setup --install-file FILE, then ate-setup deploy and helm upgrade"
	case fleet.CheckIngressClients:
		return "remove the router clients you do not need from ingressAllowedSPIFFEIDs in the SubstrateInstall file"
	case fleet.CheckActorRoutes:
		return "check the DefenseClaw actor Service and the egress rule that routes to it (helm status)"
	case fleet.CheckAPIAccess:
		return "label the DefenseClaw namespace: kubectl label namespace NAMESPACE ate.dev/api-access=true"
	}
	return "read the message above and correct it on the cluster"
}

// --- TLS probes -------------------------------------------------------------

// probeFailure is a failed connection with what kind of failure it was:
// dns, connect, certificate, cafile or handshake.
type probeFailure struct {
	kind string
	err  error
}

func (p *probeFailure) Error() string { return p.err.Error() }
func (p *probeFailure) Unwrap() error { return p.err }

type probeInfo struct {
	// Version is the TLS version that was negotiated, or "plain http".
	Version string
	// Alert is a TLS alert the server sent after the handshake.
	Alert string
}

// substrateTLSConfig trusts the system roots and the CA file when one is given.
func substrateTLSConfig(caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("the CA file cannot be read: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("the CA file holds no certificate")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
}

func classifyProbe(err error) string {
	var dnsErr *net.DNSError
	var verr *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var op *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &verr), errors.As(err, &unknown), errors.As(err, &host), errors.As(err, &invalid):
		return "certificate"
	case errors.As(err, &op) && op.Op == "dial":
		return "connect"
	}
	return "handshake"
}

// probeTLS opens a TLS connection to rawURL and closes it. With watchAlert
// it waits a moment for an alert the server sends once the handshake is
// done, which is how a TLS 1.3 server refuses a client certificate.
func probeTLS(ctx context.Context, rawURL, caFile string, cert *tls.Certificate, watchAlert bool) (probeInfo, *probeFailure) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return probeInfo{}, &probeFailure{kind: "address", err: errors.New("the address is not a valid URL")}
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	dialer := &net.Dialer{Timeout: substrateDoctorDialWait}
	if u.Scheme == "http" {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return probeInfo{}, &probeFailure{kind: classifyProbe(err), err: err}
		}
		_ = conn.Close()
		return probeInfo{Version: "plain http, localhost only"}, nil
	}
	cfg, err := substrateTLSConfig(caFile)
	if err != nil {
		return probeInfo{}, &probeFailure{kind: "cafile", err: err}
	}
	cfg.ServerName = u.Hostname()
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return probeInfo{}, &probeFailure{kind: classifyProbe(err), err: err}
	}
	defer conn.Close()
	info := probeInfo{}
	if tc, ok := conn.(*tls.Conn); ok {
		switch tc.ConnectionState().Version {
		case tls.VersionTLS13:
			info.Version = "TLS 1.3"
		case tls.VersionTLS12:
			info.Version = "TLS 1.2"
		default:
			info.Version = "TLS"
		}
	}
	if watchAlert {
		_ = conn.SetReadDeadline(time.Now().Add(substrateDoctorAlertWait))
		var b [1]byte
		if _, err := conn.Read(b[:]); err != nil {
			var op *net.OpError
			if errors.As(err, &op) && op.Op == "remote error" {
				info.Alert = strings.TrimPrefix(op.Error(), "remote error: ")
			}
		}
	}
	return info, nil
}

// probeMessage says what failed, in plain words, for the check line.
func probeMessage(what, rawURL string, f *probeFailure) string {
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	switch f.kind {
	case "dns":
		return fmt.Sprintf("%s: the name in %s does not resolve", what, host)
	case "connect":
		return fmt.Sprintf("%s: cannot connect to %s (%s)", what, host, connectReason(f.err))
	case "certificate":
		return fmt.Sprintf("%s: the certificate of %s is not trusted (%s)", what, host, certReason(f.err))
	case "cafile":
		return fmt.Sprintf("%s: %s", what, doctorFirstLine(f.err))
	case "address":
		return fmt.Sprintf("%s: %s", what, f.err)
	}
	return fmt.Sprintf("%s: the TLS handshake with %s failed (%s)", what, host, doctorFirstLine(f.err))
}

func connectReason(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return doctorFirstLine(err)
}

func certReason(err error) string {
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) && verr.Err != nil {
		return verr.Err.Error()
	}
	return doctorFirstLine(err)
}

func probeFix(f *probeFailure, urlFlag, caFlag string) string {
	switch f.kind {
	case "dns":
		return "check the address (defenseclaw substrate login " + urlFlag + " URL), your network or VPN, and that the name exists"
	case "connect":
		return "check the address and port, your VPN, and that the cluster exposes it"
	case "certificate":
		return "give the cluster's certificate authority: defenseclaw substrate login " + caFlag + " FILE"
	case "cafile":
		return "defenseclaw substrate login " + caFlag + " FILE"
	case "address":
		return "defenseclaw substrate login " + urlFlag + " https://HOST:PORT"
	}
	return "check that the address is a TLS endpoint and the port is right"
}

// doctorWord makes a closed reason such as token_refused readable.
func doctorWord(v, def string) string {
	if v == "" {
		return def
	}
	return strings.ReplaceAll(v, "_", " ")
}

func doctorFirstLine(err error) string {
	if err == nil {
		return ""
	}
	return strings.SplitN(err.Error(), "\n", 2)[0]
}
