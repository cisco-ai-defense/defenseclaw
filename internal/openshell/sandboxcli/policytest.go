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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// PolicyTestOptions are the `policy test` flags.
type PolicyTestOptions struct {
	// Sandbox tests that sandbox's policy (the daemon's, its unblocks
	// included); otherwise Pack, Profile and Harness resolve the policy a
	// run in this folder would get, here, without the daemon.
	Sandbox, Pack, Profile, Harness string
	Host                            string
	Port                            int
	Binary                          string
	// Fixture is a YAML or JSON list of {host, port, binary, expect, rule}
	// (packs.ParseEgressFixture): a mismatch fails the command.
	Fixture string
	Output  OutputFormat
}

// policyTestReport is `policy test --output json`.
type policyTestReport struct {
	*sandboxapi.PolicyTestResult
	// Violations are the refusals a run with this policy would meet (a
	// repository policy that loosens, a harness the pack does not allow):
	// the decisions still say what the egress policy decides.
	Violations []sandboxapi.Violation `json:"violations,omitempty"`
	// Expected and Failed count a fixture's expectations and mismatches.
	Expected int `json:"expected,omitempty"`
	Failed   int `json:"failed,omitempty"`
	// Results pair each fixture case with its decision.
	Results []policyTestCase `json:"results,omitempty"`
}

type policyTestCase struct {
	packs.EgressCase
	Pass bool `json:"pass"`
}

// PolicyTest is `sandbox policy test`: what the egress policy decides for a
// destination, the rule that decides and the setting that holds it, walking
// the egress proxy's order (it asks the same egress decider the proxy uses).
// The proxy decides by destination: every program in a sandbox reaches the
// web through it, so --binary only names the program in the report. With
// --fixture every listed destination is checked against its expectation,
// and any mismatch exits 1.
func (a *App) PolicyTest(ctx context.Context, o PolicyTestOptions) error {
	a.defaults()
	if o.Sandbox != "" && (o.Pack != "" || o.Profile != "" || o.Harness != "") {
		return errors.New("--sandbox tests that sandbox's own policy; leave out --pack, --profile and --harness")
	}
	cases, err := a.policyTestCases(o)
	if err != nil {
		return err
	}
	checks := make([]sandboxapi.PolicyCheck, len(cases))
	for i, c := range cases {
		checks[i] = sandboxapi.PolicyCheck{Host: c.Host, Port: c.Port, Binary: c.Binary}
	}
	report := &policyTestReport{}
	if o.Sandbox != "" {
		api, err := a.api()
		if err != nil {
			return err
		}
		if report.PolicyTestResult, err = api.PolicyTest(ctx, sandboxapi.PolicyTestRequest{Sandbox: o.Sandbox, Checks: checks}); err != nil {
			return apiError(err)
		}
	} else if err := a.localPolicyTest(o, checks, report); err != nil {
		return err
	}
	if len(report.Decisions) != len(cases) {
		return fmt.Errorf("the policy test answered %d of %d destinations", len(report.Decisions), len(cases))
	}
	if o.Fixture != "" {
		for i, c := range cases {
			d := report.Decisions[i]
			pass := c.Matches(packs.EgressDecision{Allowed: d.Allowed, Rule: packs.EgressRule(d.Rule)})
			report.Results = append(report.Results, policyTestCase{EgressCase: c, Pass: pass})
			report.Expected++
			if !pass {
				report.Failed++
			}
		}
	}
	if o.Output == OutputJSON {
		if err := writeJSON(a.IO.Out, report); err != nil {
			return err
		}
	} else {
		a.printPolicyTest(report)
	}
	if report.Failed > 0 {
		return &ExitError{Code: 1, Err: &Silent{Err: fmt.Errorf("%d of %d destinations did not match the fixture", report.Failed, report.Expected)}}
	}
	return nil
}

// policyTestCases are the destinations to judge: --host, or the fixture.
func (a *App) policyTestCases(o PolicyTestOptions) ([]packs.EgressCase, error) {
	switch {
	case o.Fixture != "" && (o.Host != "" || o.Port != 0 || o.Binary != ""):
		return nil, errors.New("--fixture lists the destinations; leave out --host, --port and --binary")
	case o.Fixture != "":
		data, err := safefile.ReadRegularFileBounded(o.Fixture, packs.MaxFixtureBytes)
		if err != nil {
			return nil, fmt.Errorf("--fixture %s: %w", o.Fixture, err)
		}
		return packs.ParseEgressFixture(data, o.Fixture)
	case o.Host == "":
		return nil, errors.New("name a destination with --host (and --port), or a list of them with --fixture")
	case o.Port < 0 || o.Port > 65535:
		return nil, fmt.Errorf("--port %d must be between 1 and 65535", o.Port)
	}
	host, port := o.Host, o.Port
	// host:port (or [v6]:port) reads as --host host --port port; --port wins.
	if h, p, err := net.SplitHostPort(host); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--host %s: the port must be a number between 1 and 65535", o.Host)
		}
		host = h
		if port == 0 {
			port = n
		}
	}
	return []packs.EgressCase{{Host: host, Port: port, Binary: o.Binary}}, nil
}

// localPolicyTest resolves the policy a run in this folder would get with
// the pack, profile and harness, as `run` does, the folder's repository
// policy included, and judges the destinations with its decider. It needs
// no daemon (no unblocks apply), so CI can check a pack.
func (a *App) localPolicyTest(o PolicyTestOptions, checks []sandboxapi.PolicyCheck, report *policyTestReport) error {
	cfg := a.Cfg
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	flags := packs.Flags{Pack: o.Pack, Profile: o.Profile}
	if o.Harness != "" {
		spec, err := ResolveHarness(o.Harness)
		if err != nil {
			return err
		}
		flags.Harness = spec.Name
	}
	if project, err := a.project(); err == nil {
		flags.Project = project
		if flags.RepoPolicy, err = packs.LoadRepoPolicy(project); err != nil {
			return err
		}
	}
	eff, violations, err := packs.Resolve(cfg, flags)
	if err != nil {
		return err
	}
	d, err := eff.EgressDecider(nil)
	if err != nil {
		return err
	}
	res := &sandboxapi.PolicyTestResult{Profile: eff.Profile, NetworkMode: eff.NetworkMode}
	if eff.Pack != nil {
		res.Pack = eff.Pack.Name
	}
	for _, c := range checks {
		chk := eff.CheckEgress(d, egress.Principal{BindingID: "sandbox-policy-test"}, c.Host, c.Port)
		res.Decisions = append(res.Decisions, sandboxapi.PolicyDecision{PolicyCheck: c, Allowed: chk.Allowed, Rule: string(chk.Rule),
			Match: chk.Match, Source: chk.Source, Reason: chk.Reason, Unblockable: chk.Unblockable})
	}
	report.PolicyTestResult = res
	for _, v := range violations {
		if v.Fatal {
			report.Violations = append(report.Violations, wireViolation(v))
		}
	}
	return nil
}

func (a *App) printPolicyTest(r *policyTestReport) {
	head := "pack " + r.Pack + " · profile " + r.Profile + " · network " + r.NetworkMode
	if r.Sandbox != "" {
		head = "sandbox " + r.Sandbox + " · " + head
	}
	a.line(head)
	headers := []string{"DESTINATION", "DECISION", "RULE", "SOURCE"}
	if r.Expected > 0 {
		headers = append(headers, "EXPECTED")
	}
	rows := make([][]string, 0, len(r.Decisions))
	for i, d := range r.Decisions {
		dest := d.Host
		if d.Port != 0 {
			dest = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
		}
		if d.Binary != "" {
			dest += " (" + d.Binary + ")"
		}
		decision := "allowed"
		if !d.Allowed {
			decision = "blocked"
			if d.Unblockable {
				decision += " (unblockable)"
			}
		}
		rule := d.Rule
		if d.Match != "" {
			rule += " " + d.Match
		}
		row := []string{truncate(dest, 60), decision, truncate(rule, 40), truncate(d.Source, 70)}
		if r.Expected > 0 {
			mark := a.style("✓ "+r.Results[i].Expect, ansiGreen)
			if !r.Results[i].Pass {
				want := r.Results[i].Expect
				if r.Results[i].Rule != "" {
					want += " by " + r.Results[i].Rule
				}
				mark = a.style("✗ "+want, ansiRed)
			}
			row = append(row, mark)
		}
		rows = append(rows, row)
	}
	a.table(headers, rows)
	for _, d := range r.Decisions {
		if d.Direct != "" {
			a.note(d.Host + ": " + d.Direct + ", around the egress proxy")
		}
	}
	for i := range r.Violations {
		v := r.Violations[i]
		a.warn("a run with this policy is refused: " + violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	if r.Expected > 0 {
		if r.Failed == 0 {
			a.ok(fmt.Sprintf("all %d destinations match the fixture", r.Expected))
		} else {
			a.bad(fmt.Sprintf("%d of %d destinations do not match the fixture", r.Failed, r.Expected))
		}
	}
	if len(r.Decisions) == 1 && r.Decisions[0].Reason != "" && !r.Decisions[0].Allowed {
		a.note(strings.TrimSpace(r.Decisions[0].Reason))
	}
}
