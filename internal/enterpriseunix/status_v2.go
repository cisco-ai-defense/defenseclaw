// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The status v2 blocks (enterprisestatus connector_block.go,
// openshell_block.go, identity_block.go) on Linux and macOS appear on status
// and verify only. Hermes session-home attestation and the hook-process
// failure limit also run for lifecycle changes, so those actions cannot claim
// coverage or security that verify cannot prove.

// statusV2 reports whether this run prints the status v2 blocks.
func (l *lifecycle) statusV2() bool {
	return l.opts.Action == ActionStatus || l.opts.Action == ActionVerify
}

// describeStatusV2 adds the connectors block, and the identity block when
// the gateway did not report one (it is not ready).
func (l *lifecycle) describeStatusV2(record *Deployment) {
	if !l.statusV2() {
		return
	}
	r := l.result
	l.describeConnectors(record)
	if r.Identity == nil {
		r.Identity = enterprisestatus.IdentityGatewayNotReady()
	}
}

// describeConnectors builds the connectors block from the installed config,
// the enumerator's manifest and unprotected-agents record, and the guardian
// state the attestation vouches for. Only status/verify publish the block;
// every lifecycle action uses its Hermes coverage verdict and hook-process
// failure limit. The fail mode is
// the hook renderer's (enterprisehooks.ManagedHookFailMode).
func (l *lifecycle) describeConnectors(record *Deployment) {
	env, r := l.env, l.result
	registry := connector.NewDefaultRegistry()
	in := enterprisestatus.ConnectorInputs{Known: func(name string) bool {
		_, ok := registry.Get(name)
		return ok
	}}
	var cfg *config.Config
	if raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes); err == nil {
		if loaded, err := env.loadConfigCandidate(raw); err == nil && loaded != nil {
			cfg = loaded
		} else {
			r.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors: the installed config could not be loaded, "+
				"so effective_mode and effective_hook_fail_mode are not reported")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		r.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors: the installed config could not be read, "+
			"so effective_mode and effective_hook_fail_mode are not reported")
	}
	if cfg != nil {
		in.ConfigLoaded = true
		in.Enabled = enterprisehooks.EffectiveUnixHookConnectors(cfg, registry)
		in.Mode = cfg.EffectiveGuardrailModeForConnector
	}
	switch manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath)); {
	case err == nil:
		in.ManifestRead = true
		for _, target := range manifest.Targets {
			in.Manifest = append(in.Manifest, enterprisestatus.ConnectorInstall{Connector: target.Connector, Version: target.AgentVersion, Enabled: target.IsEnabled()})
		}
	case !errors.Is(err, os.ErrNotExist):
		r.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors: the enumerator's targets.yaml could not be read, "+
			"so detected and versions are not reported")
	}
	if data, err := readBounded(env.P(enterprisehooks.UnprotectedAgentsPath(env.Layout.ManifestPath)), enterprisehooks.UnprotectedAgentsMaxBytes); err == nil {
		// An unreadable record is already reported by describeUnprotectedAgents.
		if agents, err := enterprisehooks.ParseUnprotectedAgents(data); err == nil {
			for _, agent := range agents {
				in.Unprotected = append(in.Unprotected, enterprisestatus.ConnectorInstall{Connector: agent.Connector, Version: agent.Version})
			}
		}
	}
	in.Guardian, in.GuardianKnown = l.attestedGuardianRows()
	if record != nil {
		in.MachinePolicy = record.MachinePolicyConnectors
		in.MachinePolicyCoverage = machinePolicyCoverage(record.MachinePolicyConnectors, r.MachinePolicy)
	}
	failMode := func(name string) string { return enterprisehooks.ManagedHookFailMode(cfg, name) }
	block, hidden := enterprisestatus.BuildConnectors(in, failMode)
	if state, ok := block["hermes"]; ok && state.Enabled &&
		(state.Detected == nil || *state.Detected || state.Targets != nil && state.Targets.Total > 0) {
		state.HooksInstalled = enterprisestatus.HooksInstalledUnknown
		failedTargets := state.Targets != nil && state.Targets.Failed > 0
		// Persistent-home targets cannot establish coverage of a session-only
		// HERMES_HOME. Do not publish their counts as coverage for this state.
		state.Targets = nil
		block["hermes"] = state
		// The limit is reported, not certified: security_complete stays
		// false for it and verify exits 0. coverage_complete says the
		// enabled hooks are installed, and they are, so a documented
		// platform limit keeps its warning but does not make it false, as on
		// Windows (GAP-1861, GAP-1593).
		r.MarkSecurityIncomplete(enterprisestatus.CodeStatusDetailUnavailable)
		if failedTargets {
			// An enrolled Hermes hook the guardian could not install is
			// not covered.
			r.MarkCoverageIncomplete(codeGuardianTargetFailed)
		}
		if err := enterprisehooks.ManagedHermesSessionHomeAttestation(env.GOOS, "hermes", true, false); err != nil {
			message := "connectors.hermes: NOT COVERED: " + err.Error()
			r.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, message)
			if env.ReportLaunchCoverage != nil {
				if auditErr := env.ReportLaunchCoverage(context.Background(), managed.LaunchCoverageReport{
					Connector: "hermes", Reason: "session_only_hermes_home_unobservable", UID: 0,
				}); auditErr != nil {
					r.AddWarning(codeManagedLaunchAuditUnavailable, "could not audit the managed Hermes session-home limit: "+auditErr.Error())
				}
			}
		}
	}
	r.AddHookProcessFailureWarnings(block)
	if l.statusV2() {
		r.Connectors = block
		if hidden > 0 {
			r.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, fmt.Sprintf("connectors: %d agent version(s) not shown: "+
				"they are not plain version strings", hidden))
		}
	}
}

// verifyManagedHermesRegistration proves the installed default-home hook on
// lifecycle Verify. The public hooks Verify keeps refusing session-home
// attestation; the hidden readiness check verifies the same physical hook,
// render, credentials and protected authorization without that claim.
//
// One account's or one target's Hermes state never fails another target or
// the host: an enabled Hermes the enumerator could not enroll has no hook to
// prove (GAP-1420), and a Hermes target the guardian's attested last
// reconcile recorded as failed is reported NOT COVERED here and classified
// by the guardian target warnings (describeHookContracts), as every other
// connector's target is. A Hermes hook that fails live while the guardian
// last proved it, a report that omits or duplicates a target, and invalid
// protected authorization still fail Verify.
func (l *lifecycle) verifyManagedHermesRegistration(ctx context.Context) error {
	state, ok := l.result.Connectors["hermes"]
	if !ok || !state.Enabled || state.HooksInstalled != enterprisestatus.HooksInstalledUnknown {
		return nil
	}
	manifest, err := enterprisehooks.LoadStandaloneManifest(l.env.P(l.env.Layout.ManifestPath))
	if err != nil {
		return fmt.Errorf("read managed Hermes targets: %w", err)
	}
	expected := make(map[string]bool)
	key := func(connector, user, home string) string {
		return strings.ToLower(strings.TrimSpace(connector)) + "\x00" + strings.TrimSpace(user) + "\x00" +
			strings.TrimSpace(home)
	}
	for _, target := range manifest.Targets {
		if target.IsEnabled() && strings.EqualFold(target.Connector, "hermes") {
			expected[key(target.Connector, target.User, target.UserHome)] = false
		}
	}
	if len(expected) == 0 {
		// No Hermes target is enrolled, so no DefenseClaw Hermes hook is
		// installed to prove. The install the enumerator could not enroll
		// stays NOT COVERED with its reason (connectors.hermes and the
		// unprotected-agent warning, which is audited).
		return nil
	}
	out, err := l.env.runGatewayCLI(ctx, "enterprise", "hooks", "readiness", "--manifest", l.env.Layout.ManifestPath, "--json")
	// ExecRunner returns the report together with an error when another
	// target makes readiness exit nonzero. A launch failure has no exit code.
	if err != nil && out.ExitCode <= 0 {
		return fmt.Errorf("live registration check failed: %w", err)
	}
	var proof struct {
		OK                    bool   `json:"ok"`
		Scope                 string `json:"scope"`
		HermesSessionCoverage string `json:"hermes_session_coverage"`
		AuthorizationError    string `json:"authorization_error"`
		Results               []struct {
			Connector string `json:"connector"`
			User      string `json:"user"`
			UserHome  string `json:"user_home"`
			OK        bool   `json:"ok"`
			Pending   bool   `json:"pending"`
		} `json:"results"`
	}
	if json.Unmarshal(out.Stdout, &proof) != nil || proof.Scope != "machine_hook_registration" ||
		proof.HermesSessionCoverage != "not_covered" || proof.AuthorizationError != "" ||
		(out.ExitCode == 0) != proof.OK {
		return errors.New("live registration check did not prove the current managed Hermes target")
	}
	guardianFailed := map[string]bool{}
	if rows, known := l.attestedGuardianResults(); known {
		for _, row := range rows {
			if !row.OK && !row.Pending {
				guardianFailed[key(row.Connector, row.User, row.UserHome)] = true
			}
		}
	}
	explainedFailure := false
	var notCovered []string
	for _, row := range proof.Results {
		failed := !row.OK && !row.Pending
		if !strings.EqualFold(row.Connector, "hermes") {
			explainedFailure = explainedFailure || failed
			continue
		}
		rowKey := key(row.Connector, row.User, row.UserHome)
		if _, enrolled := expected[rowKey]; !enrolled || expected[rowKey] {
			return errors.New("live registration check reported an unprotected Hermes target")
		}
		expected[rowKey] = true
		if failed {
			if !guardianFailed[rowKey] {
				return errors.New("live registration check reported an unprotected Hermes target")
			}
			explainedFailure = true
			notCovered = append(notCovered, strings.TrimSpace(row.User))
		}
	}
	for _, found := range expected {
		if !found {
			return errors.New("live registration check omitted the managed Hermes target")
		}
	}
	if !proof.OK && !explainedFailure {
		return errors.New("live registration check did not prove the current managed Hermes target")
	}
	sort.Strings(notCovered)
	for _, user := range notCovered {
		l.result.MarkCoverageIncomplete(enterprisestatus.CodeStatusDetailUnavailable)
		l.result.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors.hermes: NOT COVERED for user "+user+
			": the guardian's last reconcile could not protect its Hermes hook; the guardian target warning names the cause")
	}
	return nil
}

// machinePolicyCoverage is the hooks_installed value of each connector the
// last transaction put in vendor machine policy, from the machine policy
// describeMachinePolicy just read: on Linux and macOS these connectors get no
// per-user target, so the guardian has no row for them.
func machinePolicyCoverage(connectors []string, states map[string]enterprisestatus.MachinePolicyState) map[string]string {
	coverage := make(map[string]string, len(connectors))
	for _, name := range connectors {
		state, ok := states[name]
		switch {
		case !ok:
			coverage[name] = enterprisestatus.HooksInstalledUnknown
		case state.OwnedEntries == 0:
			coverage[name] = enterprisestatus.HooksInstalledNone
		case len(state.Conflicts) > 0:
			coverage[name] = enterprisestatus.HooksInstalledPartial
		default:
			coverage[name] = enterprisestatus.HooksInstalledAll
		}
	}
	return coverage
}

// attestedGuardianRows are the rows of the guardian's last reconcile, and
// whether they can be trusted: the state is in DataDir, which the service
// account can replace, so its rows count only while the root-only
// attestation is bound to the ledger of the same reconcile (as
// describeHookContracts reads them).
func (l *lifecycle) attestedGuardianRows() ([]enterprisestatus.ConnectorTarget, bool) {
	results, known := l.attestedGuardianResults()
	if !known {
		return nil, false
	}
	rows := make([]enterprisestatus.ConnectorTarget, 0, len(results))
	for _, row := range results {
		rows = append(rows, enterprisestatus.ConnectorTarget{Connector: row.Connector, OK: row.OK, Pending: row.Pending})
	}
	return rows, true
}

// attestedGuardianResult is one target row of the guardian's last reconcile.
type attestedGuardianResult struct {
	Connector string `json:"connector"`
	User      string `json:"user"`
	UserHome  string `json:"user_home"`
	OK        bool   `json:"ok"`
	Pending   bool   `json:"pending"`
}

// attestedGuardianResults are attestedGuardianRows with each target's
// account and home.
func (l *lifecycle) attestedGuardianResults() ([]attestedGuardianResult, bool) {
	env := l.env
	ledgerPath := env.P(filepath.Join(env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
	ledger, err := readBounded(ledgerPath, 4<<20)
	if err != nil {
		return nil, false
	}
	attestation, err := env.readAttestation()
	if err != nil || !attestation.BoundTo(ledger) {
		return nil, false
	}
	data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20)
	if err != nil {
		return nil, false
	}
	var state struct {
		Results []attestedGuardianResult `json:"results"`
	}
	if json.Unmarshal(data, &state) != nil {
		return nil, false
	}
	if again, err := readBounded(ledgerPath, 4<<20); err != nil || !bytes.Equal(again, ledger) {
		return nil, false
	}
	return state.Results, true
}

// noteIdentityHealth keeps the identity block of the gateway's /health body
// for status and verify.
func (l *lifecycle) noteIdentityHealth(body []byte) {
	if l.statusV2() {
		l.result.Identity = enterprisestatus.ParseIdentityHealth(body)
	}
}

// noteOpenShellCapability sets the openshell block for status and verify
// from the sandbox rows describeOpenShell computed (on: sandboxes are
// enabled). The docker row only says Docker is installed; on Linux, where
// one system engine serves every user, a block that would report docker
// also asks the engine, so a stopped engine is driver_available none
// (GAP-0006). On a Mac Docker Desktop runs per user, so sandbox doctor
// checks it for each user instead.
func (l *lifecycle) noteOpenShellCapability(ctx context.Context, settings openshellSettings, on bool, primary, fallback []prereqRow) {
	if !l.statusV2() {
		return
	}
	c := openShellCapability(settings, on, primary, fallback)
	if c.DriverAvailable == enterprisestatus.OpenShellDriverDocker && l.env.GOOS == "linux" {
		if socket, err := l.env.dockerEngineAnswers(ctx); err != nil {
			c.DriverAvailable, c.ReasonCode = enterprisestatus.OpenShellDriverNone, codeOpenShellPrerequisite
			l.result.AddWarning(codeOpenShellPrerequisite, fmt.Sprintf("sandboxes cannot run for users on this host (docker): "+
				"the Docker engine does not answer on %s (%v); start it (systemctl start docker)", socket, err))
		}
	}
	l.result.OpenShell = c
}

// dockerEngineTimeout bounds one connect to the Docker engine socket.
const dockerEngineTimeout = time.Second

// dockerEngineAnswers connects to the first Docker engine socket that
// exists; socket is the path it tried (the first candidate when none
// exists).
func (e *Env) dockerEngineAnswers(ctx context.Context) (socket string, err error) {
	socket = e.firstExisting(dockerSockets)
	if socket == "" {
		return dockerSockets[0], errors.New("no engine socket")
	}
	return socket, e.DockerEngine(ctx, e.P(socket))
}

// dialDockerEngine is the production DockerEngine: one bounded unix
// connect, closed at once, nothing written.
func dialDockerEngine(ctx context.Context, socket string) error {
	ctx, cancel := context.WithTimeout(ctx, dockerEngineTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	return conn.Close()
}

// openShellCapability maps the sandbox rows to the openshell block: codes and
// a version only, never a row's detail or fix (they name paths).
func openShellCapability(s openshellSettings, on bool, primary, fallback []prereqRow) *enterprisestatus.OpenShellCapability {
	if !on {
		return enterprisestatus.OpenShellDisabledCapability()
	}
	c := &enterprisestatus.OpenShellCapability{Enabled: true, Install: s.Install, Driver: s.Driver}
	if s.Install == config.EnterpriseOpenShellInstallSetup {
		if enterprisestatus.ValidVersionToken(s.Version) && !versionRange.MatchString(s.Version) {
			c.Version = s.Version
		}
	} else {
		installed, version, same := true, "", true
		for _, row := range primary {
			if !openShellPartRow(row.Name) {
				continue
			}
			installed = installed && (row.OK || row.Version != "")
			switch {
			case row.Version == "":
				same = false
			case version == "":
				version = row.Version
			case version != row.Version:
				same = false
			}
		}
		c.Installed = &installed
		if same && enterprisestatus.ValidVersionToken(version) {
			c.Version = version
		}
	}
	firstFailure := func(rows []prereqRow) string {
		for _, row := range rows {
			if !row.OK {
				if row.Code != "" {
					return row.Code
				}
				return codeOpenShellPrerequisite
			}
		}
		return ""
	}
	primaryDriver := enterprisestatus.OpenShellDriverDocker
	if s.wantsVM() {
		primaryDriver = enterprisestatus.OpenShellDriverVM
	}
	switch {
	case rowsReady(primary):
		c.DriverAvailable = primaryDriver
	case fallback != nil && rowsReady(fallback):
		c.DriverAvailable, c.ReasonCode = enterprisestatus.OpenShellDriverDocker, codeDriverFallback
	default:
		c.DriverAvailable, c.ReasonCode = enterprisestatus.OpenShellDriverNone, firstFailure(primary)
	}
	return c
}

// openShellPartRow reports whether a prerequisite row is one OpenShell part
// (checkPrerequisiteMode's part rows).
func openShellPartRow(name string) bool {
	switch name {
	case "openshell cli", "openshell gateway", "microvm driver":
		return true
	}
	return false
}
