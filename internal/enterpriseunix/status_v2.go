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
		// Persistent-home targets cannot establish coverage of a session-only
		// HERMES_HOME. Do not publish their counts as coverage for this state.
		state.Targets = nil
		block["hermes"] = state
		r.CoverageComplete, r.SecurityComplete = false, false
		// A coverage verdict, never an error: verify keeps a verified
		// install verified, and an upgrade is not rolled back for it.
		if limit := enterprisehooks.ManagedHermesSessionHomeCoverageLimit(env.GOOS, "hermes", true, false); limit != "" {
			r.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors.hermes: "+limit)
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
		Results []struct {
			Connector string `json:"connector"`
			OK        bool   `json:"ok"`
			Pending   bool   `json:"pending"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &state) != nil {
		return nil, false
	}
	if again, err := readBounded(ledgerPath, 4<<20); err != nil || !bytes.Equal(again, ledger) {
		return nil, false
	}
	rows := make([]enterprisestatus.ConnectorTarget, 0, len(state.Results))
	for _, row := range state.Results {
		rows = append(rows, enterprisestatus.ConnectorTarget{Connector: row.Connector, OK: row.OK, Pending: row.Pending})
	}
	return rows, true
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
