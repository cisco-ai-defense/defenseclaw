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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Rendering of the sandbox subsystem's files. Everything here is a pure
// function of the validated config and the embedded unit assets, so the
// plan compares it with the recorded digests and a rerun of ensure changes
// nothing.

// renderGatewayFiles renders the OpenShell gateway's configuration from
// enterprise.openshell into root:root 0644 files under <ConfigDir>/openshell
// (spec 2.8): gateway.toml always, and gateway.env, which carries
// OpenShell's telemetry switch, unless the organization's sandbox floor
// allows that telemetry. They hold no secrets.
//
// Who reads them: gateway.toml reaches the gateway through the --config the
// sandbox-openshell-exec shim passes, and the shim appends
// openshell.RenderedEnvironment of gateway.env (the telemetry switch, which
// gateway.toml cannot carry) and openshell.AccountVMEnvironment (the MicroVM
// workload identity, which is the account's own and so cannot be a value in
// a file every account shares, GAP-0254) to the environment it builds. The
// shim runs in both install modes (the administrator's binary in
// prerequisite mode, the account's own in setup mode), so an account's
// gateway runs the render by construction. A gateway of the account's that
// the managed unit did not start (NVIDIA's own unit on the account's own
// files, say) is compared against the render by the account's sandbox
// daemon before every create and start: drift pauses sandboxes and is
// reported as settings_drift.
//
// The render is host-wide, so the switch follows the organization's floor
// (openshell.admin.allow_upstream_telemetry). A profile's tighter
// allow_upstream_telemetry: false is per user and is enforced where the user's
// settings are known, in the sandbox daemon, not here.
func (e *Env) renderGatewayFiles(op *openshellPlan) error {
	root := rootOwner()
	driverDir := ""
	if op.settings.Install == config.EnterpriseOpenShellInstallPrerequisite {
		driverDir = e.systemDriverDir()
	}
	op.rendered = op.settings.rendered(driverDir)
	tomlData, err := op.rendered.TOML()
	if err != nil {
		return fmt.Errorf("render the OpenShell gateway configuration from enterprise.openshell: %w", err)
	}
	envData := op.rendered.EnvFile()
	op.digest = openshell.RenderedDigest(tomlData, envData)
	op.files = append(op.files, desiredFile{Path: e.renderedTOMLPath(), Data: tomlData, SHA: sha256Bytes(tomlData), Mode: 0o644, Owner: root, Kind: "openshell-gateway-toml"})
	digestData := []byte(op.digest + "\n")
	op.files = append(op.files, desiredFile{Path: filepath.Join(e.openshellDir(), openshell.GatewayRenderedDigestFile),
		Data: digestData, SHA: sha256Bytes(digestData), Mode: 0o644, Owner: root, Kind: "openshell-gateway-digest"})
	if e.GOOS == "linux" && op.settings.dockerFallback() {
		// The docker fallback's configuration: what a user's gateway starts
		// with when its KVM probe fails (sandbox-openshell-exec). Same
		// listener and telemetry switch, the docker driver.
		fallback := op.settings.fallbackSettings().rendered("")
		fbData, err := fallback.TOML()
		if err != nil {
			return fmt.Errorf("render the OpenShell docker fallback configuration: %w", err)
		}
		op.files = append(op.files, desiredFile{Path: e.renderedFallbackTOMLPath(), Data: fbData, SHA: sha256Bytes(fbData), Mode: 0o644, Owner: root, Kind: "openshell-gateway-toml"})
	}
	if op.defaultNamespaceBridge {
		// The docker configuration as 1.0.1 rendered it (no sandbox_label),
		// which the exec shim starts an account's docker gateway on while
		// the account keeps a sandbox in OpenShell's default namespace
		// (dockerBridgeHolds, GAP-0587). 1.0.1 upgrade bridge, remove when
		// 1.0.1 is out of support.
		bridge := op.settings.fallbackSettings().rendered("")
		bridge.DefaultDockerNamespaceBridge = true
		brData, err := bridge.TOML()
		if err != nil {
			return fmt.Errorf("render the OpenShell docker configuration of the 1.0.1 upgrade bridge: %w", err)
		}
		op.files = append(op.files, desiredFile{Path: e.renderedBridgeTOMLPath(), Data: brData, SHA: sha256Bytes(brData), Mode: 0o644, Owner: root, Kind: "openshell-gateway-toml"})
	}
	if envData != nil {
		op.files = append(op.files, desiredFile{Path: e.renderedEnvPath(), Data: envData, SHA: sha256Bytes(envData), Mode: 0o644, Owner: root, Kind: "openshell-gateway-env"})
	}
	return nil
}

// renderUserUnits installs the user units of the sandbox daemon and of the
// account's OpenShell gateway, and the administrator's proxy in their
// environment. It returns the digest of every unit file by path and
// the socket unit's definition. On a Linux package install the package placed
// the units: the plan only records their digests.
func (e *Env) renderUserUnits(p *plan, op *openshellPlan) (units map[string]string, socket []byte, err error) {
	root := rootOwner()
	units = map[string]string{}
	for _, u := range e.userUnits() {
		data, err := e.userUnitBytes(u)
		if err != nil {
			return nil, nil, fmt.Errorf("this build carries no %s unit (%v): upgrade the DefenseClaw enterprise package or turn openshell.enabled off", u.Name, err)
		}
		if e.GOOS == "darwin" {
			if data, err = injectPlistEnvironment(data, proxyEnvironment(p.config)); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", u.Name, err)
			}
		}
		path := e.userUnitPath(u, p.channel)
		units[path] = sha256Bytes(data)
		if u.Name == userUnitSandboxSocket {
			socket = data
		}
		if e.GOOS == "darwin" || p.channel != ChannelPackage {
			op.files = append(op.files, desiredFile{Path: path, Data: data, SHA: sha256Bytes(data), Mode: 0o644, Owner: root, Kind: "user-unit"})
			if dir := filepath.Dir(path); dir != "/Library/LaunchAgents" {
				op.dirs = append(op.dirs, desiredDir{Path: dir, Mode: 0o755, Owner: root, External: true})
			}
			continue
		}
		if p.packageUnits == nil {
			p.packageUnits = map[string]string{}
		}
		if got, err := sha256File(e.P(path)); err == nil {
			p.packageUnits[path] = got
		}
	}
	if e.GOOS != "linux" {
		return units, socket, nil
	}
	op.dirs = append(op.dirs, desiredDir{Path: "/etc/systemd/user", Mode: 0o755, Owner: root, External: true})
	proxy := proxyEnvironment(p.config)
	if len(proxy) == 0 {
		return units, socket, nil
	}
	var b strings.Builder
	b.WriteString("# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n# enterprise.network: the proxy of the sandbox daemon and of the setup-mode download.\n[Service]\n")
	for _, key := range sortedKeys(proxy) {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(key+"="+proxy[key]))
	}
	data := []byte(b.String())
	for _, name := range []string{userUnitSandboxService, userUnitGatewayService} {
		path := filepath.Join("/etc/systemd/user", name+".d", dropinNetwork)
		op.files = append(op.files, desiredFile{Path: path, Data: data, SHA: sha256Bytes(data), Mode: 0o644, Owner: root, Kind: "dropin"})
		op.dirs = append(op.dirs, desiredDir{Path: filepath.Dir(path), Mode: 0o755, Owner: root, External: true})
		units[path] = sha256Bytes(data)
	}
	return units, socket, nil
}
