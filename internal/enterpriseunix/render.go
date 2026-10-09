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
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	launchdstandalone "github.com/defenseclaw/defenseclaw/packaging/launchd-standalone"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// Drop-in names the lifecycle owns. Administrators may add their own
// drop-ins with other names; the lifecycle never touches those.
const (
	dropinCredentials = "60-defenseclaw-credentials.conf"
	dropinNetwork     = "70-defenseclaw-network.conf"
	dropinPaths       = "50-defenseclaw-paths.conf"
	dropinAgents      = "40-defenseclaw-agent-prefixes.conf"
	// dropinTetragon carries enterprise.tetragon to the sensor helper.
	dropinTetragon = "30-defenseclaw-tetragon.conf"
)

// renderInputs are the host-specific values rendering needs.
type renderInputs struct {
	Account        Account
	Channel        string
	Version        string
	InstalledAt    string
	Config         *validatedConfig
	Secrets        []string // credential names present in the secrets dir
	LoadCredential bool
	// MachinePolicy are the connectors the descriptor records as protected
	// by vendor machine policy.
	MachinePolicy []string
}

// renderFiles returns every non-binary file the deployment consists of.
func (e *Env) renderFiles(in renderInputs) ([]desiredFile, error) {
	var files []desiredFile
	add := func(path string, data []byte, mode os.FileMode, owner fileOwner, kind string) {
		files = append(files, desiredFile{Path: path, Data: data, SHA: sha256Bytes(data), Mode: mode, Owner: owner, Kind: kind})
	}
	root := rootOwner()

	descriptor, err := e.renderDescriptor(in)
	if err != nil {
		return nil, err
	}
	add(e.Layout.DescriptorPath, descriptor, 0o644, root, "descriptor")

	// The vendor default policies and rule packs, read-only for every
	// service; the gateway fails to start without a rule pack.
	vendorPolicies, err := policyassets.Files()
	if err != nil {
		return nil, fmt.Errorf("embedded vendor policies: %w", err)
	}
	for _, policy := range vendorPolicies {
		add(filepath.Join(e.Layout.VendorPolicyDir, filepath.FromSlash(policy.Path)), policy.Data, 0o644, root, "vendor-policy")
	}
	// The managed OpenCode plugin, readable by every user. OpenCode's
	// managed config names it once it is installed (machine policy route).
	add(enterprisepolicy.OpenCodeManagedPluginPath(e.Layout), enterprisepolicy.OpenCodeManagedPlugin(), 0o644, root, "opencode-plugin")

	switch e.GOOS {
	case "linux":
		if in.Channel != ChannelPackage {
			for _, unit := range e.Services.Units() {
				data, err := systemdunits.ReadFile(unit.Name)
				if err != nil {
					return nil, fmt.Errorf("embedded unit %s: %w", unit.Name, err)
				}
				add(e.Services.DefinitionPath(unit, in.Channel), data, 0o644, root, "unit")
			}
			tmpfiles, err := systemdunits.ReadFile(systemdunits.TmpfilesName)
			if err != nil {
				return nil, err
			}
			add(tmpfilesInstallPath(in.Channel), tmpfiles, 0o644, root, "tmpfiles")
			sysusers, err := systemdunits.ReadFile(systemdunits.SysusersName)
			if err != nil {
				return nil, err
			}
			add(sysusersInstallPath(in.Channel), sysusers, 0o644, root, "sysusers")
		}
		for _, dropin := range e.renderDropins(in) {
			add(dropin.Path, dropin.Data, 0o644, root, "dropin")
		}
	case "darwin":
		for _, unit := range e.Services.Units() {
			data, err := launchdstandalone.ReadPlist(unit.Name)
			if err != nil {
				return nil, fmt.Errorf("embedded plist %s: %w", unit.Name, err)
			}
			if unit.Name == labelGateway {
				data, err = injectPlistEnvironment(data, proxyEnvironment(in.Config))
				if err != nil {
					return nil, err
				}
			}
			if unit.Name == labelGuardian || unit.Name == labelEnumerator {
				data, err = injectPlistEnvironment(data, agentPrefixEnvironment(in.Config))
				if err != nil {
					return nil, err
				}
			}
			add(e.Services.DefinitionPath(unit, in.Channel), data, 0o644, root, "plist")
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

type renderedDropin struct {
	Path string
	Data []byte
}

// renderDropins renders the host-specific systemd drop-ins.
func (e *Env) renderDropins(in renderInputs) []renderedDropin {
	var out []renderedDropin
	dropinPath := func(unit, name string) string {
		return filepath.Join("/etc/systemd/system", unit+".d", name)
	}
	if in.LoadCredential && len(in.Secrets) > 0 {
		var b strings.Builder
		b.WriteString("# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n[Service]\n")
		for _, name := range in.Secrets {
			fmt.Fprintf(&b, "LoadCredential=%s:%s\n", name, filepath.Join(e.Layout.SecretsDir, name))
		}
		fmt.Fprintf(&b, "InaccessiblePaths=-%s\n", e.Layout.SecretsDir)
		out = append(out, renderedDropin{Path: dropinPath(unitGateway, dropinCredentials), Data: []byte(b.String())})
	}
	if env := proxyEnvironment(in.Config); len(env) > 0 {
		var b strings.Builder
		b.WriteString("# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n[Service]\n")
		for _, key := range sortedKeys(env) {
			fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(key+"="+env[key]))
		}
		out = append(out, renderedDropin{Path: dropinPath(unitGateway, dropinNetwork), Data: []byte(b.String())})
	}
	if env := agentPrefixEnvironment(in.Config); len(env) > 0 {
		var b strings.Builder
		b.WriteString("# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n# Administrator install prefixes where agent CLIs are discovered.\n[Service]\n")
		for _, key := range sortedKeys(env) {
			fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(key+"="+env[key]))
		}
		data := []byte(b.String())
		// The sensor helper resolves the same installs to anchor its kernel
		// controls (an agent under an administrator prefix is otherwise
		// observe-only there).
		for _, unit := range []string{unitGuardian, unitGuardianOneshot, unitEnumerator, unitSensorHelper} {
			out = append(out, renderedDropin{Path: dropinPath(unit, dropinAgents), Data: data})
		}
	}
	paths := e.guardianWritablePaths(in.Config)
	if len(paths) > 0 {
		var b strings.Builder
		b.WriteString("# Written by the DefenseClaw enterprise lifecycle. Do not edit.\n# Enrollment home roots and enabled vendor machine-policy directories.\n[Service]\n")
		for _, path := range paths {
			fmt.Fprintf(&b, "ReadWritePaths=-%s\n", systemdQuote(path))
		}
		data := []byte(b.String())
		out = append(out,
			renderedDropin{Path: dropinPath(unitGuardian, dropinPaths), Data: data},
			renderedDropin{Path: dropinPath(unitGuardianOneshot, dropinPaths), Data: data},
		)
	}
	// enterprise.tetragon reaches the sensor helper only through this
	// drop-in; the helper never reads config.yaml. None is rendered while the
	// helper's defaults (consume) already say the same.
	if in.Config != nil {
		if data := in.Config.Tetragon.dropin(); data != nil {
			out = append(out, renderedDropin{Path: dropinPath(unitSensorHelper, dropinTetragon), Data: data})
		}
	}
	return out
}

// guardianWritablePaths are the extra paths the guardian sandbox must allow.
func (e *Env) guardianWritablePaths(cfg *validatedConfig) []string {
	if cfg == nil {
		return nil
	}
	set := map[string]bool{}
	for _, root := range cfg.HomeRoots {
		set[filepath.Clean(root)] = true
	}
	for _, connector := range cfg.machinePolicyEnabled(e.GOOS) {
		dirs := machinePolicyDirs(e.GOOS, connector)
		if len(dirs) > 0 {
			set[dirs[0]] = true
		}
	}
	return sortedKeys(set)
}

// agentPrefixEnvironment passes enrollment.agent_prefixes to the agent
// discovery in the enumerator and guardian, and on Linux to the sensor
// helper's kernel-control anchors.
func agentPrefixEnvironment(cfg *validatedConfig) map[string]string {
	env := map[string]string{}
	if cfg != nil && len(cfg.AgentPrefixes) > 0 {
		env[enterprisehooks.TrustedBinPrefixesEnv] = strings.Join(cfg.AgentPrefixes, ":")
	}
	return env
}

func proxyEnvironment(cfg *validatedConfig) map[string]string {
	env := map[string]string{}
	if cfg == nil {
		return env
	}
	if cfg.HTTPSProxy != "" {
		env["HTTPS_PROXY"] = cfg.HTTPSProxy
		env["https_proxy"] = cfg.HTTPSProxy
	}
	if cfg.NoProxy != "" {
		env["NO_PROXY"] = cfg.NoProxy
		env["no_proxy"] = cfg.NoProxy
	}
	return env
}

func (e *Env) renderDescriptor(in renderInputs) ([]byte, error) {
	d := &managed.RuntimeDescriptor{
		SchemaVersion:           managed.RuntimeDescriptorSchemaVersion,
		Profile:                 managed.ProfileStandalone,
		ProductVersion:          in.Version,
		ServiceUser:             in.Account.Name,
		ServiceUID:              in.Account.UID,
		ServiceGID:              in.Account.GID,
		APIAddr:                 e.Layout.APIAddr,
		HookSocket:              e.Layout.HookSocketPath,
		MachinePolicyConnectors: append([]string{}, in.MachinePolicy...),
		DisableSelfUpdate:       true,
		InstalledAt:             in.InstalledAt,
	}
	sort.Strings(d.MachinePolicyConnectors)
	if in.Config != nil {
		d.DisableSelfUpdate = in.Config.SelfUpdateDisabled
	}
	return managed.MarshalRuntimeDescriptor(d)
}

// injectPlistEnvironment adds variables to a plist's EnvironmentVariables
// dictionary. The embedded plists are fixed documents, so a textual
// insertion after the dictionary's opening tag is exact; the result is
// checked to still be well-formed XML.
func injectPlistEnvironment(data []byte, env map[string]string) ([]byte, error) {
	if len(env) == 0 {
		return data, nil
	}
	marker := []byte("<key>EnvironmentVariables</key>")
	index := bytes.Index(data, marker)
	if index < 0 {
		return nil, fmt.Errorf("plist has no EnvironmentVariables dictionary")
	}
	open := bytes.Index(data[index:], []byte("<dict>"))
	if open < 0 {
		return nil, fmt.Errorf("plist EnvironmentVariables is not a dictionary")
	}
	insertAt := index + open + len("<dict>")
	var b bytes.Buffer
	for _, key := range sortedKeys(env) {
		b.WriteString("\n\t\t<key>")
		_ = xml.EscapeText(&b, []byte(key))
		b.WriteString("</key>\n\t\t<string>")
		_ = xml.EscapeText(&b, []byte(env[key]))
		b.WriteString("</string>")
	}
	out := append(append(append([]byte{}, data[:insertAt]...), b.Bytes()...), data[insertAt:]...)
	decoder := xml.NewDecoder(bytes.NewReader(out))
	decoder.Strict = true
	for {
		if _, err := decoder.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("rendered plist is not well-formed: %w", err)
		}
	}
	return out, nil
}

// systemdQuote quotes a value for a systemd directive when it contains
// whitespace, quotes or specifiers.
func systemdQuote(value string) string {
	if !strings.ContainsAny(value, " \t\"'\\%") {
		return value
	}
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + replacer.Replace(value) + `"`
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
