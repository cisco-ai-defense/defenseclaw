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

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"gopkg.in/yaml.v3"
)

// The YAML form is the OpenShell policy file format accepted by
// `openshell sandbox create --policy` and `openshell policy set`. Only the
// fields DefenseClaw renders are modelled; ParseYAML rejects every other key,
// so a document that round-trips is free of unknown fields.

type yamlPolicy struct {
	Version         uint32              `yaml:"version"`
	Filesystem      *yamlFilesystem     `yaml:"filesystem_policy,omitempty"`
	Landlock        *yamlLandlock       `yaml:"landlock,omitempty"`
	Process         *yamlProcess        `yaml:"process,omitempty"`
	NetworkPolicies map[string]yamlRule `yaml:"network_policies"`
}

type yamlFilesystem struct {
	IncludeWorkdir bool     `yaml:"include_workdir"`
	ReadOnly       []string `yaml:"read_only,omitempty"`
	ReadWrite      []string `yaml:"read_write,omitempty"`
}

type yamlLandlock struct {
	Compatibility string `yaml:"compatibility"`
}

type yamlProcess struct {
	RunAsUser  string `yaml:"run_as_user,omitempty"`
	RunAsGroup string `yaml:"run_as_group,omitempty"`
}

type yamlRule struct {
	Endpoints []yamlEndpoint `yaml:"endpoints"`
	Binaries  []yamlBinary   `yaml:"binaries"`
}

type yamlEndpoint struct {
	Host        string   `yaml:"host"`
	Port        uint32   `yaml:"port,omitempty"`
	Ports       []uint32 `yaml:"ports,omitempty"`
	Protocol    string   `yaml:"protocol,omitempty"`
	TLS         string   `yaml:"tls,omitempty"`
	Enforcement string   `yaml:"enforcement,omitempty"`
	Access      string   `yaml:"access,omitempty"`
	AllowedIPs  []string `yaml:"allowed_ips,omitempty"`
	Path        string   `yaml:"path,omitempty"`
}

type yamlBinary struct {
	Path string `yaml:"path"`
}

var (
	tlsNames = map[v1.NetworkTLSMode]string{
		v1.NetworkTLSModeUnspecified: "",
		v1.NetworkTLSModeSkip:        "skip",
	}
	enforcementNames = map[v1.NetworkEnforcementMode]string{
		v1.NetworkEnforcementModeUnspecified: "",
		v1.NetworkEnforcementModeEnforce:     "enforce",
		v1.NetworkEnforcementModeAudit:       "audit",
	}
	accessNames = map[v1.NetworkAccessPreset]string{
		v1.NetworkAccessPresetUnspecified: "",
		v1.NetworkAccessPresetReadOnly:    "read-only",
		v1.NetworkAccessPresetReadWrite:   "read-write",
		v1.NetworkAccessPresetFull:        "full",
	}
)

// representableEndpoint is the subset of PolicyNetworkEndpoint the YAML form
// carries. Any other populated field would be silently dropped, so
// MarshalYAML refuses it instead.
func representableEndpoint(ep v1.PolicyNetworkEndpoint) v1.PolicyNetworkEndpoint {
	return v1.PolicyNetworkEndpoint{
		Host:        ep.Host,
		Port:        ep.Port,
		Ports:       ep.Ports,
		Protocol:    ep.Protocol,
		TLS:         ep.TLS,
		Enforcement: ep.Enforcement,
		Access:      ep.Access,
		AllowedIPs:  ep.AllowedIPs,
		Path:        ep.Path,
	}
}

// MarshalYAML renders a validated policy in the OpenShell policy file format.
func MarshalYAML(p *v1.SandboxPolicy) ([]byte, error) {
	if err := Validate(p); err != nil {
		return nil, err
	}
	doc := yamlPolicy{Version: p.Version, NetworkPolicies: map[string]yamlRule{}}
	doc.Filesystem = &yamlFilesystem{
		IncludeWorkdir: p.Filesystem.IncludeWorkdir,
		ReadOnly:       p.Filesystem.ReadOnly,
		ReadWrite:      p.Filesystem.ReadWrite,
	}
	doc.Landlock = &yamlLandlock{Compatibility: p.Landlock.Compatibility}
	doc.Process = &yamlProcess{RunAsUser: p.Process.RunAsUser, RunAsGroup: p.Process.RunAsGroup}
	for name, rule := range p.NetworkPolicies {
		out := yamlRule{}
		for _, ep := range rule.Endpoints {
			if !reflect.DeepEqual(ep, representableEndpoint(ep)) {
				return nil, fmt.Errorf("openshell policy: rule %q endpoint %s uses fields the policy file format does not carry", name, ep.Host)
			}
			tls, okTLS := tlsNames[ep.TLS]
			enforcement, okEnforcement := enforcementNames[ep.Enforcement]
			access, okAccess := accessNames[ep.Access]
			if !okTLS || !okEnforcement || !okAccess {
				return nil, fmt.Errorf("openshell policy: rule %q endpoint %s has an unknown enum value", name, ep.Host)
			}
			out.Endpoints = append(out.Endpoints, yamlEndpoint{
				Host:        ep.Host,
				Port:        ep.Port,
				Ports:       ep.Ports,
				Protocol:    ep.Protocol,
				TLS:         tls,
				Enforcement: enforcement,
				Access:      access,
				AllowedIPs:  ep.AllowedIPs,
				Path:        ep.Path,
			})
		}
		for _, b := range rule.Binaries {
			out.Binaries = append(out.Binaries, yamlBinary{Path: b.Path})
		}
		doc.NetworkPolicies[name] = out
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("openshell policy: encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("openshell policy: encode yaml: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseYAML decodes one OpenShell policy document strictly: unknown keys,
// trailing documents and unknown enum values are errors, and the result must
// pass Validate.
func ParseYAML(data []byte) (*v1.SandboxPolicy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc yamlPolicy
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("openshell policy: decode yaml: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("openshell policy: yaml holds more than one document")
	}
	p := &v1.SandboxPolicy{Version: doc.Version, NetworkPolicies: map[string]v1.NetworkPolicyRule{}}
	if doc.Filesystem != nil {
		p.Filesystem = &v1.FilesystemPolicy{
			IncludeWorkdir: doc.Filesystem.IncludeWorkdir,
			ReadOnly:       doc.Filesystem.ReadOnly,
			ReadWrite:      doc.Filesystem.ReadWrite,
		}
	}
	if doc.Landlock != nil {
		p.Landlock = &v1.LandlockPolicy{Compatibility: doc.Landlock.Compatibility}
	}
	if doc.Process != nil {
		p.Process = &v1.ProcessPolicy{RunAsUser: doc.Process.RunAsUser, RunAsGroup: doc.Process.RunAsGroup}
	}
	for name, rule := range doc.NetworkPolicies {
		out := v1.NetworkPolicyRule{Name: name}
		for _, ep := range rule.Endpoints {
			tls, okTLS := reverseLookup(tlsNames, ep.TLS)
			enforcement, okEnforcement := reverseLookup(enforcementNames, ep.Enforcement)
			access, okAccess := reverseLookup(accessNames, ep.Access)
			if !okTLS || !okEnforcement || !okAccess {
				return nil, fmt.Errorf("openshell policy: rule %q endpoint %s has an unknown tls, enforcement or access value", name, ep.Host)
			}
			out.Endpoints = append(out.Endpoints, v1.PolicyNetworkEndpoint{
				Host:        ep.Host,
				Port:        ep.Port,
				Ports:       ep.Ports,
				Protocol:    ep.Protocol,
				TLS:         tls,
				Enforcement: enforcement,
				Access:      access,
				AllowedIPs:  ep.AllowedIPs,
				Path:        ep.Path,
			})
		}
		for _, b := range rule.Binaries {
			out.Binaries = append(out.Binaries, v1.PolicyNetworkBinary{Path: b.Path})
		}
		p.NetworkPolicies[name] = out
	}
	if err := Validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

func reverseLookup[K comparable](m map[K]string, name string) (K, bool) {
	for k, v := range m {
		if v == name {
			return k, true
		}
	}
	var zero K
	return zero, false
}
