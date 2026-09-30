// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RuntimeDescriptorSchemaVersion is the current managed runtime descriptor
// schema. Readers reject any other value.
const RuntimeDescriptorSchemaVersion = 1

// runtimeDescriptorLimit bounds the descriptor read; the document is a few
// hundred bytes, so anything larger is malformed or hostile.
const runtimeDescriptorLimit = 64 << 10

// RuntimeDescriptor is the public, non-secret description of a standalone
// managed deployment. The lifecycle writes it administrator-owned and
// world-readable; the admin-owned hook binary, the per-user installers and
// status read it to learn that the host is managed, which gateway identity
// to trust and where the hook socket lives. It never carries credentials.
type RuntimeDescriptor struct {
	SchemaVersion  int    `json:"schema_version"`
	Profile        string `json:"profile"`
	ProductVersion string `json:"product_version"`
	// ServiceUser is the gateway identity: a unix account name, or the
	// Windows virtual service account (NT SERVICE\DefenseClawGateway).
	ServiceUser string `json:"service_user"`
	// ServiceUID/ServiceGID are the unix gateway ids (-1 on Windows).
	ServiceUID int `json:"service_uid"`
	ServiceGID int `json:"service_gid"`
	// ServiceName is the Windows SCM service name (empty on unix).
	ServiceName string `json:"service_name,omitempty"`
	APIAddr     string `json:"api_addr"`
	HookSocket  string `json:"hook_socket,omitempty"`
	// MachinePolicyConnectors lists connectors whose DefenseClaw hooks are
	// published through vendor machine policy, so every local user of that
	// agent is inspected without a per-user registration.
	MachinePolicyConnectors []string `json:"machine_policy_connectors"`
	DisableSelfUpdate       bool     `json:"disable_self_update"`
	InstalledAt             string   `json:"installed_at"`
}

// ErrNoRuntimeDescriptor reports that the host has no standalone managed
// deployment.
var ErrNoRuntimeDescriptor = errors.New("no managed runtime descriptor")

// Validate checks the descriptor's internal consistency.
func (d *RuntimeDescriptor) Validate() error {
	if d == nil {
		return errors.New("managed runtime descriptor is nil")
	}
	if d.SchemaVersion != RuntimeDescriptorSchemaVersion {
		return fmt.Errorf("managed runtime descriptor schema_version %d is not supported (want %d)", d.SchemaVersion, RuntimeDescriptorSchemaVersion)
	}
	if !IsStandaloneProfile(d.Profile) {
		return fmt.Errorf("managed runtime descriptor profile %q is not %s", d.Profile, ProfileStandalone)
	}
	if strings.TrimSpace(d.ServiceUser) == "" {
		return errors.New("managed runtime descriptor service_user is empty")
	}
	if d.APIAddr != StandaloneAPIAddr {
		return fmt.Errorf("managed runtime descriptor api_addr %q is not %s", d.APIAddr, StandaloneAPIAddr)
	}
	if d.HookSocket != "" && !filepath.IsAbs(d.HookSocket) {
		return fmt.Errorf("managed runtime descriptor hook_socket %q is not absolute", d.HookSocket)
	}
	seen := make(map[string]bool, len(d.MachinePolicyConnectors))
	for _, name := range d.MachinePolicyConnectors {
		if name == "" || name != strings.ToLower(strings.TrimSpace(name)) {
			return fmt.Errorf("managed runtime descriptor connector %q is not a canonical name", name)
		}
		if seen[name] {
			return fmt.Errorf("managed runtime descriptor lists connector %q twice", name)
		}
		seen[name] = true
	}
	return nil
}

// HasMachinePolicyConnector reports whether connector is published through
// machine policy.
func (d *RuntimeDescriptor) HasMachinePolicyConnector(connector string) bool {
	if d == nil {
		return false
	}
	connector = strings.ToLower(strings.TrimSpace(connector))
	for _, name := range d.MachinePolicyConnectors {
		if name == connector {
			return true
		}
	}
	return false
}

// MarshalRuntimeDescriptor renders the canonical descriptor bytes: sorted
// connectors, indented JSON and a trailing newline, so an unchanged
// deployment rewrites byte-identical content.
func MarshalRuntimeDescriptor(d *RuntimeDescriptor) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	canonical := *d
	canonical.MachinePolicyConnectors = append([]string{}, d.MachinePolicyConnectors...)
	sort.Strings(canonical.MachinePolicyConnectors)
	data, err := json.MarshalIndent(&canonical, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseRuntimeDescriptor strictly decodes and validates descriptor bytes.
func ParseRuntimeDescriptor(data []byte) (*RuntimeDescriptor, error) {
	if len(data) > runtimeDescriptorLimit {
		return nil, fmt.Errorf("managed runtime descriptor exceeds %d bytes", runtimeDescriptorLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var d RuntimeDescriptor
	if err := decoder.Decode(&d); err != nil {
		return nil, fmt.Errorf("decode managed runtime descriptor: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("managed runtime descriptor has trailing data")
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// LoadRuntimeDescriptor reads the descriptor at path after the same trust
// checks the managed config gets: administrator-owned file and ancestors,
// no symlinks or reparse points, no untrusted writers. A missing file
// returns ErrNoRuntimeDescriptor.
func LoadRuntimeDescriptor(path string) (*RuntimeDescriptor, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoRuntimeDescriptor
		}
		return nil, fmt.Errorf("inspect managed runtime descriptor: %w", err)
	}
	if err := ValidateTrustedFilePath(path, "managed runtime descriptor"); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open managed runtime descriptor: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, runtimeDescriptorLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read managed runtime descriptor: %w", err)
	}
	return ParseRuntimeDescriptor(data)
}
