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

package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	recordVersion  = 1
	recordDirName  = "manager"
	recordMaxBytes = 1 << 20
)

// runFlags are the `sandbox run` inputs a sandbox was created with. They
// are kept so the sandbox's policy can be re-resolved against the current
// configuration (an administrator change applies to running sandboxes).
type runFlags struct {
	Pack      string   `json:"pack,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	Copy      bool     `json:"copy,omitempty"`
	Safe      bool     `json:"safe,omitempty"`
	Yolo      bool     `json:"yolo,omitempty"`
	Unmask    []string `json:"unmask,omitempty"`
	HostPorts []int    `json:"host_ports,omitempty"`
	NoMCP     bool     `json:"no_mcp,omitempty"`
	Learn     bool     `json:"learn,omitempty"`
	CPU       string   `json:"cpu,omitempty"`
	Memory    string   `json:"memory,omitempty"`
	Context   []string `json:"context,omitempty"`
}

func (f runFlags) packs(harness, project string, gatewayPort int) packs.Flags {
	return packs.Flags{
		Pack: f.Pack, Harness: harness, Project: project, Profile: f.Profile, Copy: f.Copy, Safe: f.Safe,
		Yolo: f.Yolo, Unmask: f.Unmask, HostPorts: f.HostPorts, NoMCP: f.NoMCP, Learn: f.Learn,
		CPU: f.CPU, Memory: f.Memory, OpenShellGatewayPort: gatewayPort,
	}
}

// record is the daemon's durable state of one sandbox, kept under
// <data_dir>/sandboxes/manager/<name>.json (owner-only). Secrets are never
// stored: the ingress token lives only as a hash in the binding store and
// in the OpenShell provider, and the egress proxy credential is recovered
// from the sandbox's own environment.
type record struct {
	Version     int       `json:"version"`
	Name        string    `json:"name"`
	ID          string    `json:"id,omitempty"`
	Harness     string    `json:"harness"`
	BindingID   string    `json:"binding_id"`
	Owner       string    `json:"owner"`
	Project     string    `json:"project,omitempty"`
	Flags       runFlags  `json:"flags"`
	WorkdirMode string    `json:"workdir_mode"`
	Workdir     string    `json:"workdir"`
	CreatedAt   time.Time `json:"created_at"`

	Pack        string `json:"pack,omitempty"`
	PackDigest  string `json:"pack_digest,omitempty"`
	Profile     string `json:"profile"`
	NetworkMode string `json:"network_mode,omitempty"`
	Approvals   string `json:"approvals,omitempty"`
	Yolo        bool   `json:"yolo"`

	Image          string `json:"image"`
	ImageID        string `json:"image_id,omitempty"`
	HarnessVersion string `json:"harness_version,omitempty"`
	HookContract   string `json:"hook_contract,omitempty"`
	TamperTier     string `json:"tamper_tier,omitempty"`

	// TokenDelivery is how the sandbox received its ingress token
	// (openshell.token_delivery at create; empty in older records, see
	// tokenDelivery).
	TokenDelivery string `json:"token_delivery,omitempty"`

	CredentialProfile string   `json:"credential_profile,omitempty"`
	BedrockRegion     string   `json:"bedrock_region,omitempty"`
	Providers         []string `json:"providers,omitempty"`
	// EgressUser is the proxy credential's username (the password is in
	// the sandbox environment only).
	EgressUser string `json:"egress_user,omitempty"`

	// Phase is the last lifecycle phase recorded for the sandbox, so a
	// restarted daemon reports the transition it observes.
	Phase string `json:"phase,omitempty"`
	// Cursor resumes the WatchSandbox stream.
	Cursor string `json:"cursor,omitempty"`
	// Unblocks are sandbox-scoped egress unblock patterns.
	Unblocks []string `json:"unblocks,omitempty"`

	Workspace  *sandboxapi.WorkspaceSummary `json:"workspace,omitempty"`
	Violations []sandboxapi.Violation       `json:"violations,omitempty"`
	Warnings   []string                     `json:"warnings,omitempty"`
}

type recordStore struct {
	dir string
}

func newRecordStore(dataDir string) recordStore {
	return recordStore{dir: filepath.Join(dataDir, "sandboxes", recordDirName)}
}

func (s recordStore) path(name string) (string, error) {
	if !openshell.ValidSandboxName(name) {
		return "", fmt.Errorf("invalid sandbox name %q", name)
	}
	return filepath.Join(s.dir, name+".json"), nil
}

func (s recordStore) save(r *record) error {
	p, err := s.path(r.Name)
	if err != nil {
		return err
	}
	r.Version = recordVersion
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WritePrivate(p, append(data, '\n'))
}

func (s recordStore) remove(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// loadAll reads every record; unreadable files are reported and skipped.
func (s recordStore) loadAll() ([]*record, []error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []error{err}
	}
	var out []*record
	var errs []error
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() || !openshell.ValidSandboxName(name) {
			continue
		}
		data, err := safefile.ReadRegularFileBounded(filepath.Join(s.dir, e.Name()), recordMaxBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("sandbox record %s: %w", name, err))
			continue
		}
		var r record
		if err := json.Unmarshal(data, &r); err != nil || r.Name != name {
			errs = append(errs, fmt.Errorf("sandbox record %s is malformed", name))
			continue
		}
		out = append(out, &r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, errs
}
