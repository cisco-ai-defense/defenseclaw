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
	"context"
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
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const (
	recordVersion = 1
	recordDirName = "manager"
	// recordMaxBytes bounds one record file, read and written alike: save
	// refuses a record a restart could not read back.
	recordMaxBytes = 8 << 20
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

	// Gateway, GatewayEndpoint and GatewayWorkspace say where the sandbox
	// lives: the gateway registration, its endpoint and the OpenShell
	// workspace (older records learn them once reconciliation finds the
	// sandbox). While DefenseClaw is connected to another gateway or
	// workspace, not finding the sandbox proves nothing, so it is not
	// released (see gatewayElsewhere).
	Gateway          string `json:"gateway,omitempty"`
	GatewayEndpoint  string `json:"gateway_endpoint,omitempty"`
	GatewayWorkspace string `json:"gateway_workspace,omitempty"`

	CredentialProfile string   `json:"credential_profile,omitempty"`
	BedrockRegion     string   `json:"bedrock_region,omitempty"`
	Providers         []string `json:"providers,omitempty"`
	// EgressUser is the proxy credential's username (the password is in
	// the sandbox environment only).
	EgressUser string `json:"egress_user,omitempty"`

	// Phase is the last lifecycle phase recorded for the sandbox, so a
	// restarted daemon reports the transition it observes.
	Phase string `json:"phase,omitempty"`
	// ReadyAt is when DefenseClaw saw the sandbox become ready (zero while
	// it is not): a restarted daemon that finds it still ready reports its
	// uptime from then. OpenShell 0.1.1 reports no transition times.
	ReadyAt time.Time `json:"ready_at,omitempty"`
	// Cursor resumes the WatchSandbox stream.
	Cursor string `json:"cursor,omitempty"`
	// Unblocks are sandbox-scoped egress unblock patterns.
	Unblocks []string `json:"unblocks,omitempty"`
	// ApprovedRules are the triaged OpenShell rules (allow_*) approvals
	// applied, each with who approved it: automatic (triage, on its own) or
	// operator (the user, whose approval stays with the rule). A rule only
	// DefenseClaw approved is removed once the policy would no longer
	// approve it on its own (enforceApprovedRules). The map is replaced,
	// never changed in place.
	ApprovedRules map[string]string `json:"approved_rules,omitempty"`

	Workspace *sandboxapi.WorkspaceSummary `json:"workspace,omitempty"`
	MCP       *sandboxapi.MCPSummary       `json:"mcp,omitempty"`
	// RunConfig renders the per-run harness files again on start (nil for
	// a harness without them, and in records from before it existed).
	RunConfig  *runConfigRecord       `json:"run_config,omitempty"`
	Violations []sandboxapi.Violation `json:"violations,omitempty"`
	Warnings   []string               `json:"warnings,omitempty"`

	// Guard is the nested-repository guard state of the current session
	// (mount mode). Copies of a record share it, so it is replaced, never
	// changed in place.
	Guard *guardRecord `json:"guard,omitempty"`

	// Retained marks a sandbox that is gone (deleted with --keep-snapshot,
	// or outside DefenseClaw) whose record is kept only for its
	// pre-session snapshot: undo, review and delete still reach it.
	Retained bool `json:"retained,omitempty"`
}

type recordStore struct {
	dir string
	// beforeWrite, when set (tests), runs before each record is written.
	beforeWrite func(name string)
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
	if len(data)+1 > recordMaxBytes {
		// A restart would skip the file and adopt the sandbox without its
		// run flags; keep the last record that fits instead.
		return fmt.Errorf("the record of sandbox %s would be %d bytes, more than the %d a restart reads back", r.Name, len(data)+1, recordMaxBytes)
	}
	if s.beforeWrite != nil {
		s.beforeWrite(r.Name)
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

func (s recordStore) has(name string) bool {
	p, err := s.path(name)
	if err != nil {
		return false
	}
	_, err = os.Lstat(p)
	return err == nil
}

// OrphanedSandboxData lists the sandboxes that have data under
// <data_dir>/sandboxes/<name> (mount state and masks, copy-mode state, run
// files) or a pre-session snapshot under <data_dir>/snapshots/<name> (with
// its refs in the project) but no daemon record: an interrupted create or
// delete, or an older build, left it. RemoveOrphanedSandboxData removes it.
func OrphanedSandboxData(dataDir string) []string {
	records := newRecordStore(dataDir)
	seen := map[string]bool{}
	var out []string
	for _, root := range []string{"sandboxes", orphanSnapshotsDir} {
		entries, err := os.ReadDir(filepath.Join(dataDir, root))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || name == recordDirName || seen[name] || !openshell.ValidSandboxName(name) || records.has(name) {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// orphanSnapshotsDir is where package workspace keeps the pre-session
// snapshots, one directory per sandbox name.
const orphanSnapshotsDir = "snapshots"

// orphanSnapshotTimeout bounds the removal of an orphaned snapshot, which
// deletes its refs in the project with git.
const orphanSnapshotTimeout = 2 * time.Minute

// RemoveOrphanedSandboxData releases and removes the data an orphaned
// sandbox left (see OrphanedSandboxData): its mount pins and mask files,
// its pre-session snapshot and the refs it holds in the project, its
// copy-mode state and its run files, then the directory. A sandbox the
// daemon still records is refused, and a directory that holds anything
// else is left in place.
func RemoveOrphanedSandboxData(dataDir, name string) error {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return fmt.Errorf("invalid sandbox name %q", name)
	}
	if newRecordStore(dataDir).has(name) {
		return fmt.Errorf("sandbox %s is still recorded; delete it with `defenseclaw sandbox delete %s`", name, name)
	}
	var errs []error
	keep := func(err error) {
		if err != nil && !errors.Is(err, openshell.ErrInvalidName) {
			errs = append(errs, err)
		}
	}
	keep(workspace.ReleaseMount(dataDir, name))
	ctx, cancel := context.WithTimeout(context.Background(), orphanSnapshotTimeout)
	defer cancel()
	if err := workspace.DeleteSnapshot(ctx, dataDir, name); !errors.Is(err, workspace.ErrSnapshotNotFound) {
		keep(err)
	}
	keep(workspace.DeleteCopy(dataDir, name))
	dir := filepath.Join(dataDir, "sandboxes", name)
	keep(os.RemoveAll(filepath.Join(dir, runConfigDirName)))
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("%s holds files DefenseClaw did not write there; it is left in place", dir))
	}
	return errors.Join(errs...)
}

// RecordedSandbox is a sandbox the daemon keeps a record of under a data
// dir (RecordedSandboxes).
type RecordedSandbox struct {
	Name string
	// Retained marks a sandbox that is gone, whose record keeps only its
	// pre-session snapshot.
	Retained bool
}

// RecordedSandboxes lists the sandboxes recorded under dataDir, for sandbox
// teardown while the daemon is not running (RemoveSandboxState).
// Unreadable records are left out.
func RecordedSandboxes(dataDir string) []RecordedSandbox {
	recs, _ := newRecordStore(dataDir).loadAll()
	out := make([]RecordedSandbox, 0, len(recs))
	for _, r := range recs {
		out = append(out, RecordedSandbox{Name: r.Name, Retained: r.Retained})
	}
	return out
}

// RemoveSandboxState is the local half of the daemon's delete (cleanup and
// deleteRetained) for a sandbox that is gone from the OpenShell gateway
// while the daemon is not running: sandbox teardown deletes it there
// directly, and turns openshell.enabled off, so no daemon would reconcile
// it later. It releases a live mount (the protection pins PlanMount set in
// the project's .git, and the mask files), deletes the pre-session snapshot
// and its refs or the copy-mode state, the run files and the ingress
// binding, then the record and the sandbox directory. The gateway side (the
// sandbox, its providers) is the caller's, and so is making sure no daemon
// runs on dataDir. Every step is attempted and the errors are joined; the
// record stays while one failed, so a retry finds the sandbox again.
func RemoveSandboxState(ctx context.Context, dataDir, name string) error {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return fmt.Errorf("invalid sandbox name %q", name)
	}
	store := newRecordStore(dataDir)
	var rec record
	if p, err := store.path(name); err == nil {
		data, err := safefile.ReadRegularFileBounded(p, recordMaxBytes)
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &rec); err != nil || rec.Name != name {
				return fmt.Errorf("sandbox record %s is malformed; it is left in place", name)
			}
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("sandbox record %s: %w", name, err)
		}
	}
	var errs []error
	keep := func(err error) {
		if err != nil && !errors.Is(err, openshell.ErrInvalidName) && !errors.Is(err, workspace.ErrSnapshotNotFound) &&
			!errors.Is(err, workspace.ErrCopyNotFound) {
			errs = append(errs, err)
		}
	}
	keep(workspace.ReleaseMount(dataDir, name))
	keep(workspace.DeleteSnapshot(ctx, dataDir, name))
	keep(workspace.DeleteCopy(dataDir, name))
	dir := filepath.Join(dataDir, "sandboxes", name)
	keep(os.RemoveAll(filepath.Join(dir, runConfigDirName)))
	if rec.BindingID != "" {
		keep(revokeStoredBinding(dataDir, rec.BindingID))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := store.remove(name); err != nil {
		return err
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s holds files DefenseClaw did not write there; it is left in place", dir)
	}
	return nil
}

// revokeStoredBinding revokes an ingress binding in dataDir's binding store
// directly (the daemon is not running); one already gone is no error.
func revokeStoredBinding(dataDir, id string) error {
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(dataDir), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		return fmt.Errorf("open the ingress binding store: %w", err)
	}
	if err := store.Revoke(id); err != nil && !errors.Is(err, sandboxauth.ErrNotFound) {
		return fmt.Errorf("revoke the ingress binding %s: %w", id, err)
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
