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

// Package bundle applies signed policy bundles to a DefenseClaw Agent
// Substrate cluster (PLAN §9, J16). A Substrate bundle is an enterprise
// bundle (internal/enterprisebundle: the same manifest, signature, anchors
// and archive) that targets the linux platform and whose config.yaml holds
// only guardrail profiles (their sandbox sections) and match.substrate
// profile assignments. It is applied to a stage, a list of atespaces or
// every atespace; the controller layers the stage's active bundle over
// config.yaml for the actors of those atespaces, and substrate.admin still
// tightens every profile. State, the kept bundles and receipts live in two
// ConfigMaps of the DefenseClaw namespace; the trust anchors come from an
// admin-only Secret.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Platform is the platform a Substrate bundle must target: actors and the
// controller run on Linux.
const Platform = eb.PlatformLinux

// MaxArchiveBytes bounds one bundle archive: two are kept per stage in a
// ConfigMap (1 MiB in all), and a policy bundle is a few KiB of YAML.
const MaxArchiveBytes = 48 << 10

// Refusal codes this package adds to the enterprise bundle codes.
const (
	CodeNotSubstrate eb.Code = "not_substrate_policy"
	CodeStageInvalid eb.Code = "stage_invalid"
	CodeNoPrevious   eb.Code = "no_previous_bundle"
	CodeStateInvalid eb.Code = "state_invalid"
)

func refuse(code eb.Code, path, format string, a ...any) *eb.Error {
	return &eb.Error{Code: code, Path: path, Detail: fmt.Sprintf(format, a...)}
}

// Policy is what a Substrate bundle sets.
type Policy struct {
	// Profiles are guardrail profiles: only description and sandbox.
	Profiles map[string]config.GuardrailProfile
	// Assignments are profile assignments that select actors
	// (match.substrate only), in order.
	Assignments []config.ProfileAssignment
}

// Overlay returns base with the policy layered over it: a bundle profile
// replaces the sandbox section (and description) of the profile of the same
// name or adds the profile; the bundle's assignments replace every
// match.substrate assignment of base. Host assignments stay (they never
// select an actor). base is not modified.
func (p Policy) Overlay(base *config.Config) *config.Config {
	out := *base
	out.Guardrail.Profiles = maps.Clone(base.Guardrail.Profiles)
	if out.Guardrail.Profiles == nil {
		out.Guardrail.Profiles = map[string]config.GuardrailProfile{}
	}
	for name, bp := range p.Profiles {
		cur := out.Guardrail.Profiles[name]
		cur.Sandbox = bp.Sandbox
		if bp.Description != "" {
			cur.Description = bp.Description
		}
		out.Guardrail.Profiles[name] = cur
	}
	assignments := slices.Clone(p.Assignments)
	for _, a := range base.Guardrail.ProfileAssignments {
		if a.Match.Substrate.Empty() {
			assignments = append(assignments, a)
		}
	}
	out.Guardrail.ProfileAssignments = assignments
	return &out
}

// Verified is a bundle that passed every check.
type Verified struct {
	Manifest       *eb.Manifest
	ManifestSHA256 string
	ArchiveSHA256  string
	KeyID          string
	Policy         Policy
	Archive        []byte
	// AlreadyApplied is set when the bundle is the stage's active one.
	AlreadyApplied bool
}

// Record names it.
func (v *Verified) Record(now time.Time, source string) *Record {
	return &Record{BundleID: v.Manifest.BundleID, Version: v.Manifest.Version, ManifestSHA256: v.ManifestSHA256,
		ArchiveSHA256: v.ArchiveSHA256, KeyID: v.KeyID, CreatedBy: v.Manifest.CreatedBy,
		ChangeSummary: v.Manifest.ChangeSummary, AppliedAt: now.UTC(), Source: source}
}

// Check says what a verification is for.
type Check struct {
	// Active is the stage's active bundle; Floor the highest version the
	// stage ever applied. A bundle equal to Active is AlreadyApplied; any
	// other at or below the floor (or the anchors' min_version) is refused
	// (version_not_newer), so an older or replayed bundle never applies.
	Active *Record
	Floor  uint64
	// Reactivate verifies a bundle the stage applied before (a rollback,
	// or the controller re-reading its state): the version floor is not
	// checked and a retired key still verifies it; a revoked or expired
	// key never does.
	Reactivate bool
}

// Verify reads and verifies a bundle archive against the anchors and base,
// in the enterprise bundle order: anchor, key, signature, manifest, tenant
// and device group, platform, version floor, files[], inline secrets and
// secret references, then the Substrate policy rules.
func Verify(archive []byte, anchors *eb.Anchors, base *config.Config, now time.Time, chk Check) (*Verified, error) {
	if len(archive) > MaxArchiveBytes {
		return nil, refuse(eb.CodeArchiveInvalid, "", "larger than %d bytes", MaxArchiveBytes)
	}
	if anchors == nil {
		return nil, refuse(eb.CodeAnchorMissing, eb.AnchorsName, "no trust anchors; bundle mode needs bundle-anchors.json from the admin Secret")
	}
	b, err := eb.ReadArchive(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	sig, err := eb.DecodeSignature(b.Signature)
	if err != nil {
		return nil, err
	}
	key := anchors.Key(sig.KeyID)
	switch {
	case key == nil:
		return nil, refuse(eb.CodeKeyUnknown, eb.SignatureName, "key %s is not a trust anchor key", sig.KeyID)
	case key.Status == eb.KeyRevoked:
		return nil, refuse(eb.CodeKeyRevoked, eb.SignatureName, "key %s is revoked", sig.KeyID)
	case !key.ValidAt(now):
		return nil, refuse(eb.CodeKeyExpired, eb.SignatureName, "key %s is valid from %s to %s", sig.KeyID, key.NotBefore, key.NotAfter)
	case len(b.Manifest) == 0:
		return nil, refuse(eb.CodeManifestInvalid, eb.ManifestName, "the bundle has no manifest")
	}
	if err := eb.VerifySignature(b.Manifest, sig, key.Public()); err != nil {
		return nil, err
	}
	m, err := eb.DecodeManifest(b.Manifest)
	if err != nil {
		return nil, err
	}
	if m.TenantID != anchors.TenantID {
		return nil, refuse(eb.CodeTenantMismatch, "tenant_id", "the bundle is for tenant %s, this cluster for tenant %s", m.TenantID, anchors.TenantID)
	}
	if !anchors.AllowsDeviceGroup(m.Target.DeviceGroup) {
		return nil, refuse(eb.CodeTargetMismatch, "target.device_group", "this cluster is not in device group %s", m.Target.DeviceGroup)
	}
	if !slices.Contains(m.Target.Platforms, Platform) {
		return nil, refuse(eb.CodeTargetMismatch, "target.platforms", "a Substrate bundle must target linux")
	}
	if created, _ := m.CreatedTime(); !key.ValidAt(created) {
		return nil, refuse(eb.CodeKeyExpired, "created_at", "the bundle was created outside the validity of key %s", sig.KeyID)
	}
	msum, asum := sha256.Sum256(b.Manifest), sha256.Sum256(archive)
	v := &Verified{Manifest: m, ManifestSHA256: hex.EncodeToString(msum[:]), ArchiveSHA256: hex.EncodeToString(asum[:]),
		KeyID: sig.KeyID, Archive: archive}
	if a := chk.Active; a != nil && a.BundleID == m.BundleID && a.Version == m.Version {
		if a.ManifestSHA256 != v.ManifestSHA256 {
			return nil, refuse(eb.CodeVersionNotNewer, "version", "the manifest differs from the active bundle %s version %d", m.BundleID, m.Version)
		}
		v.AlreadyApplied = true
	}
	if m.Version < anchors.MinVersion {
		return nil, refuse(eb.CodeVersionNotNewer, "version", "version %d is below the anchors' min_version %d", m.Version, anchors.MinVersion)
	}
	if !chk.Reactivate && !v.AlreadyApplied {
		if floor := max(chk.Floor, anchors.MinVersion); m.Version <= floor {
			return nil, refuse(eb.CodeVersionNotNewer, "version", "version %d is not above the stage floor %d (a rollback is bundle rollback, or a new, higher version)", m.Version, floor)
		}
		if key.Status == eb.KeyRetired {
			return nil, refuse(eb.CodeKeyExpired, eb.SignatureName, "key %s is retired; it verifies only bundles already applied", sig.KeyID)
		}
	}
	if err := eb.CheckFiles(m, b); err != nil {
		return nil, err
	}
	if err := eb.CheckInlineSecrets(b); err != nil {
		return nil, err
	}
	if len(m.SecretRefs) > 0 {
		return nil, refuse(CodeNotSubstrate, "secret_refs", "a Substrate bundle carries no credentials; actors get secrets as references in substrate.secrets")
	}
	for _, p := range b.Paths() {
		if p != eb.ConfigName {
			return nil, refuse(CodeNotSubstrate, p, "a Substrate bundle holds config.yaml only")
		}
	}
	raw, ok := b.Files[eb.ConfigName]
	if !ok {
		return nil, refuse(eb.CodeFileMissing, eb.ConfigName, "the bundle has no config.yaml")
	}
	pol, err := ParsePolicy(raw, base)
	if err != nil {
		return nil, err
	}
	v.Policy = pol
	return v, nil
}

// ParsePolicy reads a Substrate bundle's config.yaml: config_version and
// guardrail.profiles / guardrail.profile_assignments only, profiles with
// description and sandbox only, assignments that select actors only. The
// policy layered over base must validate, and every profile's sandbox
// section must tighten substrate.admin.
func ParsePolicy(raw []byte, base *config.Config) (Policy, error) {
	bad := func(path, format string, a ...any) (Policy, error) {
		return Policy{}, refuse(eb.CodeConfigInvalid, path, format, a...)
	}
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return bad(eb.ConfigName, "not a YAML mapping")
	}
	for k := range top {
		if k != "config_version" && k != "deployment_mode" && k != "guardrail" {
			return Policy{}, refuse(CodeNotSubstrate, k, "a Substrate bundle sets only guardrail.profiles and guardrail.profile_assignments")
		}
	}
	var doc struct {
		ConfigVersion  int    `yaml:"config_version"`
		DeploymentMode string `yaml:"deployment_mode"`
		Guardrail      struct {
			Profiles    map[string]config.GuardrailProfile `yaml:"profiles"`
			Assignments []config.ProfileAssignment         `yaml:"profile_assignments"`
		} `yaml:"guardrail"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return Policy{}, refuse(CodeNotSubstrate, "guardrail", "a Substrate bundle sets only guardrail.profiles and guardrail.profile_assignments: %s", boundedYAMLError(err))
	}
	if doc.DeploymentMode != "" && doc.DeploymentMode != "managed_enterprise" {
		return bad("deployment_mode", "want managed_enterprise (bundle sign needs it) or nothing")
	}
	if doc.ConfigVersion != 0 && doc.ConfigVersion != 8 && doc.ConfigVersion != 9 {
		return bad("config_version", "want 8 or 9")
	}
	pol := Policy{Profiles: doc.Guardrail.Profiles, Assignments: doc.Guardrail.Assignments}
	if len(pol.Profiles) == 0 && len(pol.Assignments) == 0 {
		return bad("guardrail", "the bundle sets no profile and no assignment")
	}
	names := slices.Sorted(maps.Keys(pol.Profiles))
	for _, name := range names {
		p := pol.Profiles[name]
		probe := config.GuardrailProfile{Description: p.Description, Sandbox: p.Sandbox}
		if !profileEqual(p, probe) {
			return Policy{}, refuse(CodeNotSubstrate, "guardrail.profiles."+name, "only description and sandbox apply to actors")
		}
		if _, err := config.TightenOpenShellAdmin(base.Substrate.Admin, p.Sandbox); err != nil {
			return bad("guardrail.profiles."+name+".sandbox", "%s", bounded(err.Error()))
		}
	}
	for i, a := range pol.Assignments {
		if a.Match.Substrate.Empty() || !a.Match.Empty() {
			return Policy{}, refuse(CodeNotSubstrate, fmt.Sprintf("guardrail.profile_assignments[%d]", i), "an assignment in a Substrate bundle selects actors with match.substrate only")
		}
	}
	if err := pol.Overlay(base).ValidateGuardrailProfiles(); err != nil {
		return bad("guardrail", "%s", bounded(err.Error()))
	}
	return pol, nil
}

func profileEqual(a, b config.GuardrailProfile) bool {
	ay, _ := yaml.Marshal(a)
	by, _ := yaml.Marshal(b)
	return bytes.Equal(ay, by)
}

func boundedYAMLError(err error) string {
	// yaml.v3 names the field and line, never a value of another key.
	return bounded(strings.TrimPrefix(err.Error(), "yaml: "))
}

func bounded(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// profileNames are the profile names a policy sets, sorted.
func (p Policy) profileNames() []string {
	names := make([]string, 0, len(p.Profiles))
	for n := range p.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
