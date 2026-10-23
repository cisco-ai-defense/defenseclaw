// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"time"
)

// ComposeInput is what bundle sign writes into a new manifest.
type ComposeInput struct {
	// Bundle holds the files to sign (any manifest or signature in it is
	// replaced); Root is the directory that holds the same files.
	Bundle *Bundle
	Root   string

	BundleID          string
	TenantID          string
	DeviceGroup       string
	Platforms         []string
	Version           uint64
	Parent            string
	RollbackOf        string
	CreatedAt         time.Time
	CreatedBy         string
	ChangeSummary     string
	MinProductVersion string

	// ProductVersion and HostPlatform record which build, on which
	// platform, computed the digests.
	ProductVersion string
	HostPlatform   string
	Digester       PolicyDigester

	// SecretValues are the values of the credentials config.yaml
	// references, by name: each secret_refs entry binds its value
	// (CredentialValueSHA256). The manifest never carries a value.
	SecretValues map[string][]byte
}

// Compose runs the full validator over the files and returns the manifest
// and its exact bytes: the inline-secret scan, the canonical config load,
// secret_refs from the credentials config.yaml names (all required, each
// bound to its value in SecretValues), files[], the per-platform effective
// digests and the reachability warnings. It refuses errors; warnings never
// block.
func Compose(ctx context.Context, in ComposeInput) (*Manifest, []byte, error) {
	b := &Bundle{Files: in.Bundle.Files}
	if err := CheckInlineSecrets(b); err != nil {
		return nil, nil, err
	}
	// Judge the config by the target platforms, never by the signer's own
	// operating system (GAP-0005): a Linux workstation signs a macOS-only
	// key such as enterprise.openshell.e2fsprogs_dir for a darwin target,
	// and every signer refuses it for a Linux or Windows target. The
	// per-platform digest loads below check each remaining target.
	platforms := canonicalPlatforms(in.Platforms)
	cfg, _, err := LoadConfigForPlatform(b, in.Root, platforms[0])
	if err != nil {
		return nil, nil, err
	}
	names, err := ConfigCredentials(b.Files[ConfigName])
	if err != nil {
		return nil, nil, err
	}
	refs := make([]SecretRef, 0, len(names))
	for _, name := range names {
		value, ok := in.SecretValues[name]
		if !ok {
			return nil, nil, refuse(CodeSecretRefUnbound, "secret_refs", "config.yaml references the credential %s; give its value with --secret-file %s=<file> so the bundle binds it", safePath(name), safePath(name))
		}
		refs = append(refs, SecretRef{Ref: SecretRefScheme + name, Required: true, ValueSHA256: CredentialValueSHA256(in.TenantID, name, value)})
	}
	for name := range in.SecretValues {
		if !slices.Contains(names, name) {
			return nil, nil, refuse(CodeManifestInvalid, "secret_refs", "a value is given for the credential %s, which config.yaml does not reference", safePath(name))
		}
	}
	ruleWarnings, _, err := RuleNotBlockingWarnings(cfg)
	if err != nil {
		return nil, nil, refuse(CodeConfigInvalid, ConfigName, "custom rule pack: %s", boundedDetail(err.Error()))
	}
	sectionWarnings, err := AbsentSectionWarnings(b.Files[ConfigName])
	if err != nil {
		return nil, nil, err
	}
	digests, components, err := effectivePolicyDigestsWithComponents(ctx, b, in.Root, platforms, in.Digester)
	if err != nil {
		return nil, nil, err
	}
	m := &Manifest{
		SchemaVersion:     ManifestSchemaVersion,
		BundleID:          in.BundleID,
		TenantID:          in.TenantID,
		Target:            Target{DeviceGroup: in.DeviceGroup, Platforms: platforms},
		Version:           in.Version,
		Parent:            in.Parent,
		RollbackOf:        in.RollbackOf,
		CreatedAt:         in.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		CreatedBy:         in.CreatedBy,
		ChangeSummary:     in.ChangeSummary,
		MinProductVersion: in.MinProductVersion,
		Files:             FileEntries(b),
		SecretRefs:        refs,
		EffectivePolicy:   EffectivePolicy{ProductVersion: in.ProductVersion, ComputedOn: in.HostPlatform, Digests: digests, Components: components},
		Warnings:          limitBundleWarnings(append(append(ruleWarnings, Reachability(cfg, platforms)...), sectionWarnings...)),
	}
	raw, err := m.Marshal()
	if err != nil {
		return nil, nil, err
	}
	// Decode what will be signed, so sign refuses exactly what a device
	// refuses.
	decoded, err := DecodeManifest(raw)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckFiles(decoded, b); err != nil {
		return nil, nil, err
	}
	if err := CheckSecretRefs(decoded, b); err != nil {
		return nil, nil, err
	}
	return decoded, raw, nil
}

// canonicalPlatforms returns the known platforms of names in canonical
// order (all three when names is empty); unknown names are kept at the end
// for the manifest validator to refuse.
func canonicalPlatforms(names []string) []string {
	if len(names) == 0 {
		return append([]string(nil), Platforms...)
	}
	want := map[string]int{}
	for _, name := range names {
		want[name]++
	}
	out := make([]string, 0, len(names))
	for _, platform := range Platforms {
		for ; want[platform] > 0; want[platform]-- {
			out = append(out, platform)
		}
	}
	for _, name := range names {
		if !knownPlatform(name) {
			out = append(out, name)
		}
	}
	return out
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewBundleID returns "b-" and a ULID for t (48-bit milliseconds, 80 random
// bits from r, or crypto/rand when r is nil).
func NewBundleID(t time.Time, r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	ms := t.UnixMilli()
	if ms < 0 || ms >= 1<<48 {
		return "", errors.New("time outside the ULID range")
	}
	var id [16]byte
	for i := 0; i < 6; i++ {
		id[i] = byte(ms >> (8 * (5 - i)))
	}
	if _, err := io.ReadFull(r, id[6:]); err != nil {
		return "", err
	}
	// 128 bits in 26 base32 digits: the first digit carries the top 3 bits.
	out := make([]byte, 26)
	var acc uint64
	bits := 0
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(id[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = crockford[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	if pos == 0 {
		out[0] = crockford[acc&31]
	}
	return "b-" + string(out), nil
}
