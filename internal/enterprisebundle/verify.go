// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"time"

	"golang.org/x/mod/semver"
)

// Warning codes verify adds.
const (
	WarnDigestUnverifiable       = "digest_unverifiable"
	WarnDigestLayoutUnverifiable = "digest_layout_unverifiable"
	WarnDigestDiffers            = "digest_differs"
	WarnSecretPresenceUnchecked  = "secret_presence_unchecked"
)

// Confirmed is the last bundle a device confirmed (bundle-state.json); the
// zero value means none.
type Confirmed struct {
	Version  uint64
	BundleID string
	// ManifestSHA256 is the hex SHA-256 of the confirmed manifest.json
	// bytes. A bundle is the confirmed one only when all three match, so a
	// key retired since (which verifies only the applied bundle) cannot
	// sign new content under the confirmed id and version.
	ManifestSHA256 string
}

// CheckFloor is the rollback check of the manifest m whose bytes hash to
// manifestSHA256 (hex). The floor is the higher of the last confirmed
// version and the anchor min_version. The confirmed bundle itself (same
// bundle_id, version and manifest bytes, not below min_version) is already
// applied: a no-op success. Any other version at or below the floor is
// version_not_newer, also another manifest under the confirmed id and
// version; a rollback is a new, higher version.
func CheckFloor(m *Manifest, manifestSHA256 string, confirmed Confirmed, anchorMin uint64) (alreadyApplied bool, floor uint64, err error) {
	floor = max(confirmed.Version, anchorMin)
	same := confirmed.BundleID != "" && m.BundleID == confirmed.BundleID && m.Version == confirmed.Version
	if same && confirmed.ManifestSHA256 != "" && confirmed.ManifestSHA256 == manifestSHA256 && m.Version >= anchorMin {
		return true, floor, nil
	}
	if same && m.Version >= anchorMin {
		return false, floor, refuse(CodeVersionNotNewer, "version", "the manifest differs from the confirmed bundle %s version %d", m.BundleID, m.Version)
	}
	if m.Version <= floor {
		return false, floor, refuse(CodeVersionNotNewer, "version", "version %d is not above the floor %d (set by %s)", m.Version, floor, FloorSourceText(FloorSource(confirmed, anchorMin)))
	}
	return false, floor, nil
}

// FloorSource names the authority that sets the effective device floor.
func FloorSource(confirmed Confirmed, anchorMin uint64) string {
	switch {
	case anchorMin == 0 && confirmed.Version == 0:
		return "none"
	case anchorMin > confirmed.Version:
		return "trust_anchor_min_version"
	case confirmed.Version > anchorMin:
		return "last_confirmed_bundle"
	default:
		return "both"
	}
}

func FloorSourceText(source string) string {
	switch source {
	case "trust_anchor_min_version":
		return "trust anchor min_version"
	case "last_confirmed_bundle":
		return "the last confirmed bundle"
	case "both":
		return "trust anchor min_version and the last confirmed bundle"
	default:
		return "no existing version floor"
	}
}

// CheckProductVersion refuses (product_too_old) a running product version
// below min, or one that is not a release version when min is set.
func CheckProductVersion(min, running string) error {
	if min == "" {
		return nil
	}
	if !productVersionRegex.MatchString(running) {
		return refuse(CodeProductTooOld, "min_product_version", "this build (%s) is not a release version; the bundle needs %s or later", boundedText(running, 64), min)
	}
	if semver.Compare("v"+running, "v"+min) < 0 {
		return refuse(CodeProductTooOld, "min_product_version", "this build is %s; the bundle needs %s or later", running, min)
	}
	return nil
}

// VerifyInput is what Verify checks a bundle against.
type VerifyInput struct {
	Bundle *Bundle
	// Anchors are the trust anchors (nil: anchor_missing).
	Anchors *Anchors
	// Platform is the platform the bundle must target.
	Platform string
	// Now is the time the key validity is checked at.
	Now time.Time
	// Confirmed is the device's last confirmed bundle (zero off a device).
	Confirmed Confirmed
	// ProductVersion is the running product version and HostPlatform the
	// platform this process runs on: the manifest digest is compared only
	// when both equal those of the signer.
	ProductVersion string
	HostPlatform   string
	// DeviceLayout is the installed layout on a device. Nil uses the target's
	// standard layout for offline verification.
	DeviceLayout *DeviceLayout
	// SecretPresent reports whether the device holds an enterprise
	// credential; nil does not check presence (off a device).
	SecretPresent func(name string) (bool, error)
	// Stage writes the bundle files to a private directory and returns it;
	// the config loader and the digest read the policy files from there.
	Stage func(*Bundle) (string, error)
	// Digester computes the effective policy digest.
	Digester PolicyDigester
}

// VerifyResult is what Verify established. On a refusal it holds what was
// established before the first failure (the manifest once decoded).
type VerifyResult struct {
	Manifest       *Manifest
	Signature      *Signature
	Key            *AnchorKey
	AlreadyApplied bool
	Floor          uint64
	FloorSource    string
	// EffectivePolicyDigest is the digest this host computed for Platform;
	// ExpectedDigest is the manifest entry; DigestVerified reports that
	// they were compared and equal. A different signer product version or
	// platform is the only reason to report WarnDigestUnverifiable.
	EffectivePolicyDigest    string
	ExpectedDigest           string
	DigestVerified           bool
	DigestUnverifiable       bool
	DigestLayoutUnverifiable bool
	Warnings                 []Warning
}

// Verify runs every bundle check in the order of spec section 4: anchor,
// key, signature, manifest, tenant and target, version floor, product
// version, files[], inline secrets, secret references, the canonical
// config validator and the effective digest. The first failure wins.
func Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	res := &VerifyResult{}
	b := in.Bundle
	if in.Anchors == nil {
		return res, refuse(CodeAnchorMissing, AnchorsName, "no trust anchors; bundle mode is off")
	}
	sig, err := DecodeSignature(b.Signature)
	if err != nil {
		return res, err
	}
	res.Signature = sig
	key := in.Anchors.Key(sig.KeyID)
	if key == nil {
		return res, refuse(CodeKeyUnknown, SignatureName, "key %s is not a trust anchor key", sig.KeyID)
	}
	res.Key = key
	if key.Status == KeyRevoked {
		return res, refuse(CodeKeyRevoked, SignatureName, "key %s is revoked", sig.KeyID)
	}
	if !key.ValidAt(in.Now) {
		return res, refuse(CodeKeyExpired, SignatureName, "key %s is valid from %s to %s", sig.KeyID, key.NotBefore, key.NotAfter)
	}
	if len(b.Manifest) == 0 {
		return res, refuse(CodeManifestInvalid, ManifestName, "the bundle has no manifest")
	}
	if err := VerifySignature(b.Manifest, sig, key.Public()); err != nil {
		return res, err
	}
	m, err := DecodeManifest(b.Manifest)
	if err != nil {
		return res, err
	}
	res.Manifest = m
	if m.TenantID != in.Anchors.TenantID {
		return res, refuse(CodeTenantMismatch, "tenant_id", "the bundle is for tenant %s, this device for tenant %s", m.TenantID, in.Anchors.TenantID)
	}
	if !in.Anchors.AllowsDeviceGroup(m.Target.DeviceGroup) {
		return res, refuse(CodeTargetMismatch, "target.device_group", "this device is not in device group %s", m.Target.DeviceGroup)
	}
	if !slices.Contains(m.Target.Platforms, in.Platform) {
		return res, refuse(CodeTargetMismatch, "target.platforms", "the bundle does not target %s", safePath(in.Platform))
	}
	created, _ := m.CreatedTime()
	if !key.ValidAt(created) {
		return res, refuse(CodeKeyExpired, "created_at", "the bundle was created outside the validity of key %s", sig.KeyID)
	}
	manifestSum := sha256.Sum256(b.Manifest)
	res.FloorSource = FloorSource(in.Confirmed, in.Anchors.MinVersion)
	res.AlreadyApplied, res.Floor, err = CheckFloor(m, hex.EncodeToString(manifestSum[:]), in.Confirmed, in.Anchors.MinVersion)
	if err != nil {
		return res, err
	}
	if key.Status == KeyRetired && !res.AlreadyApplied {
		return res, refuse(CodeKeyExpired, SignatureName, "key %s is retired; it verifies only the bundle already applied", sig.KeyID)
	}
	if err := CheckProductVersion(m.MinProductVersion, in.ProductVersion); err != nil {
		return res, err
	}
	if err := CheckFiles(m, b); err != nil {
		return res, err
	}
	if err := CheckInlineSecrets(b); err != nil {
		return res, err
	}
	if err := CheckSecretRefs(m, b); err != nil {
		return res, err
	}
	if in.SecretPresent != nil {
		unchecked := false
		for _, ref := range m.SecretRefs {
			present, err := in.SecretPresent(ref.Name())
			switch {
			case err != nil:
				unchecked = true
			case !present && ref.Required:
				return res, refuse(CodeSecretRefMissing, "secret_refs", "this device has no credential %s", safePath(ref.Name()))
			}
		}
		if unchecked {
			res.Warnings = append(res.Warnings, Warning{Code: WarnSecretPresenceUnchecked, Message: "the enterprise secret store could not be read; credential presence was not checked"})
		}
	}
	root, err := in.Stage(b)
	if err != nil {
		return res, refuse(CodeArchiveInvalid, "", "cannot stage the bundle files: %s", boundedDetail(err.Error()))
	}
	layout, err := StandardDeviceLayout(in.Platform)
	if err != nil {
		return res, refuse(CodeManifestInvalid, "target.platforms", "%s", boundedDetail(err.Error()))
	}
	if in.DeviceLayout != nil {
		layout = *in.DeviceLayout
	}
	cfg, rendered, err := LoadConfigForDeviceLayout(b, root, in.Platform, layout)
	if err != nil {
		return res, err
	}
	ruleWarnings, _, err := RuleNotBlockingWarnings(cfg)
	if err != nil {
		return res, refuse(CodeConfigInvalid, ConfigName, "custom rule pack: %s", boundedDetail(err.Error()))
	}
	if err := validateTargetConfig(b, cfg, rendered, []string{in.Platform}); err != nil {
		return res, err
	}
	var details map[string]string
	digest, err := in.Digester(withPolicyComponents(ctx, func(got map[string]string) { details = got }), cfg, rendered, in.Platform, root)
	if err != nil {
		return res, refuse(CodeConfigInvalid, ConfigName, "effective policy for %s: %s", in.Platform, boundedDetail(err.Error()))
	}
	res.EffectivePolicyDigest = digest
	res.ExpectedDigest = m.EffectivePolicy.Digests[in.Platform]
	standardLayout := layout.IsStandard(in.Platform)
	if DigestComparableWithLocal(m, in.ProductVersion, in.HostPlatform, in.Platform, digest) {
		if digest != res.ExpectedDigest {
			if !standardLayout {
				res.DigestLayoutUnverifiable = true
				res.Warnings = append(res.Warnings, Warning{Code: WarnDigestLayoutUnverifiable, Platform: in.Platform,
					Message: "this device uses a non-standard managed layout whose paths the offline signer could not know; files[] hashes still hold, and this host reports its own digest"})
			} else {
				component := differingDigestComponent(m.EffectivePolicy.Components[in.Platform], details)
				if component != "" {
					return res, refuse(CodeDigestMismatch, "effective_policy.digests."+in.Platform, "this host computes %s; component %s differs", digest, boundedDetail(component))
				}
				return res, refuse(CodeDigestMismatch, "effective_policy.digests."+in.Platform, "this host computes %s", digest)
			}
		} else {
			res.DigestVerified = true
		}
	} else {
		res.DigestUnverifiable = true
		message := "the signer used another product version; its signed digest cannot be compared with this build's policy digest; files[] hashes still hold"
		if m.EffectivePolicy.ProductVersion == in.ProductVersion {
			message = "the signer computed the " + in.Platform + " digest on " + m.EffectivePolicy.ComputedOn + "; it differs from this " + in.Platform + " device's digest"
			// The signed components say which input the signing host saw
			// differently, so the difference can be traced (GAP-0107).
			if component := differingDigestComponent(m.EffectivePolicy.Components[in.Platform], details); component != "" {
				message += " in component " + boundedDetail(component)
			}
			message += ", so signed-versus-enforcing comparison is unavailable; files[] hashes still hold"
		}
		res.Warnings = append(res.Warnings, Warning{
			Code:     WarnDigestUnverifiable,
			Platform: in.Platform,
			Message:  message,
		})
	}
	res.Warnings = append(res.Warnings, Reachability(cfg, []string{in.Platform})...)
	res.Warnings = append(res.Warnings, ruleWarnings...)
	sectionWarnings, err := AbsentSectionWarnings(b.Files[ConfigName])
	if err != nil {
		return res, err
	}
	res.Warnings = append(res.Warnings, sectionWarnings...)
	return res, nil
}

// DigestComparable is derived from the signed manifest for each delivery.
// A receipt from an earlier attempt must never decide comparability.
func DigestComparable(m *Manifest, productVersion, hostPlatform string) bool {
	return m != nil && m.EffectivePolicy.ProductVersion == productVersion && m.EffectivePolicy.ComputedOn == hostPlatform
}

// A target digest computed on a different signing host is comparable when
// its signed value equals the digest computed on this device. A difference
// remains informational: host-specific inputs cannot safely be ruled out.
func DigestComparableWithLocal(m *Manifest, productVersion, hostPlatform, targetPlatform, localDigest string) bool {
	return DigestComparable(m, productVersion, hostPlatform) ||
		(m != nil && m.EffectivePolicy.ProductVersion == productVersion &&
			digestPattern.MatchString(localDigest) && m.EffectivePolicy.Digests[targetPlatform] == localDigest)
}

func differingDigestComponent(expected []DigestComponent, actual map[string]string) string {
	if len(expected) == 0 || len(actual) == 0 {
		return ""
	}
	want := make(map[string]string, len(expected))
	for _, component := range expected {
		want[component.Name] = component.Digest
	}
	names := make([]string, 0, len(want)+len(actual))
	for name := range want {
		names = append(names, name)
	}
	for name := range actual {
		if _, ok := want[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if want[name] != actual[name] {
			return name
		}
	}
	return ""
}
