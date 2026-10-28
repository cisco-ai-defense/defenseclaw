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
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
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
	if !IsReleaseVersion(min) {
		return refuse(CodeProductTooOld, "min_product_version", "the signed minimum is not a valid release version; run defenseclaw-gateway enterprise bundle sign --help and redeliver a corrected signed bundle")
	}
	if !IsReleaseVersion(running) {
		return refuse(CodeProductTooOld, "min_product_version", "this build (%s) is not a release version; the bundle needs %s or later", boundedText(running, 64), min)
	}
	if semver.Compare("v"+running, "v"+min) < 0 {
		return refuse(CodeProductTooOld, "min_product_version", "this build is %s; the bundle needs %s or later", running, min)
	}
	return nil
}

// IsReleaseVersion reports whether v is a release version
// (MAJOR.MINOR.PATCH, an optional prerelease and build), the only kind
// CheckProductVersion places against a min_product_version.
func IsReleaseVersion(v string) bool {
	return productVersionRegex.MatchString(v) && semver.IsValid("v"+v)
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
	// ProductVersion is the running product version. The signed digest is
	// compared whenever it equals the signer's product version, whatever
	// platform the signer ran on (compareSignedDigest).
	ProductVersion string
	// DeviceLayout is the installed layout on a device. Nil uses the target's
	// standard layout for offline verification.
	DeviceLayout *DeviceLayout
	// SecretValue reads an enterprise credential as the gateway would: the
	// value when it is stored and usable, nil when it is missing or the
	// gateway's read would refuse it, an error when the store could not be
	// read. Verify compares the value with the signed value_sha256 and
	// clears it. Nil checks no credential (off a device).
	SecretValue func(name string) ([]byte, error)
	// RequireSecretPresence is set by the apply: a required reference whose
	// presence could not be checked refuses (secret_ref_missing) instead of
	// only warning secret_presence_unchecked, as read-only verify does.
	RequireSecretPresence bool
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
	// they were compared and equal. A different signer product version is
	// the only reason to report WarnDigestUnverifiable.
	EffectivePolicyDigest    string
	ExpectedDigest           string
	DigestVerified           bool
	DigestUnverifiable       bool
	DigestLayoutUnverifiable bool
	Warnings                 []Warning
	// SecretRefsMissing names, in manifest order, every secret_refs entry
	// (required or optional) the device does not hold, and
	// SecretRefsMismatch every one it holds with a value the entry does not
	// sign. Both are nil unless every reference was checked: off a device,
	// with a store that could not be read, or on a refusal before that step.
	SecretRefsMissing  []string
	SecretRefsMismatch []string
	// Rendered is the config.yaml Verify validated, rendered for the device
	// layout against the private stage directory. The apply renders the
	// same file against its version directory, so the two differ only in
	// the bundle-relative values, which differ from the installed config in
	// either rendering; nil before the config loads.
	Rendered []byte
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
	if in.SecretValue != nil {
		// Every reference is looked up, so a refusal names the first
		// required credential missing or the first one stored with another
		// value, and the result lists all of them: the caller stores them
		// in one pass.
		unchecked, missing, mismatch := false, []string{}, []string{}
		var refusal error
		for _, ref := range m.SecretRefs {
			value, err := in.SecretValue(ref.Name())
			bound := err == nil && ref.Binds(m.TenantID, value)
			stored := len(value) > 0
			clear(value)
			switch {
			case err != nil:
				unchecked = true
				if in.RequireSecretPresence && ref.Required && refusal == nil {
					refusal = refuse(CodeSecretRefMissing, "secret_refs", "credential %s could not be checked, so the apply does not rely on it; store it again with enterprise secret set", safePath(ref.Name()))
				}
			case !stored:
				missing = append(missing, ref.Name())
				if ref.Required && refusal == nil {
					refusal = refuse(CodeSecretRefMissing, "secret_refs", "this device has no credential %s", safePath(ref.Name()))
				}
			case !bound:
				// The gateway would use a value the bundle does not sign,
				// also for an optional reference.
				mismatch = append(mismatch, ref.Name())
				if refusal == nil {
					refusal = refuse(CodeSecretRefMismatch, "secret_refs", "credential %s on this device is not the value the bundle signs; store the value it signs with enterprise secret set --bundle and this bundle, or sign the bundle again with --secret-file for the stored one", safePath(ref.Name()))
				}
			}
		}
		// The warning comes before a refusal for another credential, so the
		// refusal still says the store was partly unreadable and the lists
		// are incomplete.
		if unchecked {
			res.Warnings = append(res.Warnings, Warning{Code: WarnSecretPresenceUnchecked, Message: "the enterprise secret store could not be read; credential presence and values were not checked"})
		} else {
			res.SecretRefsMissing, res.SecretRefsMismatch = missing, mismatch
		}
		if refusal != nil {
			return res, refusal
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
	res.Rendered = rendered
	ruleWarnings, _, err := RuleNotBlockingWarnings(cfg)
	if err != nil {
		if refusal := unreadableRulePackForAccount(err); refusal != nil {
			return res, refusal
		}
		return res, refuse(CodeConfigInvalid, ConfigName, "custom rule pack: %s", boundedDetail(err.Error()))
	}
	if err := validateTargetConfig(b, cfg, rendered, []string{in.Platform}); err != nil {
		return res, err
	}
	device, err := computeDigest(ctx, in, cfg, rendered, root, "")
	if err != nil {
		return res, err
	}
	res.EffectivePolicyDigest = device.digest
	res.ExpectedDigest = m.EffectivePolicy.Digests[in.Platform]
	// The signer computed the standard layout's digest. A device on another
	// managed layout recomputes it, so a signed digest it disproves still
	// refuses (GAP-0113).
	var standard func() (computedDigest, error)
	if !layout.IsStandard(in.Platform) {
		standard = func() (computedDigest, error) {
			standardLayout, err := StandardDeviceLayout(in.Platform)
			if err != nil {
				return computedDigest{}, refuse(CodeManifestInvalid, "target.platforms", "%s", boundedDetail(err.Error()))
			}
			cfg, rendered, err := LoadConfigForDeviceLayout(b, root, in.Platform, standardLayout)
			if err != nil {
				return computedDigest{}, err
			}
			return computeDigest(ctx, in, cfg, rendered, root, " on the standard managed layout")
		}
	}
	outcome, err := compareSignedDigest(m.EffectivePolicy, in.Platform, in.ProductVersion, device, standard)
	if err != nil {
		return res, err
	}
	switch outcome {
	case digestVerified:
		res.DigestVerified = true
	case digestOtherProduct:
		res.DigestUnverifiable = true
		res.Warnings = append(res.Warnings, Warning{Code: WarnDigestUnverifiable, Platform: in.Platform,
			Message: "the signer used product version " + m.EffectivePolicy.ProductVersion + " and this build is " + boundedText(in.ProductVersion, 64) +
				"; the built-in policy differs by version, so the signed digest cannot be compared with this build's digest; files[] hashes still hold"})
	case digestLayoutDependent:
		res.DigestLayoutUnverifiable = true
		res.Warnings = append(res.Warnings, Warning{Code: WarnDigestLayoutUnverifiable, Platform: in.Platform,
			Message: "this device's non-standard managed layout changes the effective digest; the signed digest equals this host's digest for the standard managed layout, files[] hashes still hold, and this host reports its own digest"})
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

// DigestComparable is derived from the signed manifest for each delivery: a
// build compares the signed digest of a signer that ran its product version.
// A receipt from an earlier attempt must never decide comparability.
func DigestComparable(m *Manifest, productVersion string) bool {
	return m != nil && m.EffectivePolicy.ProductVersion == productVersion
}

// digestOutcome is how a signed digest that compareSignedDigest did not
// refuse relates to the digest this device computed.
type digestOutcome uint8

const (
	// digestVerified: the signed digest equals this device's digest.
	digestVerified digestOutcome = iota + 1
	// digestOtherProduct: the signer ran another product version. Its
	// built-in policy and digest rules are not this build's, so this build
	// cannot reproduce what the signer saw (digest_unverifiable).
	digestOtherProduct
	// digestLayoutDependent: this device's non-standard managed layout
	// changed its digest, and the signed digest equals the digest this
	// device computes for the standard layout the signer models
	// (digest_layout_unverifiable).
	digestLayoutDependent
)

// computedDigest is an effective policy digest a device computed and its
// component sub-digests.
type computedDigest struct {
	digest     string
	components map[string]string
}

// computeDigest runs the verify input's digester for cfg; where names the
// layout in a refusal.
func computeDigest(ctx context.Context, in VerifyInput, cfg *config.Config, rendered []byte, root, where string) (computedDigest, error) {
	var out computedDigest
	digest, err := in.Digester(withPolicyComponents(ctx, func(got map[string]string) { out.components = got }), cfg, rendered, in.Platform, root)
	if err != nil {
		if refusal := unreadableRulePackForAccount(err); refusal != nil {
			return computedDigest{}, refusal
		}
		return computedDigest{}, refuse(CodeConfigInvalid, ConfigName, "effective policy for %s%s: %s", in.Platform, where, boundedDetail(err.Error()))
	}
	out.digest = digest
	return out, nil
}

func unreadableRulePackForAccount(err error) error {
	var packErr *guardrail.RulePackError
	if !errors.As(err, &packErr) {
		return nil
	}
	if packErr.Code != "directory_unreadable" && packErr.Code != "inventory_unreadable" && packErr.Code != "file_unreadable" {
		return nil
	}
	if !strings.Contains(packErr.Reason, "access denied") && !strings.Contains(packErr.Reason, "permission denied") {
		return nil
	}
	return refuse(CodeNotAdmin, ConfigName,
		"this account cannot read and list a rule pack referenced by the signed config; run the same enterprise bundle verify command as root on Linux/macOS or as an elevated administrator/SYSTEM on Windows, or ask an administrator to grant this account read and list access to that pack and its parent directories")
}

// compareSignedDigest is the signed-digest rule for every signer and device
// platform pair (GAP-0113). A signer that ran this product version computes
// the target platform's digest with that platform's defaults and standard
// managed layout on any host (GAP-0107), so it computes what this device
// computes from the same files for that layout. A different digest from such
// a signer is disproved here and refused with digest_mismatch, naming the
// signed components that differ; the signing platform (computed_on) is
// reported, never an excuse. The built-in policy is compiled into the build
// and pinned by the product version, so a signer build of the same version
// with other built-in policy is refused as well (component builtin): sign
// with the build the devices run.
//
// standard is nil on the standard layout. On another layout (Windows
// ProgramData on another drive) it computes this device's digest for the
// standard layout, and that digest decides. Both loads read the same staged
// files and differ only in the layout paths, so a signed digest equal to the
// standard-layout one is the signer's policy and only this device's paths
// changed its own digest (digest_layout_unverifiable; an explicit standard
// data_dir on a relocated ProgramData does this); any other is disproved.
func compareSignedDigest(signed EffectivePolicy, platform, productVersion string, device computedDigest, standard func() (computedDigest, error)) (digestOutcome, error) {
	want := signed.Digests[platform]
	switch {
	case signed.ProductVersion != productVersion:
		return digestOtherProduct, nil
	case device.digest == want:
		return digestVerified, nil
	}
	disproved, layoutNote := device, ""
	if standard != nil {
		got, err := standard()
		if err != nil {
			return 0, err
		}
		if got.digest == want {
			return digestLayoutDependent, nil
		}
		if got.digest != device.digest {
			layoutNote = " (" + got.digest + " for the standard managed layout)"
		}
		disproved = got
	}
	detail := "this host computes " + device.digest + " for " + platform + layoutNote + "; the signer computed the digest on " + safePath(signed.ComputedOn) + " with the same product version " + boundedText(productVersion, 64)
	if differing := differingDigestComponents(signed.Components[platform], disproved.components); len(differing) > 0 {
		if len(differing) > maxNamedComponents {
			differing = append(differing[:maxNamedComponents], "...")
		}
		detail += "; component " + boundedDetail(strings.Join(differing, ", ")) + " differs"
		if slices.Contains(differing, builtinComponent) {
			detail += " (the signer build's built-in policy is not this build's: sign with the build the devices run)"
		}
	}
	return 0, refuse(CodeDigestMismatch, "effective_policy.digests."+platform, "%s", detail)
}

// builtinComponent is the digest component of the policy compiled into the
// build; maxNamedComponents bounds the components a refusal names.
const (
	builtinComponent   = "builtin"
	maxNamedComponents = 8
)

// differingDigestComponents names, sorted, the components whose signed and
// local sub-digests differ, including one only either side has. It is nil
// when either side reported no components.
func differingDigestComponents(expected []DigestComponent, actual map[string]string) []string {
	if len(expected) == 0 || len(actual) == 0 {
		return nil
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
	var differing []string
	for _, name := range names {
		if want[name] != actual[name] {
			differing = append(differing, name)
		}
	}
	return differing
}
