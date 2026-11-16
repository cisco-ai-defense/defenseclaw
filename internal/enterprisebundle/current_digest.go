// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"context"
	"fmt"
	"slices"
)

// VerifiedCurrentDigest computes this build's digest from the bundle pinned
// by the confirmed state. ReadVersion checks the stored manifest and every
// bundled file against their recorded hashes; the identity check also binds
// the manifest and signer to the state. The returned config is rendered from
// those same bytes for comparison with the installed config.
func VerifiedCurrentDigest(ctx context.Context, store *Store, ref *Ref, platform string, layout DeviceLayout,
	digester PolicyDigester) (string, []byte, error) {
	digest, rendered, _, err := verifiedVersionDigest(ctx, store, ref, platform, layout, store.VersionDir(ref.Dir), digester)
	return digest, rendered, err
}

// VerifiedReceiptDigest computes the policy this build expects from a
// pending receipt's stored bundle. The rendered config must still be the
// exact bytes the receipt says were installed. A signed digest verified by
// an older product remains historical, not comparable with this digest.
// installedRoot is the device path used to render the installed config; it
// can differ from the filesystem path of a test-rooted store.
func VerifiedReceiptDigest(ctx context.Context, store *Store, receipt *Receipt, platform string, layout DeviceLayout,
	productVersion, installedRoot string, digester PolicyDigester) (string, bool, error) {
	if receipt == nil {
		return "", false, fmt.Errorf("bundle receipt is unavailable")
	}
	ref := &Ref{BundleID: receipt.BundleID, Version: receipt.Version, ManifestSHA256: receipt.ManifestSHA256,
		Dir: receipt.Dir, SignerKeyID: receipt.SignerKeyID}
	digest, rendered, signedProductVersion, err := verifiedVersionDigest(ctx, store, ref, platform, layout, installedRoot, digester)
	if err != nil {
		return "", false, err
	}
	if sha256Hex(rendered) != receipt.ConfigSHA256 {
		return "", false, fmt.Errorf("stored bundle config differs from the receipt's installed config")
	}
	return digest, receipt.DigestComparable && signedProductVersion == productVersion, nil
}

// verifiedVersionDigest also returns the signed product version. Settle uses
// it to decide whether an old receipt's signed digest is comparable with the
// digest this build computes for the same stored bundle.
func verifiedVersionDigest(ctx context.Context, store *Store, ref *Ref, platform string, layout DeviceLayout,
	installedRoot string, digester PolicyDigester) (string, []byte, string, error) {
	b, err := store.ReadVersion(ref)
	if err != nil {
		return "", nil, "", err
	}
	manifest, err := DecodeManifest(b.Manifest)
	if err != nil {
		return "", nil, "", err
	}
	signature, err := DecodeSignature(b.Signature)
	if err != nil {
		return "", nil, "", err
	}
	if manifest.BundleID != ref.BundleID || manifest.Version != ref.Version || signature.KeyID != ref.SignerKeyID ||
		!slices.Contains(manifest.Target.Platforms, platform) {
		return "", nil, "", fmt.Errorf("bundle identity does not match its stored manifest and signer")
	}
	if digester == nil {
		return "", nil, "", fmt.Errorf("this build cannot compute the bundle's effective policy digest")
	}
	root := store.VersionDir(ref.Dir)
	cfg, policyRendered, err := LoadConfigForDeviceLayout(b, root, platform, layout)
	if err != nil {
		return "", nil, "", err
	}
	digest, err := digester(ctx, cfg, policyRendered, platform, root)
	if err != nil {
		return "", nil, "", err
	}
	if !digestPattern.MatchString(digest) {
		return "", nil, "", fmt.Errorf("this build computed no valid effective policy digest for the bundle")
	}
	// Prepare installs RenderConfig against the device's canonical version
	// path. The verifier loads policy assets from the (possibly test-rooted)
	// store path; those rendered bytes need not be the installed bytes.
	installed, err := RenderConfig(b, installedRoot)
	if err != nil {
		return "", nil, "", err
	}
	return digest, installed, manifest.EffectivePolicy.ProductVersion, nil
}
