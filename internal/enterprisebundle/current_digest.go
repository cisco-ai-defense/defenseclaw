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
	b, err := store.ReadVersion(ref)
	if err != nil {
		return "", nil, err
	}
	manifest, err := DecodeManifest(b.Manifest)
	if err != nil {
		return "", nil, err
	}
	signature, err := DecodeSignature(b.Signature)
	if err != nil {
		return "", nil, err
	}
	if manifest.BundleID != ref.BundleID || manifest.Version != ref.Version || signature.KeyID != ref.SignerKeyID ||
		!slices.Contains(manifest.Target.Platforms, platform) {
		return "", nil, fmt.Errorf("confirmed bundle identity does not match its stored manifest and signer")
	}
	if digester == nil {
		return "", nil, fmt.Errorf("this build cannot compute the confirmed bundle's effective policy digest")
	}
	root := store.VersionDir(ref.Dir)
	cfg, rendered, err := LoadConfigForDeviceLayout(b, root, platform, layout)
	if err != nil {
		return "", nil, err
	}
	digest, err := digester(ctx, cfg, rendered, platform, root)
	if err != nil {
		return "", nil, err
	}
	if digest == "" {
		return "", nil, fmt.Errorf("this build computed no effective policy digest for the confirmed bundle")
	}
	return digest, rendered, nil
}
