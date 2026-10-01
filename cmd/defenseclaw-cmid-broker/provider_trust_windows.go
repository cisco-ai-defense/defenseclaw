// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

type trustedCMIDLibrary interface {
	Close() error
	Signer() cmidbroker.LibrarySigner
}

// constructVerifiedCMIDProvider is called by the release's deferred provider
// at every adoption. Its first refresh loads the native library while the
// signed file is leased against writes, renames, and replacement. A missing
// library or failed refresh leaves the broker available to retry later.
func constructVerifiedCMIDProvider(
	ctx context.Context,
	path string,
	open func(string) (trustedCMIDLibrary, error),
	build func(string) (cmidbroker.Provider, error),
) (provider cmidbroker.Provider, signer cmidbroker.LibrarySigner, err error) {
	if open == nil || build == nil {
		return nil, signer, errors.New("CMID provider requires trust and construction steps")
	}
	lease, err := open(path)
	if err != nil {
		return nil, signer, fmt.Errorf("verify the CMID library before loading: %w", err)
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			provider = nil
			err = errors.Join(err, fmt.Errorf("release the verified CMID library: %w", closeErr))
		}
	}()
	provider, err = build(path)
	if err != nil {
		return nil, signer, err
	}
	if provider == nil {
		return nil, signer, errors.New("managed CMID provider construction failed")
	}
	firstCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = provider.Refresh(firstCtx)
	cancel()
	if err != nil {
		return nil, signer, fmt.Errorf("first CMID refresh under signer lease: %w", err)
	}
	return provider, lease.Signer(), nil
}
