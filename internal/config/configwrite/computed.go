// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"bytes"
	"context"
	"errors"
)

// ApplyComputed computes a patch from the current document while holding the
// config writer lock. Actor, compare-and-swap and managed checks run before
// compute; the usual candidate validation and durable commit run afterward.
// The callback must not write configuration or call another config writer.
func ApplyComputed(ctx context.Context, path string, compute func(current []byte) ([]Change, error), opt Options) (Result, error) {
	if compute == nil {
		return Result{}, errors.New("configwrite: a patch callback is required")
	}
	return transact(ctx, path, opt, func(current []byte) ([]byte, []string, error) {
		changes, err := compute(bytes.Clone(current))
		if err != nil {
			return nil, nil, err
		}
		return patchDocument(current, changes)
	})
}
