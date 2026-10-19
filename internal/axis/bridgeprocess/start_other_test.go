// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package bridgeprocess

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

func TestUnsupportedHostRefusesBeforeOpeningOrLaunching(t *testing.T) {
	if image, err := SealImage(context.Background(), nil, ""); image != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsupported image admission: %v, %v", image, err)
	}
	if session, err := Start(context.Background(), bridgeproto.Binding{}, bridgeproto.Preparation{}, Inputs{}, bridgeowner.Limits{}); session != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsupported process launch: %v, %v", session, err)
	}
}
