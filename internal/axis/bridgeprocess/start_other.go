// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package bridgeprocess

import (
	"context"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

func sealImage(context.Context, *os.File, string) (*Image, error) {
	return nil, ErrUnavailable
}

func start(context.Context, bridgeproto.Binding, bridgeproto.Preparation, Inputs, bridgeowner.Limits) (*Session, error) {
	return nil, ErrUnavailable
}
