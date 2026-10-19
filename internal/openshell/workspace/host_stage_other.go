// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux

package workspace

import "context"

func prepareHostStagePlatform(context.Context, StageOptions) (*HostStage, error) {
	return nil, ErrUnsupportedPlatform
}
