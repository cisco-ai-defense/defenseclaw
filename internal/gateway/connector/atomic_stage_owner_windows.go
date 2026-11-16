//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "os"

// Windows files take their owner and ACL from the handle-bound create, so there
// is no root-owned stage to give back.
func atomicStageKeepOwner(_, _ string) error { return nil }

func atomicMkdirAll(dir string, perm os.FileMode) error { return os.MkdirAll(dir, perm) }
