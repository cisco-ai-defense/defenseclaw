// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"context"
	"errors"
)

func runSupervised(context.Context, options, reviewedRegistry, map[string]any, *cleanupOwner) error {
	return errors.New("fixed native peer harness requires native Linux amd64")
}

func executeWorker(args []string) (map[string]any, *cleanupOwner, error) {
	return executeWorkerWithRegistry(args, liveRegistry)
}

func executeWorkerWithRegistry([]string, reviewedRegistry) (map[string]any, *cleanupOwner, error) {
	return map[string]any{"passed": false, "execution_performed": false}, nil, errors.New("fixed native peer harness requires native Linux amd64")
}
