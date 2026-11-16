// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/spf13/cobra"

// platformBundleVerbs adds no verb on Windows: trust anchors are installed
// with `enterprise windows ensure --profile standalone --trust-anchors F`,
// which already takes bundle.lock, checks the source and settles the result.
func platformBundleVerbs() []*cobra.Command { return nil }
