// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

// The Linux tetragon group exists on Windows builds so help stays identical
// everywhere; it refuses to run.
func runUnixTetragon(_ *cobra.Command, _ string, _ *unixTetragonOptions) error {
	return withExitCode(errors.New("`enterprise linux tetragon` reads Linux hosts; Windows has no Tetragon"), 1639)
}
