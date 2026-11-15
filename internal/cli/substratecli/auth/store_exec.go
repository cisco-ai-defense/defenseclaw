// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
)

// execRunner runs a keychain helper for real.
func execRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return o.Bytes(), e.String(), ee.ExitCode(), nil
	}
	if err != nil {
		return nil, "", -1, fmt.Errorf("run %s: %w", filepath.Base(name), err)
	}
	return o.Bytes(), e.String(), 0, nil
}
