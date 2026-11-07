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

package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// runPinnedVersionScript runs the image's POSIX version check on every test
// platform. Image scripts run in Linux, but the pin contract is also checked
// by native Windows CI.
func runPinnedVersionScript(t *testing.T, script, reply string, external interp.ExecHandlerFunc) (string, error) {
	t.Helper()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(script), "image-version-check")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runner, err := interp.New(
		interp.Env(expand.ListEnviron("VERSION_REPLY="+reply)),
		interp.StdIO(nil, &output, &output),
		interp.ExecHandlers(func(interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return func(ctx context.Context, args []string) error {
				if external != nil {
					return external(ctx, args)
				}
				return fmt.Errorf("unexpected image command %q", args)
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = runner.Run(context.Background(), file)
	if err != nil {
		var status interp.ExitStatus
		if !errors.As(err, &status) {
			t.Fatalf("image version check did not complete: %v", err)
		}
	}
	return output.String(), err
}
