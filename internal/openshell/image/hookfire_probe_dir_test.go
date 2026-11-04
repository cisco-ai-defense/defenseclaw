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

//go:build !windows

package image

import (
	"context"
	"strings"
	"testing"
)

// TestR108OSMINMicroVMProbeUsesStandardResolution checks that a vm image
// uses the regular hook verification without replacing name-resolution files.
func TestR108OSMINMicroVMProbeUsesStandardResolution(t *testing.T) {
	c := hookFireVMContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true}
	docker := verifyDocker(t, c, sim, func(args []string) int {
		for _, arg := range args {
			if strings.Contains(arg, "target=/etc/hosts") || strings.Contains(arg, "target=/etc/resolv.conf") {
				t.Errorf("hook probe replaced sandbox name-resolution files: %v", args)
			}
		}
		return 0
	})
	b := &Builder{Docker: docker, Store: testStore(t)}
	if _, err := b.Build(context.Background(), c.Spec, BuildOptions{SkipHookFire: true}); err != nil {
		t.Fatal(err)
	}
	rec, result, err := b.VerifyHooks(context.Background(), c, HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"})
	if err != nil || !rec.HookFireVerified || len(result.Runs) != 3 {
		t.Fatalf("VerifyHooks = %+v, %d runs, %v", rec, len(result.Runs), err)
	}
}
