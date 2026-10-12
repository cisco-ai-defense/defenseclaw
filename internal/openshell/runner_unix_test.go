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

//go:build unix

package openshell_test

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestAttachedRunSurvivesCtrlC (GAP-0064): a Ctrl-C at the sudo prompt of
// the OpenShell install ended DefenseClaw, so nothing cleaned up or said
// what happened. While an attached command runs, the interrupt is the
// command's: this process waits for it and returns ErrInterrupted.
func TestAttachedRunSurvivesCtrlC(t *testing.T) {
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()
	err := openshell.ExecRunner{}.Run(context.Background(), openshell.Command{Name: "sleep", Args: []string{"1"}})
	if !errors.Is(err, openshell.ErrInterrupted) {
		t.Fatalf("Run = %v, want ErrInterrupted", err)
	}
}
