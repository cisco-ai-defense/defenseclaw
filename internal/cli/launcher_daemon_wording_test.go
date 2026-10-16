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

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// transportStatus answers first (when set) once, then fails with err.
type transportStatus struct {
	first *sandboxapi.Status
	err   error
	calls int
}

func (s *transportStatus) Status(context.Context) (*sandboxapi.Status, error) {
	s.calls++
	if s.calls == 1 && s.first != nil {
		return s.first, nil
	}
	return nil, s.err
}

// rel-1-0-2:GAP-0170 (#1202 part d): a sandbox service that was started or
// restarted but does not answer is one sentence with the doctor hint; the
// transport error with the daemon's internal URL stays out of it, wrapped
// for callers.
func TestLauncherEnsureDaemonLeavesTheTransportErrorOutOfItsSentence(t *testing.T) {
	fastLauncherWaits(t)
	recordRuns(t, nil)
	raw := errors.New(`Get "http://sandbox-daemon/api/v1/sandbox/status": context deadline exceeded`)
	pending := &sandboxapi.Status{Managed: &sandboxapi.ManagedStatus{PendingRestart: true}}
	for _, tc := range []struct {
		name   string
		client *transportStatus
		want   string
	}{
		{"started", &transportStatus{err: raw}, "your sandbox service was started but does not answer; `defenseclaw sandbox doctor` shows why"},
		{"restarted", &transportStatus{first: pending, err: raw}, "your sandbox service was restarted but does not answer; `defenseclaw sandbox doctor` shows why"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			_, err := launcherEnsureDaemon(context.Background(), tc.client, "linux", 501, &stderr)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "http://") || strings.Contains(err.Error(), "deadline") {
				t.Fatalf("the sentence shows the transport error: %q", err.Error())
			}
			if !errors.Is(err, raw) {
				t.Fatal("the transport error is no longer wrapped")
			}
		})
	}
}
