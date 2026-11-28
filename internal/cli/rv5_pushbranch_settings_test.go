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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// RV4-9: pull --push-branch stops, and says why, when it cannot read the
// cluster's launcher settings (push_branch, https_rewrite); it does not go
// on with the defaults and reach the agent.
func TestRV5PushBranchStopsWhenSettingsCannotBeRead(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	var other atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/launcher") {
			other.Add(1)
		}
		http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	cl, err := api.New(api.Options{Base: srv.URL, HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "t", nil }})
	if err != nil {
		t.Fatal(err)
	}
	s := &substrateSession{Name: "test", Client: cl, Bearer: func(context.Context) (string, error) { return "t", nil }}
	cmd := &cobra.Command{}
	err = runSubstratePushBranch(context.Background(), cmd, &substratePullFlags{pushBranch: "agent/x"}, s, api.Actor{Atespace: "eng-web", Name: "alice-1"}, false)
	if err == nil || !strings.Contains(err.Error(), "could not read the cluster's settings") {
		t.Fatalf("err = %v, want it to name the settings read", err)
	}
	if n := other.Load(); n != 0 {
		t.Fatalf("%d calls past the failed settings read", n)
	}
}
