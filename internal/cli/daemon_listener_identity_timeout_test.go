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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GAP-1668: a running gateway that answers /status after more than the 1 s
// readiness poll timeout is still identified, not called an auth failure.
func TestListenerIdentityStatusWaitsForSlowGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1300 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"runtime": map[string]interface{}{"pid": 4242}})
	}))
	defer srv.Close()
	status, err := fetchListenerIdentityStatus(&http.Client{Timeout: defaultReadinessHTTPTimeout}, srv.URL, "tok")
	if err != nil || status.Runtime.PID != 4242 {
		t.Fatalf("fetchListenerIdentityStatus() = pid %d, err %v; want the slow answer", status.Runtime.PID, err)
	}
	if !isHTTPTimeout(context.DeadlineExceeded) {
		t.Fatal("isHTTPTimeout(context.DeadlineExceeded) = false")
	}
}
