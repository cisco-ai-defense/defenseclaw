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

package gateway

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

type signInAlert struct {
	severity, summary string
	details           map[string]any
}

// substrate-1 GAP-0463: a sign-in server outage was only a gateway log
// line; the audit export showed nothing. The watcher now writes one audit
// alert when a check sees the cause change (failing, then restored) and nothing while
// the same failure goes on.
func TestGAP0463SignInServerOutageIsAnAuditRow(t *testing.T) {
	saved := signInRetryAfter
	signInRetryAfter = time.Millisecond
	t.Cleanup(func() { signInRetryAfter = saved })

	srv := &seqSignInServer{seq: []identity.IssuerDiagnosis{
		signInOK,                                                           // check 1: pass
		blip(identity.IssuerUnreachable), blip(identity.IssuerUnreachable), // check 2: outage (with its retry)
		blip(identity.IssuerUnreachable), blip(identity.IssuerUnreachable), // check 3: still out
		signInOK, // check 4: back
	}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.SignInServer = srv })
	st := f.api.substrateState()
	var mu sync.Mutex
	var got []signInAlert
	st.alert = func(_ context.Context, severity, summary string, details map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, signInAlert{severity, summary, details})
	}
	// The watcher and an administrator's doctor run the same check.
	for range 4 {
		st.checkSignIn(context.Background())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("audit alerts for pass, outage, outage, restore = %d, want 2 (failing, restored): %+v", len(got), got)
	}
	out, back := got[0], got[1]
	if out.severity != "HIGH" || out.details["event"] != "sign_in_server" || out.details["state"] != "failing" ||
		out.details["cause"] != identity.IssuerUnreachable || out.details["issuer"] != signInOK.Issuer || out.details["since"] == nil ||
		!strings.Contains(out.summary, "sign-in server failing") {
		t.Fatalf("outage alert %+v", out)
	}
	if back.severity != "INFO" || back.details["state"] != "restored" || back.details["previous_cause"] != identity.IssuerUnreachable {
		t.Fatalf("restore alert %+v", back)
	}
}
