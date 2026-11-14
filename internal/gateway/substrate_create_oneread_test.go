//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0201 residual (R6): a launcher create read the template's attestation
// twice, once for the connector (the route) and once for the versions
// (Create), and treated a failed second read as "no versions". One create is
// one attestation read: the route's kit goes to Create, so the connector and
// the registration's versions come from the same read, and an unreadable
// attestation is reported once, not hidden on a second read.
func TestSubstrateCreateReadsTheTemplateAttestationOnce(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	reads := 0
	var answer func(n int) (SubstrateTemplateKit, error)
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { return nil },
		TemplateKit: func(context.Context, *ateapi.ActorTemplate) (SubstrateTemplateKit, error) {
			reads++
			return answer(reads)
		}}
	create := func(name string) int {
		t.Helper()
		return f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice",
			fmt.Sprintf(`{"template":"cc","connector":"claudecode","name":%q}`, name)).Code
	}

	// A second read would answer something else: the route's read is the one used.
	answer = func(n int) (SubstrateTemplateKit, error) {
		if n > 1 {
			return SubstrateTemplateKit{}, errors.New("the second read must not happen")
		}
		return attestedClaudeKit(), nil
	}
	if code := create("alice-k1"); code != http.StatusCreated || reads != 1 {
		t.Fatalf("attested template: status %d, %d attestation reads, want 201 and 1", code, reads)
	}
	actor, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-k1"))
	if err != nil {
		t.Fatal(err)
	}
	reg, ok, err := st.cfg.Registrations.Get(context.Background(), "eng-web", actor.GetMetadata().GetUid())
	if err != nil || !ok || reg.HarnessVersion != attestedClaudeKit().AgentVersion || reg.TemplateDigest != attestedClaudeKit().Digest {
		t.Fatalf("registration %+v ok=%v err=%v: it must carry the kit the route read", reg, ok, err)
	}

	// An unreadable attestation (open source: the create goes on with a warning)
	// is read once too, not once for the route and once more for Create.
	reads = 0
	answer = func(int) (SubstrateTemplateKit, error) {
		return SubstrateTemplateKit{}, &SubstrateTemplateAttestation{Retryable: true, Reason: "registry outage"}
	}
	if code := create("alice-k2"); code != http.StatusCreated || reads != 1 {
		t.Fatalf("unreadable attestation: status %d, %d attestation reads, want 201 and 1", code, reads)
	}
}
