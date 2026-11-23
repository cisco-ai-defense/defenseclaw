// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// slowResume answers a resume like a busy microVM node: it records the
// deadline the gateway gave the call, then fails with code.
type slowResume struct {
	*ateapifake.Fake
	code     codes.Code
	deadline time.Duration
}

func (s *slowResume) ResumeActor(ctx context.Context, _ *ateapi.ObjectRef) (*ateapi.Actor, bool, error) {
	if d, ok := ctx.Deadline(); ok {
		s.deadline = time.Until(d)
	}
	return nil, false, status.Error(s.code, "resume did not finish")
}

// GAP-0468: a burst of microVM creates on one node failed with the bare
// 'resume failed' (502): the resume ran under the control API client's 10 s
// default deadline and a slow restore was called a broken cluster. The
// resume now has its own deadline, and a busy answer is a retryable 503
// resume_busy, not resume_failed.
func TestSubstrateCreateOnABusyNodeGAP0468(t *testing.T) {
	for _, c := range []struct {
		code   codes.Code
		status int
		reason string
	}{
		{codes.DeadlineExceeded, http.StatusServiceUnavailable, "resume_busy"},
		{codes.Unavailable, http.StatusServiceUnavailable, "resume_busy"},
		{codes.Internal, http.StatusBadGateway, "resume_failed"},
	} {
		fake := ateapifake.New()
		fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
		f := newSubstrateFixture(t, func(cfg *SubstrateConfig) {
			cfg.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
		})
		slow := &slowResume{Fake: fake, code: c.code}
		f.api.substrateState().cfg.Actions = &SubstrateATEActions{Client: slow, Ensure: func(context.Context, string, string) error { return nil }}
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-busy"}`)
		var e struct{ Reason string }
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if rec.Code != c.status || e.Reason != c.reason {
			t.Errorf("%s: %d %q, want %d %q", c.code, rec.Code, e.Reason, c.status, c.reason)
		}
		if slow.deadline < time.Minute {
			t.Errorf("%s: the resume ran with a %s deadline, want its own (minutes)", c.code, slow.deadline.Round(time.Second))
		}
		if _, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-busy")); !ateapi.IsNotFound(err) {
			t.Errorf("%s: the half-made actor stayed: %v", c.code, err)
		}
	}
}
