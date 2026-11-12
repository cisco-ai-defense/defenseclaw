// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

func signinServer(connector string, managed bool, env map[string]string) *Server {
	cfg := kit.DefaultConfig()
	cfg.Managed = managed
	cfg.Relay.Connector = connector
	cfg.Relay.Interactive = []string{"/bin/true"}
	cfg.Relay.Env = env
	return NewServer(Options{Config: cfg, Warm: func(context.Context, string) error { return nil }})
}

// E9 inside the actor: a managed image does not start an agent that signs in
// to a vendor account, unless its vendor key is bound; an open-source image
// starts it and says what the sign-in costs.
func TestRelaySigninRefusedInManagedWarnedInOpenSource(t *testing.T) {
	for _, c := range []string{"cursor", "amp", "devin", "kiro", "antigravity"} {
		s := signinServer(c, true, nil)
		err := s.init()
		if err == nil || !strings.Contains(err.Error(), "managed") {
			t.Errorf("%s managed: init error %v, want a refusal that says why", c, err)
		}
		o := signinServer(c, false, nil)
		if err := o.init(); err != nil {
			t.Errorf("%s open source: init %v", c, err)
			continue
		}
		if !strings.Contains(o.agent.Banner, "snapshot") {
			t.Errorf("%s open source: banner %q, want the snapshot warning", c, o.agent.Banner)
		}
	}
}

func TestRelaySigninNotAskedOfOtherRoutes(t *testing.T) {
	for _, c := range []string{"claudecode", "codex", "opencode", "copilot", "hermes"} {
		s := signinServer(c, true, nil)
		if err := s.init(); err != nil || s.agent.Banner != "" {
			t.Errorf("%s managed: init %v banner %q, want none", c, err, s.agent.Banner)
		}
	}
	for c, env := range map[string]string{"cursor": "CURSOR_API_KEY", "amp": "AMP_API_KEY", "kiro": "KIRO_API_KEY", "antigravity": "GEMINI_API_KEY"} {
		s := signinServer(c, true, map[string]string{env: "placeholder-not-a-secret"})
		if err := s.init(); err != nil || s.agent.Banner != "" {
			t.Errorf("%s managed with %s: init %v banner %q, want a clean start", c, env, err, s.agent.Banner)
		}
	}
	// Devin has no key route: a variable named like one does not help.
	d := signinServer("devin", true, map[string]string{"DEVIN_API_KEY": "x"})
	if err := d.init(); err == nil {
		t.Error("devin managed with a made-up key variable started")
	}
}

// The refusal is a rule, not a fault: the relay answers 403 with the reason.
func TestRelaySigninRefusalIsForbidden(t *testing.T) {
	s := signinServer("devin", true, nil)
	err := s.init()
	var refused *signinRefusal
	if !errors.As(err, &refused) {
		t.Fatalf("init error %T %v, want a signinRefusal", err, err)
	}
}
