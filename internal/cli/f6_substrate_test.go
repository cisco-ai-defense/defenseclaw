// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0039 (lane F6): the serve wiring refuses an unscanned skill folder
// where hooks fail closed (managed installs, the strict tier) and only
// alerts in the OSS default tiers; receipts hold on every replica with the
// shared chain key.
func TestSubstrateUnscannedSkillsFollowTheHookPosture(t *testing.T) {
	for _, tc := range []struct {
		name, mode, pack string
		want             bool
	}{
		{"OSS default", "", "default", false},
		{"OSS permissive", "", "permissive", false},
		{"OSS strict", "", "strict", true},
		{"managed default pack", "managed_enterprise", "default", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &config.Config{DeploymentMode: tc.mode}
			c.Guardrail.RulePack = tc.pack
			if got := substrateBlocksUnscannedSkills(c)("claudecode"); got != tc.want {
				t.Fatalf("refuse unscanned = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSubstrateSkillReceiptKeyComesFromTheChainKey(t *testing.T) {
	if substrateSkillReceiptKey(nil) != nil {
		t.Fatal("no chain key must mean no shared receipt key")
	}
	a, b := substrateSkillReceiptKey([]byte("chain")), substrateSkillReceiptKey([]byte("chain"))
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatal("replicas with one chain key must derive one receipt key")
	}
	if bytes.Equal(a, []byte("chain")) || bytes.Equal(a, substrateSkillReceiptKey([]byte("other"))) {
		t.Fatal("the receipt key must be derived, and differ per chain key")
	}
}

// GAP-0053 (lane F6): the controller the shipped substrate-controller
// command and the create path build (newSubstrateController) admits through
// A9's attestation verifier when attestation is required (the default). A
// stand-in that refuses everything (NoAttestor) would leave the product
// without admission, and every other test green.
func TestShippedControllerUsesTheAttestationVerifier(t *testing.T) {
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Templates.TrustAnchors = filepath.Join(t.TempDir(), "absent.pem")
	var sink bytes.Buffer
	ctl, err := newSubstrateController(cfg, ateapifake.New(), controller.NewMemoryRegistry(), nil, nil, &controller.JSONSink{W: &sink}, false, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ta, ok := ctl.Attestor().(*controller.TemplateAttestor)
	if !ok || ta.Verifier == nil {
		t.Fatalf("the shipped controller admits with %T, not the attestation verifier", ctl.Attestor())
	}
	off := false
	cfg.Substrate.RequireAttestedTemplates = &off
	if ctl, err = newSubstrateController(cfg, ateapifake.New(), controller.NewMemoryRegistry(), nil, nil, &controller.JSONSink{W: &sink}, false, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := ctl.Attestor().(controller.NoAttestor); !ok {
		t.Fatalf("attestation off: %T", ctl.Attestor())
	}
}

// GAP-0154: the create path builds its controller the way serve does
// (substrate_serve.go) and reads the anchors from
// substrate.templates.trust_anchors, the file the chart mounts in the
// gateway pod (setup TestTemplateAnchorsReachTheCreatePath pins the mount
// to config.DefaultSubstrateTemplateAnchors). With the file there it warns
// nothing; without it, it says every template is refused.
func TestCreatePathReadsTheTemplateAnchors(t *testing.T) {
	createPath := func(anchors string) string {
		cfg := &config.Config{}
		cfg.Substrate.Enabled = true
		cfg.Substrate.Templates.TrustAnchors = anchors
		var sink bytes.Buffer
		ctl, err := newSubstrateController(cfg, ateapifake.New(), &controller.LeaderRegistry{Store: nil}, nil, nil, &controller.JSONSink{W: &sink}, false, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ctl.Attestor().(*controller.TemplateAttestor); !ok {
			t.Fatalf("the create path admits with %T", ctl.Attestor())
		}
		return sink.String()
	}
	p := filepath.Join(t.TempDir(), "anchors.pem")
	if out := createPath(p); !strings.Contains(out, "every template is refused") {
		t.Fatalf("a missing anchors file must be reported: %q", out)
	}
	s, err := attest.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pemBytes, 0o440); err != nil {
		t.Fatal(err)
	}
	if out := createPath(p); strings.Contains(out, "trust anchors") {
		t.Fatalf("the create path did not find the mounted anchors: %q", out)
	}
	if config.DefaultSubstrateTemplateAnchors != "/etc/defenseclaw/substrate/template-anchors/anchors.pem" {
		t.Fatal("the default anchors path moved: move the chart mount (dc.templateAnchorsMount) with it")
	}
}
