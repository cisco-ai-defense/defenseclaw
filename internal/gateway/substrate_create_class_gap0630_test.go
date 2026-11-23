//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// GAP-0630: the sandbox class on records (Registration.SandboxClass, the
// defenseclaw.sandbox.driver attribute) is the class of the pool the actor
// runs on. A template pinned to the microVM pool with --worker-label and no
// class label recorded gvisor; a template that may land on either pool
// records the weaker one.
func TestGAP0630CreatedClassIsThePoolsClass(t *testing.T) {
	fake := ateapifake.New()
	client := poolWorkers{Fake: fake, workers: []*pb.Worker{
		poolWorker("gv", "dc-gv", "gvisor"), poolWorker("mv", "dc-mv", "microvm"),
	}}
	for name, sel := range map[string]map[string]string{"claude": {"workload": "dc-gv"}, "claude-mv": {"workload": "dc-mv"}, "any": nil} {
		t0 := &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "dc-eng", Name: name}}
		if sel != nil {
			t0.WorkerSelector = &ateapi.Selector{MatchLabels: sel}
		}
		fake.PutTemplate(t0)
	}
	acts := &SubstrateATEActions{Client: client, Ensure: func(context.Context, string, string) error { return nil }}
	for _, tc := range []struct{ name, tmpl, asked, want string }{
		{"c1", "claude-mv", "", "microvm"}, {"c2", "claude-mv", "gvisor", "microvm"},
		{"c3", "claude", "", "gvisor"}, {"c4", "any", "", "gvisor"}, {"c5", "any", "microvm", "microvm"},
	} {
		got, err := acts.Create(context.Background(), SubstrateCreate{Atespace: "dc-eng", Template: tc.tmpl, Connector: "claudecode",
			Name: tc.name, SandboxClass: tc.asked, Kit: &SubstrateTemplateKit{}})
		if err != nil {
			t.Fatalf("create %s (asked %q): %v", tc.tmpl, tc.asked, err)
		}
		if got.SandboxClass != tc.want {
			t.Errorf("template %s asked %q: records %q, want %q (the pool it runs on)", tc.tmpl, tc.asked, got.SandboxClass, tc.want)
		}
	}
}
