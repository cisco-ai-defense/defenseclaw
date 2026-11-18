//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// poolWorkers is a fake whose workers are pools labelled like the D3 kind
// stack: workload=dc-gv (gvisor) and workload=dc-mv (microvm), no
// DefenseClaw class label.
type poolWorkers struct {
	*ateapifake.Fake
	workers []*pb.Worker
}

func (p poolWorkers) ListWorkers(context.Context, ateapi.ListOptions) (ateapi.Page[*pb.Worker], error) {
	return ateapi.Page[*pb.Worker]{Items: p.workers}, nil
}

func poolWorker(pool, workload, class string) *pb.Worker {
	return &pb.Worker{WorkerNamespace: "dc-workers", WorkerPool: pool, Labels: map[string]string{"workload": workload},
		Status: &pb.WorkerStatus{SandboxClasses: []*pb.WorkerSandboxClass{{SandboxClass: class}}}}
}

// placedOn is the classes of the workers the scheduler may place a on: the
// AND of its selector and its template's.
func placedOn(workers []*pb.Worker, a *ateapi.Actor, tmpl *ateapi.ActorTemplate) map[string]bool {
	sel := map[string]string{}
	for k, v := range tmpl.GetWorkerSelector().GetMatchLabels() {
		sel[k] = v
	}
	for k, v := range a.GetWorkerSelector().GetMatchLabels() {
		if have, ok := sel[k]; ok && have != v {
			return nil
		}
		sel[k] = v
	}
	out := map[string]bool{}
next:
	for _, w := range workers {
		for k, v := range sel {
			if got, ok := w.GetLabels()[k]; !ok || got != v {
				continue next
			}
		}
		out[w.GetStatus().GetSandboxClasses()[0].GetSandboxClass()] = true
	}
	return out
}

// GAP-0386: with substrate.default_sandbox_class microvm, a run of a
// template pinned to the microVM pool with --worker-label (no class label)
// lands on that pool, a template with no selector is narrowed to it, and a
// template pinned to the gVisor pool is refused before any actor exists.
// Before the fix every one got the class label the pools do not carry, so
// no worker could take the actor ("no free worker").
func TestSubstrateCreateMicroVMDefaultUsesTheTemplatesPool(t *testing.T) {
	cfg := &config.Config{}
	cfg.Substrate.DefaultSandboxClass = "microvm"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {}}
	classFor := SubstrateSandboxClassFor(cfg)
	if got := classFor("eng"); got != "microvm" {
		t.Fatalf("eng class %q, want the cluster default microvm", got)
	}

	fake := ateapifake.New()
	client := poolWorkers{Fake: fake, workers: []*pb.Worker{
		poolWorker("gv", "dc-gv", "gvisor"), poolWorker("gv", "dc-gv", "gvisor"),
		poolWorker("mv", "dc-mv", "microvm"), poolWorker("mv", "dc-mv", "microvm"),
	}}
	tmpls := map[string]*ateapi.ActorTemplate{}
	for name, sel := range map[string]map[string]string{"claude": {"workload": "dc-gv"}, "claude-mv": {"workload": "dc-mv"}, "any": nil} {
		t0 := &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "dc-eng", Name: name}}
		if sel != nil {
			t0.WorkerSelector = &ateapi.Selector{MatchLabels: sel}
		}
		tmpls[name] = fake.PutTemplate(t0)
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "dc-eng", nil }
		c.SandboxClass = classFor
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: client, Ensure: func(context.Context, string, string) error { return nil }}
	create := func(tmpl, name string) (int, string) {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"`+tmpl+`","connector":"claudecode","name":"`+name+`"}`)
		return rec.Code, rec.Body.String()
	}
	for _, tc := range []struct{ tmpl, name string }{{"claude-mv", "j01m1"}, {"any", "j01m2"}} {
		if code, body := create(tc.tmpl, tc.name); code != http.StatusCreated {
			t.Fatalf("run %s: %d %s", tc.tmpl, code, body)
		}
		a, err := fake.GetActor(context.Background(), ateapi.Ref("dc-eng", tc.name))
		if err != nil {
			t.Fatal(err)
		}
		if got := placedOn(client.workers, a, tmpls[tc.tmpl]); len(got) != 1 || !got["microvm"] {
			t.Errorf("run %s: actor selector %v places it on %v, want only the microvm workers", tc.tmpl, a.GetWorkerSelector().GetMatchLabels(), got)
		}
	}
	code, body := create("claude", "j01m3")
	if code != http.StatusForbidden || !strings.Contains(body, "sandbox_class_unavailable") || !strings.Contains(body, "gvisor") {
		t.Errorf("run of the gVisor-pinned template under microvm: %d %s, want 403 sandbox_class_unavailable", code, body)
	}
	if _, err := fake.GetActor(context.Background(), ateapi.Ref("dc-eng", "j01m3")); !ateapi.IsNotFound(err) {
		t.Errorf("a refused run left an actor: %v", err)
	}
}
