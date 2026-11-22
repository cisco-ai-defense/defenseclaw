// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestKubeFactProjection: the Kubernetes request tuple (GAP-1824) reaches the
// CEL activation as f.kube.
func TestKubeFactProjection(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	program, code := compiler.Compile(`f.kube.exists(k, k.source == 'kubectl' &&
k.verb == 'list' && k.resource == 'secrets' && k.all_namespaces && k.reveals_content)`)
	if code != CompileOK {
		t.Fatalf("Compile() code = %q", code)
	}
	for command, want := range map[string]bool{
		"kubectl get secrets -A -o yaml": true,
		"kubectl get pods -A -o yaml":    false,
	} {
		facts, projection := Project(actionfacts.Analyze(actionfacts.Input{
			Tool: "execute_command", Command: command, DialectHint: actionfacts.DialectPOSIX,
		}))
		if projection != ProjectionOK {
			t.Fatalf("%s: Project() code = %q", command, projection)
		}
		result, eval := program.EvalBool(context.Background(), facts)
		if eval != EvalOK || result.Matched != want {
			t.Fatalf("%s: EvalBool() = (%+v, %q), want %v", command, result, eval, want)
		}
	}

	over := actionfacts.Facts{KubeRequests: make([]actionfacts.KubeRequestFact, maxKube+1)}
	if _, projection := Project(over); projection != ProjectionCountLimit {
		t.Fatalf("over-bound kube list: Project() code = %q", projection)
	}
}
