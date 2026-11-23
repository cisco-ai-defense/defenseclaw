// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestT20KubeRequestCutInventsNoSecretRead (DET111 T20 review P2-3): the
// reviewer's 33 x "kubectl get pods;" is cut at maxKubeRequests and the cut
// is recorded (TestKubeRequestBound), but it is no Secret read; a Secret read after the plain ones
// is kept. Red at 23ee0d55e2 (the last request became an Unknown one).
func TestT20KubeRequestCutInventsNoSecretRead(t *testing.T) {
	plain := strings.Repeat("kubectl get pods; ", 33)
	facts := kubeShellFacts(plain)
	if KubernetesSecretContentRequest(facts) {
		t.Fatalf("33 x kubectl get pods read as a Secret read: %+v", facts.KubeRequests[len(facts.KubeRequests)-1])
	}
	facts = kubeShellFacts(plain + "kubectl get secrets -A -o yaml")
	if !KubernetesSecretContentRequest(facts) {
		t.Fatalf("a Secret read past the bound was dropped: %d requests", len(facts.KubeRequests))
	}
}
