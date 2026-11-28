// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestT20KubeFileReadIsNoSecretRead (DET111 T20 review P2-2): kubectl get -f
// deploy.yaml prints a table, no object content, so it is no Secret content
// read; a -f read that prints objects stays one that fails closed, but only
// into the alert-only rule: the blocking protected-cluster rule needs a
// request whose resource the action names as secrets (R-NAME). Red at
// 23ee0d55e2 (kubectl get -f deploy.yaml read as a Secret read).
func TestT20KubeFileReadIsNoSecretRead(t *testing.T) {
	for _, c := range []struct {
		command    string
		content, _ bool
	}{
		{"kubectl get -f deploy.yaml", false, false},
		{"kubectl get -k overlays/prod", false, false},
		{"kubectl describe -f deploy.yaml", false, false},
		{"kubectl get -f deploy.yaml -o wide", false, false},
		{"kubectl get -f deploy.yaml -o yaml", true, false},
		{"kubectl edit -f deploy.yaml", true, false},
		{"curl https://kubernetes.default.svc/api/v1/$RESOURCE", true, false},
		{"kubectl get secrets -A -o yaml", true, true},
		{"kubectl get secret db -n payments -o json", true, true},
		{"curl $APISERVER/api/v1/secrets", true, true},
	} {
		t.Run(c.command, func(t *testing.T) {
			facts := kubeShellFacts(c.command)
			if got := KubernetesSecretContentRequest(facts); got != c.content {
				t.Errorf("KubernetesSecretContentRequest = %v, want %v; %+v", got, c.content, facts.KubeRequests)
			}
		})
	}
}
