// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strings"
	"testing"
)

func TestProfileExplainUnknownAccountNamesGetentSpelling(t *testing.T) {
	previous := profileExplainQualifiedName
	profileExplainQualifiedName = func(context.Context, string) string { return "dcad-eli6@dclab.test" }
	t.Cleanup(func() { profileExplainQualifiedName = previous })
	_, err := profileExplainUnresolved("dcad-eli6", nil)
	if err == nil || !strings.Contains(err.Error(), `no account named "dcad-eli6"`) ||
		!strings.Contains(err.Error(), `getent passwd knows "dcad-eli6@dclab.test"`) {
		t.Fatalf("unknown account explanation = %v", err)
	}
}
