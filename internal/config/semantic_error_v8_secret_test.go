// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

func TestObservabilityV8SemanticErrorNamesUnsetEnvironmentSecret(t *testing.T) {
	err := annotateObservabilityV8SemanticError(nil, &V8SecretReferenceError{
		Destination: "galileo",
		Path:        `observability.destinations[1].headers["Galileo-API-Key"]`,
		Reference:   "GALILEO_API_KEY",
	})
	message := err.Error()
	for _, want := range []string{
		`environment variable "GALILEO_API_KEY" is not set`,
		"defenseclaw keys set GALILEO_API_KEY",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "received") || strings.Contains(message, "documented semantic constraint") {
		t.Errorf("message %q is still the generic semantic text", message)
	}
	var secretErr *V8SecretReferenceError
	if !errors.As(err, &secretErr) {
		t.Fatal("the annotated error must still unwrap to the secret reference error")
	}
}
