// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A missing destination secret used to send start to the default port of the
// fallback configuration, which then blamed whoever held that port.
func TestMissingObservabilitySecretErrorNamesTheVariable(t *testing.T) {
	loadErr := fmt.Errorf("compile: %w", &config.V8SecretReferenceError{
		Destination: "galileo",
		Path:        `observability.destinations[1].headers["Galileo-API-Key"]`,
		Reference:   "GALILEO_API_KEY",
	})
	err := missingObservabilitySecretError("start", loadErr)
	if err == nil {
		t.Fatal("expected a refusal for a missing destination secret")
	}
	for _, want := range []string{
		`destination "galileo" needs GALILEO_API_KEY`,
		"defenseclaw keys set GALILEO_API_KEY",
		"defenseclaw-gateway start",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "--api-port") {
		t.Errorf("error %q still points at the port", err)
	}
	for _, other := range []error{nil, errors.New("config file is missing")} {
		if got := missingObservabilitySecretError("start", other); got != nil {
			t.Errorf("missingObservabilitySecretError(%v) = %v, want nil", other, got)
		}
	}
}
