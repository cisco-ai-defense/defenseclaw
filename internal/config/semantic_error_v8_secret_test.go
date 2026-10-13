// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

// The real OTLP scheme rule reaches the message instead of the generic
// semantic wording (GAP-0081); a rule that carries a URL does not.
func TestObservabilityV8SemanticErrorShowsTheRuleNotTheGenericText(t *testing.T) {
	_, compileErr := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{
		{Name: "otlp", Kind: ObservabilityV8DestinationOTLP, Protocol: "http/protobuf", Endpoint: "http://otel.example.test/v1/traces"},
	}})
	if compileErr == nil {
		t.Fatal("an http endpoint without tls.insecure compiled")
	}
	message := annotateObservabilityV8SemanticError(nil, compileErr).Error()
	if !strings.Contains(message, "OTLP endpoint scheme and tls.insecure disagree (an http endpoint needs tls.insecure: true") ||
		strings.Contains(message, "documented semantic constraint") {
		t.Errorf("message %q does not state the rule", message)
	}
	err := annotateObservabilityV8SemanticError(nil, errors.New("observability.destinations[0].endpoint: cannot reach https://user:pw@host"))
	if strings.Contains(err.Error(), "pw@host") || !strings.Contains(err.Error(), "documented semantic constraint") {
		t.Errorf("message %q relayed a value", err.Error())
	}
}

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
