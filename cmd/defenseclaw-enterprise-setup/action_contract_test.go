package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
)

func TestStandaloneSetupFailureWithoutActionUsesSchemaAction(t *testing.T) {
	schemaBytes, err := os.ReadFile("../../packaging/mdm/contract/lifecycle-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Action struct {
				Enum []string `json:"enum"`
			} `json:"action"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName,
		enterpriseSetupOptions{JSON: true}, errors.New("missing action"), enterpriseInvalidArgsExitCode)
	var result struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(schema.Properties.Action.Enum, result.Action) {
		t.Fatalf("Setup action %q is outside the lifecycle schema enum %v: %s", result.Action,
			schema.Properties.Action.Enum, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}
