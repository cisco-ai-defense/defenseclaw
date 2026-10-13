// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"testing"
)

func TestNewBuiltinJetBrainsIDPreservesOperatorPack(t *testing.T) {
	data := t.TempDir()
	mustWrite(t, filepath.Join(data, "signature-packs", "jetbrains.json"), `{"version":1,"signatures":[{"id":"jetbrains-ai","name":"Operator JetBrains","vendor":"Example","category":"ai_cli","confidence":0.7,"process_names":["jbai"]}]}`)
	sigs, err := LoadAISignaturesWithOptions(AISignatureLoadOptions{DataDir: data})
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range sigs {
		if sig.ID == "jetbrains-ai" {
			if sig.Name != "Operator JetBrains" {
				t.Fatalf("signature = %+v", sig)
			}
			return
		}
	}
	t.Fatal("operator signature missing")
}
