// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestLoadFromBytesMatchesFileLoaderForExactSource(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultConfigName)
	raw := []byte("config_version: 7\n" +
		"data_dir: " + directory + "\n" +
		"environment: parity\n" +
		"guardrail:\n  mode: action\n" +
		"otel:\n  resource:\n    attributes:\n      service.name: defenseclaw-test\n      defenseclaw.test: exact\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromBytes, err := LoadFromBytes(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromFile, fromBytes) {
		t.Fatalf("file and byte loaders diverged\nfile:  %#v\nbytes: %#v", fromFile, fromBytes)
	}
	if got := fromBytes.OTel.Resource.Attributes["service.name"]; got != "defenseclaw-test" {
		t.Fatalf("dotted resource attribute = %q", got)
	}
}

func TestLoadFromBytesIgnoresDifferentAmbientFileAndHashesSnapshot(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultConfigName)
	snapshot := []byte("config_version: 7\ndata_dir: " + directory + "\nguardrail:\n  mode: observe\n")
	ambient := []byte("config_version: 7\ndata_dir: " + directory + "\nguardrail:\n  mode: action\n")
	if err := os.WriteFile(path, ambient, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromBytes(path, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Guardrail.Mode != "observe" || loaded.ConfigFilePath != path {
		t.Fatalf("snapshot mode/source = %q/%q", loaded.Guardrail.Mode, loaded.ConfigFilePath)
	}
	sum := sha256.Sum256(snapshot)
	if got, want := version.Current().ContentHash, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("content hash = %q, want snapshot hash %q", got, want)
	}
}

func TestLoadCandidateFromBytesDoesNotPublishProvenance(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultConfigName)
	raw := []byte("config_version: 7\ndata_dir: " + directory + "\nguardrail:\n  mode: action\n")
	version.SetContentHash([]byte("accepted config"))
	want := version.Current().ContentHash
	loaded, err := LoadCandidateFromBytes(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Guardrail.Mode != "action" {
		t.Fatalf("candidate mode = %q", loaded.Guardrail.Mode)
	}
	if got := version.Current().ContentHash; got != want {
		t.Fatalf("candidate load changed provenance from %q to %q", want, got)
	}
}
