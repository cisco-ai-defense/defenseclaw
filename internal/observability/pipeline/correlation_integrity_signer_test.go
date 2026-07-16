// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestCorrelationKeyProjectionIntegritySignerDeterministicAndVerifiable(t *testing.T) {
	key := loadPipelineCorrelationKey(t)
	signer, err := NewCorrelationKeyProjectionIntegritySigner(key)
	if err != nil {
		t.Fatalf("construct signer: %v", err)
	}
	message := []byte("defenseclaw-projection-integrity-v1\x00one-projected-record")

	first, err := signer.HMACSHA256(context.Background(), message)
	if err != nil {
		t.Fatalf("sign first message: %v", err)
	}
	second, err := signer.HMACSHA256(context.Background(), message)
	if err != nil {
		t.Fatalf("sign second message: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("same immutable key and message produced different signatures")
	}
	if len(first) != sha256.Size {
		t.Fatalf("signature length = %d, want %d", len(first), sha256.Size)
	}

	material, available := key.Material()
	if !available {
		t.Fatal("loaded correlation key is unavailable")
	}
	want := hmac.New(sha256.New, material[:])
	_, _ = want.Write(message)
	if !hmac.Equal(first, want.Sum(nil)) {
		t.Fatal("signature does not verify with the snapshotted correlation key")
	}
	if signer.KeyID() != key.ID() {
		t.Fatalf("key ID = %q, want loaded correlation key identity", signer.KeyID())
	}
}

func TestCorrelationKeyProjectionIntegritySignerSeparatesMessagesAndDomains(t *testing.T) {
	signer := newPipelineCorrelationSigner(t)
	messages := [][]byte{
		[]byte("defenseclaw-projection-integrity-v1\x00same-payload"),
		[]byte("defenseclaw-projection-integrity-v2\x00same-payload"),
		[]byte("defenseclaw-projection-integrity-v1\x00different-payload"),
	}
	signatures := make([][]byte, 0, len(messages))
	for _, message := range messages {
		signature, err := signer.HMACSHA256(context.Background(), message)
		if err != nil {
			t.Fatalf("sign domain-separated message: %v", err)
		}
		for _, prior := range signatures {
			if hmac.Equal(prior, signature) {
				t.Fatal("different message or domain produced the same signature")
			}
		}
		signatures = append(signatures, signature)
	}
}

func TestCorrelationKeyProjectionIntegritySignerSnapshotsSourceKey(t *testing.T) {
	key := loadPipelineCorrelationKey(t)
	signer, err := NewCorrelationKeyProjectionIntegritySigner(key)
	if err != nil {
		t.Fatalf("construct signer: %v", err)
	}
	message := []byte("projection whose signature must remain stable")
	want, err := signer.HMACSHA256(context.Background(), message)
	if err != nil {
		t.Fatalf("sign before source-copy mutation: %v", err)
	}

	sourceCopy, available := key.Material()
	if !available {
		t.Fatal("loaded correlation key is unavailable")
	}
	for index := range sourceCopy {
		sourceCopy[index] ^= 0xff
	}
	key = redaction.CorrelationKey{}

	got, err := signer.HMACSHA256(context.Background(), message)
	if err != nil {
		t.Fatalf("sign after source-copy mutation: %v", err)
	}
	if !hmac.Equal(got, want) {
		t.Fatal("mutating caller-owned key copies changed the signer snapshot")
	}
}

func TestCorrelationKeyProjectionIntegritySignerHonorsCancellation(t *testing.T) {
	signer := newPipelineCorrelationSigner(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	signature, err := signer.HMACSHA256(ctx, []byte("sensitive-message"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if signature != nil {
		t.Fatal("cancelled signing returned a signature")
	}
	if strings.Contains(err.Error(), "sensitive-message") {
		t.Fatal("cancellation error exposed message content")
	}
}

func TestCorrelationKeyProjectionIntegritySignerNilAndInvalidAreUnavailable(t *testing.T) {
	var nilSigner *CorrelationKeyProjectionIntegritySigner
	if nilSigner.KeyID() != "" {
		t.Fatal("nil signer exposed a key identity")
	}
	signature, err := nilSigner.HMACSHA256(context.Background(), []byte("private-message"))
	if !errors.Is(err, audit.ErrIntegrityKeyUnavailable) {
		t.Fatalf("nil signer error = %v, want integrity-key-unavailable", err)
	}
	if signature != nil || strings.Contains(err.Error(), "private-message") {
		t.Fatal("nil signer returned output or exposed message content")
	}

	signer, err := NewCorrelationKeyProjectionIntegritySigner(redaction.CorrelationKey{})
	if !errors.Is(err, audit.ErrIntegrityKeyUnavailable) {
		t.Fatalf("zero-key constructor error = %v, want integrity-key-unavailable", err)
	}
	if signer != nil {
		t.Fatal("zero-key constructor returned a signer")
	}
}

func TestCorrelationKeyProjectionIntegritySignerConcurrentUse(t *testing.T) {
	signer := newPipelineCorrelationSigner(t)
	message := []byte("one immutable projection integrity message")
	want, err := signer.HMACSHA256(context.Background(), message)
	if err != nil {
		t.Fatalf("sign reference message: %v", err)
	}

	const workers = 64
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 100; attempt++ {
				got, signErr := signer.HMACSHA256(context.Background(), message)
				if signErr != nil {
					errorsFound <- signErr
					return
				}
				if !hmac.Equal(got, want) || signer.KeyID() == "" {
					errorsFound <- errors.New("concurrent signer result changed")
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func newPipelineCorrelationSigner(t *testing.T) *CorrelationKeyProjectionIntegritySigner {
	t.Helper()
	signer, err := NewCorrelationKeyProjectionIntegritySigner(loadPipelineCorrelationKey(t))
	if err != nil {
		t.Fatalf("construct correlation-key signer: %v", err)
	}
	return signer
}

func loadPipelineCorrelationKey(t *testing.T) redaction.CorrelationKey {
	t.Helper()
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatalf("secure temporary data directory: %v", err)
	}
	key, err := redaction.LoadOrCreateCorrelationKey(dataDir)
	if redaction.IsKeyStoreError(err, redaction.KeyStoreErrorUnsupported) {
		t.Skip("correlation-key custody is unavailable on this platform")
	}
	if err != nil {
		t.Fatalf("load correlation key: %v", err)
	}
	return key
}
