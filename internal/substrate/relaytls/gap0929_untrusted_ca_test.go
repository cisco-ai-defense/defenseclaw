// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relaytls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

// GAP-0929: a CA rotation that drops the old CA keeps a proof that holds
// apart (ErrRenewalUntrustedCA, with the certificate) from a bad proof,
// and Trusts names the CAs still in the pool.
func TestGAP0929UntrustedCARenewal(t *testing.T) {
	oldPEM, oldKey, err := GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old, _ := LoadCA(oldPEM, oldKey)
	newPEM, newKey, _ := GenerateCA(time.Now())
	fresh, _ := LoadCA(newPEM, newKey)
	bundle, err := LoadCA(append(append([]byte{}, newPEM...), oldPEM...), newKey)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Trusts(old.Fingerprint()) || fresh.Trusts(old.Fingerprint()) || !bundle.Trusts(old.Fingerprint()) || !bundle.Trusts(fresh.Fingerprint()) {
		t.Fatal("Trusts does not follow the pool")
	}
	uid := "aaaa-0001"
	key, csr, _ := NewKeyAndCSR()
	certPEM, err := old.Sign(csr, uid, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := KeyPair(certPEM, key)
	_, csr2, _ := NewKeyAndCSR()
	proof, _ := RenewalProof(kp, csr2)
	if _, err := bundle.CheckRenewal(uid, certPEM, csr2, proof, time.Now()); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	cur, err := fresh.CheckRenewal(uid, certPEM, csr2, proof, time.Now())
	if !errors.Is(err, ErrRenewalUntrustedCA) || cur == nil {
		t.Fatalf("dropped CA: %v %v", cur, err)
	}
	// A bad signature is never ErrRenewalUntrustedCA.
	other, _ := ecdsa.GenerateKey(key.Curve, rand.Reader)
	sum := sha256.Sum256(csr2)
	bad, _ := ecdsa.SignASN1(rand.Reader, other, sum[:])
	if cur, err := fresh.CheckRenewal(uid, certPEM, csr2, bad, time.Now()); err == nil || errors.Is(err, ErrRenewalUntrustedCA) || cur != nil {
		t.Fatalf("bad proof: %v %v", cur, err)
	}
	if b, _ := pem.Decode(certPEM); b == nil {
		t.Fatal("pem")
	}
}
