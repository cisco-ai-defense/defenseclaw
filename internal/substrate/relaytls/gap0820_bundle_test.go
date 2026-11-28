// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relaytls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// GAP-0820: ca.pem holds the new CA first and the previous one after it.
// The gateway signs with the first and trusts both, so a relay still on its
// old-CA certificate attaches until it renews; without the previous CA it
// would not.
func TestGAP0820CABundleTrustsThePreviousCA(t *testing.T) {
	now := time.Now()
	oldCert, oldKey, err := GenerateCA(now)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey, err := GenerateCA(now)
	if err != nil {
		t.Fatal(err)
	}
	const uid = "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"
	san, _ := SANForUID(uid)
	sign := func(ca *CA) *x509.Certificate {
		_, csr, err := NewKeyAndCSR()
		if err != nil {
			t.Fatal(err)
		}
		p, err := ca.Sign(csr, uid, now)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(p)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	oldCA, err := LoadCA(oldCert, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	onOld := sign(oldCA)
	bundle, err := LoadCA(append(append([]byte{}, newCert...), oldCert...), newKey)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	verifies := func(ca *CA, c *x509.Certificate) bool {
		_, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: san, CurrentTime: now.Add(time.Minute),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err == nil
	}
	if !verifies(bundle, onOld) {
		t.Fatal("a certificate from the previous CA must verify during the rotation window")
	}
	onNew := sign(bundle)
	newOnly, _ := LoadCA(newCert, newKey)
	if !verifies(newOnly, onNew) || verifies(newOnly, onOld) {
		t.Fatal("the bundle must sign with the first CA; the new CA alone must not trust the old one")
	}
	if _, err := LoadCA(append(append([]byte{}, newCert...), oldKey...), newKey); err == nil {
		t.Fatal("a key block after the CA certificate must be refused")
	}
	if _, err := LoadCA(append(append([]byte{}, oldCert...), newCert...), newKey); err == nil {
		t.Fatal("the key must match the first (signing) CA")
	}
}
