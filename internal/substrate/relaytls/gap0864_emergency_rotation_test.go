// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relaytls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// GAP-0864: an emergency rotation (the CA key leaked) puts only the new CA
// in ca.pem. A relay certificate from the dropped CA is then no longer
// trusted at once: the attach handshake fails, and the dropped CA's
// certificate cannot prove a renewal onto the new CA.
func TestGAP0864DroppedCAIsNoLongerTrusted(t *testing.T) {
	now := time.Now()
	oldCert, oldKey, err := GenerateCA(now)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey, err := GenerateCA(now)
	if err != nil {
		t.Fatal(err)
	}
	oldCA, err := LoadCA(oldCert, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	const uid = "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"
	key, csr, err := NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	onOld, err := oldCA.Sign(csr, uid, now)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := KeyPair(onOld, key)
	if err != nil {
		t.Fatal(err)
	}
	handshake := func(ca *CA) error {
		conf, err := ClientConfig(ca.Pool(), uid)
		if err != nil {
			t.Fatal(err)
		}
		c, s := net.Pipe()
		defer c.Close()
		defer s.Close()
		go func() {
			_ = tls.Server(s, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*kp}}).Handshake()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return tls.Client(c, conf).HandshakeContext(ctx)
	}
	rotation, err := LoadCA(append(append([]byte{}, newCert...), oldCert...), newKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(rotation); err != nil {
		t.Fatalf("planned rotation (old CA kept): %v", err)
	}
	emergency, err := LoadCA(newCert, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(emergency); err == nil {
		t.Fatal("a relay certificate from the dropped CA still verifies on attach")
	}
	_, csr2, _ := NewKeyAndCSR()
	proof, err := RenewalProof(kp, csr2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotation.CheckRenewal(uid, onOld, csr2, proof, now); err != nil {
		t.Fatalf("planned rotation renewal: %v", err)
	}
	if _, err := emergency.CheckRenewal(uid, onOld, csr2, proof, now); err == nil {
		t.Fatal("a certificate from the dropped CA still proves a renewal")
	}
}
