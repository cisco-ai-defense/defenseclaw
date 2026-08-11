// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package privatekeyfixture builds deterministic, publicly known, test-only
// private-key material. These fixtures must never be used as production keys.
package privatekeyfixture

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp/packet" //nolint:staticcheck // fixture must match the OpenPGP structures validPrivateKeyPayload parses
	"golang.org/x/crypto/ssh"
)

// MustPEM returns a structurally valid deterministic fixture for an allowed
// private-key PEM label. The deliberately tiny RSA and DSA parameters are not
// suitable for cryptographic use.
func MustPEM(label string) string {
	var der []byte
	var err error

	switch label {
	case "PRIVATE KEY":
		der, err = x509.MarshalPKCS8PrivateKey(syntheticRSAKey())
	case "RSA PRIVATE KEY":
		der = x509.MarshalPKCS1PrivateKey(syntheticRSAKey())
	case "EC PRIVATE KEY":
		der, err = x509.MarshalECPrivateKey(syntheticECKey())
	case "DSA PRIVATE KEY":
		der, err = asn1.Marshal(struct {
			Version int
			P       *big.Int
			Q       *big.Int
			G       *big.Int
			Y       *big.Int
			X       *big.Int
		}{
			Version: 0,
			P:       big.NewInt(23),
			Q:       big.NewInt(11),
			G:       big.NewInt(2),
			Y:       big.NewInt(8),
			X:       big.NewInt(3),
		})
	case "OPENSSH PRIVATE KEY":
		seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
		block, marshalErr := ssh.MarshalPrivateKey(ed25519.NewKeyFromSeed(seed), "deterministic detector fixture")
		if marshalErr != nil {
			panic(marshalErr)
		}
		return string(pem.EncodeToMemory(block))
	case "PGP PRIVATE KEY":
		var payload bytes.Buffer
		key := packet.NewRSAPrivateKey(time.Unix(0, 0), syntheticRSAKey())
		if err = key.Serialize(&payload); err == nil {
			der = payload.Bytes()
		}
	default:
		panic("unsupported private-key fixture label: " + label)
	}
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
}

// MustLegacyEncryptedRSAPEM returns deterministic RFC 1423 armor. Its fixed
// password and tiny RSA parameters make it publicly known test-only material.
func MustLegacyEncryptedRSAPEM() string {
	der := x509.MarshalPKCS1PrivateKey(syntheticRSAKey())
	randomness := bytes.NewReader(bytes.Repeat([]byte{0x24}, 32))
	block, err := x509.EncryptPEMBlock( //nolint:staticcheck // fixture must produce RFC 1423 armor for validLegacyEncryptedPrivateKey
		randomness,
		"RSA PRIVATE KEY",
		der,
		[]byte("detector-fixture-password"),
		x509.PEMCipherAES256,
	)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(block))
}

func syntheticRSAKey() *rsa.PrivateKey {
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
		D:         big.NewInt(2753),
		Primes:    []*big.Int{big.NewInt(61), big.NewInt(53)},
	}
	key.Precompute()
	return key
}

func syntheticECKey() *ecdsa.PrivateKey {
	key, err := ecdsa.ParseRawPrivateKey(
		elliptic.P256(),
		bytes.Repeat([]byte{0x37}, 32),
	)
	if err != nil {
		panic(err)
	}
	return key
}
