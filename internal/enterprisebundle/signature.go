// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// SignatureSchemaVersion is the manifest.sig schema this build reads.
const SignatureSchemaVersion = 1

// SignatureDomain prefixes the manifest bytes a bundle signature covers, so
// a key that also signs other material can never have one of those
// signatures read as a bundle signature (or the other way round).
const SignatureDomain = "defenseclaw-bundle-manifest-v1\x00"

// Signature algorithms. ecdsa-p256-sha256 is the KMS/HSM algorithm (an
// ASN.1 DER signature over the SHA-256 of the signed message).
const (
	AlgEd25519         = "ed25519"
	AlgECDSAP256SHA256 = "ecdsa-p256-sha256"
)

var keyIDPattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidKeyID reports whether id can name a signing key.
func ValidKeyID(id string) bool { return keyIDPattern.MatchString(id) }

var errKeyID = errors.New("key id: want 1-128 characters of [A-Za-z0-9._:-]")

// Signature is manifest.sig: the key that signed the manifest, its
// algorithm and the signature (standard base64).
type Signature struct {
	SchemaVersion int    `json:"schema_version"`
	KeyID         string `json:"key_id"`
	Alg           string `json:"alg"`
	Sig           string `json:"sig"`
}

// SignedMessage is the exact byte string a bundle signature covers: the
// domain prefix and manifest.json as stored, never re-encoded.
func SignedMessage(manifest []byte) []byte {
	msg := make([]byte, 0, len(SignatureDomain)+len(manifest))
	msg = append(msg, SignatureDomain...)
	return append(msg, manifest...)
}

// SignedDigest is the SHA-256 of SignedMessage(manifest): what a KMS or HSM
// signs for ecdsa-p256-sha256 in digest mode.
func SignedDigest(manifest []byte) [32]byte { return sha256.Sum256(SignedMessage(manifest)) }

// DecodeSignature decodes manifest.sig strictly (signature_invalid): the
// size limit, UTF-8 without a byte-order mark, no unknown, repeated or
// upper-case keys, no trailing data, a known algorithm and a base64
// signature of a length that algorithm allows.
func DecodeSignature(raw []byte) (*Signature, error) {
	bad := func(format string, args ...any) error {
		return refuse(CodeSignatureInvalid, SignatureName, format, args...)
	}
	if len(raw) == 0 {
		return nil, bad("the bundle has no signature")
	}
	if len(raw) > MaxSignatureBytes {
		return nil, bad("larger than %d bytes", MaxSignatureBytes)
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, bad("not UTF-8 JSON without a byte-order mark")
	}
	if err := checkJSONKeys(raw, CodeSignatureInvalid, SignatureName); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sig Signature
	if err := dec.Decode(&sig); err != nil {
		return nil, bad("%s", jsonProblem(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, bad("data after the signature object")
	}
	if sig.SchemaVersion != SignatureSchemaVersion {
		return nil, bad("unsupported schema version %d (this build reads %d)", sig.SchemaVersion, SignatureSchemaVersion)
	}
	if !ValidKeyID(sig.KeyID) {
		return nil, bad("key_id: want 1-128 characters of [A-Za-z0-9._:-]")
	}
	if _, err := sig.raw(); err != nil {
		return nil, err
	}
	return &sig, nil
}

// raw decodes Sig and checks its form for Alg.
func (s *Signature) raw() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s.Sig)
	if err != nil {
		return nil, refuse(CodeSignatureInvalid, SignatureName, "sig: not standard base64")
	}
	switch s.Alg {
	case AlgEd25519:
		if len(raw) != ed25519.SignatureSize {
			return nil, refuse(CodeSignatureInvalid, SignatureName, "sig: an ed25519 signature has %d bytes", ed25519.SignatureSize)
		}
	case AlgECDSAP256SHA256:
		if !validDERSignature(raw) {
			return nil, refuse(CodeSignatureInvalid, SignatureName, "sig: not a DER ECDSA signature")
		}
	default:
		return nil, refuse(CodeSignatureInvalid, SignatureName, "alg: want ed25519 or ecdsa-p256-sha256")
	}
	return raw, nil
}

// Marshal encodes s as manifest.sig.
func (s *Signature) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// KeyAlg returns the bundle algorithm of a public key: ed25519, or
// ecdsa-p256-sha256 for an ECDSA key on P-256. Any other key is refused.
func KeyAlg(public crypto.PublicKey) (string, error) {
	switch key := public.(type) {
	case ed25519.PublicKey:
		if len(key) == ed25519.PublicKeySize {
			return AlgEd25519, nil
		}
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return AlgECDSAP256SHA256, nil
		}
	}
	return "", errors.New("the key is not an Ed25519 or ECDSA P-256 key")
}

// ParsePublicKey parses a DER SubjectPublicKeyInfo holding an Ed25519 or
// ECDSA P-256 key and returns it with its algorithm.
func ParsePublicKey(der []byte) (crypto.PublicKey, string, error) {
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", errors.New("not a DER SubjectPublicKeyInfo")
	}
	alg, err := KeyAlg(public)
	if err != nil {
		return nil, "", err
	}
	return public, alg, nil
}

// Sign signs manifest with signer (an Ed25519 or ECDSA P-256 key) and
// returns manifest.sig for keyID.
func Sign(manifest []byte, signer crypto.Signer, keyID string) (*Signature, error) {
	if !ValidKeyID(keyID) {
		return nil, errKeyID
	}
	alg, err := KeyAlg(signer.Public())
	if err != nil {
		return nil, err
	}
	var sig []byte
	if alg == AlgEd25519 {
		sig, err = signer.Sign(rand.Reader, SignedMessage(manifest), crypto.Hash(0))
	} else {
		digest := SignedDigest(manifest)
		sig, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		return nil, err
	}
	return AttachSignature(manifest, signer.Public(), keyID, sig)
}

// AttachSignature checks sig, made outside this process (an HSM or a KMS)
// over SignedMessage(manifest) or, for ECDSA, its SHA-256, against the
// public key and returns manifest.sig. An ECDSA signature may be ASN.1 DER
// or the raw 64-byte r||s form PKCS#11 returns; it is stored as DER.
func AttachSignature(manifest []byte, public crypto.PublicKey, keyID string, sig []byte) (*Signature, error) {
	if !ValidKeyID(keyID) {
		return nil, errKeyID
	}
	alg, err := KeyAlg(public)
	if err != nil {
		return nil, err
	}
	if alg == AlgECDSAP256SHA256 && len(sig) == 64 && !validDERSignature(sig) {
		if der, ok := rawECDSAToDER(sig); ok {
			sig = der
		}
	}
	if !verifyRaw(public, alg, manifest, sig) {
		return nil, refuse(CodeSignatureInvalid, SignatureName, "the signature does not verify with the public key")
	}
	return &Signature{SchemaVersion: SignatureSchemaVersion, KeyID: keyID, Alg: alg, Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifySignature checks sig over manifest with public; the key algorithm
// must be the signature algorithm (signature_invalid).
func VerifySignature(manifest []byte, sig *Signature, public crypto.PublicKey) error {
	alg, err := KeyAlg(public)
	if err != nil || alg != sig.Alg {
		return refuse(CodeSignatureInvalid, SignatureName, "the signature algorithm is not the algorithm of key %s", sig.KeyID)
	}
	raw, err := sig.raw()
	if err != nil {
		return err
	}
	if !verifyRaw(public, alg, manifest, raw) {
		return refuse(CodeSignatureInvalid, SignatureName, "the signature does not verify with key %s", sig.KeyID)
	}
	return nil
}

func verifyRaw(public crypto.PublicKey, alg string, manifest, sig []byte) bool {
	switch alg {
	case AlgEd25519:
		key, ok := public.(ed25519.PublicKey)
		return ok && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, SignedMessage(manifest), sig)
	case AlgECDSAP256SHA256:
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || !validDERSignature(sig) {
			return false
		}
		digest := SignedDigest(manifest)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	}
	return false
}

type ecdsaDER struct{ R, S *big.Int }

// validDERSignature reports whether sig is exactly one minimal DER
// ECDSA-Sig-Value with positive r and s and no trailing bytes, so a
// signature has one spelling.
func validDERSignature(sig []byte) bool {
	if len(sig) < 8 || len(sig) > 72 {
		return false
	}
	var v ecdsaDER
	rest, err := asn1.Unmarshal(sig, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil || v.R.Sign() <= 0 || v.S.Sign() <= 0 {
		return false
	}
	again, err := asn1.Marshal(v)
	return err == nil && bytes.Equal(again, sig)
}

func rawECDSAToDER(sig []byte) ([]byte, bool) {
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, false
	}
	der, err := asn1.Marshal(ecdsaDER{R: r, S: s})
	return der, err == nil
}
