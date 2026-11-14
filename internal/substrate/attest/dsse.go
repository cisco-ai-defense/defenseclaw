// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Envelope is a DSSE envelope (https://github.com/secure-systems-lab/dsse).
// It is the same JSON cosign writes for an attestation, so
// "cosign verify-attestation --key <public key>" reads it.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // standard base64
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"` // standard base64 of the ASN.1 DER ECDSA signature
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	out := []byte("DSSEv1 ")
	out = strconv.AppendInt(out, int64(len(payloadType)), 10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(payload)), 10)
	out = append(out, ' ')
	return append(out, payload...)
}

// SignStatement signs a statement into a DSSE envelope.
func SignStatement(st *Statement, signer *Signer) (*Envelope, error) {
	payload, err := st.Marshal()
	if err != nil {
		return nil, err
	}
	sig, err := signer.sign(pae(PayloadType, payload))
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: signer.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// Marshal encodes the envelope as the JSON stored in the registry.
func (e *Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

// ParseEnvelope decodes a stored envelope.
func ParseEnvelope(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	if e.PayloadType != PayloadType {
		return nil, fmt.Errorf("envelope: payload type %q, want %q", e.PayloadType, PayloadType)
	}
	if len(e.Signatures) == 0 {
		return nil, errors.New("envelope: no signatures")
	}
	return &e, nil
}

// Payload returns the decoded payload bytes.
func (e *Envelope) payloadBytes() ([]byte, error) {
	p, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: payload is not base64: %w", err)
	}
	return p, nil
}

// verifyWith checks the envelope against a set of anchors and returns the
// anchor that signed it. A signature counts only if its key is an unexpired,
// unrevoked anchor at now. The key id in the envelope is a hint, never
// trusted: every anchor is tried when the id is unknown.
func (e *Envelope) verifyWith(anchors *TrustAnchors, now time.Time) (*Anchor, []byte, error) {
	payload, err := e.payloadBytes()
	if err != nil {
		return nil, nil, err
	}
	msg := pae(e.PayloadType, payload)
	digest := sha256.Sum256(msg)
	var firstFail error
	for _, s := range e.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			firstFail = errBadSignature
			continue
		}
		hinted := s.KeyID != "" && anchors.has(s.KeyID)
		for _, a := range anchors.candidates(s.KeyID) {
			if !ecdsa.VerifyASN1(a.Public, digest[:], raw) {
				continue
			}
			if anchors.IsRevoked(a.KeyID) {
				return a, nil, errAnchorRevoked
			}
			if rejected := a.usable(now); rejected != nil {
				return a, nil, rejected
			}
			return a, payload, nil
		}
		if hinted {
			firstFail = errBadSignature
		} else if firstFail == nil {
			firstFail = errUntrustedSigner
		}
	}
	if firstFail == nil {
		firstFail = errUntrustedSigner
	}
	return nil, nil, firstFail
}

var (
	errBadSignature    = errors.New("signature does not decode")
	errUntrustedSigner = errors.New("no trust anchor verifies the signature")
)
