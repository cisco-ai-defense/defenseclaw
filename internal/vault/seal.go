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

package vault

// A sealed vault keeps each value encrypted to the vault's public key with
// HPKE (RFC 9180: DHKEM(X25519), HKDF-SHA256, AES-256-GCM). The private key
// lives only in the OS keystore. Writing a value needs only the public key,
// which sits in the vault header: the per-user gateway and sandbox daemon
// capture into a sealed vault without ever reaching the keystore (no
// prompt, no wait on the hook path, nothing that fails when the keychain is
// locked or no Secret Service runs). Reading a value needs the private key:
// only the CLI does that (sandbox run --vault, and the changes that compare
// or re-seal values).

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

const (
	// sealedVersion is the file version of a sealed vault: a DefenseClaw
	// that reads only version 1 refuses it instead of finding no values.
	sealedVersion = 2

	sealInfoDomain = "defenseclaw-vault-v2"
	fpDomain       = "defenseclaw-vault-fp-v1"
)

// sealHeader is a sealed vault's public part.
type sealHeader struct {
	// Keystore names where the private key is (a keystore ID).
	Keystore string `json:"keystore"`
	// KeyID names the key in that keystore.
	KeyID string `json:"key_id"`
	// PublicKey is the HPKE public key values are sealed to.
	PublicKey string `json:"public_key"`
	// FPSalt keys the fingerprints that let a process without the private
	// key find a captured value the vault already holds.
	FPSalt string `json:"fp_salt"`
}

var (
	suiteKEM  = hpke.DHKEM(ecdh.X25519())
	suiteKDF  = hpke.HKDFSHA256()
	suiteAEAD = hpke.AES256GCM()

	keyIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// sealer is a parsed header, with the private key once it was read.
type sealer struct {
	h    sealHeader
	pub  hpke.PublicKey
	salt []byte
	priv hpke.PrivateKey
}

func parseHeader(h *sealHeader) (*sealer, error) {
	if h == nil {
		return nil, errors.New("it has no seal header")
	}
	if !keyIDPattern.MatchString(h.KeyID) {
		return nil, errors.New("its key id is not valid")
	}
	if keystoreName(h.Keystore) == "" {
		return nil, errors.New("it names a keystore this DefenseClaw does not know")
	}
	pb, err := base64.StdEncoding.DecodeString(h.PublicKey)
	if err != nil {
		return nil, errors.New("its public key is not valid")
	}
	pub, err := suiteKEM.NewPublicKey(pb)
	if err != nil {
		return nil, errors.New("its public key is not valid")
	}
	salt, err := base64.StdEncoding.DecodeString(h.FPSalt)
	if err != nil || len(salt) != 32 {
		return nil, errors.New("its fingerprint salt is not valid")
	}
	return &sealer{h: *h, pub: pub, salt: salt}, nil
}

// newSealer makes a new key pair for a vault whose key goes in keystoreID.
// raw is the private key to keep in the keystore.
func newSealer(keystoreID string) (*sealer, []byte, error) {
	priv, err := suiteKEM.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	raw, err := priv.Bytes()
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, 16)
	salt := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	s := &sealer{
		h: sealHeader{
			Keystore:  keystoreID,
			KeyID:     hex.EncodeToString(id),
			PublicKey: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
			FPSalt:    base64.StdEncoding.EncodeToString(salt),
		},
		pub: priv.PublicKey(), salt: salt, priv: priv,
	}
	return s, raw, nil
}

// withKey takes the private key read from the keystore. A key that does
// not match the header's public key is refused.
func (s *sealer) withKey(raw []byte) error {
	priv, err := suiteKEM.NewPrivateKey(raw)
	if err != nil {
		return errors.New("the keystore item is not a vault key")
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), s.pub.Bytes()) {
		return errors.New("the key in the keystore is not this vault's key")
	}
	s.priv = priv
	return nil
}

// info binds a sealed value to this vault, its entry name and the one
// host it may be sent to: a sealed value moved to another entry, or an
// entry re-pointed at another host in the file, no longer opens.
func (s *sealer) info(name, host string, port int) string {
	return sealInfoDomain + "\x00" + s.h.KeyID + "\x00" + name + "\x00" + host + "\x00" + strconv.Itoa(port)
}

func (s *sealer) infoOf(r *record) string { return s.info(r.Name, r.Host, r.Port) }

func (s *sealer) seal(r *record) (string, error) {
	ct, err := hpke.Seal(s.pub, suiteKDF, suiteAEAD, []byte(s.infoOf(r)), []byte(r.Value))
	if err != nil {
		return "", fmt.Errorf("seal the secret %s: %w", r.Name, err)
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (s *sealer) open(r *record) (string, error) {
	if s.priv == nil {
		return "", errors.New("the vault key was not read")
	}
	ct, err := base64.StdEncoding.DecodeString(r.Sealed)
	if err != nil {
		return "", fmt.Errorf("the sealed value of %s is damaged", r.Name)
	}
	plain, err := hpke.Open(s.priv, suiteKDF, suiteAEAD, []byte(s.infoOf(r)), ct)
	if err != nil {
		return "", fmt.Errorf("the secret %s does not open with the vault key: it was sealed with another key, or the file was changed", r.Name)
	}
	if ValidValue(string(plain)) != nil {
		return "", fmt.Errorf("the secret %s opened to a value a sandbox cannot take", r.Name)
	}
	return string(plain), nil
}

// fingerprint is a keyed digest of a value. Its key sits in the same file,
// so only values that cannot be guessed get one (wantsFingerprint): a
// captured credential, an issuer prefix followed by a long random part.
func (s *sealer) fingerprint(value string) string {
	m := hmac.New(sha256.New, s.salt)
	m.Write([]byte(fpDomain))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return base64.RawStdEncoding.EncodeToString(m.Sum(nil))
}

// wantsFingerprint: a captured entry, or a value that is wholly one
// capturable credential. Capture only ever stores such values, so a
// process without the private key still finds every value it could
// capture twice; a person's other values get no fingerprint.
func wantsFingerprint(r *record) bool {
	if r.Source == SourceCaptured {
		return true
	}
	f := FindCapturable(r.Value)
	return len(f) == 1 && f[0].Start == 0 && f[0].End == len(r.Value)
}
