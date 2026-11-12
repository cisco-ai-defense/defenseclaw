// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package budgetstore is the opt-in fleet budget store: one HTTPS service
// an administrator runs (defenseclaw-gateway budget-store serve) that sums
// routing.admin budget spend across managed devices and gateway replicas,
// and the device client that implements routingadmin.SpendCounter.
//
// The store holds only charge keys (budget id plus a pseudonymous subject:
// an account join key, a keyed hash of a group or user entry, a connector
// name), UTC days and dollar amounts; never a user, group or device name.
// Every request is signed with a key derived from the tenant secret both
// sides hold (HMAC-SHA256 over method, path, time and body digest), inside
// TLS.
package budgetstore

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Paths of the protocol.
const (
	PathPush   = "/v1/push"
	PathTotals = "/v1/totals"
	PathHealth = "/v1/health"
)

// Request headers.
const (
	HeaderTime      = "X-DC-Store-Time"
	HeaderSignature = "X-DC-Store-Signature"
)

// Bounds.
const (
	MaxBodyBytes  = 1 << 20
	MaxRows       = 20000
	MaxKeys       = 20000
	MaxClockSkew  = 5 * time.Minute
	SecretBytes   = 32
	RetentionDays = 62
	maxUSD        = 1e7
	authInfo      = "defenseclaw.budget-store.auth.v1"
	subjectInfo   = "defenseclaw.budget-store.subject.v1"
)

var (
	keyPattern   = lazyregexp.New(`^(user|group|connector):[a-z0-9][a-z0-9_-]{0,63}:[A-Za-z0-9:*=._-]{1,160}$`)
	epochPattern = lazyregexp.New(`^[0-9a-z][0-9a-z-]{0,63}$`)
)

// Row is the spend of one charge key on one UTC day.
type Row struct {
	Day string  `json:"day"` // YYYY-MM-DD
	Key string  `json:"key"`
	USD float64 `json:"usd"`
}

// PushRequest carries one writer's absolute per-(key, day) totals. Seq
// grows with every push of an epoch, so a replayed push is refused.
type PushRequest struct {
	Epoch string `json:"epoch"`
	Seq   uint64 `json:"seq"`
	Rows  []Row  `json:"rows"`
}

// TotalsRequest asks for the spend of every other epoch since a UTC day,
// for the listed keys.
type TotalsRequest struct {
	Epoch string   `json:"epoch"`
	Since string   `json:"since"` // YYYY-MM-DD
	Keys  []string `json:"keys"`
}

// TotalsResponse is the summed spend.
type TotalsResponse struct {
	Rows []Row `json:"rows"`
}

// ErrorResponse is every refusal (a reason code, never an input).
type ErrorResponse struct {
	Error string `json:"error"`
}

// Keys are the keys derived from the tenant secret.
type Keys struct {
	auth    []byte
	subject []byte
}

// DeriveKeys derives the request-signing key and the subject-hash key from
// the 32-byte tenant secret.
func DeriveKeys(secret []byte) (Keys, error) {
	if len(secret) != SecretBytes {
		return Keys{}, errors.New("budget store secret must be 32 bytes")
	}
	auth, err := hkdf.Key(sha256.New, secret, nil, authInfo, sha256.Size)
	if err != nil {
		return Keys{}, err
	}
	subject, err := hkdf.Key(sha256.New, secret, nil, subjectInfo, sha256.Size)
	if err != nil {
		return Keys{}, err
	}
	return Keys{auth: auth, subject: subject}, nil
}

// SubjectHash is the pseudonymous form of a budget subject (a users or
// groups entry): the same on every device that holds the tenant secret,
// unreadable to anyone who does not.
func (k Keys) SubjectHash(subject string) string {
	mac := hmac.New(sha256.New, k.subject)
	_, _ = mac.Write([]byte(subject))
	return "h" + hex.EncodeToString(mac.Sum(nil))[:24]
}

// Sign returns the signature header value of one request.
func (k Keys) Sign(method, path string, at time.Time, body []byte) string {
	return hex.EncodeToString(k.mac(method, path, strconv.FormatInt(at.Unix(), 10), body))
}

func (k Keys) mac(method, path, at string, body []byte) []byte {
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, k.auth)
	_, _ = mac.Write([]byte(method + "\n" + path + "\n" + at + "\n" + hex.EncodeToString(digest[:])))
	return mac.Sum(nil)
}

// Verify checks a request signature and its time against now.
func (k Keys) Verify(method, path, atHeader, signature string, body []byte, now time.Time) error {
	at, err := strconv.ParseInt(strings.TrimSpace(atHeader), 10, 64)
	if err != nil {
		return errors.New("bad_time")
	}
	if d := now.Sub(time.Unix(at, 0)); d > MaxClockSkew || d < -MaxClockSkew {
		return errors.New("clock_skew")
	}
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil || !hmac.Equal(got, k.mac(method, path, strconv.FormatInt(at, 10), body)) {
		return errors.New("bad_signature")
	}
	return nil
}

// ValidKey reports whether key is a charge key the store accepts.
func ValidKey(key string) bool { return keyPattern.MatchString(key) }

// ValidEpoch reports whether epoch names a writer.
func ValidEpoch(epoch string) bool { return epochPattern.MatchString(epoch) }

func validDay(day string) bool {
	_, err := time.Parse(time.DateOnly, day)
	return err == nil
}

func validUSD(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= maxUSD
}

// validate checks a push request.
func (r PushRequest) validate() error {
	if !ValidEpoch(r.Epoch) || r.Seq == 0 {
		return errors.New("bad_epoch")
	}
	if len(r.Rows) > MaxRows {
		return errors.New("too_many_rows")
	}
	for _, row := range r.Rows {
		if !validDay(row.Day) || !ValidKey(row.Key) || !validUSD(row.USD) {
			return errors.New("bad_row")
		}
	}
	return nil
}

// validate checks a totals request.
func (r TotalsRequest) validate() error {
	if !ValidEpoch(r.Epoch) || !validDay(r.Since) {
		return errors.New("bad_request")
	}
	if len(r.Keys) > MaxKeys {
		return errors.New("too_many_keys")
	}
	for _, key := range r.Keys {
		if !ValidKey(key) {
			return errors.New("bad_key")
		}
	}
	return nil
}
