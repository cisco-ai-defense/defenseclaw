// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package budgetstore is the opt-in fleet budget store: one HTTPS service
// an administrator runs (defenseclaw-gateway budget-store serve) that sums
// routing.admin budget spend across managed devices, and the device client
// that implements routingadmin.SpendCounter.
//
// Every device has its own credential, issued by an administrator (budget-store
// device issue) and installed by MDM: a device id, a device secret and the
// exact charge keys the device may use. The store accepts a device's spend
// only for those keys, answers a device with the fleet spend of its own users
// only, and answers pooled (group, connector) budgets with exceeded or not.
// Rollups are read on the store host only (budget-store report). The store
// holds pseudonymous keys, days and amounts; never a user, group or device
// name. The tenant secret that makes the pseudonyms stays on the admin
// workstation.
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

// Headers.
const (
	HeaderDevice    = "X-DC-Store-Device"
	HeaderTime      = "X-DC-Store-Time"
	HeaderSignature = "X-DC-Store-Signature"
	// HeaderResponse signs an answer over the request signature, the status
	// and the body digest, so a TLS-inspecting middlebox cannot rewrite it.
	HeaderResponse = "X-DC-Store-Response"
)

// Bounds.
const (
	MaxBodyBytes     = 1 << 20
	MaxResponseBytes = 4 << 20
	MaxRows          = 20000
	MaxKeys          = 20000
	MaxClockSkew     = 5 * time.Minute
	SecretBytes      = 32
	RetentionDays    = 62
	maxUSD           = 1e7
	maxSeq           = 1<<63 - 1
	authInfo         = "defenseclaw.budget-store.device.v1"
	subjectInfo      = "defenseclaw.budget-store.subject.v1"
)

// ExceededUSD is the amount a device ledger applies for a pooled key the
// store says is over its limit (above any limit_usd, so the budget acts).
const ExceededUSD = 1e9

var (
	keyPattern    = lazyregexp.New(`^(user|group|connector):[a-z0-9][a-z0-9_-]{0,63}:[A-Za-z0-9:*=._-]{1,160}$`)
	epochPattern  = lazyregexp.New(`^[0-9a-z][0-9a-z-]{0,63}$`)
	devicePattern = lazyregexp.New(`^d[0-9a-f]{24}$`)
)

// Row is the spend of one charge key on one UTC day.
type Row struct {
	Day string  `json:"day"` // YYYY-MM-DD
	Key string  `json:"key"`
	USD float64 `json:"usd"`
}

// PushRequest carries one writer's absolute per-(key, day) totals. Seq
// grows with every push of a writer (device and epoch).
type PushRequest struct {
	Epoch string `json:"epoch"`
	Seq   uint64 `json:"seq"`
	Rows  []Row  `json:"rows"`
}

// TotalsRequest asks for the fleet spend of the listed keys since a day.
type TotalsRequest struct {
	Epoch string   `json:"epoch"`
	Since string   `json:"since"` // YYYY-MM-DD
	Keys  []string `json:"keys"`
}

// TotalsResponse answers a device: the fleet spend of its own users' keys
// (other writers only), and the pooled keys that are over their limit in the
// current period. A pooled total is never sent.
type TotalsResponse struct {
	Rows     []Row    `json:"rows"`
	Exceeded []string `json:"exceeded,omitempty"`
}

// ErrorResponse is every refusal (a reason code, never an input).
type ErrorResponse struct {
	Error string `json:"error"`
}

// DeviceKey signs and verifies one device's requests and answers.
type DeviceKey struct {
	id   string
	auth []byte
}

// NewDeviceKey derives the signing key of a device from its secret.
func NewDeviceKey(id string, secret []byte) (DeviceKey, error) {
	if !ValidDevice(id) {
		return DeviceKey{}, errors.New("budget store device id is malformed")
	}
	if len(secret) != SecretBytes {
		return DeviceKey{}, errors.New("budget store device secret must be 32 bytes")
	}
	auth, err := hkdf.Key(sha256.New, secret, nil, authInfo+"\x00"+id, sha256.Size)
	if err != nil {
		return DeviceKey{}, err
	}
	return DeviceKey{id: id, auth: auth}, nil
}

// ID is the device id.
func (k DeviceKey) ID() string { return k.id }

// Sign returns the signature header value of one request.
func (k DeviceKey) Sign(method, path string, at time.Time, body []byte) string {
	return hex.EncodeToString(k.mac(method, path, strconv.FormatInt(at.Unix(), 10), body))
}

func (k DeviceKey) mac(method, path, at string, body []byte) []byte {
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, k.auth)
	_, _ = mac.Write([]byte("request\n" + k.id + "\n" + method + "\n" + path + "\n" + at + "\n" + hex.EncodeToString(digest[:])))
	return mac.Sum(nil)
}

// errUnauthorized is every authentication refusal (one code: a caller
// without the key learns nothing, not even the store clock).
var errUnauthorized = errors.New("unauthorized")

// Verify checks a request signature and its time against now.
func (k DeviceKey) Verify(method, path, atHeader, signature string, body []byte, now time.Time) error {
	at, err := strconv.ParseInt(strings.TrimSpace(atHeader), 10, 64)
	if err != nil {
		return errUnauthorized
	}
	if d := now.Sub(time.Unix(at, 0)); d > MaxClockSkew || d < -MaxClockSkew {
		return errUnauthorized
	}
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil || !hmac.Equal(got, k.mac(method, path, strconv.FormatInt(at, 10), body)) {
		return errUnauthorized
	}
	return nil
}

// SignResponse signs an answer to the request that carried requestSig.
func (k DeviceKey) SignResponse(requestSig string, status int, body []byte) string {
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, k.auth)
	_, _ = mac.Write([]byte("response\n" + k.id + "\n" + requestSig + "\n" + strconv.Itoa(status) + "\n" + hex.EncodeToString(digest[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyResponse checks an answer signature.
func (k DeviceKey) VerifyResponse(requestSig string, status int, body []byte, signature string) bool {
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return false
	}
	want, _ := hex.DecodeString(k.SignResponse(requestSig, status, body))
	return hmac.Equal(got, want)
}

// SubjectKey makes the pseudonymous ids of users and budget subjects. It is
// derived from the tenant secret on the administrator workstation when a
// device is issued; no device or store holds it.
type SubjectKey struct{ key []byte }

// NewSubjectKey derives the subject key from the 32-byte tenant secret.
func NewSubjectKey(secret []byte) (SubjectKey, error) {
	if len(secret) != SecretBytes {
		return SubjectKey{}, errors.New("budget store tenant secret must be 32 bytes")
	}
	key, err := hkdf.Key(sha256.New, secret, nil, subjectInfo, sha256.Size)
	if err != nil {
		return SubjectKey{}, err
	}
	return SubjectKey{key: key}, nil
}

// Hash is the pseudonymous form of a budget subject (a users or groups
// entry, or "account:" and a canonical SID or UPN).
func (k SubjectKey) Hash(subject string) string {
	mac := hmac.New(sha256.New, k.key)
	_, _ = mac.Write([]byte(subject))
	return "h" + hex.EncodeToString(mac.Sum(nil))[:24]
}

// ValidKey reports whether key is a charge key the store accepts.
func ValidKey(key string) bool { return keyPattern.MatchString(key) }

// ValidEpoch reports whether epoch names a writer process.
func ValidEpoch(epoch string) bool { return epochPattern.MatchString(epoch) }

// ValidDevice reports whether id names a device.
func ValidDevice(id string) bool { return devicePattern.MatchString(id) }

func validDay(day string) bool {
	_, err := time.Parse(time.DateOnly, day)
	return err == nil
}

// recentDay accepts only days the budgets can count: the retention window up
// to tomorrow (a clock a little ahead), so no row lives past the prune.
func recentDay(day string, now time.Time) bool {
	t, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return false
	}
	today := now.UTC().Truncate(24 * time.Hour)
	return !t.Before(today.AddDate(0, 0, -RetentionDays)) && !t.After(today.AddDate(0, 0, 1))
}

func validUSD(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= maxUSD
}

func (r PushRequest) validate(now time.Time) error {
	if !ValidEpoch(r.Epoch) || r.Seq == 0 || r.Seq > maxSeq {
		return errors.New("bad_request")
	}
	if len(r.Rows) > MaxRows {
		return errors.New("too_many_rows")
	}
	for _, row := range r.Rows {
		if !recentDay(row.Day, now) || !ValidKey(row.Key) || !validUSD(row.USD) {
			return errors.New("bad_row")
		}
	}
	return nil
}

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

// pooled reports whether a key sums several people (group or connector):
// a device learns only whether it is over its limit.
func pooled(key string) bool {
	return strings.HasPrefix(key, "group:") || strings.HasPrefix(key, "connector:")
}

// budgetIDOf returns the budget id of a charge key (<scope>:<id>:...).
func budgetIDOf(key string) string {
	_, rest, ok := strings.Cut(key, ":")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, ":")
	return id
}
