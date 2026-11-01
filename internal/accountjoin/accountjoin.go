// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package accountjoin computes the account join key: a per-tenant keyed
// digest of an account's directory identifier, which a management service
// that holds the same tenant secret can compute from its own directory to
// join the device's records to its accounts without the device sending the
// identifier. The key is pseudonymous: anyone with the tenant secret can
// compute the key of any identifier.
//
// Key = "ak1:" + generation + ":" + hex(HMAC-SHA256(K, M))[:32], where
//
//	K = HKDF-SHA256(secret, salt = none, info = L || 0x00 || u32be(generation), 32 bytes)
//	M = u32be(len(L)) || L || u32be(len(T)) || T || u32be(len(C)) || C
//
// L is Label, T the canonical tenant ID (CanonicalTenant) and C the
// canonical account input (Canonical): "sid:" or "upn:" and the canonical
// identifier. Errors carry only a reason code (Reason*), never an input.
package accountjoin

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// Label is the domain separation label of the key.
	Label = "defenseclaw.account-join.v1"
	// SecretName and NextSecretName are the managed credentials that hold
	// the current and the next generation's tenant secret.
	SecretName     = "account-join-key"
	NextSecretName = "account-join-key-next"
	// SecretBytes is the decoded secret length.
	SecretBytes = 32
	// MaxNextOverlap bounds how far ahead next_not_after may be.
	MaxNextOverlap = 30 * 24 * time.Hour
	// MaxAccounts caps the accounts one device reports.
	MaxAccounts = 64
	// Retention drops an account not seen for this long.
	Retention = 30 * 24 * time.Hour
	keyPrefix = "ak1"
	keyHexLen = 32
)

// Reason codes: the only failure text the package reports.
const (
	ReasonFeatureOff             = "feature_off"
	ReasonSecretMissing          = "secret_missing"
	ReasonSecretMalformed        = "secret_malformed"
	ReasonSecretUnreadable       = "secret_unreadable"
	ReasonNoDirectoryID          = "no_directory_id"
	ReasonCanonicalizationFailed = "canonicalization_failed"
	ReasonNextGenerationExpired  = "next_generation_expired"
	ReasonGenerationInvalid      = "generation_invalid"
	ReasonGenerationRollback     = "generation_rollback"
	ReasonTenantMissing          = "tenant_missing"
	ReasonAccountCap             = "account_cap"
	// ReasonSecretMismatch: the stored secret is not the value the signed
	// config binds to its generation (secret_sha256, next_secret_sha256).
	ReasonSecretMismatch = "secret_mismatch"
	// ReasonGenerationStateUnreadable: the record of the highest generation
	// reported cannot be read; nothing is reported until it is removed.
	ReasonGenerationStateUnreadable = "generation_state_unreadable"
)

// Error is a failure named only by its reason code.
type Error struct{ Reason string }

func (e *Error) Error() string { return "account join key: " + e.Reason }

func fail(reason string) error { return &Error{Reason: reason} }

// ReasonOf returns err's reason code, or canonicalization_failed for any
// other error.
func ReasonOf(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Reason
	}
	return ReasonCanonicalizationFailed
}

// ParseSecret decodes a stored tenant secret: base64url (padding optional)
// of exactly SecretBytes bytes. Anything else is secret_malformed; there is
// no fallback secret.
func ParseSecret(value []byte) ([]byte, error) {
	text := strings.TrimRight(string(value), "\r\n")
	if text == "" {
		return nil, fail(ReasonSecretMissing)
	}
	encoding := base64.RawURLEncoding
	if strings.HasSuffix(text, "=") {
		encoding = base64.URLEncoding
	}
	decoded, err := encoding.Strict().DecodeString(text)
	if err != nil || len(decoded) != SecretBytes {
		clear(decoded)
		return nil, fail(ReasonSecretMalformed)
	}
	return decoded, nil
}

// CanonicalTenant is the tenant ID of the verified signed bundle in
// lowercase. Bundle tenant IDs are 1-128 characters of [A-Za-z0-9._-].
func CanonicalTenant(tenant string) (string, error) {
	if tenant == "" || len(tenant) > 128 {
		return "", fail(ReasonTenantMissing)
	}
	for _, r := range tenant {
		if !tenantRune(r) {
			return "", fail(ReasonTenantMissing)
		}
	}
	return strings.ToLower(tenant), nil
}

func tenantRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		return true
	}
	return false
}

// CanonicalSID parses a domain account SID (S-1-5-21-a-b-c-RID: the
// NT authority, the domain prefix 21 with three domain subauthorities, and a
// RID of an account, 1000 or above) and renders it canonically: an
// uppercase S, decimal numbers without leading zeros.
func CanonicalSID(sid string) (string, error) {
	parts := strings.Split(sid, "-")
	if len(parts) != 8 || (parts[0] != "S" && parts[0] != "s") {
		return "", fail(ReasonCanonicalizationFailed)
	}
	numbers := make([]uint64, 0, 7)
	for i, part := range parts[1:] {
		limit := 32
		if i == 1 {
			limit = 48 // the identifier authority
		}
		if part == "" || len(part) > 20 {
			return "", fail(ReasonCanonicalizationFailed)
		}
		value, err := strconv.ParseUint(part, 10, limit)
		if err != nil {
			return "", fail(ReasonCanonicalizationFailed)
		}
		numbers = append(numbers, value)
	}
	if numbers[0] != 1 || numbers[1] != 5 || numbers[2] != 21 || numbers[6] < 1000 {
		return "", fail(ReasonCanonicalizationFailed)
	}
	out := make([]string, 0, 8)
	out = append(out, "S")
	for _, value := range numbers {
		out = append(out, strconv.FormatUint(value, 10))
	}
	return strings.Join(out, "-"), nil
}

// CanonicalUPN is the userPrincipalName in Unicode NFC, then folded with
// Unicode simple case folding (SimpleFold) over the whole string. It must
// be one name@suffix with neither part empty, and no space or control
// character.
func CanonicalUPN(upn string) (string, error) {
	if upn == "" || len(upn) > 1024 || !utf8.ValidString(upn) {
		return "", fail(ReasonCanonicalizationFailed)
	}
	upn = SimpleFold(norm.NFC.String(upn))
	at := strings.Count(upn, "@")
	name, suffix, _ := strings.Cut(upn, "@")
	if at != 1 || name == "" || suffix == "" {
		return "", fail(ReasonCanonicalizationFailed)
	}
	for _, r := range upn {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fail(ReasonCanonicalizationFailed)
		}
	}
	return upn, nil
}

// SimpleFold maps every code point of s with Unicode simple case folding
// (CaseFolding.txt, status C and S): locale independent, one code point to
// one code point. A code point with only a full or Turkic folding (such as
// U+0130) is unchanged.
func SimpleFold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(simpleFoldRune(r))
	}
	return b.String()
}

func simpleFoldRune(r rune) rune {
	// Cherokee folds to its uppercase letters.
	switch {
	case r >= 0xAB70 && r <= 0xABBF:
		return r - 0xAB70 + 0x13A0
	case r >= 0x13F8 && r <= 0x13FD:
		return r - 8
	case r >= 0x13A0 && r <= 0x13F5:
		return r
	}
	if lower := unicode.ToLower(r); lower != r && sameFoldOrbit(r, lower) {
		return lower
	}
	if lower := unicode.ToLower(unicode.ToUpper(r)); lower != r && sameFoldOrbit(r, lower) {
		return lower
	}
	return r
}

// sameFoldOrbit reports whether b is in a's simple case folding orbit.
func sameFoldOrbit(a, b rune) bool {
	for next := unicode.SimpleFold(a); next != a; next = unicode.SimpleFold(next) {
		if next == b {
			return true
		}
	}
	return false
}

// Account is what a device knows about one account that ran an agent.
type Account struct {
	// SID is the account's domain objectSid, only when the collector
	// verified it as a domain account's SID of the joined domain (never
	// sIDHistory, never a local or machine-domain account).
	SID string
	// UPN is the userPrincipalName attribute, only when the collector
	// verified it with the directory (never a derived name@REALM).
	UPN string
	// LastSeen is when the account last ran an agent.
	LastSeen time.Time
}

// Canonical returns the canonical input C of account: its SID when it has
// one, else its UPN. An account with neither has no key (no_directory_id).
func Canonical(account Account) (string, error) {
	if account.SID != "" {
		sid, err := CanonicalSID(account.SID)
		if err != nil {
			return "", err
		}
		return "sid:" + sid, nil
	}
	if account.UPN != "" {
		upn, err := CanonicalUPN(account.UPN)
		if err != nil {
			return "", err
		}
		return "upn:" + upn, nil
	}
	return "", fail(ReasonNoDirectoryID)
}

// Key computes the key of canonical input c for tenant t (both canonical)
// with the decoded secret of generation gen.
func Key(secret []byte, gen uint32, tenant, c string) (string, error) {
	if len(secret) != SecretBytes || gen == 0 {
		return "", fail(ReasonSecretMalformed)
	}
	info := make([]byte, 0, len(Label)+5)
	info = append(info, Label...)
	info = append(info, 0)
	info = binary.BigEndian.AppendUint32(info, gen)
	purpose, err := hkdf.Key(sha256.New, secret, nil, string(info), sha256.Size)
	if err != nil {
		return "", fail(ReasonSecretMalformed)
	}
	defer clear(purpose)
	mac := hmac.New(sha256.New, purpose)
	_, _ = mac.Write(lengthPrefixed(Label, tenant, c))
	sum := mac.Sum(nil)
	defer clear(sum)
	return keyPrefix + ":" + strconv.FormatUint(uint64(gen), 10) + ":" + hex.EncodeToString(sum)[:keyHexLen], nil
}

func lengthPrefixed(fields ...string) []byte {
	var out []byte
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out
}

// Generations is the tenant secret state on the device. The generation
// numbers, the SHA-256 of each secret value and next_not_after come from
// the administrator's signed config; the secrets from the managed
// credential store (nil when not stored).
type Generations struct {
	Current       uint32
	CurrentSecret []byte
	CurrentSHA256 string
	Next          uint32
	NextSecret    []byte
	NextSHA256    string
	NextNotAfter  time.Time
	// SignedAt is when the administrator signed next_not_after: the
	// created_at of the confirmed policy bundle whose config carries it.
	// Zero when the config did not come from a confirmed bundle; the
	// device clock then bounds next_not_after.
	SignedAt time.Time
	// Highest is the highest generation this device applied before.
	Highest uint32
}

// Slot is one generation the device reports keys for.
type Slot struct {
	Generation uint32
	secret     []byte
}

// Plan decides which generations are reported, with the reason codes of
// the ones that are not. The current generation is reported when its
// secret is valid and its number is not below Highest; the next one in
// addition while its secret is valid, its number is above the current one
// and now is before NextNotAfter, which is at most MaxNextOverlap after the
// signing time (SignedAt; now when there is none), so a device clock that is
// behind or ahead does not move the signed bound (rel-1-0-6:GAP-0277).
// Removing the next secret without promotion leaves the current one as it
// is. The returned highest is what the device records after reporting.
func Plan(g Generations, now time.Time) (slots []Slot, reasons []string, highest uint32) {
	highest = g.Highest
	bound := now
	if !g.SignedAt.IsZero() {
		bound = g.SignedAt
	}
	switch {
	case g.CurrentSecret == nil:
		reasons = append(reasons, ReasonSecretMissing)
	case g.Current == 0:
		reasons = append(reasons, ReasonGenerationInvalid)
	case g.Current < g.Highest:
		reasons = append(reasons, ReasonGenerationRollback)
	case !valueMatches(g.CurrentSecret, g.CurrentSHA256):
		reasons = append(reasons, ReasonSecretMismatch)
	default:
		secret, err := ParseSecret(g.CurrentSecret)
		if err != nil {
			reasons = append(reasons, ReasonOf(err))
			break
		}
		slots = append(slots, Slot{Generation: g.Current, secret: secret})
		highest = max(highest, g.Current)
	}
	if g.NextSecret != nil || g.Next != 0 {
		switch {
		case g.NextSecret == nil:
			// A next generation with no secret: nothing to report.
		case g.Next == 0 || g.Next <= g.Current || g.NextNotAfter.IsZero() || g.NextNotAfter.After(bound.Add(MaxNextOverlap)):
			reasons = append(reasons, ReasonGenerationInvalid)
		case !now.Before(g.NextNotAfter):
			reasons = append(reasons, ReasonNextGenerationExpired)
		case !valueMatches(g.NextSecret, g.NextSHA256):
			reasons = append(reasons, ReasonSecretMismatch)
		default:
			secret, err := ParseSecret(g.NextSecret)
			if err != nil {
				reasons = append(reasons, ReasonOf(err))
				break
			}
			slots = append(slots, Slot{Generation: g.Next, secret: secret})
		}
	}
	return slots, reasons, highest
}

// valueMatches reports whether the stored value (as stored, one line) has
// the signed SHA-256 (lowercase hex).
func valueMatches(value []byte, want string) bool {
	sum := sha256.Sum256([]byte(strings.TrimRight(string(value), "\r\n")))
	return want != "" && hmac.Equal([]byte(hex.EncodeToString(sum[:])), []byte(strings.ToLower(strings.TrimSpace(want))))
}

// Summary is the account_join block of a status document: counts and
// reason codes, never a key (the keys are only in the output of
// `enterprise account-keys`).
type Summary struct {
	State              string            `json:"state"`
	Generations        []GenerationCount `json:"generations,omitempty"`
	AccountsWithoutKey int               `json:"accounts_without_key,omitempty"`
	ReasonCodes        []string          `json:"reason_codes,omitempty"`
}

// GenerationCount is how many keys a generation has.
type GenerationCount struct {
	Generation uint32 `json:"generation"`
	KeyCount   int    `json:"key_count"`
}

// Summary drops the keys of r.
func (r Report) Summary() Summary {
	s := Summary{State: r.State, AccountsWithoutKey: r.AccountsWithoutKey, ReasonCodes: r.ReasonCodes}
	for _, g := range r.Generations {
		s.Generations = append(s.Generations, GenerationCount{Generation: g.Generation, KeyCount: len(g.AccountKeys)})
	}
	return s
}

// GenerationKeys are the keys of one generation, sorted.
type GenerationKeys struct {
	Generation  uint32   `json:"generation"`
	AccountKeys []string `json:"account_keys"`
}

// Report is the account_join block of a root-only status document.
type Report struct {
	// State is on (keys computed), off (enterprise.account_join is off or
	// absent, or under Secure Client) or unavailable (on, but no
	// generation could be reported).
	State string `json:"state"`
	// Generations holds the keys of each reported generation.
	Generations []GenerationKeys `json:"generations,omitempty"`
	// AccountsWithoutKey counts the selected accounts that got no key.
	AccountsWithoutKey int `json:"accounts_without_key,omitempty"`
	// ReasonCodes are the closed reason codes of what was not reported.
	ReasonCodes []string `json:"reason_codes,omitempty"`
}

// Input is everything Compute needs.
type Input struct {
	// On is enterprise.account_join on; SecureClient forces off.
	On           bool
	SecureClient bool
	Tenant       string
	Generations  Generations
	Accounts     []Account
	Now          time.Time
}

// Compute builds the report. It computes keys only for accounts seen within
// Retention, at most MaxAccounts (the most recently seen), and nothing when
// the feature is off. The secrets in in.Generations are cleared.
func Compute(in Input) (Report, uint32) {
	defer clear(in.Generations.CurrentSecret)
	defer clear(in.Generations.NextSecret)
	if !in.On || in.SecureClient {
		return Report{State: "off", ReasonCodes: []string{ReasonFeatureOff}}, in.Generations.Highest
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	reasons := map[string]bool{}
	tenant, err := CanonicalTenant(in.Tenant)
	if err != nil {
		return Report{State: "unavailable", ReasonCodes: []string{ReasonOf(err)}}, in.Generations.Highest
	}
	slots, planReasons, highest := Plan(in.Generations, now)
	defer func() {
		for _, slot := range slots {
			clear(slot.secret)
		}
	}()
	for _, reason := range planReasons {
		reasons[reason] = true
	}
	accounts := SelectAccounts(in.Accounts, now)
	if len(accounts) < countRecent(in.Accounts, now) {
		reasons[ReasonAccountCap] = true
	}
	report := Report{State: "on"}
	if len(slots) == 0 {
		report.State = "unavailable"
	}
	inputs := make([]string, 0, len(accounts))
	for _, account := range accounts {
		c, err := Canonical(account)
		if err != nil {
			report.AccountsWithoutKey++
			reasons[ReasonOf(err)] = true
			continue
		}
		inputs = append(inputs, c)
	}
	for _, slot := range slots {
		keys := GenerationKeys{Generation: slot.Generation, AccountKeys: []string{}}
		seen := map[string]bool{}
		for _, c := range inputs {
			key, err := Key(slot.secret, slot.Generation, tenant, c)
			if err != nil {
				reasons[ReasonOf(err)] = true
				continue
			}
			if !seen[key] {
				seen[key] = true
				keys.AccountKeys = append(keys.AccountKeys, key)
			}
		}
		sort.Strings(keys.AccountKeys)
		report.Generations = append(report.Generations, keys)
	}
	for reason := range reasons {
		report.ReasonCodes = append(report.ReasonCodes, reason)
	}
	sort.Strings(report.ReasonCodes)
	return report, highest
}

// SelectAccounts keeps the accounts seen within Retention of now, the most
// recently seen first, at most MaxAccounts.
func SelectAccounts(accounts []Account, now time.Time) []Account {
	out := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if !account.LastSeen.IsZero() && now.Sub(account.LastSeen) <= Retention {
			out = append(out, account)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > MaxAccounts {
		out = out[:MaxAccounts]
	}
	return out
}

func countRecent(accounts []Account, now time.Time) int {
	n := 0
	for _, account := range accounts {
		if !account.LastSeen.IsZero() && now.Sub(account.LastSeen) <= Retention {
			n++
		}
	}
	return n
}
