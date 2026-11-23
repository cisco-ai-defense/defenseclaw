// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

// capturable are the credential kinds DefenseClaw takes out of a sandboxed
// agent's prompt or tool call: single-line values with an issuer prefix
// that identifies them without context. name is the entry name the vault
// gives them; host is the API they are sent to, when there is one obvious
// API (empty: the person binds a host before a sandbox can use it). AWS
// access key IDs are not captured: the ID is not the secret, and AWS
// requests are signed with it, which a placeholder swap cannot do.
var capturable = map[string]struct{ name, host string }{
	"anthropic-key":             {"ANTHROPIC_API_KEY", "api.anthropic.com"},
	"openai-key":                {"OPENAI_API_KEY", "api.openai.com"},
	"github-token":              {"GITHUB_TOKEN", "api.github.com"},
	"github-fine-grained-token": {"GITHUB_TOKEN", "api.github.com"},
	"slack-token":               {"SLACK_TOKEN", "slack.com"},
	"stripe-secret-key":         {"STRIPE_API_KEY", "api.stripe.com"},
	"google-api-key":            {"GOOGLE_API_KEY", ""},
}

// MaxCaptured bounds the entries capture keeps: a session that keeps
// writing token-shaped test fixtures cannot fill the vault. Past it a call
// is still stopped and redacted, and nothing more is stored.
const MaxCaptured = 16

// CaptureWait bounds how long a hook call waits for the vault lock.
const CaptureWait = 500 * time.Millisecond

// ErrCaptureFull is returned when the vault holds MaxCaptured captured
// entries.
var ErrCaptureFull = fmt.Errorf("the vault already holds %d captured secrets; remove the ones you do not need", MaxCaptured)

// Prefixes are the issuer prefixes of the capturable kinds: a text holding
// none of them holds no capturable credential (a cheap first screen).
var Prefixes = []string{"sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "AIza", "sk_live_", "rk_live_"}

// Found is one capturable credential in a text.
type Found struct {
	Kind  string
	Start int
	End   int
}

// FindCapturable returns the capturable credentials in text, in order.
func FindCapturable(text string) []Found {
	if text == "" {
		return nil
	}
	var out []Found
	keep := func(label string) bool { _, ok := capturable[label]; return ok }
	for _, s := range secretshape.FindInlineSecretSpansOf(text, keep) {
		out = append(out, Found{Kind: s.Label, Start: s.Start, End: s.End})
	}
	return out
}

// CaptureInput is one credential taken out of a sandboxed agent's call.
type CaptureInput struct {
	Value string
	Kind  string
	// Exposed: the agent's model produced or saw the value (a tool call it
	// wrote), so the value must be rotated.
	Exposed bool
	// From says where it was captured, for people ("claudecode prompt in
	// sandbox demo").
	From string
}

// Captured is the result of one capture.
type Captured struct {
	Entry Entry
	// New: the vault did not hold this value before.
	New bool
}

// Capture stores one captured credential (CaptureAll with the CLI wait).
func (s *Store) Capture(in CaptureInput) (Captured, error) {
	out, err := s.CaptureAll([]CaptureInput{in}, lockWait)
	if err != nil {
		return Captured{}, err
	}
	return out[0], nil
}

// CaptureAll stores the credentials of one call in one write, waiting at
// most wait for the vault lock. A value the vault already holds is not
// stored twice: the existing entry is returned (and marked exposed if this
// capture exposed it). A new value gets the kind's name, with _2 to _9
// added when that name is taken, and the kind's host when it has one. An
// exposed entry (an agent produced the value) is never handed to a sandbox
// until the person replaces it (Resolve), so a value an agent planted
// under a real API's name is never used. Any error stores nothing.
func (s *Store) CaptureAll(ins []CaptureInput, wait time.Duration) ([]Captured, error) {
	for _, in := range ins {
		if _, ok := capturable[in.Kind]; !ok {
			return nil, fmt.Errorf("%q credentials are not captured", in.Kind)
		}
		if err := ValidValue(in.Value); err != nil {
			return nil, err
		}
	}
	var out []Captured
	err := s.updateWait(wait, needNothing, func(f *file) error {
		out = out[:0]
		now := s.now().UTC()
		captured := 0
		for _, e := range f.Entries {
			if e.Source == SourceCaptured {
				captured++
			}
		}
		for _, in := range ins {
			kind := capturable[in.Kind]
			if i := f.indexValue(in.Value); i >= 0 {
				if in.Exposed && !f.Entries[i].Exposed {
					f.Entries[i].Exposed = true
					f.Entries[i].UpdatedAt = now
				}
				out = append(out, Captured{Entry: f.Entries[i].Entry})
				continue
			}
			if len(f.Entries) >= MaxEntries {
				return ErrFull
			}
			if captured >= MaxCaptured {
				return ErrCaptureFull
			}
			name := ""
			for n := 1; n <= 9; n++ {
				candidate := kind.name
				if n > 1 {
					candidate = fmt.Sprintf("%s_%d", kind.name, n)
				}
				if f.index(candidate) < 0 {
					name = candidate
					break
				}
			}
			if name == "" {
				return fmt.Errorf("the vault already holds %s and %s_2 to %s_9; rename or remove one", kind.name, kind.name, kind.name)
			}
			port := 0
			if kind.host != "" {
				port = 443
			}
			r := record{Entry: Entry{
				Name: name, Host: kind.host, Port: port, Source: SourceCaptured, Kind: in.Kind,
				Exposed: in.Exposed, CapturedFrom: strings.TrimSpace(in.From), CreatedAt: now, UpdatedAt: now,
			}, Value: in.Value}
			f.Entries = append(f.Entries, r)
			captured++
			out = append(out, Captured{Entry: r.Entry, New: true})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Redact replaces every capturable credential in text with its vault tag
// ([vault:NAME]) using the names in names (keyed by the credential's
// value). A credential with no name in names is replaced with
// [vault:redacted].
func Redact(text string, found []Found, names map[string]string) string {
	if len(found) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, f := range found {
		if f.Start < last || f.End > len(text) {
			continue
		}
		b.WriteString(text[last:f.Start])
		name := names[text[f.Start:f.End]]
		if name == "" {
			name = "redacted"
		}
		b.WriteString(Tag(name))
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// Tag is how a captured credential appears in place of its value.
func Tag(name string) string { return "[vault:" + name + "]" }

// IsNotFound reports whether err means the entry does not exist.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
