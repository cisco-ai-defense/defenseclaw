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

// Capture keeps two bounded sets of entries. MaxCaptured bounds the ones
// taken from people's prompts; MaxCapturedFromModel bounds the ones taken
// where an agent's model wrote or read the value (a tool call, a tool's
// output). Only entries the person has not confirmed or replaced count.
// They are separate so a session whose tools keep printing
// token-shaped test fixtures can never use up the room a prompt's secret
// needs. Past a bound the call is still answered and the value still
// removed from the body; only nothing more of that kind is stored.
const (
	MaxCaptured          = 16
	MaxCapturedFromModel = 8
)

// CaptureWait bounds how long a hook call waits for the vault lock.
const CaptureWait = 500 * time.Millisecond

var (
	// ErrCaptureFull is returned when the vault holds MaxCaptured entries
	// captured from prompts.
	ErrCaptureFull = fmt.Errorf("the vault already holds %d unconfirmed secrets captured from prompts; confirm the ones that are yours and remove the others", MaxCaptured)
	// ErrModelCaptureFull is returned when the vault holds
	// MaxCapturedFromModel entries captured from agents' tool calls and
	// output.
	ErrModelCaptureFull = fmt.Errorf("the vault already holds %d secrets captured from agents' tool calls and output that are not replaced yet; rotate and replace them, or remove the ones you do not need", MaxCapturedFromModel)
)

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
	// FromModel: the agent's model wrote or read the value (a tool call, a
	// tool's output), not the person's prompt. A new entry counts toward
	// MaxCapturedFromModel instead of MaxCaptured.
	FromModel bool
	// KnownOnly: store no new entry; only mark a value the vault already
	// holds exposed (a reply or another event, where a value the vault does
	// not hold is only removed from the body).
	KnownOnly bool
}

// Captured is the result of one capture. Entry.Name is empty when the value
// was not kept (KnownOnly and not held, or the vault could not store it).
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
// most wait for the vault lock, and returns one result per input, in
// order. A value the vault already holds is not stored twice: the existing
// entry is returned, and marked exposed if this capture exposed it. A new
// value gets the kind's name, with _2 to _9 added when that name is taken,
// and the kind's host when it has one. An exposed entry (an agent's model
// saw the value) is never handed to a sandbox until the person replaces
// it (Resolve), so a value an agent planted under a real API's name is
// never used.
//
// Marking held values exposed never depends on storing the new ones: when
// a new value cannot be stored (ErrFull, ErrCaptureFull,
// ErrModelCaptureFull, no free name), the exposures and the other new
// values are still written, the value's result is left empty, and the
// first such error is returned with the results. When the lock is busy
// (ErrBusy) nothing is written, and the results name the values the vault
// already held. A call that changes nothing is answered from a read,
// without the lock or a write.
func (s *Store) CaptureAll(ins []CaptureInput, wait time.Duration) ([]Captured, error) {
	for _, in := range ins {
		if _, ok := capturable[in.Kind]; !ok {
			return nil, fmt.Errorf("%q credentials are not captured", in.Kind)
		}
		if err := ValidValue(in.Value); err != nil {
			return nil, err
		}
	}
	held, readErr := s.read()
	if readErr == nil {
		// The answer from a read is the vault's only while it is the
		// pinned one: a swapped or unsealed file goes to the locked path,
		// which refuses it.
		if _, err := s.checkPin(held, false, false); err != nil {
			held, readErr = nil, err
		}
	}
	if readErr == nil {
		if out, changes := heldCaptures(held, ins); !changes {
			return out, nil
		}
	}
	var out []Captured
	var partial error
	err := s.updateWait(wait, needNothing, func(f *file) error {
		var changed bool
		out, changed, partial = s.capture(f, ins)
		if !changed {
			return errUnchanged
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrBusy) && readErr == nil {
			out, _ = heldCaptures(held, ins)
			return out, err
		}
		return nil, err
	}
	return out, partial
}

// heldCaptures answers ins from f without changing it; changes reports
// whether storing them would change the vault.
func heldCaptures(f *file, ins []CaptureInput) ([]Captured, bool) {
	out := make([]Captured, len(ins))
	changes := false
	for i, in := range ins {
		j := f.indexValue(in.Value)
		switch {
		case j >= 0:
			out[i] = Captured{Entry: f.Entries[j].Entry}
			if in.Exposed && !f.Entries[j].Exposed {
				changes = true
			}
		case !in.KnownOnly:
			changes = true
		}
	}
	return out, changes
}

// capture applies ins to f: exposures of held values first, then new
// values. partial is the first new value that could not be stored.
func (s *Store) capture(f *file, ins []CaptureInput) (out []Captured, changed bool, partial error) {
	now := s.now().UTC()
	out = make([]Captured, len(ins))
	for i, in := range ins {
		j := f.indexValue(in.Value)
		if j < 0 {
			continue
		}
		if in.Exposed && !f.Entries[j].Exposed {
			f.Entries[j].Exposed = true
			f.Entries[j].UpdatedAt = now
			changed = true
		}
		out[i] = Captured{Entry: f.Entries[j].Entry}
	}
	fromPrompts, fromModel := 0, 0
	for _, e := range f.Entries {
		switch {
		case e.Source != SourceCaptured || e.Confirmed:
			// The person's own now: confirmed, or its value replaced.
		case e.FromModel:
			fromModel++
		default:
			fromPrompts++
		}
	}
	for i, in := range ins {
		if out[i].Entry.Name != "" || in.KnownOnly {
			continue
		}
		if j := f.indexValue(in.Value); j >= 0 {
			// The same value twice in one call.
			out[i] = Captured{Entry: f.Entries[j].Entry}
			continue
		}
		var err error
		switch {
		case len(f.Entries) >= MaxEntries:
			err = ErrFull
		case in.FromModel && fromModel >= MaxCapturedFromModel:
			err = ErrModelCaptureFull
		case !in.FromModel && fromPrompts >= MaxCaptured:
			err = ErrCaptureFull
		}
		kind := capturable[in.Kind]
		name := ""
		if err == nil {
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
				err = fmt.Errorf("the vault already holds %s and %s_2 to %s_9; rename or remove one", kind.name, kind.name, kind.name)
			}
		}
		if err != nil {
			if partial == nil {
				partial = err
			}
			continue
		}
		port := 0
		if kind.host != "" {
			port = 443
		}
		r := record{Entry: Entry{
			Name: name, Host: kind.host, Port: port, Source: SourceCaptured, Kind: in.Kind,
			Exposed: in.Exposed, FromModel: in.FromModel, CapturedFrom: strings.TrimSpace(in.From),
			CreatedAt: now, UpdatedAt: now,
		}, Value: in.Value}
		f.Entries = append(f.Entries, r)
		if in.FromModel {
			fromModel++
		} else {
			fromPrompts++
		}
		changed = true
		out[i] = Captured{Entry: r.Entry, New: true}
	}
	return out, changed, partial
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
