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

// Capture keeps bounded sets of entries. Entries taken from people's
// prompts and entries taken where an agent's model wrote or read the value
// (a tool call, a tool's output) are bounded separately, so a session whose
// tools keep printing token-shaped test fixtures can never use up the room
// a prompt's secret needs. Only entries the person has not confirmed or
// replaced count. Past a bound the call is still answered and the value
// still removed from the body; only nothing more of that kind is stored.
//
// Each sandbox has its own room: MaxCapturedPerSandbox prompt entries and
// MaxCapturedFromModelPerSandbox model-side ones. A process inside a
// sandbox can post hook events the way its harness does, and nothing tells
// them apart, so a sandbox's events may only ever fill that sandbox's room,
// never another sandbox's (GAP-1979). MaxCaptured and MaxCapturedFromModel
// bound the entries captured with no sandbox named. All captures together,
// from every sandbox and none, stop at MaxCapturedTotal, so
// MaxEntries-MaxCapturedTotal entries always stay for the person's own
// secrets. One sandbox holds at most MaxCapturedPerSandbox +
// MaxCapturedFromModelPerSandbox, well under MaxCapturedTotal, so one
// sandbox cannot reach it; several sandboxes together can, and past it a
// prompt is still stopped (fail closed). The names of a kind run to
// MaxEntries, so captures cannot use them up.
const (
	MaxCaptured                    = 16
	MaxCapturedFromModel           = 8
	MaxCapturedPerSandbox          = MaxCaptured / 2
	MaxCapturedFromModelPerSandbox = MaxCapturedFromModel
	MaxCapturedTotal               = MaxEntries - 16
)

// CaptureWait bounds how long a hook call waits for the vault lock.
const CaptureWait = 500 * time.Millisecond

var (
	// ErrCaptureFull is returned when the vault holds MaxCaptured entries
	// captured from prompts.
	ErrCaptureFull = fmt.Errorf("the vault already holds %d unconfirmed secrets captured from prompts; review them with `defenseclaw sandbox vault list` and confirm the ones that are yours or remove the others", MaxCaptured)
	// ErrSandboxCaptureFull is returned when one sandbox's prompts hold
	// MaxCapturedPerSandbox unconfirmed entries. It is an ErrCaptureFull.
	ErrSandboxCaptureFull error = &captureFullError{kind: ErrCaptureFull, msg: fmt.Sprintf(
		"this sandbox already holds %d unconfirmed secrets captured from its prompts; review them with `defenseclaw sandbox vault list` and confirm the ones that are yours or remove the others", MaxCapturedPerSandbox)}
	// ErrModelCaptureFull is returned when the vault holds
	// MaxCapturedFromModel entries captured from agents' tool calls and
	// output.
	ErrModelCaptureFull = fmt.Errorf("the vault already holds %d secrets captured from agents' tool calls and output that are not replaced yet; rotate and replace them, or remove the ones you do not need", MaxCapturedFromModel)
	// ErrAllCapturesFull is returned when the vault holds MaxCapturedTotal
	// captured entries the person has not confirmed or replaced, from all
	// sandboxes together. It is an ErrCaptureFull.
	ErrAllCapturesFull error = &captureFullError{kind: ErrCaptureFull, msg: fmt.Sprintf(
		"the vault already holds %d captured secrets from your sandboxes that are not confirmed or replaced yet; review them with `defenseclaw sandbox vault list`, confirm or replace the ones that are yours and remove the others", MaxCapturedTotal)}
	// ErrSandboxModelCaptureFull is returned when one sandbox's tool calls
	// and output hold MaxCapturedFromModelPerSandbox entries not replaced
	// yet. It is an ErrModelCaptureFull.
	ErrSandboxModelCaptureFull error = &captureFullError{kind: ErrModelCaptureFull, msg: fmt.Sprintf(
		"this sandbox already holds %d secrets captured from its agent's tool calls and output that are not replaced yet; rotate and replace them, or remove the ones you do not need (`defenseclaw sandbox vault list`)", MaxCapturedFromModelPerSandbox)}
)

// captureFullError is a sandbox's own bound: its text names the sandbox's
// room, and errors.Is matches the vault-wide bound of the same kind.
type captureFullError struct {
	kind error
	msg  string
}

func (e *captureFullError) Error() string { return e.msg }

func (e *captureFullError) Is(target error) bool { return target == e.kind }

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
	// Sandbox names the sandbox the value came from ("" when unknown); a
	// sandbox's captures count only toward its own room.
	Sandbox string
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
//
// When nothing could be written (a busy lock, a failed write), the values
// the call exposed are recorded as pending exposures (recordPending), and
// the error also wraps ErrExposurePending, or ErrExposureNotRecorded when
// even that failed: no sandbox gets a pending value, and the next change
// of the vault writes the exposure.
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
	// seen is the vault as read, pinned or not: its seal header gives a
	// pending exposure the value's fingerprint.
	seen := held
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
		// Nothing was written: every exposed value the vault holds, or
		// would store, is recorded pending (a reply's value the vault does
		// not hold is only removed from the body, as when it is written).
		var exposed []string
		for _, in := range ins {
			if in.Exposed && (!in.KnownOnly || seen == nil || seen.indexValue(in.Value) >= 0) {
				exposed = append(exposed, in.Value)
			}
		}
		err = s.recordExposures(seen, exposed, err, true)
		if errors.Is(err, ErrBusy) && readErr == nil {
			out, _ = heldCaptures(held, ins)
			return out, err
		}
		return nil, err
	}
	if partial != nil {
		// A value the vault refused to store (a limit) that the model saw
		// is recorded pending, so a later capture of it is stored exposed.
		var exposed []string
		for i, in := range ins {
			if in.Exposed && !in.KnownOnly && out[i].Entry.Name == "" {
				exposed = append(exposed, in.Value)
			}
		}
		partial = s.recordExposures(seen, exposed, partial, false)
	}
	return out, partial
}

// recordExposures records values as pending exposures and returns cause
// joined with what became of them: ErrExposureNotRecorded when they could
// not be recorded, ErrExposurePending when they were and wrote is false
// (nothing was written, so a retry should write them); cause alone when
// there is nothing to record. f is the vault as last read (nil when it
// could not be read).
func (s *Store) recordExposures(f *file, values []string, cause error, nothingWritten bool) error {
	if len(values) == 0 {
		return cause
	}
	if err := s.recordPending(f, values); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: %v", ErrExposureNotRecorded, err))
	}
	if nothingWritten {
		return errors.Join(cause, ErrExposurePending)
	}
	return cause
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
	// Unconfirmed captures with no sandbox named share the vault-wide room;
	// a sandbox's count toward its own (GAP-1979); all of them count toward
	// MaxCapturedTotal.
	fromPrompts, fromModel, captured := 0, 0, 0
	promptsBySandbox, modelBySandbox := map[string]int{}, map[string]int{}
	for _, e := range f.Entries {
		if e.Source == SourceCaptured && !e.Confirmed {
			captured++
		}
		switch {
		case e.Source != SourceCaptured || e.Confirmed:
			// The person's own now: confirmed, or its value replaced.
		case e.FromModel && e.Sandbox != "":
			modelBySandbox[e.Sandbox]++
		case e.FromModel:
			fromModel++
		case e.Sandbox != "":
			promptsBySandbox[e.Sandbox]++
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
		sandbox := strings.TrimSpace(in.Sandbox)
		switch {
		case len(f.Entries) >= MaxEntries:
			err = ErrFull
		case captured >= MaxCapturedTotal:
			err = ErrAllCapturesFull
		case in.FromModel && sandbox != "" && modelBySandbox[sandbox] >= MaxCapturedFromModelPerSandbox:
			err = ErrSandboxModelCaptureFull
		case in.FromModel && sandbox == "" && fromModel >= MaxCapturedFromModel:
			err = ErrModelCaptureFull
		case !in.FromModel && sandbox != "" && promptsBySandbox[sandbox] >= MaxCapturedPerSandbox:
			err = ErrSandboxCaptureFull
		case !in.FromModel && sandbox == "" && fromPrompts >= MaxCaptured:
			err = ErrCaptureFull
		}
		kind := capturable[in.Kind]
		name := ""
		if err == nil {
			// Names run to MaxEntries, so no sandbox's captures can use up
			// the names of a kind before the vault is full (GAP-1979).
			for n := 1; n <= MaxEntries; n++ {
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
				err = fmt.Errorf("the vault already holds %s and %s_2 to %s_%d; rename or remove one", kind.name, kind.name, kind.name, MaxEntries)
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
			// A value with a pending exposure is stored exposed.
			Exposed: in.Exposed || f.pendingExposes(in.Value), FromModel: in.FromModel, CapturedFrom: strings.TrimSpace(in.From),
			Sandbox: sandbox, CreatedAt: now, UpdatedAt: now,
		}, Value: in.Value}
		f.Entries = append(f.Entries, r)
		captured++
		switch {
		case in.FromModel && sandbox != "":
			modelBySandbox[sandbox]++
		case in.FromModel:
			fromModel++
		case sandbox != "":
			promptsBySandbox[sandbox]++
		default:
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
