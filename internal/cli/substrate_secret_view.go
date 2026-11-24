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

package cli

import (
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
)

// substrateExpiryWarning is how far ahead list warns of an expiry.
const substrateExpiryWarning = 7 * 24 * time.Hour

// substrateSecretKind is the KIND column: template <name> for the person's
// own binding, admin (shared) or admin (per person) for an
// administrator's entry.
func substrateSecretKind(sec api.Secret) string {
	switch {
	case sec.Kind == "template":
		return strings.TrimSpace("template " + sec.Template)
	case sec.Scope == "per_person":
		return "admin (per person)"
	}
	return "admin (shared)"
}

// substrateUntil is the EXPIRES column: in N d (or N h), expired, or -.
func substrateUntil(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	d := t.Sub(now)
	switch {
	case d <= 0:
		return "expired"
	case d < 24*time.Hour:
		return fmt.Sprintf("in %d h", int(math.Ceil(d.Hours())))
	}
	return fmt.Sprintf("in %d d", int(d.Hours()/24))
}

// substrateSince is the LAST USED column; - when not known.
func substrateSince(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	d := now.Sub(t.UTC())
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d d ago", int(d.Hours()/24))
}

// substrateExpiresSoon reports a usable binding that expires within the
// warning window, with the days left (rounded up).
func substrateExpiresSoon(sec api.Secret, now time.Time) (int, bool) {
	if sec.Expires == nil || sec.Expires.IsZero() || sec.Reason != "" {
		return 0, false
	}
	d := sec.Expires.Sub(now)
	if d <= 0 || d > substrateExpiryWarning {
		return 0, false
	}
	return int(math.Ceil(d.Hours() / 24)), true
}

// substrateReasonText is the reason table message for code with the
// placeholders of its fix filled in.
func substrateReasonText(code, name, agent string) string {
	msg := reasons.Message(code)
	if msg == "" {
		return code
	}
	msg = strings.ReplaceAll(msg, " NAME", " "+name)
	if agent != "" {
		msg = strings.ReplaceAll(msg, " AGENT", " "+agent)
	}
	return msg
}

// substrateStatusWords are the words of a secret status.
func substrateStatusWords(status string) string {
	for _, s := range reasons.Statuses {
		if s.Status == status {
			return s.Words
		}
	}
	return status
}

// printSubstrateSecretTest says in words what secrets test found: the
// status, where the secret is bound, why it is not used and, for --agent,
// whether that agent's policy carries it.
func printSubstrateSecretTest(w io.Writer, res api.SecretTest, now time.Time) {
	fmt.Fprintf(w, "%s: %s (%s)\n", res.Name, strings.TrimSuffix(substrateStatusWords(res.Status), "."), res.Status)
	if len(res.Hosts) > 0 {
		line := "Bound to " + strings.Join(res.Hosts, ", ") + " (" + substrateSecretKind(res.Secret) + ")"
		if e := substrateUntil(res.Expires, now); e != "-" {
			line += ", expires " + e
		}
		fmt.Fprintln(w, line+".")
	}
	if res.LastUsed != nil && !res.LastUsed.IsZero() {
		line := "Last used " + substrateSince(res.LastUsed, now)
		if res.LastUsedAgent != "" {
			line += " by " + res.LastUsedAgent
		}
		if res.LastUsedHost != "" {
			line += " on " + res.LastUsedHost
		}
		fmt.Fprintln(w, line+".")
	}
	if res.AskID != "" {
		fmt.Fprintf(w, "Ask: %s\n", res.AskID)
	}
	if res.Reason != "" {
		fmt.Fprintln(w, substrateReasonText(res.Reason, res.Name, ""))
	}
	if a := res.Agent; a != nil {
		switch {
		case a.InPolicy == nil:
			fmt.Fprintf(w, "Agent %s: DefenseClaw could not read its policy just now; test again in a minute.\n", a.Actor)
		case *a.InPolicy:
			fmt.Fprintf(w, "Agent %s: its policy carries the secret.\n", a.Actor)
		case a.Reason == res.Reason:
			fmt.Fprintf(w, "Agent %s: its policy does not carry the secret.\n", a.Actor)
		default:
			fmt.Fprintf(w, "Agent %s: its policy does not carry the secret. %s\n", a.Actor, substrateReasonText(a.Reason, res.Name, a.Actor))
		}
	}
}
