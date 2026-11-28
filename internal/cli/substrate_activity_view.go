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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// The ACTIVITY column of `substrate list` and the Activity, Last and Answer
// lines of `substrate status NAME` (B3.6). The times are the gateway's
// receive times; nothing here comes from the agent.

// substratePlural is "1 commit" or "3 commits": n with the word for one or
// for many.
func substratePlural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// substrateIdleSince is "idle since 09:12Z" (the time of day when it is
// today, the date otherwise), "idle" when the agent never did anything.
func substrateIdleSince(last, now time.Time, word string) string {
	if last.IsZero() {
		return word
	}
	last = last.UTC()
	if now.UTC().Sub(last) < 24*time.Hour {
		return word + " since " + last.Format("15:04") + "Z"
	}
	return word + " since " + last.Format("Jan 2")
}

// substrateActivityCell is the ACTIVITY column: "-" when the cluster did
// not say (never "idle" for an unknown state).
func substrateActivityCell(a api.Actor, now time.Time) string {
	act := a.Activity
	if act == nil {
		return "-"
	}
	switch act.State {
	case "waiting_on_ask":
		return "waiting on " + substratePlural(act.PendingAsks, "ask", "asks")
	case "thinking":
		return "thinking (" + substrateAge(act.Last, now) + " ago)"
	case "suspended":
		return substrateIdleSince(act.Last, now, "suspended")
	case "task_done":
		return "task ended (" + substrateAge(act.TaskEnded, now) + " ago)"
	case "idle":
		return substrateIdleSince(act.Last, now, "idle")
	}
	return substrateDash(act.State)
}

// substrateActivityLines are the status lines for an agent, "" lines left out.
func substrateActivityLines(a api.Actor, now time.Time) []string {
	act := a.Activity
	if act == nil {
		return nil
	}
	var out []string
	var head string
	switch act.State {
	case "waiting_on_ask":
		head = "waiting on an ask"
		if len(act.Asks) > 0 {
			var parts []string
			for _, k := range act.Asks {
				p := safetext.Line(k.Kind + " " + k.Target)
				if !k.Created.IsZero() {
					p += ", raised " + substrateAge(k.Created, now) + " ago"
				}
				parts = append(parts, p)
			}
			head += " (" + substratePlural(act.PendingAsks, "pending", "pending") + ": " + strings.Join(parts, "; ") + ")"
		} else if act.PendingAsks > 0 {
			head += " (" + fmt.Sprintf("%d pending", act.PendingAsks) + ")"
		}
	case "thinking":
		head = "thinking (a model or tool call " + substrateAge(act.Last, now) + " ago)"
	case "suspended":
		head = substrateIdleSince(act.Last, now, "suspended")
	case "task_done":
		head = "the --task run ended " + substrateAge(act.TaskEnded, now) + " ago"
	default:
		head = substrateIdleSince(act.Last, now, "idle")
	}
	out = append(out, "Activity:  "+head)
	var last []string
	if !act.LastModel.IsZero() {
		last = append(last, "model call "+substrateAge(act.LastModel, now)+" ago")
	}
	if !act.LastTool.IsZero() {
		last = append(last, "tool call "+substrateAge(act.LastTool, now)+" ago")
	}
	if !act.Attached.IsZero() {
		last = append(last, "you were attached "+substrateAge(act.Attached, now)+" ago")
	}
	if len(last) == 0 {
		last = []string{"-"}
	}
	out = append(out, "Last:      "+strings.Join(last, "; "))
	if act.PendingAsks > 0 {
		out = append(out, "Answer:    defenseclaw substrate approvals   (or press Ctrl-\\ in connect)")
	}
	return out
}
