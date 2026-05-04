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

package gatewaylog

import (
	"fmt"
	"io"
	"strings"
)

// writePretty formats an Event into the legacy "[subsystem] message"
// shape so existing TUI tail panels and human operators reading
// stderr see familiar output while the JSONL stream feeds machines.
//
// Deliberately terse: this path is high-volume in regex_judge mode,
// and long lines wrap poorly in the TUI Logs panel.
func writePretty(w io.Writer, e Event) {
	ts := e.Timestamp.Format("15:04:05.000")

	switch e.EventType {
	case EventVerdict:
		if e.Verdict == nil {
			return
		}
		v := e.Verdict
		cats := ""
		if len(v.Categories) > 0 {
			cats = " cats=[" + strings.Join(v.Categories, ",") + "]"
		}
		fmt.Fprintf(w, "%s [%s:%s] action=%s sev=%s reason=%q%s (%dms)\n",
			ts, v.Stage, e.Direction, v.Action, e.Severity, v.Reason, cats, v.LatencyMs)

	case EventJudge:
		if e.Judge == nil {
			return
		}
		j := e.Judge
		parse := ""
		if j.ParseError != "" {
			parse = " parse_err=" + j.ParseError
		}
		fmt.Fprintf(w, "%s [judge:%s] model=%s dir=%s action=%s sev=%s in=%dB lat=%dms%s\n",
			ts, j.Kind, j.Model, e.Direction, j.Action, j.Severity, j.InputBytes, j.LatencyMs, parse)

	case EventLifecycle:
		if e.Lifecycle == nil {
			return
		}
		l := e.Lifecycle
		fmt.Fprintf(w, "%s [lifecycle:%s] %s\n", ts, l.Subsystem, l.Transition)

	case EventError:
		if e.Error == nil {
			return
		}
		er := e.Error
		cause := ""
		if er.Cause != "" {
			cause = " cause=" + er.Cause
		}
		fmt.Fprintf(w, "%s [error:%s] code=%s %s%s\n",
			ts, er.Subsystem, er.Code, er.Message, cause)

	case EventDiagnostic:
		if e.Diagnostic == nil {
			return
		}
		d := e.Diagnostic
		fmt.Fprintf(w, "%s [%s] %s\n", ts, d.Component, d.Message)

	case EventLLMPrompt:
		if e.LLMPrompt == nil {
			return
		}
		p := e.LLMPrompt
		fmt.Fprintf(w, "%s [llm_prompt] model=%s provider=%s prompt_id=%s session=%s\n",
			ts, e.Model, e.Provider, p.PromptID, e.SessionID)

	case EventLLMResponse:
		if e.LLMResponse == nil {
			return
		}
		r := e.LLMResponse
		fmt.Fprintf(w, "%s [llm_response] model=%s provider=%s response_id=%s reply_to=%s\n",
			ts, e.Model, e.Provider, r.ResponseID, r.ReplyToPromptID)

	case EventToolInvocation:
		if e.Tool == nil {
			return
		}
		t := e.Tool
		fmt.Fprintf(w, "%s [tool:%s] phase=%s call_id=%s session=%s\n",
			ts, t.Tool, t.Phase, t.ToolCallID, e.SessionID)
	}
}
