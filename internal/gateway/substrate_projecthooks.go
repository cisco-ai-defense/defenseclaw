// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"strings"
)

// substrateMaxProjectHookFiles bounds the project settings files one post
// records (the kit reports at most two per connector).
const substrateMaxProjectHookFiles = 4

// substrateRecordProjectHooks writes one foreign_hook_ignored audit row per
// actor, settings file and content when the kit reports, at SessionStart,
// a project settings file that declares hooks (GAP-0479). The actor's
// managed settings ignore them (Claude Code: allowManagedHooksOnly), so
// they never run, but the attempt of an uploaded repository to add a hook
// is recorded. The fact is a claim from the actor; the row says so. It
// never changes the hook's answer.
func (st *substrateState) substrateRecordProjectHooks(ctx context.Context, env substrateEnvelope) {
	if st == nil || st.audit == nil || env.Facts == nil || len(env.Facts.ProjectHooks) == 0 {
		return
	}
	actor, _ := substrateActorFrom(ctx)
	hooks := env.Facts.ProjectHooks
	if len(hooks) > substrateMaxProjectHookFiles {
		hooks = hooks[:substrateMaxProjectHookFiles]
	}
	for _, ph := range hooks {
		file := substrateReportText(ph.Path)
		if file == "" || ph.Hooks <= 0 {
			continue
		}
		sum := substrateReportText(ph.SHA256)
		key := "project_hooks\x00" + actor.UID + "\x00" + file + "\x00" + sum
		st.alertMu.Lock()
		if st.alerted == nil || len(st.alerted) >= substrateAlertMemory {
			st.alerted = map[string]bool{}
		}
		seen := st.alerted[key]
		st.alerted[key] = true
		st.alertMu.Unlock()
		if seen {
			continue
		}
		events := make([]string, 0, len(ph.Events))
		for _, e := range ph.Events {
			if e = substrateReportText(e); e != "" {
				events = append(events, e)
			}
		}
		summary := fmt.Sprintf("Substrate project hooks ignored: %s/%s declares %d hook(s) in %s (%s); the managed settings run only DefenseClaw's hooks (reported by the actor)",
			actor.Atespace, actor.Name, ph.Hooks, file, strings.Join(events, ", "))
		st.audit(context.WithoutCancel(ctx), "MEDIUM", summary, map[string]any{
			"event": "foreign_hook_ignored", "atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID,
			"connector": env.Connector, "file": file, "sha256": sum, "hook_events": events, "hooks": ph.Hooks,
			"reported_by": "actor",
		})
		st.logRefusal("%s/%s: project hooks in %s ignored (%d)", actor.Atespace, actor.Name, file, ph.Hooks)
	}
}
