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
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/notify"
)

// `substrate watch` follows your agents and says when one needs an answer or
// a --task run ends (B3.6). It always prints a line; a desktop notification
// is sent only when you turned notifications on (notifications.enabled and
// notifications.substrate.asks / task_end), the cluster allows it
// (substrate.activity.notifications is not off) and the tool is installed.
// The text names the kind and the host or tool, never the ask's arguments.

const (
	substrateWatchDefaultEvery = 10 * time.Second
	substrateWatchMinEvery     = 2 * time.Second
)

// substrateNotifyPolicy is whether a desktop notification may be sent for
// each event, and why not.
type substrateNotifyPolicy struct {
	Asks, TaskEnd bool
	// Why is the plain-words reason when no notification is sent at all
	// ("" when something may be).
	Why string
}

// substrateNotifyPolicyNow reads the local notification settings, the
// platform capability and the tool.
func substrateNotifyPolicyNow() substrateNotifyPolicy {
	if cfg == nil || !cfg.Notifications.Enabled {
		return substrateNotifyPolicy{Why: "desktop notifications are off (turn them on with: defenseclaw setup notifications)"}
	}
	capab := notify.DesktopCapability()
	if !capab.Supported {
		return substrateNotifyPolicy{Why: capab.UnsupportedReason}
	}
	if err := notify.DesktopToolCheck(); err != nil {
		return substrateNotifyPolicy{Why: capab.Provider + " is not installed, so desktop notifications are off here (watch still prints each event)"}
	}
	n := cfg.Notifications.Substrate
	if !n.Asks && !n.TaskEnd {
		return substrateNotifyPolicy{Why: "notifications.substrate.asks and task_end are both off"}
	}
	return substrateNotifyPolicy{Asks: n.Asks, TaskEnd: n.TaskEnd}
}

type substrateWatchEvent struct {
	Kind   string // "ask" or "task_end"
	Actor  string // atespace/name
	Detail string // "egress api.stripe.com", "the --task run ended"
	ID     string // ask id
	// NotifyOff is set when the cluster's administrator turned desktop
	// notifications off (substrate.activity.notifications: off).
	NotifyOff bool
}

// substrateWatcher turns polls into events: one per ask id, one per task end.
type substrateWatcher struct {
	list   func(context.Context) ([]api.Actor, error)
	get    func(ctx context.Context, atespace, name string) (api.Actor, error)
	filter string

	seenAsks  map[string]string // ask id -> atespace/name of its agent
	taskEnded map[string]time.Time
	started   bool
}

func newSubstrateWatcher(list func(context.Context) ([]api.Actor, error), get func(context.Context, string, string) (api.Actor, error), filter string) *substrateWatcher {
	return &substrateWatcher{list: list, get: get, filter: strings.TrimSpace(filter), seenAsks: map[string]string{}, taskEnded: map[string]time.Time{}}
}

func (w *substrateWatcher) wants(a api.Actor) bool {
	if a.Deleted {
		return false
	}
	return w.filter == "" || w.filter == a.Name || w.filter == a.Atespace+"/"+a.Name
}

// poll reads the agents once and returns what is new. Asks pending when the
// watch starts are reported once; task ends before the first poll are not.
func (w *substrateWatcher) poll(ctx context.Context) ([]substrateWatchEvent, error) {
	actors, err := w.list(ctx)
	if err != nil {
		return nil, err
	}
	var out []substrateWatchEvent
	pending := map[string]bool{}
	// present: agents the list shows; readable: agents whose activity was read
	// this poll. A seen ask id is forgotten only when its agent was read and
	// the ask is gone, or its agent is gone: a poll that could not read an
	// agent ("-" row, failed get) keeps that agent's ids, so a blip does not
	// raise the same ask again (GAP-1044).
	present, readable := map[string]bool{}, map[string]bool{}
	for _, a := range actors {
		if !w.wants(a) {
			continue
		}
		name := a.Atespace + "/" + a.Name
		present[name] = true
		if a.Activity == nil {
			continue
		}
		act := a.Activity
		off := act.Notify != nil && !*act.Notify
		if act.PendingAsks == 0 {
			readable[name] = true
		} else {
			one, err := w.get(ctx, a.Atespace, a.Name)
			if err == nil && one.Activity != nil {
				readable[name] = true
				for _, k := range one.Activity.Asks {
					pending[k.ID] = true
					if _, seen := w.seenAsks[k.ID]; seen {
						continue
					}
					w.seenAsks[k.ID] = name
					out = append(out, substrateWatchEvent{Kind: "ask", Actor: name, ID: k.ID, NotifyOff: off, Detail: safetext.Line(strings.TrimSpace(k.Kind + " " + k.Target))})
				}
			}
		}
		if t := act.TaskEnded; !t.IsZero() {
			if prev, known := w.taskEnded[name]; (known || w.started) && t.After(prev) {
				out = append(out, substrateWatchEvent{Kind: "task_end", Actor: name, Detail: "the --task run ended", NotifyOff: off})
			}
			w.taskEnded[name] = t
		} else if _, known := w.taskEnded[name]; !known {
			w.taskEnded[name] = time.Time{}
		}
	}
	for id, name := range w.seenAsks {
		if !pending[id] && (readable[name] || !present[name]) {
			delete(w.seenAsks, id) // answered, or its agent is gone: the set does not grow
		}
	}
	w.started = true
	return out, nil
}

// substrateWatchRun polls until ctx ends (or once). It prints every event and
// notifies the ones the policy allows. send is the delivery (notify.SendNotification).
func substrateWatchRun(ctx context.Context, out, errOut io.Writer, wt *substrateWatcher, every time.Duration, once bool,
	policy substrateNotifyPolicy, send func(notify.Notification) error, now func() time.Time) error {
	if policy.Why != "" {
		fmt.Fprintln(errOut, "Note: "+policy.Why+".")
	}
	warned := false
	for {
		events, err := wt.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(errOut, "watch: could not read your agents, trying again: "+safetext.Line(err.Error()))
		}
		for _, ev := range events {
			line := now().UTC().Format("15:04:05") + "Z  " + ev.Actor + "  "
			title := "DefenseClaw: " + ev.Actor
			switch ev.Kind {
			case "ask":
				line += "needs an answer: " + ev.Detail + "  (answer: defenseclaw substrate approvals)"
				title += " needs an answer"
			default:
				line += ev.Detail
				title += " finished its task"
			}
			fmt.Fprintln(out, line)
			allowed := (ev.Kind == "ask" && policy.Asks) || (ev.Kind == "task_end" && policy.TaskEnd)
			if allowed && !ev.NotifyOff {
				if err := send(notify.Notification{Title: title, Body: ev.Detail}); err != nil && !warned {
					warned = true
					fmt.Fprintln(errOut, "Note: a desktop notification could not be sent: "+safetext.Line(err.Error()))
				}
			}
		}
		if once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(every):
		}
	}
}

func newSubstrateWatchCmd() *cobra.Command {
	var (
		com   = &substrateCommon{}
		every time.Duration
		once  bool
	)
	cmd := &cobra.Command{
		Use:   "watch [name]",
		Short: "Say when one of your agents needs an answer or finishes its task",
		Long: `Follows your agents (all of them, or the one you name) and prints a line when one raises an ask
or when a --task run ends. With notifications on (notifications.enabled and notifications.substrate in config.yaml),
it also shows a desktop notification, once per ask. A notification names the kind and the host or tool of an ask,
never its arguments. An administrator can turn notifications off for the cluster (substrate.activity.notifications: off).
Ctrl-C stops it.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if every < substrateWatchMinEvery {
				every = substrateWatchMinEvery
			}
			s, err := substrateOpen(cmd, com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			filter := ""
			if len(args) == 1 {
				a, err := resolveSubstrateActor(ctx, s.Client, args[0])
				if err != nil {
					return substrateFail(err)
				}
				filter = a.Atespace + "/" + a.Name
			}
			wt := newSubstrateWatcher(func(ctx context.Context) ([]api.Actor, error) { return s.Client.List(ctx, api.ListOptions{}) }, s.Client.Get, filter)
			return substrateWatchRun(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), wt, every, once, substrateNotifyPolicyNow(), notify.SendNotification, time.Now)
		},
	}
	com.add(cmd)
	cmd.Flags().DurationVar(&every, "every", substrateWatchDefaultEvery, "how often to look (at least 2s)")
	cmd.Flags().BoolVar(&once, "once", false, "look once, print what is new and stop")
	return cmd
}

// substrateNotifierCheck is the doctor row for the desktop notifier `watch`
// uses: off is a skip, a missing tool is a warning with the way to install it.
func substrateNotifierCheck() substrateCheck {
	const id = "notifier"
	capab := notify.DesktopCapability()
	switch {
	case !capab.Supported:
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "not checked: " + capab.UnsupportedReason}
	case cfg == nil || !cfg.Notifications.Enabled:
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "desktop notifications are off (notifications.enabled is false); substrate watch prints only"}
	}
	if err := notify.DesktopToolCheck(); err != nil {
		fix := "install " + capab.Provider
		if capab.GOOS == "linux" {
			fix = "install notify-send (Debian and Ubuntu: apt install libnotify-bin; RHEL: dnf install libnotify)"
		}
		return substrateCheck{ID: id, Status: doctorWarn, Summary: capab.Provider + " is not installed, so substrate watch cannot show desktop notifications", Fix: fix}
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: "desktop notifications can be shown with " + capab.Provider}
}
