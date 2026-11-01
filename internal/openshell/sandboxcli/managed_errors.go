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

package sandboxcli

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Refusals on a managed computer (plan §7.1). The daemon passes the managed
// gateway's refusal on as its sentence and the bare reason code
// (sandbox_not_allowed), and its own policy refusals with the openshell.admin
// key that refused them; the per-user wording of those printed both, with
// the next steps of an unmanaged install. ManagedError words them for the
// user: the organization's sentence with the caller's own profile and the
// request-access contact, an egress refusal in the access-refused form with
// what to quote, a notice as its one sentence, never a bare code or a
// configuration key (GAP-0483, GAP-0486, GAP-0493).

// managedFactsTimeout bounds the status call that fetches the caller's
// profile and contact for a refusal when no status was read before it.
const managedFactsTimeout = 5 * time.Second

// ManagedError words err for a user on a managed computer; any other error,
// and every error on any other computer, is returned as it is. An exit
// status err carries is kept.
func (a *App) ManagedError(ctx context.Context, err error) error {
	var silent *Silent
	if err == nil || errors.As(err, &silent) {
		return err
	}
	if !(a.ManagedHost()) && !(onManagedHost()) {
		return withoutReasonCode(err)
	}
	var e *sandboxapi.Error
	if !errors.As(err, &e) {
		return err
	}
	if hint := shellDockerHostHint(os.LookupEnv); hint != "" && e.Detail == "docker_unavailable" {
		// The daemon's Docker is not the one the shell's DOCKER_HOST names
		// (GAP-0613): say so, or the person starts a Docker that runs.
		text := strings.TrimRight(e.Message, "\n") + "\n" + hint
		var exit *ExitError
		if errors.As(err, &exit) {
			return &ExitError{Code: exit.Code, Err: &refusalError{text: text, err: e}}
		}
		return &refusalError{text: text, err: e}
	}
	text, ok := managedErrorText(e, a.managedFacts(ctx))
	if !ok {
		return withoutReasonCode(err)
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return &ExitError{Code: exit.Code, Err: &refusalError{text: text, err: e}}
	}
	return &refusalError{text: text, err: e}
}

// withoutReasonCode is err without the bare reason code a daemon error
// carries as its detail ("...stop them and run this again: driver_mismatch"):
// the message already says what happened and what to do, and the code is
// for programs, which read it from the detail (GAP-0607). An exit status
// err carries is kept; any other error is returned as it is.
func withoutReasonCode(err error) error {
	var e *sandboxapi.Error
	if !errors.As(err, &e) || strings.TrimSpace(e.Message) == "" || !reasonCode(strings.TrimSpace(e.Detail)) {
		return err
	}
	text := strings.Replace(err.Error(), e.Error(), strings.TrimSpace(e.Message), 1)
	var exit *ExitError
	if errors.As(err, &exit) {
		return &ExitError{Code: exit.Code, Err: &refusalError{text: text, err: e}}
	}
	return &refusalError{text: text, err: e}
}

// shellDockerHostHint is what to do when the caller's shell sets DOCKER_HOST
// ("" when it does not): the sandbox daemon is a per-user service that does
// not run in that shell, so it, and the OpenShell gateway it starts, use the
// account's current Docker context. With an engine named only by
// DOCKER_HOST (Colima started without its context, say) the shell's docker
// answers while the daemon's does not (GAP-0613).
func shellDockerHostHint(lookupEnv func(string) (string, bool)) string {
	if v, ok := lookupEnv("DOCKER_HOST"); !ok || strings.TrimSpace(v) == "" {
		return ""
	}
	return "Your shell sets DOCKER_HOST, but sandboxes do not use your shell's environment: they use your current Docker context. " +
		"Make that engine your current context: `docker context create my-engine --docker host=\"$DOCKER_HOST\"`, then `docker context use my-engine`."
}

// accountOutage is err as one readable message when err says the account
// cannot be looked up (ssh, which the OpenShell CLI runs for the upload,
// found no user for it: the directory is not answering), and err otherwise.
// A person cannot act on the ssh configuration advice the raw error gave
// (GAP-0595).
func (a *App) accountOutage(ctx context.Context, err error) error {
	var lookup *openshell.AccountLookupError
	if err == nil || (!(errors.As(err, &lookup)) && !(strings.Contains(err.Error(), "ssh found no user for it"))) {
		return err
	}
	if (!(a.ManagedHost()) && !(onManagedHost())) && a.managedSeen == nil {
		return errors.New("your account can't be looked up on this computer right now (ssh found no user for it); try again in a moment")
	}
	return errors.New(sandboxapi.AccountUnknownText + " " + accountOutageNote + " " + accountOutageContact(a.managedFacts(ctx).RequestAccess))
}

// accountOutageNote is why a managed run stops while the computer can't look
// the account up, although `sandbox policy explain` shows the organization's
// default policy (provisional) for it: OpenShell reaches every sandbox over
// ssh as the account, and ssh refuses an account the computer does not know
// (SSSD stopped, or no cached entry). The refusal is not the policy, so it
// does not ask for a policy exception (GAP-0505).
const accountOutageNote = "Until it can, a new sandbox can't start and `sandbox connect` and `sandbox exec` can't reach a running one; " +
	"agents already running keep working. This isn't your organization's sandbox policy."

// accountOutageContact is the closing sentence of the account outage refusal:
// whom to tell when it lasts.
func accountOutageContact(contact string) string {
	text := sandboxapi.RequestAccessText(contact)
	if text == sandboxapi.RequestAccessFallback {
		return "If it lasts, " + text + "."
	}
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	return "If it lasts, tell IT: " + text
}

// accountRechecks and accountRecheckEvery are how long a managed run waits
// for the computer to look the account up before it refuses: 10 seconds, as
// long as a create waits for a cold group lookup. An SSSD that restarts, or
// whose cache comes back, then starts the run instead of refusing it
// (GAP-0507).
const (
	accountRechecks     = 5
	accountRecheckEvery = 2 * time.Second
)

// checkAccount stops a managed run at its start when the account cannot be
// looked up, before the project is copied. It asks again for up to 10
// seconds first, and refuses (fails closed) if the computer still names no
// account: ssh, over which OpenShell reaches every sandbox, cannot run for
// it.
func (a *App) checkAccount(ctx context.Context) error {
	if a.AccountCheck == nil {
		return nil
	}
	err := a.AccountCheck()
	var lookup *openshell.AccountLookupError
	if errors.As(err, &lookup) {
		a.note("This computer can't look your account up right now; waiting up to 10 seconds for it.")
		for i := 0; i < accountRechecks && errors.As(err, &lookup); i++ {
			if a.Sleep == nil || a.Sleep(ctx, accountRecheckEvery) != nil {
				break
			}
			err = a.AccountCheck()
		}
	}
	return a.accountOutage(ctx, err)
}

// managedFlagRefusal refuses, before the project is copied or anything is
// created, a run flag the caller's profile does not allow on a managed
// computer: --context (a read-only mount; sandboxes there work on a copy
// only) and --host-port while the profile opens no port on this computer.
// The text names the caller's profile and the rule, like every managed
// refusal; the run used to start with a warning naming the organization's
// configuration key instead (GAP-0558, GAP-0580, GAP-0628).
func (a *App) managedFlagRefusal(ex *sandboxapi.Explain, st *sandboxapi.Status, o RunOptions) error {
	var fromStatus *sandboxapi.ManagedStatus
	if st != nil {
		fromStatus = st.Managed
	}
	m := firstManaged(managedStatusOfExplain(ex.Managed), fromStatus)
	if m == nil {
		return nil
	}
	if len(o.Context) > 0 {
		return errors.New(sandboxapi.ManagedRefusal("--context mounts a folder into the sandbox, and sandboxes on this computer work on a copy of the project only",
			m.Profile, "rule allow_mount", m.RequestAccess))
	}
	if len(o.HostPorts) == 0 {
		return nil
	}
	ports := make([]string, 0, len(o.HostPorts))
	for _, p := range o.HostPorts {
		ports = append(ports, strconv.Itoa(p))
	}
	flag := "--host-port " + strings.Join(ports, ", ")
	switch {
	case ex.Managed != nil && !ex.Managed.AllowHostPorts:
		return errors.New(sandboxapi.ManagedRefusal(flag+" isn't allowed: your profile doesn't let sandboxes reach ports on this computer",
			m.Profile, "rule allow_host_ports", m.RequestAccess))
	case settingValue(ex.Settings, "mcp.host_port_access") == "false":
		return errors.New(sandboxapi.ManagedRefusal(flag+" isn't allowed: the sandbox pack your profile requires opens no port on this computer",
			m.Profile, "rule host_ports", m.RequestAccess))
	}
	return nil
}

// managedFacts is the managed part of the daemon's status: the one a
// command read already, else a fresh one; empty when the daemon does not
// answer (the refusal then names the fallback contact).
func (a *App) managedFacts(ctx context.Context) *sandboxapi.ManagedStatus {
	if a.managedSeen != nil {
		return a.managedSeen
	}
	if api, err := a.api(); err == nil {
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), managedFactsTimeout)
		defer cancel()
		if st, err := api.Status(ctx); err == nil && st.Managed != nil {
			a.managedSeen = st.Managed
			return st.Managed
		}
	}
	return &sandboxapi.ManagedStatus{}
}

// noteManaged keeps the managed part of a status the command read.
func (a *App) noteManaged(st *sandboxapi.Status) {
	if st != nil && st.Managed != nil {
		a.managedSeen = st.Managed
	}
}

// managedAccessRules are the openshell.admin rules an egress refusal names
// in the access-refused form (sandboxapi.AccessRefused).
var managedAccessRules = map[string]bool{
	"egress_allow_only": true, "egress_block": true, "allow_unblock": true, "user_approvals": true,
}

// managedNotices are the reason codes of a refusal that is a notice: its
// sentence says all (Q2's other account, the settings drift), with no
// contact.
var managedNotices = map[string]bool{
	"sandbox_account_busy":              true,
	sandboxrelay.EventSettingsDrift:     true,
	sandboxrelay.ReasonPolicyUnloadable: true,
	sandboxrelay.DetailSetupChanging:    true,
}

// managedReasonTexts word the reason codes a refusal may carry without a
// sentence of its own.
var managedReasonTexts = map[string]string{
	"enterprise_managed_uid_unregistered":  "this agent isn't set up for your account on this computer",
	"enterprise_managed_connector_unknown": "this agent isn't set up for your account on this computer",
	sandboxrelay.ReasonNotAllowed:          "your organization doesn't allow this sandbox",
	sandboxrelay.ReasonUnavailable:         "sandboxes aren't available for your account on this computer",
}

// adminKeyNote is an openshell.admin key a policy text names in
// parentheses: the managed user has no such file.
var adminKeyNote = lazyregexp.New(`\s*\(openshell\.admin\.[a-z_]+\)`)

// managedErrorText is e as a user on a managed computer reads it, and
// whether it is a refusal ManagedError words; m is the caller's own
// profile and contact.
func managedErrorText(e *sandboxapi.Error, m *sandboxapi.ManagedStatus) (string, bool) {
	if (e.Code == sandboxapi.CodeUpstream || e.Code == sandboxapi.CodeUnavailable) &&
		gatewayTransportText(e.Detail) != e.Detail {
		return "the connection to the OpenShell gateway closed; `defenseclaw sandbox doctor` checks it, then retry the command", true
	}
	if sandboxapi.IsPolicyRefusal(e.Message) {
		// A refusal the daemon passed on complete (sandboxapi.AccessRefusedWhy
		// and the other policy refusals) keeps its words: it already names
		// the profile and the contact (GAP-0508).
		return e.Message, true
	}
	profile, access := m.Profile, m.RequestAccess
	if v := e.Violation; v != nil && (v.Admin || e.Code == sandboxapi.CodeAdminViolation) {
		rule := strings.TrimPrefix(v.Constraint, "openshell.admin.")
		if managedAccessRules[rule] && v.Attempted != "" && !strings.HasPrefix(v.Attempted, "(") {
			return sandboxapi.AccessRefused(rule, v.Attempted, profile, "", access), true
		}
		why := firstNonEmpty(v.Detail, v.Message, e.Detail)
		if v.Key == "harness" || v.Key == "harness.allowed" {
			why = harnessCommands(why)
		}
		quote := ""
		if rule != v.Constraint && rule != "" {
			quote = "rule " + rule
		}
		return sandboxapi.ManagedRefusal(adminKeyNote.ReplaceAllString(why, ""), profile, quote, access), true
	}
	sentence, code := managedSentence(e)
	if sentence != "" && (code == sandboxrelay.ReasonDaemonOutdated || code == sandboxrelay.DetailSetupChanging) {
		return sentence, true
	}
	switch e.Code {
	case sandboxapi.CodeAdminViolation:
		quote := ""
		if text, ok := managedReasonTexts[code]; ok && sentence == "" {
			sentence = text
		}
		if code != "" && !managedNotices[code] && strings.TrimSpace(e.Message) == sandboxapi.AdminMessage {
			// The code is all the daemon said: IT needs it quoted.
			quote = "reason " + code
		}
		return sandboxapi.ManagedRefusal(adminKeyNote.ReplaceAllString(sentence, ""), profile, quote, access), true
	case sandboxapi.CodeUnavailable:
		if daemonUnreachable(e) || (code == "" && strings.TrimSpace(e.Message) != sandboxapi.AdminMessage) {
			// Nothing raw to drop: the daemon's own words stand.
			return "", false
		}
		switch {
		case code == sandboxrelay.ReasonPolicyUnloadable:
			return sandboxapi.PolicyUnloadable(), true
		case managedNotices[code] && sentence != "":
			return sentence, true
		case strings.Contains(e.Message, "\nNeed an exception? "):
			return sandboxapi.ManagedRefusal(e.Message, profile, "", access), true
		}
		why := strings.TrimRight(sentence, ". ")
		if why == "" {
			why = strings.TrimRight(sandboxapi.UnavailableSentence(""), ". ")
		}
		text := why + ". " + sandboxapi.AccessContact(access)
		if code != "" && sentence == "" {
			text += " (quote reason " + code + ")"
		}
		return text, true
	}
	return "", false
}

// managedSentence is e's words without AdminMessage and without the bare
// reason code the managed gateway's refusals carry as their detail
// ("sandbox_not_allowed", "openshell_prerequisite_missing: docker is not
// installed"), and that code. What a detail says beyond its code is added
// in parentheses; a message with its own contact line keeps none of it.
func managedSentence(e *sandboxapi.Error) (sentence, code string) {
	msg := strings.TrimSpace(e.Message)
	if len(msg) >= len(sandboxapi.AdminMessage) && strings.EqualFold(msg[:len(sandboxapi.AdminMessage)], sandboxapi.AdminMessage) {
		msg = strings.TrimSpace(strings.TrimPrefix(msg[len(sandboxapi.AdminMessage):], ":"))
	}
	detail := strings.TrimSpace(e.Detail)
	if reasonCode(detail) {
		code, detail = detail, ""
	} else if head, rest, ok := strings.Cut(detail, ": "); ok && reasonCode(head) {
		code, detail = head, strings.TrimSpace(rest)
	}
	switch {
	case detail == "" || strings.Contains(msg, "\nNeed an exception? ") || code == sandboxrelay.ReasonPolicyUnloadable:
		return msg, code
	case msg == "":
		return detail, code
	}
	return strings.TrimRight(msg, ". ") + " (" + strings.TrimRight(detail, ". ") + ")", code
}

// gatewayTransportErrors are the words of the OpenShell gateway's gRPC
// transport failures as its client library prints them.
var gatewayTransportErrors = []string{
	"client connection is closing", "transport is closing", "code = unavailable", "connection error: desc",
	"error reading from server", "grpc: ",
	"h2 protocol error: error reading a body from connection", "peer closed connection without sending tls close_notify",
}

// gatewayUnreachableErrors are the words of the OpenShell CLI's failure to
// reach a gateway that does not listen ("× transport error ├─▶ tcp connect
// error ... Connection refused").
var gatewayUnreachableErrors = []string{"tcp connect error", "transport error", "connection refused"}

// gatewayTransportText is why with a raw gRPC transport failure of the
// OpenShell gateway ("Cancelled: grpc: the client connection is closing")
// put in words: such text named nothing the user could act on, and the
// message around it gives the recovery step (#1202). Any other why is
// returned unchanged.
func gatewayTransportText(why string) string {
	lower := strings.ToLower(why)
	for _, raw := range gatewayUnreachableErrors {
		if strings.Contains(lower, raw) {
			return "the OpenShell gateway does not answer"
		}
	}
	for _, raw := range gatewayTransportErrors {
		if strings.Contains(lower, raw) {
			return "the connection to the OpenShell gateway closed"
		}
	}
	return why
}

// reasonCode reports a bare snake_case reason code ("sandbox_not_allowed"):
// lowercase letters, digits and at least one underscore, at most 64 bytes.
func reasonCode(s string) bool {
	if len(s) < 3 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' || !strings.Contains(s, "_") {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}
