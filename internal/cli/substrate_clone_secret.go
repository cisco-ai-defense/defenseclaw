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
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// Ask at the moment of need (B1 2.2, D1-10): when git in the agent is
// refused for want of a token on a host one of the person's templates
// covers, run --clone offers to add the person's own secret right there,
// waits until the agent's network rules carry it and retries the clone
// once. Only on a terminal and only for a person's own run: --task,
// --batch and --json runs get the command to run instead. The offer comes
// from the launcher (the clone address the person typed), never from the
// agent, so an agent cannot forge a prompt for a host of its choosing.
var (
	substrateCloneCanAsk    = substrateInteractive
	substrateCloneConfirm   = substrateConfirm
	substrateCloneReadValue = func(cmd *cobra.Command) (string, error) {
		v, _, err := (&substrateSecretSource{}).read(cmd)
		return v, err
	}
	substrateClonePolicyWait = 30 * time.Second
	substrateClonePolicyPoll = 2 * time.Second
)

// substrateCloneOnce runs clone and, when the host refused it for want of
// a token and the person added one (substrateCloneNeed), runs it once more.
func substrateCloneOnce(ctx context.Context, cmd *cobra.Command, cl *api.Client, a api.Actor, f *substrateRunFlags,
	clone func() (*workspace.CloneResult, error)) (*workspace.CloneResult, error) {
	res, err := clone()
	var ce *workspace.CloneError
	if !errors.As(err, &ce) {
		return res, err
	}
	if ce.Refused = substrateCloneRefused(ctx, cl, a, ce, substrateGitRules(f)); !ce.NeedsCredential() || !substrateCloneNeed(ctx, cmd, cl, a, f, ce) {
		return res, err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Cloning %s in the agent again...\n", safetext.Line(f.clone))
	hint := ce.Hint
	res, err = clone()
	if errors.As(err, &ce) {
		if ce.Refused = substrateCloneRefused(ctx, cl, a, ce, substrateGitRules(f)); ce.NeedsCredential() {
			ce.Hint = hint
		}
	}
	return res, err
}

// substrateCloneURLHostRE finds the https hosts git names in its error
// (the repository, an LFS object host, a submodule).
var substrateCloneURLHostRE = regexp.MustCompile(`https?://(?:[^@/\s'"]+@)?([A-Za-z0-9.-]+)`)

// substrateCloneNetworkErrRE matches the git errors network rules can
// cause: a refused CONNECT or token (403, 401), a host the agent cannot
// resolve or connect to.
var substrateCloneNetworkErrRE = regexp.MustCompile(`(?i)\b40[13]\b|could not resolve|connection refused|failed to connect|\bCONNECT\b`)

// substrateCloneRefused is the first host of a failed clone that the
// agent's network rules do not allow, or "" (GAP-0720). It asks the
// gateway's policy explain, which reads the policy in force: the egress
// guard answers a refused CONNECT with 403, which git reports like a
// refused token, and the decisions log does not record egress refusals.
// Each ask is an audit row, so other errors (a missing branch) ask nothing.
func substrateCloneRefused(ctx context.Context, cl *api.Client, a api.Actor, ce *workspace.CloneError, rules []config.SubstrateGitRewrite) string {
	if !substrateCloneNetworkErrRE.MatchString(ce.Message) {
		return ""
	}
	var hosts []string
	if h := workspace.CloneHost(ce.URL, rules); h != "" {
		hosts = append(hosts, h)
	}
	for _, m := range substrateCloneURLHostRE.FindAllStringSubmatch(ce.Message, 4) {
		if h := strings.ToLower(strings.TrimSuffix(m[1], ".")); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	for _, h := range hosts {
		if allowed, known := cl.HostAllowed(ctx, a.Atespace+"/"+a.Name, h); known && !allowed {
			return h
		}
	}
	return ""
}

// substrateCloneNeed decides what a refused clone offers. retry is true
// once a new secret of the person's is in the agent's policy (or the wait
// ran out after it was stored); otherwise ce.Hint says what to do.
func substrateCloneNeed(ctx context.Context, cmd *cobra.Command, cl *api.Client, a api.Actor, f *substrateRunFlags, ce *workspace.CloneError) (retry bool) {
	host := workspace.CloneHost(f.clone, substrateGitRules(f))
	if host == "" {
		return false
	}
	asJSON, _ := f.out.wantJSON()
	ask := f.task == "" && f.batch == "" && !asJSON && substrateCloneCanAsk()
	if own, ok := substrateCloneOwnSecret(ctx, cl, host); ok {
		ce.Hint = substrateCloneOwnHint(own, host)
		return false
	}
	list, mode, err := cl.SecretTemplates(ctx)
	if err != nil || mode != "bindings" {
		// values_only, off or an older gateway: only an administrator can
		// add a credential for this host, which the general advice says.
		return false
	}
	t, ok := substrateCloneTemplate(list, host)
	if !ok {
		ce.Hint = fmt.Sprintf("%s needs a token: defenseclaw substrate secrets add NAME --template generic-bearer --host %s (an administrator will be asked)", host, host)
		return false
	}
	name := substrateCloneSecretName(t.Name, host)
	addCmd := fmt.Sprintf("defenseclaw substrate secrets add %s --template %s --host %s", name, t.Name, host)
	ce.Hint = fmt.Sprintf("%s needs a token. The %s template covers it: %s", host, t.Name, addCmd)
	if !ask {
		return false
	}
	w := cmd.ErrOrStderr()
	yes, err := substrateCloneConfirm(cmd, fmt.Sprintf("%s needs a token. The %s template covers it. Set it now?", host, t.Name))
	if err != nil || !yes {
		return false
	}
	value, err := substrateCloneReadValue(cmd)
	if err != nil {
		fmt.Fprintf(w, "No secret added: %v.\n", err)
		return false
	}
	res, err := cl.AddSecret(ctx, api.AddSecretRequest{Name: name, Template: t.Name, Host: host, Value: value})
	if err != nil {
		fmt.Fprintf(w, "No secret added: %v.\n", substrateFail(err))
		return false
	}
	if res.Reason != "" {
		ce.Hint = fmt.Sprintf("your new secret %s for %s waits on an administrator; clone again once it is approved (see it with: defenseclaw substrate approvals)", res.Name, host)
		return false
	}
	fmt.Fprintf(w, "Stored %s for %s (template %s). Waiting for the agent's network rules to carry it...\n", res.Name, host, t.Name)
	ce.Hint = fmt.Sprintf("%s refused your new secret %s too; store the right token with: defenseclaw substrate secrets set %s", host, res.Name, res.Name)
	if !substrateCloneWaitPolicy(ctx, cl, res.Name, a.Atespace+"/"+a.Name) {
		fmt.Fprintf(w, "The agent's network rules do not show %s yet; trying once anyway.\n", res.Name)
	}
	return true
}

// substrateCloneOwnSecret is a usable or waiting secret of the person's
// that already covers host: then the token is wrong or not approved yet,
// and adding another one does not help.
func substrateCloneOwnSecret(ctx context.Context, cl *api.Client, host string) (api.Secret, bool) {
	mine, err := cl.Secrets(ctx, true)
	if err != nil {
		return api.Secret{}, false
	}
	for _, s := range mine {
		if s.Kind == "template" && (secretbind.Template{Hosts: s.Hosts}).Covers(host) {
			return s, true
		}
	}
	return api.Secret{}, false
}

func substrateCloneOwnHint(s api.Secret, host string) string {
	switch {
	case s.Status == "set":
		return fmt.Sprintf("%s refused your secret %s; store the right token with: defenseclaw substrate secrets set %s", host, s.Name, s.Name)
	case substrateSecretReason(s.Reason) != "":
		return fmt.Sprintf("your secret %s for %s is %s: %s See: defenseclaw substrate secrets test %s", s.Name, host, s.Status, substrateSecretReason(s.Reason), s.Name)
	}
	return fmt.Sprintf("your secret %s for %s is %s; see: defenseclaw substrate secrets test %s", s.Name, host, s.Status, s.Name)
}

// substrateCloneTemplate is the first template that covers host and needs
// nothing but the token (generic-basic needs a user name: secrets add).
func substrateCloneTemplate(list []api.SecretTemplate, host string) (api.SecretTemplate, bool) {
	for _, t := range list {
		if t.Form == secretbind.FormBasic && t.BasicUser == "" {
			continue
		}
		if (secretbind.Template{Hosts: t.Hosts}).Covers(host) {
			return t, true
		}
	}
	return api.SecretTemplate{}, false
}

// substrateCloneSecretName is the name run --clone gives the new secret:
// the template and the host, in the shape of substrateBindingNameRE.
func substrateCloneSecretName(template, host string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(template + "-" + host) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	n := b.String()
	if len(n) > 63 {
		n = n[:63]
	}
	return strings.TrimRight(n, "-")
}

// substrateCloneWaitPolicy polls secrets test --agent until the agent's
// policy carries name, at most substrateClonePolicyWait.
func substrateCloneWaitPolicy(ctx context.Context, cl *api.Client, name, agent string) bool {
	deadline := time.Now().Add(substrateClonePolicyWait)
	for {
		res, err := cl.TestSecret(ctx, name, agent)
		if err == nil && res.Agent != nil && res.Agent.InPolicy != nil && *res.Agent.InPolicy {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(substrateClonePolicyPoll):
		}
	}
}
