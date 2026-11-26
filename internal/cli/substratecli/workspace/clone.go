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

package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
)

// run --clone (GAP-0175): the repository is cloned inside the actor through
// the relay, so it goes out through the actor's egress rules. A private
// repository works the way every git call in the actor does: the image's
// root-owned credential helper (kit gitConfig) answers with a placeholder,
// and egress swaps it for the person's or the shared token on the hosts the
// token is bound to. Nothing of this computer's git credentials is used.

const cloneTimeout = 15 * time.Minute

// The actor image owns this helper. Tests replace the path with a fixture
// that gives the same placeholder without writing into the actor image.
var cloneImageCredHelper = kit.CredHelper

// cloneCredentialGuard resets every inherited helper, then installs a wrapper
// for this clone operation. In particular, git-lfs asks for credentials for
// object hrefs supplied by a batch server, not just the checked endpoint.
// The wrapper never answers a request over plain http outside loopback.
func cloneCredentialGuard() []string {
	wrapper := `!f() {
input=
protocol=
host=
while IFS= read -r line && [ -n "$line" ]; do
  input="$input$line
"
  case "$line" in
  protocol=*) protocol=${line#protocol=} ;;
  host=*) host=${line#host=} ;;
  esac
done
case "$protocol" in
https) ;;
http)
  case "$host" in
  localhost|localhost:*|'[::1]'|'[::1]':*) ;;
  127.*)
    addr=${host%%:*}
    rest=${addr#127.}
    case "$rest" in *.*.*) ;; *) exit 0 ;; esac
    one=${rest%%.*}
    rest=${rest#*.}
    two=${rest%%.*}
    three=${rest#*.}
    case "$three" in *.*) exit 0 ;; esac
    for octet in "$one" "$two" "$three"; do
      case "$octet" in ''|*[!0-9]*|0?*) exit 0 ;; esac
      [ "$octet" -le 255 ] 2>/dev/null || exit 0
    done
    ;;
  *) exit 0 ;;
  esac
  ;;
*) exit 0 ;;
esac
printf '%s\n\n' "$input" | "` + cloneImageCredHelper + `" "$@"
}; f`
	return []string{"-c", "credential.helper=", "-c", "credential.helper=" + wrapper}
}

// CloneResult is where a clone landed in the actor. Note, when set, says
// why pull will not be able to review the agent's work on it.
type CloneResult struct {
	Dir  string
	Note string
	// Warnings say what the clone could not bring (LFS files left as
	// pointers); the clone itself worked.
	Warnings []string
}

// CloneOptions are the cluster's substrate.git switches for one clone.
type CloneOptions struct {
	// Submodules clones submodules too (substrate.git.submodules).
	Submodules bool
	// LFS fetches LFS files (substrate.git.lfs); off leaves pointers.
	LFS bool
}

var (
	scpLikeRE = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^/][^\x00]*$`)
	refRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
)

// CheckCloneURL refuses an address git would treat as something other than
// a repository on a server: options, local paths, file and ext transports,
// and credentials written into it (the cluster adds those).
func CheckCloneURL(raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "" || strings.HasPrefix(raw, "-") || strings.ContainsAny(raw, "\x00\r\n \t"):
		return errors.New("--clone needs a repository address such as https://git.example.test/team/app.git")
	case scpLikeRE.MatchString(raw):
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("--clone needs a repository address such as https://git.example.test/team/app.git")
	}
	switch u.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return fmt.Errorf("--clone takes an https, ssh or git address, not %s", u.Scheme)
	}
	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass || u.Scheme == "https" || u.Scheme == "http" {
			return errors.New("do not put a user name or token in the --clone address; the cluster adds the credential for hosts it allows")
		}
	}
	return nil
}

// CloneHost is the host git in the actor sends a credential to for raw:
// the https host, or the host of an ssh address the actor's git turns
// into https (the baked rules plus rules, substrate.git.https_rewrite:
// config.RewriteGitURL). It is "" for any other address, which never asks
// for a token.
func CloneHost(raw string, rules []config.SubstrateGitRewrite) string {
	raw = strings.TrimSpace(raw)
	if v, ok := config.RewriteGitURL(raw, rules); ok {
		raw = v
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// CheckCloneRef refuses a --ref git would read as an option.
func CheckCloneRef(ref string) error {
	if ref != "" && !refRE.MatchString(ref) {
		return fmt.Errorf("--ref %q is not a branch, tag or commit name", ref)
	}
	return nil
}

// cloneFolder is the clone's folder name: the repository's.
func cloneFolder(raw string) string {
	p := raw
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		p = u.Path
	} else if _, after, ok := strings.Cut(raw, ":"); ok {
		p = after
	}
	n := strings.TrimSuffix(path.Base(strings.TrimRight(p, "/")), ".git")
	var b strings.Builder
	for _, r := range n {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	if s := strings.Trim(b.String(), "."); s != "" {
		return s
	}
	return "repo"
}

// CloneError is a clone git refused in the actor, in its own words.
// Hint, when set, replaces the general advice for a refused credential
// with what this person can do (B1 2.2: the template that covers the host,
// or the add command an administrator approves).
//
// Refused is a host the agent's network rules do not allow, which the
// launcher learned from the gateway's policy explain after the clone
// failed (GAP-0720): a 403 from the egress guard then means the rules,
// not a missing token, so no credential is offered.
type CloneError struct {
	URL, Message string
	Exit         int
	Hint         string
	Refused      string
}

// NeedsCredential reports whether the host refused the clone for want of
// a credential: no user name, a refused placeholder, 401 or 403. It is
// false when the agent's network rules refused a host (Refused).
func (e *CloneError) NeedsCredential() bool {
	if e.Refused != "" {
		return false
	}
	low := strings.ToLower(e.Message)
	return strings.Contains(low, "could not read username") || strings.Contains(low, "authentication failed") ||
		strings.Contains(low, "terminal prompts disabled") || strings.Contains(low, "403") || strings.Contains(low, "401")
}

func (e *CloneError) Error() string {
	msg := fmt.Sprintf("git could not clone %s in the agent: %s", e.URL, e.Message)
	low := strings.ToLower(e.Message)
	switch {
	case e.Refused != "":
		msg += ". The agent's network rules do not allow " + e.Refused + ": " + reasons.Message(reasons.Must("not_in_allow_only"))
	case e.NeedsCredential() && e.Hint != "":
		msg += ". " + e.Hint
	case e.NeedsCredential():
		msg += ". The repository needs a credential the cluster does not add for this host; ask your administrator to allow it for your profile"
	case strings.Contains(low, "permission denied (publickey)") || strings.Contains(low, "host key verification"):
		msg += ". The agent has no SSH key; use the https:// address, for which the cluster adds the credential, or ask your administrator to add this host to substrate.git.https_rewrite"
	case strings.Contains(low, "no space left on device"):
		msg += ". The agent's disk is full; clone a smaller repository, or ask your administrator for a template with more disk"
	case strings.Contains(low, "could not resolve host") || strings.Contains(low, "connection refused"):
		msg += ". The agent's network rules may not allow this host; ask your administrator"
	case strings.Contains(low, "returned error: 503") || strings.Contains(low, "returned error: 502"):
		msg += ". The cluster's network guard refused the request or could not check it; ask your administrator to look at the DefenseClaw egress log for this agent"
	}
	return msg
}

// Clone clones rawURL (at ref) into the actor's working directory. It then
// reads the clone back once, before the agent runs, and keeps it as a host
// copy baseline on this computer (the same private git directory the host
// copy uses), so the agent starts in the clone, checkpoint and undo find it,
// and pull reviews and brings back what the agent changed on any OS.
func Clone(ctx context.Context, c *Client, dataDir, name, rawURL, ref string, opts CloneOptions) (*CloneResult, error) {
	if err := CheckCloneURL(rawURL); err != nil {
		return nil, err
	}
	if err := CheckCloneRef(ref); err != nil {
		return nil, err
	}
	root, err := c.Root(ctx)
	if err != nil {
		return nil, err
	}
	dir := path.Join(root, cloneFolder(rawURL))
	// A clone never smudges LFS files itself (GIT_LFS_SKIP_SMUDGE): a failed
	// LFS fetch must not fail the clone. With substrate.git.lfs on, git lfs
	// pull follows below and its failure is a warning.
	env := map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true", "GIT_LFS_SKIP_SMUDGE": "1"}
	// call runs one git command in the actor. An exit in okExit (git
	// config's "no such key") is not an error and comes back as "".
	call := func(okExit []int, argv ...string) (string, error) {
		res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: argv, Workdir: root, Env: env, Timeout: cloneTimeout})
		if err != nil {
			return "", err
		}
		if slices.Contains(okExit, res.ExitCode) {
			return "", nil
		}
		if res.ExitCode != 0 {
			msg := lastLine(string(res.Stderr), string(res.Stdout))
			if l := refusedLine(string(res.Stderr)); l != "" {
				msg = l
			}
			return "", &CloneError{URL: rawURL, Message: msg, Exit: res.ExitCode}
		}
		return string(res.Stdout), nil
	}
	run := func(argv ...string) error {
		_, err := call(nil, argv...)
		return err
	}
	// The wrapper lets only HTTPS and loopback HTTP ask the image helper.
	// No prompt, no local or ext transport.
	guard := append([]string{"git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never"}, cloneCredentialGuard()...)
	if err := run(append(slices.Clone(guard), "clone", "--quiet", "--", rawURL, dir)...); err != nil {
		return nil, err
	}
	if ref != "" {
		if err := run(append(slices.Clone(guard), "-C", dir, "-c", "advice.detachedHead=false", "checkout", "--quiet", ref, "--")...); err != nil {
			return nil, err
		}
	}
	if opts.Submodules {
		if err := cloneSubmodules(call, guard, rawURL, dir, 0); err != nil {
			return nil, err
		}
	}
	rec := &hostRecord{Version: hostRecordVersion, Name: name, Folder: path.Base(dir), RemoteDir: dir,
		CloneURL: rawURL, CloneRef: ref, UploadedAt: time.Now().UTC()}
	res := &CloneResult{Dir: dir}
	if opts.LFS {
		res.Warnings = append(res.Warnings, cloneLFSFetch(ctx, c, root, dir, env, opts.Submodules)...)
	}
	if w := cloneLFSWarning(ctx, c, root, dir, env, opts.LFS); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	if err := cloneBaseline(ctx, c, dataDir, rec); err != nil {
		rec.Baseline, rec.Files, rec.Bytes = "", 0, 0
		res.Note = "pull cannot review this agent's work (" + lastLine(strings.TrimPrefix(err.Error(), "workspace: ")) +
			"); push it to its origin as a branch instead with pull --push-branch NAME"
	}
	if err := rec.save(dataDir); err != nil {
		return nil, fmt.Errorf("workspace: record the clone: %w", err)
	}
	return res, nil
}

// refusedLine is git's own "transport 'http' not allowed" line, which a
// submodule clone buries under its "Failed to clone ... aborting" tail.
func refusedLine(stderr string) string {
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "fatal:")); strings.Contains(l, "not allowed") {
			return l + " (a submodule address in .gitmodules; use https)"
		}
	}
	return ""
}

// cloneSubmoduleDepth bounds how deep cloneSubmodules follows submodules
// of submodules (a repository can name itself).
const cloneSubmoduleDepth = 16

// cloneSubmodules checks out dir's submodules one at a time, then theirs.
// Their urls come from the repository's .gitmodules, which the person did
// not write: plain http would send the credential helper's placeholder in
// the clear, so http is off for every submodule whose own url is not on the
// loopback (a test or local mirror), whatever the top-level clone used
// (GAP-0907). The top-level clone may still use http: CheckCloneURL takes it.
func cloneSubmodules(call func([]int, ...string) (string, error), guard []string, rawURL, dir string, depth int) error {
	if depth >= cloneSubmoduleDepth {
		return &CloneError{URL: rawURL, Message: fmt.Sprintf("submodules nest more than %d deep", cloneSubmoduleDepth), Exit: 1}
	}
	git := func(okExit []int, args ...string) (string, error) {
		return call(okExit, append(append(slices.Clone(guard), "-C", dir), args...)...)
	}
	// init fetches nothing: it records each active submodule's url, resolved
	// against this repository's remote, in .git/config.
	if _, err := git(nil, "submodule", "init", "--quiet"); err != nil {
		return err
	}
	urls, err := git([]int{1}, "config", "-z", "--get-regexp", `^submodule\..*\.url$`)
	if err != nil || urls == "" {
		return err
	}
	paths, err := git([]int{1}, "config", "-z", "--file", ".gitmodules", "--get-regexp", `^submodule\..*\.path$`)
	if err != nil {
		return err
	}
	pathOf := configZ(paths, ".path")
	byName := configZ(urls, ".url")
	names := slices.Sorted(maps.Keys(byName))
	for _, n := range names {
		p, ok := pathOf[n]
		if !ok {
			continue
		}
		upd := []string{"submodule", "update", "--quiet", "--init", "--", p}
		if !cloneHTTPLoopback(byName[n]) {
			upd = append([]string{"-c", "protocol.http.allow=never"}, upd...)
		}
		if _, err := git(nil, upd...); err != nil {
			return err
		}
	}
	// Only the submodules that were checked out (an update = none one stays
	// empty, and git there would find this repository again).
	out, err := git(nil, "submodule", "foreach", "--quiet", `printf '%s\0' "$sm_path"`)
	if err != nil {
		return err
	}
	for _, p := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		if p == "" {
			continue
		}
		if err := cloneSubmodules(call, guard, rawURL, path.Join(dir, p), depth+1); err != nil {
			return err
		}
	}
	return nil
}

// configZ reads git config -z --get-regexp output ("submodule.NAME.KEY\n
// VALUE\0" records) into NAME -> VALUE for the keys ending in suffix.
func configZ(out, suffix string) map[string]string {
	m := map[string]string{}
	for _, rec := range strings.Split(out, "\x00") {
		k, v, ok := strings.Cut(rec, "\n")
		if !ok || !strings.HasPrefix(k, "submodule.") || !strings.HasSuffix(k, suffix) {
			continue
		}
		m[strings.TrimSuffix(strings.TrimPrefix(k, "submodule."), suffix)] = v
	}
	return m
}

// cloneHTTPLoopback is true for an http or https address on this
// computer's loopback, the only place plain http may go.
func cloneHTTPLoopback(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return osw.LoopbackURL(u.String())
	}
	return false
}

// cloneLFSEndpointOK is true for an LFS endpoint the credential helper's
// placeholder may go to: https, or http on the loopback.
func cloneLFSEndpointOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") || cloneHTTPLoopback(raw)
}

// cloneLFSList prints "PATH\tN\tENDPOINT" for the clone (".") and, with $2
// = 1, each checked-out submodule: N files the attributes mark for LFS and
// the endpoint git lfs would use there. It prints nothing without git-lfs.
const cloneLFSList = `git lfs version >/dev/null 2>&1 || exit 0
cd "$1" || exit 1
{ echo .; if [ "$2" = 1 ]; then git submodule foreach --quiet --recursive 'echo "$displaypath"'; fi; } | while IFS= read -r p; do
  n=$(cd "$p" 2>/dev/null && git ls-files -- ':(attr:filter=lfs)' | wc -l)
  e=$(cd "$p" 2>/dev/null && git lfs env 2>/dev/null | sed -n 's/^Endpoint=\([^ ]*\).*$/\1/p' | head -n 1)
  printf '%s\t%s\t%s\n' "$p" "${n:-0}" "$e"
done`

// cloneLFSFetch runs git lfs pull in the clone (and its submodules) when
// substrate.git.lfs is on and git-lfs is there. The LFS endpoint comes from
// the repository (its .lfsconfig, or its remote), which the person did not
// write, and the credential helper answers it with the placeholder: an
// endpoint that is not https or on the loopback would get it in the clear.
// Such a repository is left out with a warning, and every pull runs with
// lfs.url set to the endpoint checked here, so .lfsconfig cannot change it
// (GAP-0905). A failed fetch (a media host egress does not allow, a rate
// limit, a missing object) leaves the files as pointers and comes back as a
// warning: the clone worked.
func cloneLFSFetch(ctx context.Context, c *Client, root, dir string, env map[string]string, submodules bool) []string {
	sub := "0"
	if submodules {
		sub = "1"
	}
	pullEnv := maps.Clone(env)
	delete(pullEnv, "GIT_LFS_SKIP_SMUDGE")
	notFetched := func(where, why string) string {
		if where == "." {
			return "LFS files were not fetched (" + why + "); they stay pointers"
		}
		return "LFS files in " + where + " were not fetched (" + why + "); they stay pointers"
	}
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: []string{"sh", "-c", cloneLFSList, "sh", dir, sub}, Workdir: root, Env: env, Timeout: cloneTimeout})
	if err != nil {
		return []string{notFetched(".", lastLine(err.Error()))}
	}
	if res.ExitCode != 0 {
		return []string{notFetched(".", lastLine(string(res.Stderr), string(res.Stdout)))}
	}
	var warns []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		p, rest, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		n, ep, _ := strings.Cut(rest, "\t")
		if strings.TrimSpace(n) == "0" {
			continue
		}
		if !cloneLFSEndpointOK(ep) {
			why := "its repository names no LFS endpoint"
			if u, err := url.Parse(ep); err == nil && u.Host != "" {
				why = "its LFS endpoint " + u.Scheme + "://" + u.Host + " is not https; the credential would go unencrypted"
			}
			warns = append(warns, notFetched(p, why))
			continue
		}
		argv := append([]string{"git"}, cloneCredentialGuard()...)
		argv = append(argv, "-C", path.Join(dir, p), "-c", "lfs.url="+ep, "lfs", "pull")
		pull, err := c.Exec(ctx, "", osw.ExecRequest{Argv: argv, Workdir: root, Env: pullEnv, Timeout: cloneTimeout})
		switch {
		case err != nil:
			warns = append(warns, notFetched(p, lastLine(err.Error())))
		case pull.ExitCode != 0:
			warns = append(warns, notFetched(p, lastLine(string(pull.Stderr), string(pull.Stdout))))
		default:
			// git lfs pull can exit 0 and still leave files as pointers
			// (an object address on plain http outside the loopback gets no
			// credential, and its answer may not check out), so the files
			// are counted after it, never assumed fetched (GAP-0984).
			if n := cloneLFSPointers(ctx, c, root, path.Join(dir, p), env); n > 0 {
				warns = append(warns, notFetched(p, fmt.Sprintf("git lfs pull left %d of them as pointers: an object it could not download or check out, such as a private one at a plain http address, which gets no credential", n)))
			}
		}
	}
	return warns
}

// cloneLFSPointers counts the files in the checkout at dir that git lfs
// lists as pointers ("-"), not checked-out objects ("*"). An error counts
// as none: the pull itself said it worked.
func cloneLFSPointers(ctx context.Context, c *Client, root, dir string, env map[string]string) int {
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: []string{"git", "-C", dir, "lfs", "ls-files"}, Workdir: root, Env: env, Timeout: time.Minute})
	if err != nil || res.ExitCode != 0 {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[1] == "-" {
			n++
		}
	}
	return n
}

// cloneLFSWarning says when files the clone's attributes mark for LFS
// stayed pointers: the template has no git-lfs, or substrate.git.lfs is
// off. It is "" when there are none, or git-lfs fetched them.
func cloneLFSWarning(ctx context.Context, c *Client, root, dir string, env map[string]string, lfsOn bool) string {
	const script = `n=$(git -C "$1" ls-files -- ':(attr:filter=lfs)' | wc -l); if git lfs version >/dev/null 2>&1; then echo "$n lfs"; else echo "$n none"; fi`
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: []string{"sh", "-c", script, "sh", dir}, Workdir: root, Env: env, Timeout: time.Minute})
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	var n int
	var tool string
	if _, err := fmt.Sscan(string(res.Stdout), &n, &tool); err != nil || n == 0 {
		return ""
	}
	files := fmt.Sprintf("%d LFS files are pointers", n)
	if n == 1 {
		files = "1 LFS file is a pointer"
	}
	switch {
	case tool != "lfs":
		return "this template has no git-lfs; " + files
	case !lfsOn:
		return "LFS is off on this cluster (substrate.git.lfs); " + files
	}
	return ""
}

// gitRewriteScript writes the https rewrite pairs ($1 from, $2 to, ...)
// into the actor user's git config: a file of its own, included once from
// ~/.config/git/config, so a second start replaces it in place. The pairs
// are argv, never shell text.
const gitRewriteScript = `set -e
d="${XDG_CONFIG_HOME:-$HOME/.config}/git"
f="$d/defenseclaw-rewrite"
mkdir -p "$d"
: > "$f.tmp"
while [ "$#" -ge 2 ]; do git config --file "$f.tmp" --add "url.$2.insteadOf" "$1"; shift 2; done
mv -f "$f.tmp" "$f"
git config --file "$d/config" --get-all include.path 2>/dev/null | grep -qxF defenseclaw-rewrite || git config --file "$d/config" --add include.path defenseclaw-rewrite`

// WriteGitRewrite puts substrate.git.https_rewrite into the actor's git
// config at start (B2 2.5), before any upload or clone, so the agent's own
// git calls turn the same ssh addresses into https. It is a convenience,
// not a control: egress decides what the agent reaches. A pair that fails
// CheckSubstrateGitRewrite is left out.
func WriteGitRewrite(ctx context.Context, c *Client, rules []config.SubstrateGitRewrite) error {
	argv := []string{"sh", "-c", gitRewriteScript, "sh"}
	for _, r := range rules {
		if config.CheckSubstrateGitRewrite(r) == nil {
			argv = append(argv, r.From, r.To)
		}
	}
	root, err := c.Root(ctx)
	if err != nil {
		return err
	}
	res, err := c.Exec(ctx, "", osw.ExecRequest{Argv: argv, Workdir: root, Timeout: time.Minute})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(lastLine(string(res.Stderr), string(res.Stdout)))
	}
	return nil
}

// cloneBaseline reads the fresh clone back (the host copy's own reader:
// regular files only, no .git, no package caches, secret files held back)
// and commits it as the record's baseline in a new private git directory.
func cloneBaseline(ctx context.Context, c *Client, dataDir string, rec *hostRecord) error {
	gitDir := hostGitDir(dataDir, rec.Name)
	_ = os.RemoveAll(gitDir)
	if err := os.MkdirAll(hostDir(dataDir), 0o700); err != nil {
		return err
	}
	if _, err := hostGit(ctx, hostDir(dataDir), nil, nil, "init", "-q", "--bare", gitDir); err != nil {
		return err
	}
	stage := filepath.Join(hostDir(dataDir), rec.Name+".base")
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	files, _, _, err := c.downloadHostTree(ctx, rec, stage)
	if err != nil {
		return err
	}
	base, err := hostCommit(ctx, gitDir, stage, files, "")
	if err != nil {
		return err
	}
	rec.Baseline, rec.Files = base, len(files)
	for _, f := range files {
		rec.Bytes += f.size
	}
	return nil
}

// cloneIgnored drops the files the clone's own ignore rules exclude (build
// output the agent made) unless the baseline has them: a file the clone
// came with is always compared, so an ignore rule cannot hide its change.
func cloneIgnored(ctx context.Context, gitDir, stage, base string, files []hostFile) []hostFile {
	env := []string{"GIT_DIR=" + gitDir}
	out, err := hostGit(ctx, stage, env, nil, "ls-tree", "-r", "-z", "--name-only", base)
	if err != nil {
		return files
	}
	known := map[string]bool{}
	for _, p := range splitNUL(out) {
		known[p] = true
	}
	var in bytes.Buffer
	for _, f := range files {
		if !known[f.rel] {
			in.WriteString(f.rel)
			in.WriteByte(0)
		}
	}
	if in.Len() == 0 {
		return files
	}
	out, _ = hostGit(ctx, stage, append(env, "GIT_WORK_TREE="+stage), in.Bytes(), "check-ignore", "-z", "--stdin", "--no-index")
	ignored := map[string]bool{}
	for _, p := range splitNUL(out) {
		ignored[p] = true
	}
	kept := files[:0]
	for _, f := range files {
		if !ignored[f.rel] {
			kept = append(kept, f)
		}
	}
	return kept
}

func lastLine(v ...string) string {
	for _, s := range v {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		lines := strings.Split(s, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), "fatal:")); l != "" {
				return l
			}
		}
	}
	return "it printed no error"
}
