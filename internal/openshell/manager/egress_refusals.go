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

package manager

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The egress proxy refuses a sandbox's HTTPS destination by answering its
// CONNECT with a 403, and clients show only that the tunnel failed ("curl:
// (56) CONNECT tunnel failed, response 403"): the body that says why, and
// how the user can unblock it, never reaches the agent (#954). So the
// manager keeps each sandbox binding's recent CONNECT refusals, and the
// gateway, answering a post-tool hook of a shell or fetch tool call from
// that binding, takes the ones its agent has not been told of
// (Manager.EgressRefusals) and adds them to the hook's context. An upload
// the large-upload block cut on a tunnel it had let through ends the same
// way ("curl: (56) Failure when receiving data from the peer"), and is
// kept with them.

const (
	// egressRefusalWindow is how long a refusal waits for a post-tool
	// hook: one arriving later is not the refused call's.
	egressRefusalWindow = 2 * time.Minute
	// maxRefusedHosts bounds the refusals kept per binding (the latest
	// ones), and maxRefusalBindings the bindings kept.
	maxRefusedHosts    = 8
	maxRefusalBindings = 256
)

// EgressRefusal is a destination a sandbox's egress proxy refused, as its
// agent is told of it.
type EgressRefusal struct {
	Host string
	Port int
	// Category is the proxy's reason code (webhook_catcher, admin_block, ...).
	Category string
	// What says briefly what the destination is, or why it is refused.
	What string
	// Remedy says who can allow it, and how: the unblock command for this
	// sandbox when an unblock lifts the refusal.
	Remedy string
	// Cut marks an upload the large-upload block cut (category
	// large_upload) on a tunnel it had let through, after Sent bytes went
	// up; later refusals of the host within the window are told with it.
	Cut  bool
	Sent int64
	// Note marks what is no egress block of DefenseClaw's but is told the
	// same way: NoteSSH, NoteAsked, NoteDeclined ("" for a block).
	Note string
}

// What an EgressRefusal tells besides a block: OpenShell refused SSH, whose
// remedy is HTTPS (GAP-0216); a connection waits for the user to answer an
// ask (GAP-0268); the user declined the ask (GAP-0236); a port on the
// user's machine is closed because the run did not declare it, or because
// the sandbox policy opens none (GAP-0326).
const (
	NoteSSH         = "ssh"
	NoteAsked       = "asked"
	NoteDeclined    = "declined"
	NotePortClosed  = "port_closed"
	NotePortRefused = "port_refused"
	// NoteAccessRefused: the organization's floor refused a connection the
	// user can't approve (a host port under user_approvals: none); Remedy
	// carries the request-access contact and the Quote line (GAP-0468).
	NoteAccessRefused = "access_refused"
)

// refusalMemory is the recent CONNECT refusals of every sandbox binding.
type refusalMemory struct {
	mu        sync.Mutex
	byBinding map[string]*bindingRefusals
}

// bindingRefusals is one binding's refusals, oldest first.
type bindingRefusals struct {
	sandbox string
	last    time.Time
	hosts   []refusedHost
}

type refusedHost struct {
	host        string
	port        int
	category    egress.Category
	source      egress.Source
	unblockable bool
	at          time.Time
	// told marks a refusal the agent was told of: a repeat within the
	// window is not told again.
	told bool
	// cut marks an upload the large-upload block cut after sent bytes
	// (EgressRefusal.Cut).
	cut  bool
	sent int64
	// note is EgressRefusal.Note (noteDirect), and refusal the managed
	// refusal a NoteAccessRefused tells (noteRefused).
	note    string
	refusal string
}

func newRefusalMemory() *refusalMemory {
	return &refusalMemory{byBinding: map[string]*bindingRefusals{}}
}

// note keeps a blocked CONNECT event of a sandbox binding, or the cut of
// an upload on a CONNECT tunnel by the large-upload block. A refusal the
// client got a readable 403 body for (a plain-HTTP request, a cut one
// included), a rate limit and an invalid target are not kept: the first
// explains itself, and the others are no policy decision about a
// destination. It runs on the proxy's goroutines, so it only ever touches
// the event's binding.
func (r *refusalMemory) note(e egress.Event, now time.Time) {
	cut := e.Kind == egress.EventLargeUpload && e.Terminated
	if (e.Kind != egress.EventBlocked && !cut) || e.Method != http.MethodConnect || e.BindingID == "" || e.Host == "" {
		return
	}
	if cut {
		e.Category = egress.CategoryLargeUpload
	}
	switch e.Category {
	case egress.CategoryRateLimited, egress.CategoryInvalidDestination:
		return
	}
	host := strings.TrimSuffix(strings.ToLower(e.Host), ".")
	if !refusalHost(host) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.byBinding[e.BindingID]
	if b == nil {
		if len(r.byBinding) >= maxRefusalBindings {
			r.evictStalest()
		}
		b = &bindingRefusals{}
		r.byBinding[e.BindingID] = b
	}
	b.sandbox, b.last = e.SandboxName, now
	next := refusedHost{host: host, port: e.Port, category: e.Category, source: e.Source, unblockable: e.Unblockable, at: now}
	if cut {
		next.cut, next.sent = true, e.BytesUp
	}
	kept := b.hosts[:0]
	for _, h := range b.hosts {
		switch {
		case now.Sub(h.at) > egressRefusalWindow:
			// Expired: a later refusal of it is told again.
		case h.host == host && h.port == e.Port:
			next.told = h.told
			if h.note != "" && !next.cut {
				// A repeat of a refusal the manager explained keeps the
				// explanation, not the bare refusal or its unblock hint: the
				// agent tried again while its ask waits, after the user
				// declined it, or after the organization refused it. The ask
				// is raised by the sink after the first refusal, which races
				// this one (GAP-0665, GAP-0698).
				next.note, next.refusal = h.note, h.refusal
			}
			if h.cut && !next.cut && next.category == egress.CategoryLargeUpload {
				// A refusal after the cut: the cut is what to tell.
				next.cut, next.sent = true, h.sent
			}
		default:
			kept = append(kept, h)
		}
	}
	if len(kept) >= maxRefusedHosts {
		kept = append(kept[:0], kept[len(kept)-maxRefusedHosts+1:]...)
	}
	b.hosts = append(kept, next)
}

// noteDirect keeps a sandbox binding's connection to host and port that is
// no egress block of DefenseClaw's, as note says (NoteSSH, NoteAsked,
// NoteDeclined): the agent sees only a connection error ("Permission
// denied", "Couldn't connect") and tried the same again, or said all was
// well. Its next post-tool hook tells it what happened.
func (r *refusalMemory) noteDirect(bindingID, sandbox, host string, port int, note string, now time.Time) {
	r.addDirect(bindingID, sandbox, host, port, note, "", now)
}

// noteRefused keeps a sandbox binding's connection to host and port that
// the organization's floor refused, with refusal, its managed refusal
// text (NoteAccessRefused).
func (r *refusalMemory) noteRefused(bindingID, sandbox, host string, port int, refusal string, now time.Time) {
	r.addDirect(bindingID, sandbox, host, port, NoteAccessRefused, refusal, now)
}

func (r *refusalMemory) addDirect(bindingID, sandbox, host string, port int, note, refusal string, now time.Time) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if bindingID == "" || !refusalHost(host) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.byBinding[bindingID]
	if b == nil {
		if len(r.byBinding) >= maxRefusalBindings {
			r.evictStalest()
		}
		b = &bindingRefusals{}
		r.byBinding[bindingID] = b
	}
	b.sandbox, b.last = sandbox, now
	next := refusedHost{host: host, port: port, note: note, refusal: refusal, at: now}
	kept := b.hosts[:0]
	for _, h := range b.hosts {
		switch {
		case now.Sub(h.at) > egressRefusalWindow:
		case h.host == host && h.port == port:
			// A repeat is told once; other news of the destination (the
			// user declined what was asked) is told again.
			next.told = h.told && h.note == note
		default:
			kept = append(kept, h)
		}
	}
	if len(kept) >= maxRefusedHosts {
		kept = append(kept[:0], kept[len(kept)-maxRefusedHosts+1:]...)
	}
	b.hosts = append(kept, next)
}

// refusalHost reports a destination the agent may be told of: a host name
// or IP address, nothing the proxy only sanitized. The text reaches the
// agent's context.
func refusalHost(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' && c != ':' {
			return false
		}
	}
	return true
}

// evictStalest forgets the binding refused longest ago. The caller holds
// r.mu.
func (r *refusalMemory) evictStalest() {
	stalest, at := "", time.Time{}
	for id, b := range r.byBinding {
		if stalest == "" || b.last.Before(at) {
			stalest, at = id, b.last
		}
	}
	delete(r.byBinding, stalest)
}

// take returns the binding's refusals of the last egressRefusalWindow its
// agent has not been told of, oldest first, and marks them told. name must
// be the sandbox the refusals were made for.
func (r *refusalMemory) take(bindingID, name string, now time.Time) []refusedHost {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.byBinding[bindingID]
	if b == nil || b.sandbox != name {
		return nil
	}
	var out []refusedHost
	kept := b.hosts[:0]
	for _, h := range b.hosts {
		if now.Sub(h.at) > egressRefusalWindow {
			continue
		}
		if !h.told {
			out = append(out, h)
			h.told = true
		}
		kept = append(kept, h)
	}
	b.hosts = kept
	if len(kept) == 0 {
		delete(r.byBinding, bindingID)
	}
	return out
}

// pending is take without marking the refusals told: a managed daemon
// relays them to the managed gateway, which tells the agent, and marks
// them told (markTold) once the gateway says it did.
func (r *refusalMemory) pending(bindingID, name string, now time.Time) []refusedHost {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.byBinding[bindingID]
	if b == nil || b.sandbox != name {
		return nil
	}
	var out []refusedHost
	for _, h := range b.hosts {
		if now.Sub(h.at) <= egressRefusalWindow && !h.told {
			out = append(out, h)
		}
	}
	return out
}

// markTold marks the binding's untold refusals of host, port and
// category (a note's kind for a note) told.
func (r *refusalMemory) markTold(bindingID, name, host string, port int, category string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.byBinding[bindingID]
	if b == nil || b.sandbox != name {
		return
	}
	for i := range b.hosts {
		h := &b.hosts[i]
		kind := string(h.category)
		if h.note != "" {
			kind = h.note
		}
		if h.host == host && h.port == port && kind == category {
			h.told = true
		}
	}
}

// forgetNote drops a binding's untold note of kind note about host and
// port: an ask the user answered before the agent was told it waits.
func (r *refusalMemory) forgetNote(bindingID, host string, port int, note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.byBinding[bindingID]
	if b == nil {
		return
	}
	kept := b.hosts[:0]
	for _, h := range b.hosts {
		if h.note == note && h.host == host && h.port == port && !h.told {
			continue
		}
		kept = append(kept, h)
	}
	b.hosts = kept
}

// forget drops a binding's refusals (its sandbox is gone).
func (r *refusalMemory) forget(bindingID string) {
	r.mu.Lock()
	delete(r.byBinding, bindingID)
	r.mu.Unlock()
}

// EgressRefusals returns the destinations the sandbox's egress proxy
// refused a CONNECT to within the last two minutes that its agent has not
// been told of, and marks them told: the gateway adds them to the context
// of the sandbox's next post-tool hook of a shell or fetch tool call
// (#954). bindingID and name must be the sandbox's; a refusal is only ever
// the binding's whose proxy credential made the request. A destination the
// sandbox now reaches because of an unblock (Manager.EgressUnblock: the
// user unblocked it after the refusal) is left out, and a refusal an
// unblock would lift offers the unblock command only while the sandbox's
// policy honors unblocks.
func (m *Manager) EgressRefusals(bindingID, name string) []EgressRefusal {
	return m.egressRefusals(bindingID, name, m.refusals.take)
}

// PendingEgressRefusals is EgressRefusals without marking them told, for a
// managed daemon: it relays them to the managed gateway with the hook call
// (sandboxrelay.EgressRefusalsHeader), and EgressRefusalsTold marks them
// told once the gateway's answer told the agent (#1192).
func (m *Manager) PendingEgressRefusals(bindingID, name string) []EgressRefusal {
	return m.egressRefusals(bindingID, name, m.refusals.pending)
}

// EgressRefusalsTold marks told the refusals of the sandbox binding that
// the managed gateway's answer told its agent of.
func (m *Manager) EgressRefusalsTold(bindingID, name string, told []EgressRefusal) {
	if bindingID == "" || name == "" {
		return
	}
	for _, r := range told {
		m.refusals.markTold(bindingID, name, r.Host, r.Port, r.Category)
	}
}

// egressRefusals is EgressRefusals of the refusals list returns.
func (m *Manager) egressRefusals(bindingID, name string, list func(bindingID, name string, now time.Time) []refusedHost) []EgressRefusal {
	if bindingID == "" || name == "" {
		return nil
	}
	honored := true
	if p, ok := m.creds.Lookup(bindingID); ok {
		if p.SandboxName != name {
			return nil
		}
		honored = p.Decider == nil || p.Decider.UnblocksAllowed()
	}
	harnessName := ""
	var eff *packs.Effective
	m.mu.Lock()
	b := m.boxes[name]
	if b != nil {
		harnessName, eff = b.rec.Harness, b.eff
	}
	m.mu.Unlock()
	var out []EgressRefusal
	for _, h := range list(bindingID, name, m.now()) {
		switch h.note {
		case NoteSSH:
			out = append(out, EgressRefusal{Host: h.host, Port: h.port, Category: NoteSSH, Note: NoteSSH,
				What: "SSH, which does not leave a sandbox", Remedy: "use HTTPS instead: a git remote https://" + h.host + "/OWNER/REPO.git" +
					" (an npm github: or git+ssh dependency: git+https://" + h.host + "/OWNER/REPO.git)"})
			continue
		case NoteAsked:
			out = append(out, EgressRefusal{Host: h.host, Port: h.port, Category: NoteAsked, Note: NoteAsked,
				What: "waits for the user's approval", Remedy: "tell the user, and try again once they approve it (`defenseclaw sandbox approvals`)"})
			continue
		case NoteDeclined:
			out = append(out, EgressRefusal{Host: h.host, Port: h.port, Category: NoteDeclined, Note: NoteDeclined,
				What: "the user declined it", Remedy: "do not try it again unless the user says so"})
			continue
		case NotePortClosed:
			out = append(out, EgressRefusal{Host: h.host, Port: h.port, Category: NotePortClosed, Note: NotePortClosed,
				What:   "a port on the user's machine the run did not declare",
				Remedy: "tell the user: running the sandbox again with --host-port " + strconv.Itoa(h.port) + " makes DefenseClaw ask them about it"})
			continue
		case NotePortRefused:
			out = append(out, EgressRefusal{Host: h.host, Port: h.port, Category: NotePortRefused, Note: NotePortRefused,
				What: "a port on the user's machine the sandbox policy does not open", Remedy: "do not try it again unless the user says so"})
			continue
		case NoteAccessRefused:
			out = append(out, EgressRefusal{Host: h.host, Port: h.port, Category: NoteAccessRefused, Note: NoteAccessRefused,
				What: "refused by the organization's DefenseClaw policy", Remedy: accessRemedy(h.refusal)})
			continue
		}
		if _, lifted := m.EgressUnblock(bindingID, name, h.host); lifted {
			continue
		}
		what := refusalWhat(h.category)
		remedy := refusalRemedy(h, name, honored)
		if h.category == egress.CategoryOperatorBlock && eff != nil {
			// The block list merges the pack's, the repository policy's and
			// the user's own: the agent is told whose entry refused it, as
			// the feed and the destinations say (GAP-0125), so it does not
			// send the user to a block list they never set (#1246/GAP-0129).
			if w, r := blockOriginRefusal(eff.BlockOrigin(h.host)); w != "" {
				what, remedy = w, r
			}
		}
		if tool, ok := toolHostOf(harnessName, h.host); ok {
			// Not the site the agent fetched (GAP-0234, GAP-0263).
			what += "; " + tool
		}
		if rule := egress.AdminRule(h.category); rule != "" && b != nil {
			// The organization's own lists: the person can't approve it, and
			// the note says whom to ask and what to quote (GAP-0502).
			remedy = accessRemedy(m.accessRefusal(b, m.floor(eff), "", rule, h.host))
		}
		out = append(out, EgressRefusal{
			Host: h.host, Port: h.port, Category: string(h.category),
			What:   what,
			Remedy: remedy,
			Cut:    h.cut, Sent: h.sent,
		})
	}
	return out
}

// accessRemedy is a managed refusal (Manager.accessRefusal) as the agent's
// remedy: the user can't approve it, and how they ask for access.
func accessRemedy(refusal string) string {
	if line := sandboxapi.QuoteLine(refusal); line != "" {
		return "the user can't approve this. " + line
	}
	return "only the user's administrator can allow it"
}

// refusalWhat is the agent's short explanation of a refusal category.
func refusalWhat(c egress.Category) string {
	switch c {
	case egress.CategoryPasteSite:
		return "paste site"
	case egress.CategoryFileDrop:
		return "file-sharing site"
	case egress.CategoryWebhookCatcher:
		return "webhook catcher"
	case egress.CategoryTunnel:
		return "tunnel service"
	case egress.CategoryAnonymizer:
		return "anonymizer"
	case egress.CategoryHostInternal:
		return "this machine or a metadata address"
	case egress.CategoryPrivateNetwork:
		return "private network"
	case egress.CategoryPortNotAllowed:
		return "port the proxy does not relay"
	case egress.CategoryAdminBlock:
		return "blocked by the organization's policy"
	case egress.CategoryAdminAllowOnly:
		return "not on the organization's allowed list"
	case egress.CategoryOperatorBlock:
		return "on the sandbox's block list"
	case egress.CategoryNotAllowlisted:
		return "not on this sandbox's allowlist"
	case egress.CategoryLargeUpload:
		return "large upload to a destination this sandbox had not contacted before"
	case egress.CategoryIPLiteral:
		return "an IP address instead of a host name"
	case egress.CategoryEgressOff:
		return "this sandbox's web egress is off"
	case "":
		return "blocked"
	}
	return strings.ReplaceAll(string(c), "_", " ")
}

// blockOriginRefusal is the agent's explanation and remedy of a block-list
// refusal whose entry came from origin (packs.Effective.BlockOrigin), or ""
// for the user's own list, which refusalWhat and refusalRemedy name.
func blockOriginRefusal(origin string) (what, remedy string) {
	_, text := blockOriginText(origin)
	switch origin {
	case packs.BlockFromRepoPolicy:
		return text, "only removing it from the repository policy (" + packs.RepoPolicyPath + ") allows it"
	case packs.BlockFromPack:
		return text, "only a change to the sandbox's pack allows it"
	case packs.BlockFromFirewall:
		return text, "only the administrator of the host egress firewall can allow it"
	}
	return "", ""
}

// refusalRemedy says who can allow a refused destination, and how. It
// names nothing the agent could do to reach it another way.
func refusalRemedy(h refusedHost, sandbox string, honored bool) string {
	switch {
	case h.unblockable && honored:
		return "the user can allow it for this sandbox with `defenseclaw sandbox unblock " + h.host + " --sandbox " + sandbox + "`"
	case h.category == egress.CategoryEgressOff:
		return "only a change to this sandbox's policy turns it back on"
	case h.category == egress.CategoryHostInternal:
		return "sandboxes never reach it"
	case h.category == egress.CategoryPrivateNetwork:
		return "only the user's DefenseClaw operator can open it (openshell.egress.allow)"
	case h.category == egress.CategoryPortNotAllowed:
		return "only the user's DefenseClaw operator can add the port (openshell.egress.ports)"
	case h.category == egress.CategoryOperatorBlock:
		return "only removing it from the block list allows it"
	case h.category == egress.CategoryAdminBlock || h.category == egress.CategoryAdminAllowOnly,
		h.source == egress.SourceFeed || h.source == egress.SourceDefault ||
			h.category == egress.CategoryLargeUpload || h.category == egress.CategoryIPLiteral:
		// Unblockable in principle, but the organization turned unblocking
		// off (openshell.admin.allow_unblock: false): the proxy marks these
		// blocks not unblockable (Decision.Unblockable) only then, and
		// honored is false then too, so either way the first case missed
		// for that reason.
		return "only the user's administrator can allow it"
	}
	return "only a DefenseClaw configuration change allows it"
}
