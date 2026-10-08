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
	// note is EgressRefusal.Note (noteDirect).
	note string
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
	next := refusedHost{host: host, port: port, note: note, at: now}
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
	m.mu.Lock()
	if b := m.boxes[name]; b != nil {
		harnessName = b.rec.Harness
	}
	m.mu.Unlock()
	var out []EgressRefusal
	for _, h := range m.refusals.take(bindingID, name, m.now()) {
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
		}
		if _, lifted := m.EgressUnblock(bindingID, name, h.host); lifted {
			continue
		}
		what := refusalWhat(h.category)
		if tool, ok := toolHostOf(harnessName, h.host); ok {
			// Not the site the agent fetched (GAP-0234, GAP-0263).
			what += "; " + tool
		}
		out = append(out, EgressRefusal{
			Host: h.host, Port: h.port, Category: string(h.category),
			What:   what,
			Remedy: refusalRemedy(h, name, honored),
			Cut:    h.cut, Sent: h.sent,
		})
	}
	return out
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
