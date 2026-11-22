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

package extproc

import (
	"context"
	"fmt"
	"math/rand"
	"mime"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Property tests for GAP-0046 (lane F10). The callout's candidate methods
// must contain the method every modelled framework runs, for any mix of
// override headers, query and body, so no framework can run a method a
// url rule refuses while the callout looked at another.

type fwReq struct {
	method string
	hdrs   [][2]string // name as sent, value
	query  string
	ct     []string // Content-Type lines; nil: none
	body   string
	hasCT  bool
	hasBdy bool
}

func (r fwReq) header(canon func(string) string, want string) []string {
	var out []string
	for _, h := range r.hdrs {
		if canon(h[0]) == canon(want) {
			out = append(out, h[1])
		}
	}
	return out
}

// lenientParse splits q on sep and decodes each key and value; a pair that
// does not decode is skipped (keyFn normalises the key).
func lenientParse(q, seps string, keyFn func(string) string) [][2]string {
	var out [][2]string
	for _, pair := range strings.FieldsFunc(q, func(r rune) bool { return strings.ContainsRune(seps, r) }) {
		k, v, _ := strings.Cut(pair, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, [2]string{keyFn(dk), dv})
	}
	return out
}

func lastVal(ps [][2]string, key string) (string, bool) {
	v, ok := "", false
	for _, p := range ps {
		if p[0] == key {
			v, ok = p[1], true
		}
	}
	return v, ok
}

func firstVal(ps [][2]string, key string) (string, bool) {
	for _, p := range ps {
		if p[0] == key {
			return p[1], true
		}
	}
	return "", false
}

func same(s string) string { return s }

// phpKey is PHP's variable-name rule for $_GET and $_POST keys.
func phpKey(k string) string {
	k = strings.TrimLeft(k, " ")
	if i := strings.IndexByte(k, '['); i >= 0 && strings.Contains(k[i:], "]") {
		k = k[:i]
	}
	return strings.NewReplacer(".", "_", " ", "_").Replace(k)
}

func cgiName(n string) string { return strings.ToUpper(strings.ReplaceAll(n, "-", "_")) }

// Rack::MethodOverride (Rails, Sinatra, Hanami).
func fwRack(r fwReq) []string {
	if r.method != "POST" {
		return nil
	}
	form := false
	if r.hasBdy {
		if !r.hasCT {
			form = true
		} else {
			items := strings.FieldsFunc(r.ct[0], func(c rune) bool { return c == ';' || c == ',' })
			if strings.TrimSpace(r.ct[0]) == "" || len(items) == 0 {
				form = true
			} else if r.ct[0][0] != ';' && r.ct[0][0] != ',' {
				mt := strings.ToLower(strings.TrimSpace(items[0]))
				form = slices.Contains([]string{"application/x-www-form-urlencoded", "multipart/form-data", "multipart/related", "multipart/mixed"}, mt)
			}
		}
	}
	m := ""
	if form {
		if v, ok := lastVal(lenientParse(r.body, "&", same), "_method"); ok {
			m = v
		}
	}
	if m == "" {
		if hs := r.header(cgiName, "X-HTTP-Method-Override"); len(hs) > 0 {
			m = strings.Join(hs, ", ")
		}
	}
	m = strings.ToUpper(m)
	if slices.Contains([]string{"GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "PATCH", "LINK", "UNLINK"}, m) {
		return []string{m}
	}
	return nil
}

// Express method-override: header getter (first value of the list), query
// getter (_method) and the documented body getter (body-parser urlencoded).
func fwExpress(r fwReq) []string {
	if r.method != "POST" {
		return nil
	}
	var out []string
	if hs := r.header(strings.ToLower, "x-http-method-override"); len(hs) > 0 {
		v := strings.Split(strings.Join(hs, ", "), ",")[0]
		out = append(out, strings.ToUpper(strings.TrimSpace(v)))
	}
	if v, ok := firstVal(lenientParse(r.query, "&", same), "_method"); ok {
		out = append(out, strings.ToUpper(v))
	}
	if r.hasBdy && r.hasCT {
		if mt, _, err := mime.ParseMediaType(r.ct[0]); err == nil && mt == "application/x-www-form-urlencoded" {
			if v, ok := firstVal(lenientParse(r.body, "&", same), "_method"); ok {
				out = append(out, strings.ToUpper(v))
			}
		}
	}
	return out
}

// Symfony Request::getMethod (Laravel enables the _method parameter).
func fwSymfony(r fwReq) []string {
	if r.method != "POST" {
		return nil
	}
	if hs := r.header(cgiName, "X-HTTP-Method-Override"); len(hs) > 0 {
		return []string{strings.ToUpper(hs[0])}
	}
	if r.hasBdy && r.hasCT {
		ct := strings.ToLower(r.ct[0])
		if i := strings.IndexAny(ct, ";, "); i >= 0 {
			ct = ct[:i]
		}
		if ct == "application/x-www-form-urlencoded" {
			if v, ok := lastVal(lenientParse(r.body, "&", phpKey), "_method"); ok {
				return []string{strings.ToUpper(v)}
			}
		}
	}
	if v, ok := lastVal(lenientParse(r.query, "&", phpKey), "_method"); ok {
		return []string{strings.ToUpper(v)}
	}
	return nil
}

// Spring HiddenHttpMethodFilter on Tomcat: getParameter("_method"), the
// query first, then an urlencoded body.
func fwSpring(r fwReq) []string {
	if r.method != "POST" {
		return nil
	}
	ps := lenientParse(r.query, "&", same)
	if r.hasBdy && r.hasCT {
		ct, _, _ := strings.Cut(r.ct[0], ";")
		if strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
			ps = append(ps, lenientParse(r.body, "&", same)...)
		}
	}
	if v, ok := firstVal(ps, "_method"); ok {
		if m := strings.ToUpper(v); slices.Contains([]string{"PUT", "DELETE", "PATCH"}, m) {
			return []string{m}
		}
	}
	return nil
}

// gorilla/handlers.HTTPMethodOverrideHandler: FormValue (body, then
// query), then the header.
func fwGorilla(r fwReq) []string {
	if r.method != "POST" {
		return nil
	}
	var ps [][2]string
	if r.hasBdy && r.hasCT {
		if mt, _, err := mime.ParseMediaType(r.ct[0]); err == nil && mt == "application/x-www-form-urlencoded" {
			// ParseForm keeps the pairs it could read past a bad one.
			q, _ := url.ParseQuery(r.body)
			for _, v := range q["_method"] {
				ps = append(ps, [2]string{"_method", v})
			}
		}
	}
	q, _ := url.ParseQuery(r.query)
	for _, v := range q["_method"] {
		ps = append(ps, [2]string{"_method", v})
	}
	m, _ := firstVal(ps, "_method")
	if m == "" {
		if hs := r.header(strings.ToLower, "x-http-method-override"); len(hs) > 0 {
			m = hs[0]
		}
	}
	if slices.Contains([]string{"PUT", "PATCH", "DELETE"}, m) {
		return []string{m}
	}
	return nil
}

// ASP.NET Core UseHttpMethodOverride: the header, or a form field.
func fwASPNet(r fwReq) []string {
	if r.method != "POST" {
		return nil
	}
	var out []string
	// The joined header value becomes the method; only a single token
	// is a method a route can match.
	if hs := r.header(strings.ToLower, "x-http-method-override"); len(hs) > 0 && !strings.ContainsAny(strings.TrimSpace(strings.Join(hs, ",")), ", ") {
		out = append(out, strings.Join(hs, ","))
	}
	if r.hasBdy && r.hasCT {
		ct, _, _ := strings.Cut(r.ct[0], ";")
		if strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
			if v, ok := firstVal(lenientParse(r.body, "&", same), "_method"); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// OData (X-HTTP-Method), X-Method-Override and Salesforce (_HttpMethod).
func fwOthers(r fwReq) []string {
	var out []string
	for _, n := range []string{"x-http-method", "x-method-override"} {
		for _, v := range r.header(strings.ToLower, n) {
			for _, m := range strings.Split(v, ",") {
				out = append(out, strings.ToUpper(strings.TrimSpace(m)))
			}
		}
	}
	if v, ok := firstVal(lenientParse(r.query, "&", same), "_HttpMethod"); ok {
		out = append(out, strings.ToUpper(v))
	}
	return out
}

var frameworks = map[string]func(fwReq) []string{
	"rack": fwRack, "express": fwExpress, "symfony": fwSymfony, "spring": fwSpring,
	"gorilla": fwGorilla, "aspnet": fwASPNet, "others": fwOthers,
}

func randomFwReq(rng *rand.Rand) fwReq {
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	r := fwReq{method: pick([]string{"POST", "POST", "POST", "GET", "PUT"})}
	names := []string{"X-HTTP-Method-Override", "x-http-method-override", "X-HTTP-Method", "X-Method-Override", "X_HTTP_METHOD_OVERRIDE"}
	vals := []string{"DELETE", "delete", "DELETE, GET", "GET,DELETE", "PATCH", " DELETE ", "GET"}
	for n := rng.Intn(3); n > 0; n-- {
		r.hdrs = append(r.hdrs, [2]string{pick(names), pick(vals)})
	}
	r.query = pick([]string{"", "", "_method=DELETE", "_method=delete&x=1", "x=1;_method=DELETE", "_method=GET&_method=DELETE",
		"_HttpMethod=DELETE", "%5Fmethod=DELETE", ".method=DELETE", "_method=PATCH", "a=%zz&_method=DELETE"})
	cts := []string{"", "application/x-www-form-urlencoded", "application/x-www-form-urlencoded; charset=utf-8",
		"Application/X-WWW-Form-Urlencoded", "application/json", "text/plain", "; charset=utf-8",
		"application/x-www-form-urlencoded, application/json", "multipart/mixed; boundary=b"}
	switch rng.Intn(3) {
	case 0:
	default:
		r.hasCT, r.ct = true, []string{pick(cts)}
	}
	if rng.Intn(4) > 0 {
		r.hasBdy = true
		r.body = pick([]string{"_method=DELETE", "a=1&_method=delete", "_method=PATCH", ".method=DELETE", "%5Fmethod=DELETE",
			"_method=+DELETE", "title=x", "_method=GET&_method=DELETE", "x=%zz&_method=DELETE", "%20_method=DELETE"})
	}
	return r
}

func (r fwReq) request() *Request {
	path := "/repos/acme/web"
	if r.query != "" {
		path += "?" + r.query
	}
	var hdrs []string
	for _, h := range r.hdrs {
		hdrs = append(hdrs, h[0], h[1])
	}
	out := req("eng-web", r.method, "api.github.com", path, hdrs...)
	for _, ct := range r.ct {
		out.Headers = append(out.Headers, Header{"content-type", ct})
		out.ContentType = ct
	}
	if r.hasBdy {
		out.EndOfStream, out.ContentLength = false, int64(len(r.body))
	}
	return out
}

// TestMethodSetCoversFrameworksGAP0046: for any request, every method a
// modelled framework runs is among the callout's candidates; a body
// method is a candidate only when the callout reads the body, so this
// also proves bodyOverridable covers every body a framework reads.
func TestMethodSetCoversFrameworksGAP0046(t *testing.T) {
	rng := rand.New(rand.NewSource(46))
	for i := 0; i < 20000; i++ {
		r := randomFwReq(rng)
		R := r.request()
		cands := requestMethods(R)
		if bodyOverridable(R) {
			bm, _ := bodyMethods([]byte(r.body), R, 1<<20)
			cands = appendMethods(cands, strings.Join(bm, ","))
		}
		for name, fw := range frameworks {
			for _, m := range fw(r) {
				m = strings.ToUpper(strings.TrimSpace(m))
				if m == "" || strings.ContainsAny(m, ", \t") { // not a method token: no route runs it
					continue
				}
				if !slices.Contains(cands, m) {
					t.Fatalf("%s runs %s, not among the callout's %v for %+v (bodyOverridable=%v)", name, m, cands, r, bodyOverridable(R))
				}
			}
		}
	}
}

// TestDeleteDenyHoldsForEveryFrameworkGAP0046: end to end through the
// engine with body mode working: whenever some framework would run DELETE,
// the DELETE deny refuses the request.
func TestDeleteDenyHoldsForEveryFrameworkGAP0046(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = []URLRuleCfg{{Name: "no-delete", Hosts: []string{"api.github.com"}, Methods: []string{"DELETE"}, Action: "deny"}}
	})
	h.eng.body.arrived()
	ctx := context.Background()
	rng := rand.New(rand.NewSource(177))
	for i := 0; i < 4000; i++ {
		r := randomFwReq(rng)
		runsDelete := ""
		for name, fw := range frameworks {
			for _, m := range fw(r) {
				if strings.ToUpper(strings.TrimSpace(m)) == "DELETE" {
					runsDelete = name
				}
			}
		}
		if runsDelete == "" {
			continue
		}
		R := r.request()
		v := h.eng.DecideHeaders(ctx, R)
		if v.Allow && v.WantBody {
			v = h.eng.DecideBody(ctx, R, v, []byte(r.body))
		}
		if v.Allow {
			t.Fatalf("%s runs DELETE, the callout allowed %+v: %+v", runsDelete, r, v)
		}
	}
}

// FuzzRequestMethods: candidates are upper-case, trimmed, single methods
// and include the request's own; nothing panics.
func FuzzRequestMethods(f *testing.F) {
	for _, s := range []string{"DELETE, GET", "_method=delete&_method=PUT", "%5Fmethod=%zz", ".method=x;_HttpMethod=y", "\x00", "_method[]=DELETE"} {
		f.Add("POST", s, s, s)
	}
	f.Fuzz(func(t *testing.T, method, hv, q, body string) {
		if strings.TrimSpace(method) == "" || strings.ContainsAny(method, ", \t\r\n") {
			return
		}
		r := req("eng-web", method, "api.github.com", "/x?"+q, "x-http-method-override", hv, "x_http_method", hv)
		r.EndOfStream, r.ContentLength = false, int64(len(body))
		ms := requestMethods(r)
		bm, _ := bodyMethods([]byte(body), r, 1<<20)
		for _, m := range append(ms[1:], bm...) {
			if m == "" || m != strings.ToUpper(m) || m != strings.TrimSpace(m) || strings.Contains(m, ",") {
				t.Fatalf("bad candidate %q from %q %q %q", m, hv, q, body)
			}
		}
		if len(ms) == 0 || ms[0] != strings.ToUpper(method) {
			t.Fatalf("own method missing: %q %v", method, ms)
		}
	})
}

// Path normaliser properties.

const segAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~!$&'()*+,=:@"

func randomCanonical(rng *rand.Rand) string {
	n := rng.Intn(5)
	var segs []string
	for i := 0; i < n; i++ {
		var b strings.Builder
		for l := 1 + rng.Intn(6); l > 0; l-- {
			b.WriteByte(segAlphabet[rng.Intn(len(segAlphabet))])
		}
		if s := b.String(); s != "." && s != ".." {
			segs = append(segs, s)
		}
	}
	p := "/" + strings.Join(segs, "/")
	if len(segs) > 0 && rng.Intn(3) == 0 {
		p += "/"
	}
	return p
}

// respell writes canonical path c another way an origin reads the same:
// escaped bytes (either hex case), "." segments (escaped too), repeated
// slashes and ;parameters on a named segment.
func respell(rng *rand.Rand, c string) string {
	if c == "/" {
		return []string{"/", "//", "/./", "/%2e/"}[rng.Intn(4)]
	}
	trailing := strings.HasSuffix(c, "/")
	segs := strings.Split(strings.Trim(c, "/"), "/")
	var b strings.Builder
	for _, s := range segs {
		b.WriteString("/")
		switch rng.Intn(4) {
		case 0:
			b.WriteString("/")
		case 1:
			b.WriteString([]string{"./", "%2e/", "%2E/"}[rng.Intn(3)])
		}
		for i := 0; i < len(s); i++ {
			if rng.Intn(3) == 0 {
				hex := fmt.Sprintf("%%%02X", s[i])
				if rng.Intn(2) == 0 {
					hex = strings.ToLower(hex)
				}
				b.WriteString(hex)
			} else {
				b.WriteByte(s[i])
			}
		}
		if rng.Intn(5) == 0 {
			b.WriteString(";jsessionid=x")
		}
	}
	if trailing {
		b.WriteString("/")
	}
	return b.String()
}

// TestCanonicalPathEquivalentSpellingsGAP0046: every respelling of a
// canonical path canonicalises to it, so a prefix rule matches it the
// same; dot-dot and encoded separators are refused instead.
func TestCanonicalPathEquivalentSpellingsGAP0046(t *testing.T) {
	rng := rand.New(rand.NewSource(3986))
	for i := 0; i < 20000; i++ {
		c := randomCanonical(rng)
		if got, err := canonicalPath(c); err != nil || got != c {
			t.Fatalf("canonical %q: %q %v", c, got, err)
		}
		s := respell(rng, c)
		got, err := canonicalPath(s)
		if err != nil || got != c {
			t.Fatalf("%q (a spelling of %q): %q %v", s, c, got, err)
		}
		r := urlRule{foldedPrefix: strings.ToLower(c)}
		if !r.matchesPath(got) {
			t.Fatalf("prefix %q does not match its own spelling %q", c, s)
		}
		// A dot-dot or an encoded separator anywhere is refused.
		for _, bad := range []string{"/..", "/%2e%2e", "/.%2E", "/..;x", "%2F", "%5C", "%3B", "%25", "%00", "%c0%ae"} {
			if _, err := canonicalPath(c + bad + "/x"); err == nil {
				t.Fatalf("%q%s/x not refused", c, bad)
			}
		}
	}
}

// FuzzCanonicalPath: an accepted path's canonical form starts with "/",
// has no empty, "." or ".." segment, no escape, separator, parameter or
// control byte, is UTF-8 and canonicalises to itself.
func FuzzCanonicalPath(f *testing.F) {
	for _, s := range []string{"/", "/a/b/", "//a/./b", "/%61dmin", "/a;x/b", "/a/../b", "/%2e%2E/", "/a%2Fb", "*", "/\xc0\xae", "/a/%3F"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := canonicalPath(raw)
		if err != nil || out == "*" {
			return
		}
		if !strings.HasPrefix(out, "/") || !utf8.ValidString(out) {
			t.Fatalf("%q -> %q", raw, out)
		}
		for _, seg := range strings.Split(strings.TrimSuffix(out[1:], "/"), "/") {
			if out != "/" && (seg == "" || seg == "." || seg == "..") {
				t.Fatalf("%q -> %q has segment %q", raw, out, seg)
			}
		}
		for i := 0; i < len(out); i++ {
			if c := out[i]; c == '%' || c == ';' || c == '\\' || c < 0x20 || c == 0x7f {
				t.Fatalf("%q -> %q has byte %q", raw, out, c)
			}
		}
		if again, err := canonicalPath(out); err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q %v", raw, out, again, err)
		}
	})
}
