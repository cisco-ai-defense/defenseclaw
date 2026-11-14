// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package toolshape reads a non-shell tool call (an MCP or app tool) as
// effects: file read/write/delete on paths, network sends to hosts and
// recipients, SQL statement classes, code execution and security-setting
// changes. It is the mapping layer GAP-0016 asked for: rules decide on the
// effects, not on opaque tool names and JSON.
//
// Names and argument shapes come from the embedded table shapes.yaml. The
// role of every effect is guessed from names (Reason is always
// "mcp_semantics"); the target value itself is read from the arguments. A
// call the table cannot place is not Known, and not Known is never "clean":
// the caller keeps it visible and alerts only where a sensitive target is
// plausible.
package toolshape

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

//go:embed shapes.yaml
var shapesYAML []byte

// Bounds on what one call may contribute. A reached bound is never silent:
// the walk records it (bounded.Truncated) and the caller judges the call as
// unknown at least (internal/guardrail/bounded, the S7 bound rule).
const (
	maxDepth   = 16       // object and array nesting (bounded.Depth)
	maxItems   = 512      // elements of one array (bounded.Items)
	maxEffects = 256      // effects of one call (bounded.Effects)
	maxNodes   = 1 << 16  // values of one walk (bounded.Nodes)
	maxNested  = 4        // JSON documents nested in string arguments (bounded.Depth)
	maxString  = 1 << 20  // bytes of one string argument read (bounded.Bytes)
	maxPath    = 32 << 10 // bytes of a path value (bounded.Bytes); a longer one is still judged
	maxContent = 1 << 20  // bytes of write content collected (bounded.Bytes)
)

// Family is the kind of server or tool a call belongs to.
type Family string

// Families.
const (
	FamilyUnknown Family = ""
	FamilyFS      Family = "fs"
	FamilyVCS     Family = "vcs"
	FamilyHTTP    Family = "http"
	FamilyDB      Family = "db"
	FamilyMail    Family = "mail"
	FamilyChat    Family = "chat"
	FamilyIssue   Family = "issue"
	FamilyK8s     Family = "k8s"
	FamilyCode    Family = "code"
)

// Kind is what a call does to its target.
type Kind string

// Kinds.
const (
	KindRead     Kind = "read"
	KindWrite    Kind = "write"
	KindDelete   Kind = "delete"
	KindList     Kind = "list"
	KindExec     Kind = "exec"
	KindNetFetch Kind = "net_fetch"
	KindNetSend  Kind = "net_send"
	KindSQL      Kind = "sql"
	KindSetting  Kind = "setting"
)

// Role of a destination of a send.
type Role string

// Roles.
const (
	RolePrimary  Role = "primary"
	RoleRedirect Role = "redirect"
	RoleURL      Role = "url"
	RoleCallback Role = "callback" // a URL the call asks to be told at
)

// Effect is one thing a call does. Reason is always "mcp_semantics": the
// target is read from the arguments, the kind is a guess from names.
type Effect struct {
	Kind    Kind
	Arg     string // the argument the effect came from
	Path    string // read, write, delete, list
	URL     string // net_fetch, net_send
	Host    string // net_fetch, net_send (lower-case, no port)
	Role    Role
	SQL     []SQLClass // sql
	Setting string     // setting: what the change does
	Code    string     // exec: the code text (bounded)
	Reason  string
}

// Mapping is the reading of one call.
type Mapping struct {
	Server  string
	Name    string
	Family  Family
	Verb    Kind // the verb of the tool name; "" when the name has none
	Effects []Effect
	// RoleKnown reports that the server is one the table names with this verb
	// (a file server's read_file): the role of its path effects is known, not
	// guessed, so they are judged exactly as the native file tool is.
	RoleKnown bool
	// Truncated is the set of bounds the walk reached. A call with a bound hit
	// has unread parts: the caller judges it unknown at least, never clean.
	Truncated bounded.CapSet
	// Content is the text the call writes (values under content-style keys,
	// nested ones included), for the rules that read what is written.
	Content string
}

type table struct {
	Servers        map[string]string   `yaml:"servers"`
	Verbs          map[string][]string `yaml:"verbs"`
	PathKeys       map[string][]string `yaml:"path_keys"`
	URLKeys        []string            `yaml:"url_keys"`
	RedirectKeys   []string            `yaml:"redirect_keys"`
	RecipientKeys  []string            `yaml:"recipient_keys"`
	SQLKeys        []string            `yaml:"sql_keys"`
	SQLGenericKeys []string            `yaml:"sql_generic_keys"`
	CodeKeys       []string            `yaml:"code_keys"`
	CodeToolTokens []string            `yaml:"code_tool_tokens"`
	Settings       []struct {
		Key  string `yaml:"key"`
		When string `yaml:"when"`
		What string `yaml:"what"`
	} `yaml:"settings"`
	SettingOps string   `yaml:"setting_ops"`
	DecodeExec []string `yaml:"decode_exec"`
	LocalHosts []string `yaml:"local_hosts"`

	PathRules     []PathRule          `yaml:"path_rules"`
	CommandRules  []CommandRule       `yaml:"command_rules"`
	ShellTriggers []string            `yaml:"shell_triggers"`
	KnownRoles    map[string][]string `yaml:"known_roles"`
	PathKeySuffix []string            `yaml:"path_key_suffixes"`
	TextRules     []TextRule          `yaml:"text_rules"`
	ContentKeys   []string            `yaml:"content_keys"`
	SearchTokens  []string            `yaml:"search_tokens"`
	NameKeys      []string            `yaml:"name_keys"`
	InputKeys     []string            `yaml:"input_keys"`
	OperationKeys []string            `yaml:"operation_keys"`
	ProxyArgKeys  []string            `yaml:"proxy_arg_keys"`
	CallbackKeys  []string            `yaml:"callback_keys"`
	TextTools     struct {
		Families       []string `yaml:"families"`
		Tokens         []string `yaml:"tokens"`
		ExceptFamilies []string `yaml:"except_families"`
	} `yaml:"text_tools"`

	verbOf        map[string]Kind
	pathRead      map[string]bool
	pathWrite     map[string]bool
	urlKey        map[string]bool
	redirectKey   map[string]bool
	recipientKey  map[string]bool
	sqlKey        map[string]bool
	sqlGenericKey map[string]bool
	codeKey       map[string]bool
	codeToken     map[string]bool
	settings      []compiledSetting
	settingOps    *regexp.Regexp
	decodeExec    []*regexp.Regexp
	localHost     map[string]bool
	pathSuffix    []string
	contentKey    map[string]bool
	searchToken   map[string]bool
	callbackKey   map[string]bool
	inputKey      map[string]bool
	proxyArgKey   map[string]bool
	textFamily    map[string]bool
	textToken     map[string]bool
	textExcept    map[string]bool
}

type compiledSetting struct {
	key  *regexp.Regexp
	when *regexp.Regexp
	what string
}

var (
	tableOnce sync.Once
	tbl       *table
	tblErr    error
)

func set(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

func load() (*table, error) {
	tableOnce.Do(func() {
		var t table
		if err := yaml.Unmarshal(shapesYAML, &t); err != nil {
			tblErr = fmt.Errorf("toolshape: shapes.yaml: %w", err)
			return
		}
		t.verbOf = map[string]Kind{}
		for verb, tokens := range t.Verbs {
			kind := Kind(verb)
			if verb == "send" {
				kind = KindNetSend
			}
			for _, token := range tokens {
				if _, dup := t.verbOf[token]; !dup {
					t.verbOf[token] = kind
				}
			}
		}
		t.pathRead, t.pathWrite = set(t.PathKeys["read"]), set(t.PathKeys["write"])
		t.urlKey, t.redirectKey, t.recipientKey = set(t.URLKeys), set(t.RedirectKeys), set(t.RecipientKeys)
		t.sqlKey, t.sqlGenericKey = set(t.SQLKeys), set(t.SQLGenericKeys)
		t.codeKey, t.codeToken, t.localHost = set(t.CodeKeys), set(t.CodeToolTokens), set(t.LocalHosts)
		t.contentKey, t.searchToken = set(t.ContentKeys), set(t.SearchTokens)
		t.callbackKey = set(t.CallbackKeys)
		t.inputKey = set(t.InputKeys)
		t.proxyArgKey = set(t.ProxyArgKeys)
		t.textFamily, t.textToken = set(t.TextTools.Families), set(t.TextTools.Tokens)
		t.textExcept = set(t.TextTools.ExceptFamilies)
		for _, suf := range t.PathKeySuffix {
			t.pathSuffix = append(t.pathSuffix, "_"+suf)
		}
		for _, s := range t.Settings {
			key, err := regexp.Compile(s.Key)
			if err != nil {
				tblErr = fmt.Errorf("toolshape: setting key %q: %w", s.Key, err)
				return
			}
			when, err := regexp.Compile(s.When)
			if err != nil {
				tblErr = fmt.Errorf("toolshape: setting value %q: %w", s.When, err)
				return
			}
			t.settings = append(t.settings, compiledSetting{key: key, when: when, what: s.What})
		}
		var err error
		if t.settingOps, err = regexp.Compile(t.SettingOps); err != nil {
			tblErr = fmt.Errorf("toolshape: setting_ops: %w", err)
			return
		}
		for _, p := range t.DecodeExec {
			re, err := regexp.Compile(p)
			if err != nil {
				tblErr = fmt.Errorf("toolshape: decode_exec %q: %w", p, err)
				return
			}
			t.decodeExec = append(t.decodeExec, re)
		}
		if err := t.compileRules(); err != nil {
			tblErr = err
			return
		}
		tbl = &t
	})
	return tbl, tblErr
}

// Validate reports a defect in the embedded table. A test calls it so a bad
// edit fails the build, not a hook call.
func Validate() error { _, err := load(); return err }

// SplitName separates "mcp__server__tool" into its server and tool. A dotted
// name ("fs.read") yields the part before the dot as the server. Other names
// have no server.
func SplitName(tool string) (server, name string) {
	tool = strings.TrimSpace(tool)
	if rest, ok := strings.CutPrefix(tool, "mcp__"); ok {
		if i := strings.Index(rest, "__"); i >= 0 {
			return strings.ToLower(rest[:i]), rest[i+2:]
		}
		return "", rest
	}
	if i := strings.Index(tool, "."); i > 0 && i < len(tool)-1 {
		return strings.ToLower(tool[:i]), tool[i+1:]
	}
	return "", tool
}

// Tokens splits a name on separators and camelCase boundaries, lower-cased.
func Tokens(name string) []string {
	var tokens []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ' || r == '/' || r == ':':
			flush()
		case unicode.IsUpper(r) && len(cur) > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1])):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return tokens
}

// normKey lower-cases an argument name and turns separators and camelCase
// into single underscores.
func normKey(k string) string { return strings.Join(Tokens(k), "_") }

// Map reads one call. args is the JSON argument object (a JSON document inside
// a JSON string is read too, as a proxy tool sends it); anything else yields a
// mapping with no effects. server is the MCP server the connector reports for
// the call (a bare tool name carries none); empty means the server the name
// spells.
func Map(tool string, args json.RawMessage, server string) (Mapping, error) {
	t, err := load()
	if err != nil {
		return Mapping{}, err
	}
	nameServer, name := SplitName(tool)
	if server == "" {
		server = nameServer
	}
	server = strings.ToLower(server)
	m := Mapping{Server: server, Name: name}
	toks := Tokens(name)
	srvToks := Tokens(server)
	if fam, ok := t.Servers[server]; ok {
		m.Family = Family(fam)
	}
	if m.Family == FamilyUnknown {
		cands := append(append([]string{server}, srvToks...), toks...)
		for _, tok := range cands {
			if fam, ok := t.Servers[tok]; ok {
				m.Family = Family(fam)
				break
			}
		}
	}
	for _, kind := range []Kind{KindDelete, KindWrite, KindExec, KindNetSend, KindList, KindRead} {
		for _, tok := range toks {
			if t.verbOf[tok] == kind {
				m.Verb = kind
				break
			}
		}
		if m.Verb != "" {
			break
		}
	}
	w := &walker{t: t, m: &m, dbTool: m.Family == FamilyDB, codeTool: m.Family == FamilyCode}
	w.textTool = t.textToolOf(m.Family, toks)
	for _, tok := range toks {
		if t.codeToken[tok] {
			w.codeTool = true
		}
		if t.searchToken[tok] {
			w.searchTool = true
		}
	}
	w.effects = bounded.NewCounter(&w.trunc, bounded.Effects, maxEffects)
	w.nodes = bounded.NewCounter(&w.trunc, bounded.Nodes, maxNodes)
	if verbs, ok := t.KnownRoles[server]; ok && m.Verb != "" {
		for _, v := range verbs {
			if Kind(v) == m.Verb {
				m.RoleKnown = true
			}
		}
	}
	if len(args) > 0 {
		if root, ok := decodeLenient(args); ok {
			w.proxyVerb(root)
			w.value("", root, 0)
		} else if jsonDocument(string(args)) {
			w.trunc.Hit(bounded.Nodes) // a document the reader could not parse: unread, not clean
		}
	}
	m.Truncated = w.trunc.Set(&w.effects, &w.nodes)
	m.Content = w.content.String()
	return m, nil
}

// proxyVerb takes the verb of a proxy tool from the tool name its arguments
// carry ({"name": "write_file", "arguments": {...}}), when the name of the
// call itself has none. The first key of the table's name_keys that holds a
// short string decides.
func (w *walker) proxyVerb(root any) {
	obj, ok := root.(map[string]any)
	if !ok {
		return
	}
	for _, k := range w.t.ProxyArgKeys {
		if _, has := obj[k]; has {
			w.proxy = true
		}
	}
	if !w.proxy {
		return
	}
	for _, k := range w.t.NameKeys {
		name, ok := obj[k].(string)
		if !ok || name == "" || len(name) > 96 {
			continue
		}
		toks := Tokens(name)
		// The name the proxy calls decides what its text is: a proxied mail,
		// chat or issue tool sends data too.
		if w.t.textToolOf(w.nestedFamily(toks), toks) {
			w.textTool = true
		}
		if w.m.Verb != "" {
			continue
		}
		for _, kind := range []Kind{KindDelete, KindWrite, KindExec, KindNetSend, KindList, KindRead} {
			for _, tok := range toks {
				if w.t.verbOf[tok] == kind {
					w.m.Verb = kind
					return
				}
			}
		}
	}
}

// nestedFamily is the family of a tool name a proxy carries (the table's
// server and name tokens).
func (w *walker) nestedFamily(toks []string) Family {
	for _, tok := range toks {
		if fam, ok := w.t.Servers[tok]; ok {
			return Family(fam)
		}
	}
	return FamilyUnknown
}

// textToolOf reports a tool that sends, posts or writes text for people or a
// record (the table's text_tools): by its family, or by a token of its name
// unless its family names places by its arguments.
func (t *table) textToolOf(fam Family, toks []string) bool {
	if t.textFamily[string(fam)] {
		return true
	}
	if t.textExcept[string(fam)] {
		return false
	}
	for _, tok := range toks {
		if t.textToken[tok] {
			return true
		}
	}
	return false
}

// placeKey reports an argument name that carries a place to read, write or
// fetch: a path, input or attachment key (also by suffix) or a URL key.
func (t *table) placeKey(key string) bool {
	return t.pathRead[key] || t.pathWrite[key] || t.inputKey[key] || t.pathKeySuffix(key) || t.urlKey[key]
}

// locationKey reports an argument name that names a place or a party: a path,
// an input or attachment, a URL, a recipient or redirect, a callback, an SQL
// statement or code, or the arguments of a proxy tool. The text of a text
// tool (textToolOf) under any other key is data.
func (t *table) locationKey(key string) bool {
	return t.placeKey(key) || t.redirectKey[key] || t.recipientKey[key] || t.callbackKey[key] ||
		t.sqlKey[key] || t.sqlGenericKey[key] || t.codeKey[key] || t.proxyArgKey[key]
}

// walker reads one call. It is used by pointer (the counters are bound to
// its Truncated).
type walker struct {
	t            *table
	m            *Mapping
	trunc        bounded.Truncated
	effects      bounded.Counter
	nodes        bounded.Counter
	content      strings.Builder
	codeTool     bool
	dbTool       bool
	searchTool   bool
	proxy        bool // the call has the shape of a proxy tool: a tool name beside its arguments
	textTool     bool // the call sends, posts or writes text (table text_tools): its free text is data
	nested       int
	contentBytes int
	dests        map[string]bool
}

func (w *walker) add(e Effect) {
	if !w.effects.Take() {
		return
	}
	e.Reason = "mcp_semantics"
	w.m.Effects = append(w.m.Effects, e)
}

func (w *walker) value(key string, v any, depth int) {
	if !w.nodes.Take() || !w.trunc.Within(bounded.Depth, depth, maxDepth) {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, rawKey := range keys {
			w.value(normKey(rawKey), x[rawKey], depth+1)
		}
	case []any:
		for i, item := range x {
			if !w.trunc.Within(bounded.Items, i+1, maxItems) {
				return
			}
			if it, ok := item.(map[string]any); ok {
				w.operationObject(it)
			}
			w.value(key, item, depth+1)
		}
	case string:
		w.str(key, x)
	case bool:
		w.setting(key, fmt.Sprint(x))
	}
}

// operationObject reads {"op": "disable_mfa"} entries of an operations list.
func (w *walker) operationObject(it map[string]any) {
	for _, k := range w.t.OperationKeys {
		if s, ok := it[k].(string); ok && w.t.settingOps.MatchString(strings.ToLower(strings.TrimSpace(s))) {
			w.add(Effect{Kind: KindSetting, Arg: k, Setting: "turns a security control off (" + s + ")"})
		}
	}
}

func (w *walker) setting(key, value string) {
	value = strings.ToLower(value)
	for _, s := range w.t.settings {
		if s.key.MatchString(key) && s.when.MatchString(value) {
			w.add(Effect{Kind: KindSetting, Arg: key, Setting: s.what})
			return
		}
	}
}

func (w *walker) str(key, val string) {
	if len(val) > maxString {
		val = val[:maxString]
		w.trunc.Hit(bounded.Bytes)
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	t := w.t
	// Text the call writes: collected for the rules that read it, and never
	// read as a JSON document (a file body is data).
	if t.contentKey[key] {
		w.contentBytes += len(val)
		if w.contentBytes > maxContent {
			w.trunc.Hit(bounded.Bytes)
		} else {
			w.content.WriteString(val)
			w.content.WriteByte('\n')
		}
		if w.bodyIsData(val) {
			// A plain write's body is data: it is not read as arguments. A
			// send or proxy tool's text, a JSON document and a value a tool
			// that does not write receives under such a key are read like
			// any string.
			return
		}
	}
	// The free text of a tool that sends, posts or writes text (message,
	// html_body, description, a comment's body, whatever the key is called) is
	// data: it is not read as a JSON document, a file URI or a location. The
	// keys that name a place or a party are read as everywhere (locationKey).
	if w.textTool && !t.locationKey(key) {
		if len(val) <= 256 {
			w.setting(key, strings.ReplaceAll(val, "-", "_"))
		}
		return
	}
	// A string that holds a JSON document ("arguments": "{...}") is read as
	// that document, to a bounded nesting. A document the reader cannot parse
	// is unread, not clean.
	if jsonDocument(val) {
		if w.nested >= maxNested {
			w.trunc.Hit(bounded.Depth)
			return
		}
		if inner, ok := decodeLenient([]byte(val)); ok {
			w.nested++
			w.value(key, inner, 0)
			w.nested--
			return
		}
		// A document in the shape of JSON that no lenient reading parses is one
		// the receiving server cannot parse either. It is read as text for the
		// locations it names, so a protected path in it is still judged.
		w.textPaths(key, val)
		return
	}
	fromURI := false
	if !t.contentKey[key] || !w.bodyIsData(val) {
		switch p, kind := fileURIPath(val); kind {
		case fileURIPlaced:
			val, fromURI = p, true
		case fileURIUnplaced:
			w.trunc.Hit(bounded.Nodes)
			return
		}
	}
	if len(val) <= 256 {
		// A string value can also be a setting (acl: "public-read").
		w.setting(key, strings.ReplaceAll(val, "-", "_"))
	}

	switch {
	case t.callbackKey[key] && looksURL(val):
		w.destination(key, val, RoleCallback)
	case t.redirectKey[key] || t.recipientKey[key]:
		role := RolePrimary
		if t.redirectKey[key] {
			role = RoleRedirect
		}
		// "a@x.com, b@y.com": a list of addresses in one string.
		var over bool
		parts := addressList(val, &over)
		if over {
			w.trunc.Hit(bounded.Items)
		}
		for _, part := range parts {
			if looksAddress(part) || looksURL(part) {
				w.destination(key, part, role)
			}
		}
	case t.urlKey[key] && looksURL(val):
		w.destination(key, val, RoleURL)
	}

	switch {
	case t.sqlKey[key] || (t.sqlGenericKey[key] && w.genericSQL(val)):
		if classes := ClassifySQL(val); len(classes) > 0 {
			w.add(Effect{Kind: KindSQL, Arg: key, SQL: classes})
		}
		return
	case t.codeKey[key] && w.codeTool:
		w.add(Effect{Kind: KindExec, Arg: key, Code: val})
		return
	}

	switch {
	case t.pathWrite[key] && looksPath(val):
		w.path(KindWrite, key, val)
	case t.inputKey[key] && looksPath(val):
		w.path(KindRead, key, val)
	case (t.pathRead[key] || t.pathKeySuffix(key)) && looksPath(val):
		w.path(w.pathKind(), key, val)
	case fromURI && looksPath(val):
		w.path(w.pathKind(), key, val)
	case !t.urlKey[key] && !t.redirectKey[key] && !t.recipientKey[key] && absolutePath(val):
		w.path(w.pathKind(), key, val)
	}
}

// addressList splits an address field on commas and semicolons (at most 64
// parts) and drops a display name ("Ann <ann@x.com>").
func addressList(v string, over *bool) []string {
	if !strings.ContainsAny(v, ",; <") {
		return []string{v}
	}
	var out []string
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' }) {
		part = strings.TrimSpace(part)
		if i := strings.LastIndex(part, "<"); i >= 0 && strings.HasSuffix(part, ">") {
			part = part[i+1 : len(part)-1]
		}
		if part == "" {
			continue
		}
		if len(out) >= maxItems {
			*over = true
			break
		}
		out = append(out, part)
	}
	return out
}

var rePyWord = regexp.MustCompile(`\b(True|False|None)\b`)

// pythonLiteralToJSON reads a Python-literal document (single-quoted strings,
// True/False/None), as tool servers written in Python print them.
func pythonLiteralToJSON(v string) string {
	if strings.Contains(v, `"`) {
		return v
	}
	v = strings.ReplaceAll(v, "'", `"`)
	return rePyWord.ReplaceAllStringFunc(v, func(w string) string {
		switch w {
		case "True":
			return "true"
		case "False":
			return "false"
		}
		return "null"
	})
}

// bodyIsData reports that a value under a content-style key is what the
// call writes or sends: the verb of the tool (or of the tool a proxy names) is
// a write or a send, or the tool is a text tool (a mail, chat or issue tool, a
// comment, a reply or a post: table text_tools). What a call writes or
// sends is data, whatever its spelling (a JSON file body, a bug report, a
// path in a message). A tool that neither writes nor sends reads the value
// like any argument.
func (w *walker) bodyIsData(string) bool {
	return w.m.Verb == KindWrite || w.m.Verb == KindNetSend || w.m.Family == FamilyMail || w.m.Family == FamilyChat || w.textTool
}

var rePathToken = regexp.MustCompile("(?:[A-Za-z]:[\\\\/]|~[\\\\/]|/)[^\\s\"'`,;|&<>(){}\\[\\]]{2,}")

// textPaths reads the path-shaped tokens of a text as read effects (a bounded
// number: past it the items bound is recorded).
func (w *walker) textPaths(key, val string) {
	for i, tok := range rePathToken.FindAllString(val, maxItems+1) {
		if i >= maxItems {
			w.trunc.Hit(bounded.Items)
			return
		}
		if absolutePath(tok) {
			w.path(KindRead, key, tok)
		}
	}
}

// path adds a path effect. A path past maxPath is still judged (the native
// reader normalises and matches it); the bound is recorded.
func (w *walker) path(kind Kind, key, val string) {
	if len(val) > maxPath {
		w.trunc.Hit(bounded.Bytes)
	}
	w.add(Effect{Kind: kind, Arg: key, Path: cleanPath(val)})
}

// genericSQL reports that a value under a generic key (query, q, command) is
// SQL. The key alone says nothing (a search tool has a query too); the shape
// does: a database tool (server or name in the table's db family) reads it as
// SQL, any other tool does when the value has statement shape and the tool is
// not a search or lookup.
func (w *walker) genericSQL(val string) bool {
	if w.dbTool {
		return true
	}
	return !w.searchTool && startsLikeSQL(val)
}

// pathKind is the kind of a path under a read-style key: the verb of the name
// decides, a name with no file verb reads.
func (w *walker) pathKind() Kind {
	switch w.m.Verb {
	case KindWrite, KindDelete, KindList:
		return w.m.Verb
	}
	return KindRead
}

// pathKeySuffix reports a key that ends in one of the table's path words
// (relative_path, config_file_name).
func (t *table) pathKeySuffix(key string) bool {
	for _, suf := range t.pathSuffix {
		if strings.HasSuffix(key, suf) {
			return true
		}
	}
	return false
}

func (w *walker) destination(key, val string, role Role) {
	e := Effect{Kind: KindNetSend, Arg: key, Role: role}
	if role == RoleURL && w.m.Verb != KindNetSend {
		e.Kind = KindNetFetch
	}
	switch {
	case looksURL(val):
		e.URL = val
		e.Host = hostOf(val)
	case looksAddress(val):
		e.Host = strings.ToLower(val[strings.LastIndex(val, "@")+1:])
	}
	// Only the host matters to the rules: a list of addresses at one host is one
	// effect, so a long mailing list does not exhaust the effect bound.
	id := string(e.Role) + "\x00" + string(e.Kind) + "\x00" + e.Host + "\x00" + e.URL
	if e.Host != "" {
		id = string(e.Role) + "\x00" + string(e.Kind) + "\x00" + e.Host
	}
	if w.dests[id] {
		return
	}
	if w.dests == nil {
		w.dests = map[string]bool{}
	}
	w.dests[id] = true
	w.add(e)
}

// decodeLenient decodes a JSON document the way the servers that receive it
// do: numbers of any size (1e400), and the NaN / Infinity / -Infinity literals
// Python's json module accepts. A document that holds a JSON string (a proxy
// sends its arguments that way) is decoded once more.
func decodeLenient(raw []byte) (any, bool) {
	dec := func(b []byte) (any, bool) {
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			return nil, false
		}
		if d.More() {
			return nil, false
		}
		return v, true
	}
	if v, ok := dec(raw); ok {
		return v, true
	}
	if fixed := replaceNonFinite(raw); fixed != nil {
		if v, ok := dec(fixed); ok {
			return v, true
		}
		raw = fixed
	}
	// JSON5-style documents some servers accept: comments and trailing commas.
	if fixed := stripJSONExtras(raw); fixed != nil {
		if v, ok := dec(fixed); ok {
			return v, true
		}
		raw = fixed
	}
	// Python-literal documents (single quotes, True/False/None).
	if !strings.Contains(string(raw), `"`) {
		if v, ok := dec([]byte(pythonLiteralToJSON(string(raw)))); ok {
			return v, true
		}
	}
	return nil, false
}

// stripJSONExtras removes // and /* */ comments and trailing commas outside
// strings. It returns nil when there is nothing to remove.
func stripJSONExtras(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	var quote byte
	changed := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case quote != 0:
			out = append(out, c)
			if c == '\\' && i+1 < len(raw) {
				i++
				out = append(out, raw[i])
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			out = append(out, c)
		case c == '/' && i+1 < len(raw) && raw[i+1] == '/':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			changed = true
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			end := strings.Index(string(raw[i+2:]), "*/")
			if end < 0 {
				i = len(raw)
			} else {
				i += end + 3
			}
			changed = true
		case c == ',':
			j := i + 1
			for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\n' || raw[j] == '\r') {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				changed = true
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	if !changed {
		return nil
	}
	return out
}

// replaceNonFinite replaces the bare NaN, Infinity and -Infinity literals
// outside strings with null. It returns nil when there is none.
func replaceNonFinite(raw []byte) []byte {
	var out []byte
	inStr, esc, changed := false, false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		for _, lit := range []string{"-Infinity", "Infinity", "NaN"} {
			if strings.HasPrefix(string(raw[i:min(len(raw), i+len(lit))]), lit) {
				out = append(out, "null"...)
				i += len(lit) - 1
				changed = true
				c = 0
				break
			}
		}
		if c != 0 {
			out = append(out, c)
		}
	}
	if !changed {
		return nil
	}
	return out
}

var reJSONDoc = regexp.MustCompile(`(?s)^\s*(?:\{\s*(?:["']|\})|\[\s*(?:["'\[{\]]))`)

// jsonDocument reports a string that is a JSON object or array: it starts like
// one and ends like one. Prose that merely starts with a bracket is not.
func jsonDocument(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || !reJSONDoc.MatchString(s) {
		return false
	}
	last := s[len(s)-1]
	return last == '}' || last == ']'
}

// LocalHost reports that a host is this machine.
func LocalHost(host string) bool {
	t, err := load()
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return t.localHost[host] || strings.HasSuffix(host, ".localhost")
}

// PrivateHost reports a loopback, link-local or private IP literal.
func PrivateHost(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

var (
	reAddr = regexp.MustCompile(`^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)
	reURL  = regexp.MustCompile(`^(?i:https?|ftp|s3|gs|wss?)://[^\s/]+`)
	reWin  = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	reSQL  = regexp.MustCompile(`(?i)^\s*(?:with|select|insert|update|delete|drop|truncate|alter|create|grant|revoke|explain|begin|merge|replace|call|exec|pragma|set|show)\b`)
)

func looksAddress(s string) bool  { return reAddr.MatchString(s) }
func looksURL(s string) bool      { return reURL.MatchString(s) }
func startsLikeSQL(s string) bool { return reSQL.MatchString(s) }

const (
	fileURINone = iota
	fileURIPlaced
	fileURIUnplaced
)

// fileURIPath reads a file: URI as the servers that receive it do: file:///x,
// file:/x, file://localhost/x and a loopback host, with percent escapes
// decoded and a Windows drive (file:///C:/x) as C:/x. A file: URI of another
// host (a network share) or one with no path is unplaced: the caller must not
// treat it as clean.
func fileURIPath(s string) (string, int) {
	if len(s) < 6 || !strings.EqualFold(s[:5], "file:") {
		return "", fileURINone
	}
	rest := s[5:]
	// A percent-encoded slash right after the scheme (file:%2Fhome%2Fu) is the
	// slash it encodes: decode the leading run before the shape is tested.
	n := 0
	for len(rest) >= 3*(n+1) && rest[3*n] == '%' && rest[3*n+1] == '2' && (rest[3*n+2] == 'f' || rest[3*n+2] == 'F') {
		n++
	}
	if n > 0 {
		rest = strings.Repeat("/", n) + rest[3*n:]
	}
	// Only the spellings of a file URI: file:/x, file://host/x, file:C:/x. A
	// value that merely starts with "file:" (a search pattern, "file: notes")
	// is text.
	driveForm := len(rest) >= 3 && rest[1] == ':' && (rest[2] == '/' || rest[2] == '\\') &&
		(rest[0] >= 'a' && rest[0] <= 'z' || rest[0] >= 'A' && rest[0] <= 'Z')
	if rest[0] != '/' && !driveForm {
		return "", fileURINone
	}
	host := ""
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			return "", fileURIUnplaced
		}
		host, rest = rest[:i], rest[i:]
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "", "localhost", "127.0.0.1", "::1":
	default:
		return "", fileURIUnplaced
	}
	if q := strings.IndexAny(rest, "?#"); q >= 0 {
		rest = rest[:q]
	}
	p, err := url.PathUnescape(rest)
	if err != nil {
		p = rest
	}
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	if p == "" || (p[0] != '/' && (len(p) < 2 || p[1] != ':')) {
		return "", fileURIUnplaced
	}
	return p, fileURIPlaced
}

// cleanPath collapses a leading run of slashes to one (POSIX reads //x as /x).
func cleanPath(p string) string {
	if strings.HasPrefix(p, "//") {
		return "/" + strings.TrimLeft(p, "/")
	}
	return p
}

// absolutePath reports a value that is a path by shape alone: rooted, home
// relative or a drive path. Spaces are allowed in a rooted value that has at
// least two separators ("/home/u/My Documents/x"); other shell metacharacters
// are not.
func absolutePath(s string) bool {
	if strings.ContainsAny(s, "\n\r\x00") || looksURL(s) || looksAddress(s) || strings.Contains(s, "://") {
		return false
	}
	switch {
	case strings.HasPrefix(s, "/") && len(s) > 1 && !strings.ContainsAny(s, "*{}$`;|&<>\"'"):
		if strings.Contains(s, " ") {
			return strings.Count(s, "/") >= 2
		}
		return true
	case s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`):
		return true
	case reWin.MatchString(s):
		return true
	}
	return false
}

// looksPath is absolutePath plus relative forms, for a value under a path
// key.
func looksPath(s string) bool {
	if absolutePath(s) {
		return true
	}
	if strings.ContainsAny(s, "\n\r\x00") || looksURL(s) || looksAddress(s) || strings.Contains(s, "://") {
		return false
	}
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, `.\`) ||
		strings.Contains(s, "/") || strings.Contains(s, `\`) ||
		strings.HasPrefix(s, ".") && !strings.ContainsAny(s, " ")
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// DecodeExec reports a decode that feeds an evaluator in code text.
func DecodeExec(code string) bool {
	t, err := load()
	if err != nil {
		return false
	}
	for _, re := range t.decodeExec {
		if re.MatchString(code) {
			return true
		}
	}
	return false
}

// HasFileURIArg reports that a call carries a file: URI as the value of an
// argument that names a place: a path, input or URL argument (the table's
// path, input, attachment and URL keys; the arguments an agent's own file and
// fetch tools take their target from). The gateway reads the arguments of an
// agent's own tool with the MCP walk only then. A file: URI in a text argument
// (an Edit's old_string or new_string, a Grep pattern, a prompt, a body) is
// text, as is a file: substring anywhere that is not a file URI.
func HasFileURIArg(args json.RawMessage) bool {
	t, err := load()
	if err != nil || len(args) == 0 {
		return false
	}
	root, ok := decodeLenient(args)
	if !ok {
		return false
	}
	nodes := 0
	var walk func(key string, v any, depth int) bool
	walk = func(key string, v any, depth int) bool {
		nodes++
		if nodes > maxNodes || depth > maxDepth {
			return false
		}
		switch x := v.(type) {
		case map[string]any:
			for k, item := range x {
				if walk(normKey(k), item, depth+1) {
					return true
				}
			}
		case []any:
			for i, item := range x {
				if i >= maxItems {
					return false
				}
				if walk(key, item, depth+1) {
					return true
				}
			}
		case string:
			if t.placeKey(key) {
				if _, kind := fileURIPath(strings.TrimSpace(x)); kind != fileURINone {
					return true
				}
			}
		}
		return false
	}
	return walk("", root, 0)
}
