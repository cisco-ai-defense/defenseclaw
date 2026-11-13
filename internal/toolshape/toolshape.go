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
)

//go:embed shapes.yaml
var shapesYAML []byte

// Bounds on what one call may contribute.
const (
	maxDepth   = 5
	maxEffects = 48
	maxString  = 64 << 10
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
)

// Effect is one thing a call does. Reason is always "mcp_semantics": the
// target is read from the arguments, the kind is a guess from names.
type Effect struct {
	Kind    Kind
	Arg     string // the argument the effect came from
	Path    string // read, write, delete, list
	URL     string // net_fetch, net_send
	Host    string // net_fetch, net_send (lower-case, no port)
	Addr    string // a recipient address or channel
	Role    Role
	SQL     []SQLClass // sql
	Setting string     // setting: what the change does
	Code    string     // exec: the code text (bounded)
	DB      string     // sql: the database the call names, lower-case
	Reason  string
}

// Mapping is the reading of one call.
type Mapping struct {
	Server  string
	Name    string
	Family  Family
	Verb    Kind // the verb of the tool name; "" when the name has none
	Effects []Effect
	// Known reports that the name or the arguments placed the call in a
	// family, a verb or at least one effect. A call with Known false stays
	// unknown.
	Known bool
	// Truncated reports that a bound cut the walk short.
	Truncated bool
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

// Map reads one call. args is the JSON argument object; anything else (an
// array, a string) yields a mapping with no effects.
func Map(tool string, args json.RawMessage) (Mapping, error) {
	t, err := load()
	if err != nil {
		return Mapping{}, err
	}
	server, name := SplitName(tool)
	m := Mapping{Server: server, Name: name}
	toks := Tokens(name)
	if fam, ok := t.Servers[server]; ok {
		m.Family = Family(fam)
	}
	if m.Family == FamilyUnknown {
		for _, tok := range append([]string{server}, toks...) {
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
	codeTool := m.Family == FamilyCode
	for _, tok := range toks {
		if t.codeToken[tok] {
			codeTool = true
		}
	}
	var obj map[string]any
	if len(args) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(args)))
		dec.UseNumber()
		if err := dec.Decode(&obj); err != nil {
			obj = nil
		}
	}
	w := walker{t: t, m: &m, codeTool: codeTool, dbTool: m.Family == FamilyDB}
	w.object(obj, 0, "")
	m.Known = m.Family != FamilyUnknown || m.Verb != "" || len(m.Effects) > 0
	return m, nil
}

type walker struct {
	t        *table
	m        *Mapping
	codeTool bool
	dbTool   bool
	db       string
}

func (w *walker) add(e Effect) {
	if len(w.m.Effects) >= maxEffects {
		w.m.Truncated = true
		return
	}
	e.Reason = "mcp_semantics"
	w.m.Effects = append(w.m.Effects, e)
}

func (w *walker) object(obj map[string]any, depth int, parent string) {
	if depth > maxDepth {
		w.m.Truncated = true
		return
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch normKey(k) {
		case "database", "db", "dbname", "database_name", "db_name":
			if s, ok := obj[k].(string); ok && w.db == "" {
				w.db = strings.ToLower(strings.TrimSpace(s))
			}
		}
	}
	for _, rawKey := range keys {
		w.value(normKey(rawKey), obj[rawKey], depth, parent)
	}
}

func (w *walker) value(key string, v any, depth int, parent string) {
	switch x := v.(type) {
	case map[string]any:
		w.object(x, depth+1, key)
	case []any:
		for i, item := range x {
			if i >= 64 {
				w.m.Truncated = true
				return
			}
			if it, ok := item.(map[string]any); ok {
				w.operationObject(it)
				w.object(it, depth+1, key)
				continue
			}
			w.value(key, item, depth+1, parent)
		}
	case string:
		w.str(key, x, parent)
	case bool:
		w.setting(key, fmt.Sprint(x))
	}
}

// operationObject reads {"op": "disable_mfa"} entries of an operations list.
func (w *walker) operationObject(it map[string]any) {
	for _, k := range []string{"op", "operation", "action", "type"} {
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

func (w *walker) str(key, val, parent string) {
	if len(val) > maxString {
		val = val[:maxString]
		w.m.Truncated = true
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	t := w.t
	// A string value can also be a setting (acl: "public-read").
	w.setting(key, strings.ReplaceAll(val, "-", "_"))

	switch {
	case t.redirectKey[key]:
		w.destination(key, val, RoleRedirect)
	case t.recipientKey[key] && (looksAddress(val) || looksURL(val)):
		w.destination(key, val, RolePrimary)
	case t.urlKey[key] && looksURL(val):
		w.destination(key, val, RoleURL)
	}

	switch {
	case t.sqlKey[key] || (t.sqlGenericKey[key] && (w.dbTool || startsLikeSQL(val))):
		if classes := ClassifySQL(val); len(classes) > 0 {
			w.add(Effect{Kind: KindSQL, Arg: key, SQL: classes, DB: w.db})
		}
		return
	case t.codeKey[key] && w.codeTool:
		w.add(Effect{Kind: KindExec, Arg: key, Code: val})
		return
	}

	switch {
	case t.pathWrite[key] && looksPath(val):
		w.add(Effect{Kind: KindWrite, Arg: key, Path: val})
	case t.pathRead[key] && looksPath(val):
		w.add(Effect{Kind: w.pathKind(), Arg: key, Path: val})
	case !t.urlKey[key] && !t.redirectKey[key] && !t.recipientKey[key] && absolutePath(val):
		w.add(Effect{Kind: w.pathKind(), Arg: key, Path: val})
	}
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
		e.Addr = strings.ToLower(val)
		e.Host = e.Addr[strings.LastIndex(e.Addr, "@")+1:]
	default:
		e.Addr = val
	}
	w.add(e)
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

// absolutePath reports a value that is a path by shape alone: rooted, home
// relative or a drive path.
func absolutePath(s string) bool {
	if len(s) > 1024 || strings.ContainsAny(s, "\n\r\x00") || strings.HasPrefix(s, "//") ||
		looksURL(s) || looksAddress(s) {
		return false
	}
	switch {
	case strings.HasPrefix(s, "/") && len(s) > 1 && !strings.ContainsAny(s, " *{}$`;|&<>\"'"):
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
	if strings.ContainsAny(s, "\n\r\x00") || len(s) > 1024 || looksURL(s) || looksAddress(s) || strings.Contains(s, "://") {
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
	if len(code) > maxString {
		code = code[:maxString]
	}
	for _, re := range t.decodeExec {
		if re.MatchString(code) {
			return true
		}
	}
	return false
}

// Native reports a tool name that has its own typed path (shell, the file and
// web tools of the agents). The mapper does not read those: the shell and
// file-tool rules already do.
func Native(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "bash", "read", "write", "edit", "multiedit", "glob", "grep", "webfetch", "websearch",
		"todowrite", "task", "notebookedit", "toolsearch", "exitplanmode", "askuserquestion",
		"skill", "killshell", "bashoutput", "slashcommand", "apply_patch", "applypatch":
		return true
	}
	return false
}
