//go:build !windows

package unixidentity

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// plistRecord renders one record the way dscl -plist -readall does.
func plistRecord(uids []string, homes []string, names []string) string {
	field := func(key string, values []string) string {
		if values == nil {
			return ""
		}
		var b strings.Builder
		b.WriteString("\t\t<key>dsAttrTypeStandard:" + key + "</key>\n\t\t<array>\n")
		for _, v := range values {
			b.WriteString("\t\t\t<string>" + v + "</string>\n")
		}
		b.WriteString("\t\t</array>\n")
		return b.String()
	}
	return "\t<dict>\n" + field("NFSHomeDirectory", homes) + field("RecordName", names) + field("UniqueID", uids) + "\t</dict>\n"
}

// plistAnswer is what dscl -plist prints for the given records.
func plistAnswer(records ...string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\">\n<array>\n" + strings.Join(records, "") + "</array>\n</plist>\n"
}

// jsonRecord and jsonAnswer are what `plutil -convert json -o - -` prints for
// the same records: an array of objects whose values are arrays of strings.
func jsonRecord(uids []string, homes []string, names []string) string {
	list := func(values []string) string {
		quoted := make([]string, len(values))
		for i, v := range values {
			quoted[i] = fmt.Sprintf("%q", v)
		}
		return "[" + strings.Join(quoted, ",") + "]"
	}
	var fields []string
	for _, f := range []struct {
		key    string
		values []string
	}{{"NFSHomeDirectory", homes}, {"RecordName", names}, {"UniqueID", uids}} {
		if f.values != nil {
			fields = append(fields, fmt.Sprintf("%q:%s", "dsAttrTypeStandard:"+f.key, list(f.values)))
		}
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func jsonAnswer(records ...string) string { return "[" + strings.Join(records, ",") + "]\n" }

var (
	jsonAlice = jsonRecord([]string{"502"}, []string{"/Users/shared"}, []string{"alice"})
	jsonCorp  = jsonRecord([]string{"1000501"}, []string{"/Users/corp", "/Users/shared"}, []string{"corp", "corp.alias"})
	jsonBob   = jsonRecord([]string{"503"}, []string{"/Users/bob"}, []string{"bob"})
	dsclAlice = plistRecord([]string{"502"}, []string{"/Users/shared"}, []string{"alice"})
	dsclBob   = plistRecord([]string{"503"}, []string{"/Users/bob"}, []string{"bob"})
)

func dsclResult(s string) func() (commandResult, error) {
	return func() (commandResult, error) { return commandResult{stdout: []byte(s)}, nil }
}

// plutilStub stands for the system tool: it records what was piped in and
// answers with the recorded output and exit code.
type plutilStub struct {
	input  string
	called bool
	out    string
	exit   int
	err    error
}

func (p *plutilStub) convert(plist []byte) (commandResult, error) {
	p.input, p.called = string(plist), true
	return commandResult{stdout: []byte(p.out), exitCode: p.exit}, p.err
}

// The accounts at a home are read from the system tool's JSON of one dscl
// plist answer across the search policy: a local account and a directory
// account both answer and other homes are not held.
func TestDSCLHomeAccounts(t *testing.T) {
	const home = "/Users/shared"
	cases := []struct {
		name string
		json string
		want []HomeAccount
	}{
		{"one holder", jsonAnswer(jsonAlice, jsonBob), []HomeAccount{{"alice", 502}}},
		{"a local and a directory holder", jsonAnswer(jsonAlice, jsonBob, jsonCorp), []HomeAccount{{"alice", 502}, {"corp", 1000501}}},
		{"no holder among other records", jsonAnswer(jsonBob), nil},
		{"no records at all", jsonAnswer(), nil},
		{"pretty printed output", "[\n  {\n    \"dsAttrTypeStandard:NFSHomeDirectory\" : [\n      \"/Users/shared\"\n    ],\n    \"dsAttrTypeStandard:RecordName\" : [\n      \"alice\"\n    ],\n    \"dsAttrTypeStandard:UniqueID\" : [\n      \"502\"\n    ]\n  }\n]\n", []HomeAccount{{"alice", 502}}},
		{"a home that only shares a prefix", jsonAnswer(jsonRecord([]string{"504"}, []string{"/Users/shared2"}, []string{"dan"})), nil},
		{"a negative uid", jsonAnswer(jsonRecord([]string{"-2"}, []string{home}, []string{"nobody"})), []HomeAccount{{"nobody", -2}}},
		{"an extra field that is an array of strings", strings.Replace(jsonAnswer(jsonAlice), "}", `,"dsAttrTypeStandard:Other":["x"]}`, 1), []HomeAccount{{"alice", 502}}},
	}
	for _, tc := range cases {
		stub := &plutilStub{out: tc.json}
		dscl := plistAnswer(dsclAlice, dsclBob)
		got, err := dsclHomeAccounts(home, dsclResult(dscl), stub.convert)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, %v; want %v", tc.name, got, err, tc.want)
		}
		if !stub.called || stub.input != dscl {
			t.Errorf("%s: the converter must be given the dscl answer unchanged, got %q", tc.name, stub.input)
		}
	}
}

// A dscl answer the system tool refuses to convert (non-zero exit: another
// document's doctype, a declaration without a version or with an unknown
// field, text before or after the plist, the old text rows, an empty answer,
// a cut answer) is an error and never an empty list or a shorter one. The
// plist itself is not read by this code.
func TestDSCLHomeAccountsRefusedConversionIsAnError(t *testing.T) {
	const home = "/Users/shared"
	plain := plistAnswer(dsclAlice, dsclBob)
	answers := map[string]string{
		"an empty answer":                     "",
		"the old text rows":                   "alice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n",
		"text after the plist":                plain + "more\n",
		"warning text before the plist":       "directory warning: truncated holder list\n<plist><array/></plist>",
		"a doctype named like plist":          "<!DOCTYPE plistBackup>\n<plist><array/></plist>",
		"a doctype with a suffix":             "<!DOCTYPE plist:extra>\n<plist><array/></plist>",
		"a doctype of another document":       "<!DOCTYPE html>\n<plist><array/></plist>",
		"a version of garbage":                "<?xml version=garbage?>\n<plist><array/></plist>",
		"a declaration with no version":       "<?xml encoding=\"UTF-8\"?>\n<plist><array/></plist>",
		"a declaration with an unknown field": "<?xml version=\"1.0\" other=\"x\"?>\n<plist><array/></plist>",
		"two declarations":                    "<?xml version=\"1.0\"?>\n<?xml version=\"1.0\"?>\n<plist><array/></plist>",
		"a second plist after the first":      plain + plain,
		"a cut answer":                        plain[:len(plain)/2],
	}
	for name, dscl := range answers {
		stub := &plutilStub{exit: 1}
		if got, err := dsclHomeAccounts(home, dsclResult(dscl), stub.convert); err == nil {
			t.Errorf("%s: accepted as %v", name, got)
		}
		if !stub.called || stub.input != dscl {
			t.Errorf("%s: the converter must be given the dscl answer unchanged, got %q", name, stub.input)
		}
	}
	stub := &plutilStub{err: errors.New("timed out")}
	if _, err := dsclHomeAccounts(home, dsclResult(plain), stub.convert); err == nil {
		t.Error("a conversion that did not run must be an error")
	}
}

// The tool's output must be exactly the expected structure with the field
// types: anything else leaves the holders unknown and is an error.
func TestDSCLHomeAccountsUnexpectedJSONIsAnError(t *testing.T) {
	const home = "/Users/shared"
	cases := map[string]string{
		"no output":                        "",
		"not json":                         "alice\t\tNFSHomeDirectory\n",
		"text after the array":             jsonAnswer(jsonAlice) + "more\n",
		"a second array after the first":   jsonAnswer(jsonAlice) + jsonAnswer(jsonBob),
		"an object, not an array":          jsonAlice,
		"an array of arrays":               `[[]]`,
		"an item that is not an object":    `["alice"]`,
		"null":                             `null`,
		"a null item":                      `[null]`,
		"a record with no uid":             jsonAnswer(jsonRecord(nil, []string{home}, []string{"alice"})),
		"a record with no home":            jsonAnswer(jsonAlice, jsonRecord([]string{"503"}, nil, []string{"bob"})),
		"a record with no name":            jsonAnswer(jsonRecord([]string{"502"}, []string{home}, nil)),
		"a record with an empty home list": jsonAnswer(jsonRecord([]string{"502"}, []string{}, []string{"alice"})),
		"a record with two uids":           jsonAnswer(jsonRecord([]string{"502", "503"}, []string{home}, []string{"alice"})),
		"a uid that is not a number":       jsonAnswer(jsonRecord([]string{"abc"}, []string{home}, []string{"alice"})),
		"a uid that is a json number":      `[{"dsAttrTypeStandard:UniqueID":502,"dsAttrTypeStandard:NFSHomeDirectory":["/Users/shared"],"dsAttrTypeStandard:RecordName":["alice"]}]`,
		"a value that is a string":         `[{"dsAttrTypeStandard:UniqueID":"502","dsAttrTypeStandard:NFSHomeDirectory":"/Users/shared","dsAttrTypeStandard:RecordName":["alice"]}]`,
		"a value that is null":             `[{"dsAttrTypeStandard:UniqueID":["502"],"dsAttrTypeStandard:NFSHomeDirectory":null,"dsAttrTypeStandard:RecordName":["alice"]}]`,
		"a value with a non-string item":   `[{"dsAttrTypeStandard:UniqueID":["502"],"dsAttrTypeStandard:NFSHomeDirectory":["/Users/shared",1],"dsAttrTypeStandard:RecordName":["alice"]}]`,
		"an empty home string":             jsonAnswer(jsonRecord([]string{"502"}, []string{" "}, []string{"alice"})),
		"a name that is not an account":    jsonAnswer(jsonRecord([]string{"502"}, []string{home}, []string{"a/b"})),
		"a field repeated in one record":   `[{"dsAttrTypeStandard:UniqueID":["502"],"dsAttrTypeStandard:UniqueID":["1"],"dsAttrTypeStandard:NFSHomeDirectory":["/Users/shared"],"dsAttrTypeStandard:RecordName":["alice"]}]`,
		"an extra field of another type":   `[{"dsAttrTypeStandard:UniqueID":["502"],"dsAttrTypeStandard:NFSHomeDirectory":["/Users/shared"],"dsAttrTypeStandard:RecordName":["alice"],"x":1}]`,
		"an unclosed array":                `[` + jsonAlice,
		"a trailing comma":                 `[` + jsonAlice + `,]`,
		"a record after a bad record":      `[{},` + jsonAlice + `]`,
	}
	for name, out := range cases {
		stub := &plutilStub{out: out}
		if got, err := dsclHomeAccounts(home, dsclResult(plistAnswer(dsclAlice)), stub.convert); err == nil {
			t.Errorf("%s: accepted as %v", name, got)
		}
	}
}

// Every proper prefix of a valid JSON answer is an error: output cut anywhere
// never turns into a shorter list of holders or an empty one.
func TestDSCLHomeAccountsTruncatedOutputIsAnError(t *testing.T) {
	full := jsonAnswer(jsonCorp, jsonBob, jsonAlice)
	stub := &plutilStub{out: full}
	if got, err := dsclHomeAccounts("/Users/shared", dsclResult("x"), stub.convert); err != nil || len(got) != 2 {
		t.Fatalf("the full answer: got %v, %v", got, err)
	}
	for cut := 0; cut < len(full)-1; cut++ {
		if strings.TrimSpace(full[cut:]) == "" {
			continue
		}
		stub := &plutilStub{out: full[:cut]}
		if got, err := dsclHomeAccounts("/Users/shared", dsclResult("x"), stub.convert); err == nil {
			t.Fatalf("output cut at %d bytes was accepted as %v", cut, got)
		}
	}
}

func TestDSCLHomeAccountsFailuresAreErrors(t *testing.T) {
	good := &plutilStub{out: jsonAnswer(jsonBob)}
	if _, err := dsclHomeAccounts("/Users/shared", func() (commandResult, error) { return commandResult{}, errors.New("timed out") }, good.convert); err == nil {
		t.Error("a failed read must be an error")
	}
	if good.called {
		t.Error("a failed read must not be converted")
	}
	if _, err := dsclHomeAccounts("/Users/shared", func() (commandResult, error) {
		return commandResult{stdout: []byte(plistAnswer(dsclBob)), exitCode: 14}, nil
	}, good.convert); err == nil {
		t.Error("a non-zero exit must be an error, whatever it printed")
	}
	if good.called {
		t.Error("a failed dscl must not be converted")
	}
	var many []string
	for i := 0; i <= homeAccountsLimit; i++ {
		many = append(many, jsonRecord([]string{fmt.Sprint(600 + i)}, []string{"/Users/shared"}, []string{fmt.Sprintf("u%d", i)}))
	}
	tooMany := &plutilStub{out: jsonAnswer(many...)}
	if _, err := dsclHomeAccounts("/Users/shared", dsclResult("x"), tooMany.convert); err == nil {
		t.Error("more holders than the bound must be an error")
	}
}

// The firmlinked /private spelling of a system path is the same home.
func TestComparableHome(t *testing.T) {
	for _, tc := range [][2]string{
		{"/private/var/root", "/var/root"},
		{"/var/root/", "/private/var/root"},
		{"/private/tmp", "/tmp"},
		{"/Users/a//b", "/Users/a/b"},
	} {
		if comparableHome(tc[0]) != comparableHome(tc[1]) {
			t.Errorf("%q and %q should be one home", tc[0], tc[1])
		}
	}
	if comparableHome("/private/variable") == comparableHome("/variable") {
		t.Error("a name that only starts like /var is not /var")
	}
}
