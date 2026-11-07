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

func plistAnswer(records ...string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\">\n<array>\n" + strings.Join(records, "") + "</array>\n</plist>\n"
}

var (
	recordAlice = plistRecord([]string{"502"}, []string{"/Users/shared"}, []string{"alice"})
	recordCorp  = plistRecord([]string{"1000501"}, []string{"/Users/corp", "/Users/shared"}, []string{"corp", "corp.alias"})
	recordBob   = plistRecord([]string{"503"}, []string{"/Users/bob"}, []string{"bob"})
)

func plistResult(s string) func() (commandResult, error) {
	return func() (commandResult, error) { return commandResult{stdout: []byte(s)}, nil }
}

// The accounts at a home are read from one structured answer across the whole
// search policy: a local account and a directory account both answer, other
// homes are not held, and an answer that is not a complete plist whose
// records all carry the fields is an error so the home is never taken for free.
func TestDSCLHomeAccounts(t *testing.T) {
	const home = "/Users/shared"
	cases := []struct {
		name    string
		answer  string
		want    []HomeAccount
		wantErr bool
	}{
		{"one holder", plistAnswer(recordAlice, recordBob), []HomeAccount{{"alice", 502}}, false},
		{"a local and a directory holder", plistAnswer(recordAlice, recordBob, recordCorp), []HomeAccount{{"alice", 502}, {"corp", 1000501}}, false},
		{"no holder among other records", plistAnswer(recordBob), nil, false},
		{"no records at all", plistAnswer(), nil, false},
		{"an empty array element", "<plist version=\"1.0\"><array/></plist>", nil, false},
		{"a home that only shares a prefix", plistAnswer(plistRecord([]string{"504"}, []string{"/Users/shared2"}, []string{"dan"})), nil, false},
		{"a negative uid", plistAnswer(plistRecord([]string{"-2"}, []string{home}, []string{"nobody"})), []HomeAccount{{"nobody", -2}}, false},

		{"an empty answer", "", nil, true},
		{"the old text rows", "alice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n", nil, true},
		{"an indented text row", "  alice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n", nil, true},
		{"an indented row after a valid one", "carol\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n  bob\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n", nil, true},
		{"an indented line with no record", "   something\n", nil, true},
		{"a closing parenthesis alone", ")\n", nil, true},
		{"text after the plist", plistAnswer(recordBob) + "more\n", nil, true},
		{"a second plist after the first", plistAnswer(recordBob) + plistAnswer(recordAlice), nil, true},
		{"a root that is not a plist", strings.ReplaceAll(plistAnswer(recordAlice), "plist", "other"), nil, true},
		{"a dict outside the array", "<plist><dict></dict></plist>", nil, true},
		{"an item that is not a dict", "<plist><array><string>alice</string></array></plist>", nil, true},
		{"a record with no uid", plistAnswer(plistRecord(nil, []string{home}, []string{"alice"})), nil, true},
		{"a record with no home", plistAnswer(recordAlice, plistRecord([]string{"503"}, nil, []string{"bob"})), nil, true},
		{"a record with no name", plistAnswer(plistRecord([]string{"502"}, []string{home}, nil)), nil, true},
		{"a record with an empty value list", plistAnswer(plistRecord([]string{"502"}, []string{}, []string{"alice"})), nil, true},
		{"a record with two uids", plistAnswer(plistRecord([]string{"502", "503"}, []string{home}, []string{"alice"})), nil, true},
		{"a uid that is not a number", plistAnswer(plistRecord([]string{"abc"}, []string{home}, []string{"alice"})), nil, true},
		{"an empty home string", plistAnswer(plistRecord([]string{"502"}, []string{" "}, []string{"alice"})), nil, true},
		{"a name that is not an account name", plistAnswer(plistRecord([]string{"502"}, []string{home}, []string{"a/b"})), nil, true},
		{"text in an otherwise empty record array", "<plist><array>unknown holder</array></plist>", nil, true},
		{"text in the plist beside the array", "<plist>unknown holder<array/></plist>", nil, true},
		{"text among the records", strings.Replace(plistAnswer(recordAlice), "<array>\n", "<array>\nunknown holder\n", 1), nil, true},
		{"text inside a record", plistAnswer(strings.Replace(recordAlice, "<dict>\n", "<dict>\nunknown field\n", 1)), nil, true},
		{"text inside a value array", plistAnswer(strings.Replace(recordAlice, "<string>/Users/shared</string>", "<string>/Users/shared</string>unknown second home", 1)), nil, true},
		{"an element inside a key", plistAnswer(strings.Replace(recordAlice, "<key>dsAttrTypeStandard:UniqueID</key>", "<key>dsAttrTypeStandard:UniqueID<x/></key>", 1)), nil, true},
		{"white space and a comment between elements", strings.Replace(plistAnswer(recordAlice, recordBob), "<array>\n", "<array>\n  <!-- note -->\n  ", 1), []HomeAccount{{"alice", 502}}, false},
		{"a key with no value", strings.Replace(plistAnswer(recordAlice), "<array>\n\t\t\t<string>502</string>\n\t\t</array>", "", 1), nil, true},
		{"a field repeated in one record", strings.Replace(recordAlice, "</dict>", plistRecord([]string{"1"}, []string{home}, []string{"x"})[len("\t<dict>\n"):], 1), nil, true},
	}
	for _, tc := range cases {
		answer := tc.answer
		if strings.HasPrefix(answer, "\t<dict>") {
			answer = plistAnswer(answer)
		}
		got, err := dsclHomeAccounts(home, plistResult(answer))
		if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, %v; want %v, error=%v", tc.name, got, err, tc.want, tc.wantErr)
		}
	}
}

// Every proper prefix of a valid answer is an error: output cut anywhere never
// turns into a shorter list of holders or an empty one.
func TestDSCLHomeAccountsTruncatedAnswerIsAnError(t *testing.T) {
	full := plistAnswer(recordCorp, recordBob, recordAlice)
	if got, err := dsclHomeAccounts("/Users/shared", plistResult(full)); err != nil || len(got) != 2 {
		t.Fatalf("the full answer: got %v, %v", got, err)
	}
	for cut := 0; cut < len(full)-1; cut++ {
		prefix := full[:cut]
		if strings.TrimSpace(full[cut:]) == "" {
			continue
		}
		if got, err := dsclHomeAccounts("/Users/shared", plistResult(prefix)); err == nil {
			t.Fatalf("answer cut at %d bytes was accepted as %v", cut, got)
		}
	}
}

func TestDSCLHomeAccountsFailuresAreErrors(t *testing.T) {
	if _, err := dsclHomeAccounts("/Users/shared", func() (commandResult, error) { return commandResult{}, errors.New("timed out") }); err == nil {
		t.Error("a failed read must be an error")
	}
	if _, err := dsclHomeAccounts("/Users/shared", func() (commandResult, error) {
		return commandResult{stdout: []byte(plistAnswer(recordBob)), exitCode: 14}, nil
	}); err == nil {
		t.Error("a non-zero exit must be an error, whatever it printed")
	}
	var many []string
	for i := 0; i <= homeAccountsLimit; i++ {
		many = append(many, plistRecord([]string{fmt.Sprint(600 + i)}, []string{"/Users/shared"}, []string{fmt.Sprintf("u%d", i)}))
	}
	if _, err := dsclHomeAccounts("/Users/shared", plistResult(plistAnswer(many...))); err == nil {
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
