// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"testing"
)

// GAP-0387: accepted interpreter option forms still expose the inline code
// and any network module loaded by an option before that code.
func TestGAP0387InlineOptionForms(t *testing.T) {
	tests := []struct {
		name, command string
		want          bool
	}{
		{"python attached", "python3 -c" + shellQuote(inlinePositives[0].code), true},
		{"python cluster", inlineCommand("python3", "-Ic", inlinePositives[0].code), true},
		{"node attached", "node -e" + shellQuote(inlinePositives[1].code), true},
		{"node long equals", "node --eval=" + shellQuote(inlinePositives[1].code), true},
		{"node cluster", inlineCommand("node", "-pe", inlinePositives[1].code), true},
		{"bun long equals", "bun --eval=" + shellQuote("fetch('https://example.org'); Bun.spawn(['id'])"), true},
		{"perl attached", "perl -e" + shellQuote(inlinePositives[2].code), true},
		{"perl cluster", inlineCommand("perl", "-le", inlinePositives[2].code), true},
		{"perl module attached", "perl -MIO::Socket -e 'system(\"id\")'", true},
		{"perl module separate", "perl -M IO::Socket -e 'system(\"id\")'", true},
		{"ruby attached", "ruby -e" + shellQuote(inlinePositives[3].code), true},
		{"ruby cluster", inlineCommand("ruby", "-we", inlinePositives[3].code), true},
		{"ruby module attached", "ruby -rsocket -e 'system(\"id\")'", true},
		{"ruby module separate", "ruby -r socket -e 'system(\"id\")'", true},
		{"php attached", "php -r" + shellQuote(inlinePositives[4].code), true},
		{"lua attached", "lua -e" + shellQuote(inlinePositives[5].code), true},
		{"ruby code shaped like module flag", `ruby -e '-rsocket; system("id")'`, false},
		{"module without exec", "perl -MIO::Socket -e 'print 1'", false},
		{"exec without network module", "ruby -rjson -e 'system(\"id\")'", false},
		{"benign attached code", "python3 -c" + shellQuote("print(1)"), false},
		{"benign long equals", "node --eval=" + shellQuote("console.log(1)"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := InlineCodeNetworkAndExec(srFacts(test.command)); got != test.want {
				t.Fatalf("network-and-exec=%t, want %t", got, test.want)
			}
		})
	}
}

// The original shell-recall review generated 82 accepted option-form cases.
// This keeps that class covered without pinning one literal spelling.
func TestGAP0387GeneratedOptionForms(t *testing.T) {
	type language struct{ key, program, flag, cluster, longEq, module string }
	languages := []language{
		{"python", "python3", "-c", "-Ic", "", ""},
		{"node", "node", "-e", "-pe", "--eval=", ""},
		{"bun", "bun", "-e", "", "--eval=", ""},
		{"deno", "deno", "eval", "", "", ""},
		{"perl", "perl", "-e", "-le", "", "-M"},
		{"ruby", "ruby", "-e", "-we", "", "-r"},
		{"php", "php", "-r", "", "", ""},
		{"lua", "lua", "-e", "", "", ""},
	}
	loader := map[string]string{
		"python": "__import__(%q)", "node": "require(%q)", "bun": "require(%q)",
		"ruby": "require %q", "lua": "require(%q)",
	}
	loaderNetwork := map[string]string{
		"python": "socket", "node": "net", "bun": "net", "ruby": "socket", "lua": "socket",
	}
	call := func(name string) string { return name + "(1)" }
	positives := 0
	for _, lang := range languages {
		row := inlineCapabilityTable[lang.key]
		var bodies []string
		for i := 0; i < 4; i++ {
			bodies = append(bodies, call(row.network[i%len(row.network)])+"; "+
				call(row.exec[(i*3)%len(row.exec)])+";")
		}
		if format, ok := loader[lang.key]; ok {
			for i := 0; i < 2; i++ {
				bodies = append(bodies, fmt.Sprintf(format, loaderNetwork[lang.key])+"; "+
					call(row.exec[(i*2+1)%len(row.exec)])+";")
			}
		}
		check := func(name, command, benign string) {
			t.Helper()
			if !InlineCodeNetworkAndExec(srFacts(command)) {
				t.Errorf("%s/%s did not report", lang.key, name)
			}
			if InlineCodeNetworkAndExec(srFacts(benign)) {
				t.Errorf("%s/%s benign twin reported", lang.key, name)
			}
			positives++
		}
		for i, body := range bodies {
			name := fmt.Sprintf("%d", i)
			if lang.key != "deno" {
				check("attached/"+name,
					lang.program+" "+lang.flag+shellQuote(body),
					lang.program+" "+lang.flag+shellQuote("1"))
			}
			if lang.cluster != "" {
				check("cluster/"+name,
					inlineCommand(lang.program, lang.cluster, body),
					inlineCommand(lang.program, lang.cluster, "1"))
			}
			if lang.longEq != "" {
				check("long-eq/"+name,
					lang.program+" "+lang.longEq+shellQuote(body),
					lang.program+" "+lang.longEq+shellQuote("1"))
			}
		}
		if lang.module != "" {
			for _, name := range row.network {
				check("module/"+name,
					lang.program+" "+lang.module+name+" "+lang.flag+" "+shellQuote(call(row.exec[0])+";"),
					lang.program+" "+lang.module+name+" "+lang.flag+" "+shellQuote("1"))
			}
		}
	}
	if positives != 82 {
		t.Fatalf("generated %d positive option forms, want 82", positives)
	}
}
