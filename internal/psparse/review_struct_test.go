package psparse

import (
	"strings"
	"testing"
)

// TestRevStructure: more commands/parameters PowerShell sees that psparse loses (checked against pwsh 7.7).
func TestRevStructure(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"hashtable_value_command", `$h = @{ a = Remove-Item C:\x }`, []string{"remove-item"}},
		{"hashtable_value_pipeline", `$h = @{ a = Get-Item x | Remove-Item }`, []string{"get-item", "remove-item"}},
		{"comment_after_operator", `Write-Output %#; Remove-Item C:\x`, []string{"write-output", "remove-item"}},
		{"comment_after_variable", `Write-Output $x#; Remove-Item C:\x`, []string{"write-output", "remove-item"}},
		{"comment_after_dash", `Write-Output -#; Remove-Item C:\x`, []string{"write-output", "remove-item"}},
		{"block_comment_splits_args", `Remove-Item <#c#> C:\Windows -Recurse`, []string{"remove-item"}},
		{"dot_arg_target", `Remove-Item . -Recurse -Force`, []string{"remove-item"}},
		{"module_qualified_iex", `Microsoft.PowerShell.Utility\Invoke-Expression 'Remove-Item C:\x'`, []string{"microsoft.powershell.utility\\invoke-expression"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := revNames(c.src)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				var ds []string
				for _, cm := range revCmds(c.src) {
					ds = append(ds, revDesc(cm))
				}
				t.Errorf("commands=%q want %q  [%s]", got, c.want, strings.Join(ds, " | "))
			}
		})
	}
	// parameters inside ( ) parsed as operators
	params := []struct{ name, src, want string }{
		{"paren_param_f", `$r = (Remove-Item C:\x -f)`, "f"},
		{"paren_param_in", `$r = (Get-ChildItem C:\x -in y)`, "in"},
		{"subexpr_param_join", `$r = $(Copy-Item a -join b)`, "join"},
		{"endash_param", `Remove-Item –Recurse C:\x`, "recurse"},
	}
	for _, c := range params {
		t.Run(c.name, func(t *testing.T) {
			cs := revCmds(c.src)
			for _, cm := range cs {
				for _, el := range cm.Elements {
					if p, ok := el.(*Parameter); ok && strings.EqualFold(p.Name, c.want) {
						return
					}
				}
			}
			var ds []string
			for _, cm := range cs {
				ds = append(ds, revDesc(cm))
			}
			t.Errorf("parameter -%s missing  [%s]", c.want, strings.Join(ds, " | "))
		})
	}
}
