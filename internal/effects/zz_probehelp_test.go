package effects

import (
	"encoding/json"
	"fmt"
	"strings"
)

func sh(c string) Call { return Call{Surface: SurfaceShell, Command: c} }

func fmtRes(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  dialect=%s fullyKnown=%v unknowns=%v n=%d\n", r.Dialect, r.FullyKnown(), r.Unknowns, len(r.Effects))
	for i, e := range r.Effects {
		t := e.Target
		tgt := t.Path
		if t.Glob != "" {
			tgt = "glob:" + t.Glob
		}
		if t.URL != "" || t.Host != "" {
			tgt += " url:" + t.URL + " host:" + t.Host
		}
		if t.Type == TargetRemote {
			tgt = "remote:" + t.Spelling
		}
		if t.Physical != "" {
			tgt += " phys:" + t.Physical
		}
		var rs []string
		for _, x := range e.Reasons {
			rs = append(rs, string(x.Code)+"/"+string(x.Scope))
		}
		src := ""
		if e.Data != nil {
			sb, _ := json.Marshal(e.Data.Sources)
			src = fmt.Sprintf(" data=%s src=%s", e.Data.Kind, sb)
		}
		fmt.Fprintf(&b, "  [%d] %s %s(%s) ts=%s rs=%s prog=%s wr=%v cond=%v reasons=%v%s\n", i+1, e.Kind, t.Type, tgt, e.TargetState, e.RoleState, e.Origin.Program, e.Origin.Wrappers, e.Cond, rs, src)
	}
	return b.String()
}
