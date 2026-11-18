package gateway

import "testing"

func TestP34fbProbeHereStringRead(t *testing.T) {
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"python here-string read", `python3 - <<< 'print(open("` + `'"'"'/home/x'"'"'` + `").read())'`, false, ""},
		{"python here-string read state", "python3 - <<< 'import os; print(open(os.path.expanduser(\"~/.defenseclaw/config.yaml\")).read())'", false, ""},
		{"python here-string read state tilde", `python3 - <<< "print(open('$HOME/.defenseclaw/config.yaml').read())"`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
