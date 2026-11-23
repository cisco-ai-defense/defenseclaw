//go:build linux || darwin

package gateway

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestDET111R1LoginShellResolvesFromPeerAccount(t *testing.T) {
	account, ok := managedHookPeerHomes.account(os.Getuid())
	if !ok || account.Home == "" || account.Shell == "" {
		t.Skip("current account home or login shell unavailable")
	}
	input := actionfacts.Input{Command: "$SHELL -c 'printf k >> ~/.ssh/authorized_keys'", ActiveHome: account.Home}
	inputShell := reflect.ValueOf(&input).Elem().FieldByName("ActiveShell")
	if !inputShell.IsValid() || !inputShell.CanSet() {
		t.Fatal("trusted active login shell is not carried in action facts")
	}
	inputShell.SetString(account.Shell)
	call, opts, ok := effectCall("claude", input)
	if !ok {
		t.Fatal("shell call was not constructed")
	}
	accountOpts := reflect.ValueOf(&opts).Elem().FieldByName("Account")
	if !accountOpts.IsValid() {
		t.Fatal("effects options do not carry the trusted account record")
	}
	shellOpt := accountOpts.FieldByName("Shell")
	if !shellOpt.IsValid() || !shellOpt.CanSet() {
		t.Fatal("effects account record does not carry login shell")
	}
	shellOpt.SetString(account.Shell)
	result := effects.Extract(call, opts)
	for _, effect := range result.Effects {
		if strings.HasSuffix(effect.Target.Path, "/.ssh/authorized_keys") && effect.TargetState == effects.TargetStateKnown {
			return
		}
	}
	t.Fatalf("login-shell write target was not known: %+v", result)
}
