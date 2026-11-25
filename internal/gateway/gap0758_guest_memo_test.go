package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestTrustedDispatchMemoKeysGuestHomePlaces (substrate-1 GAP-0758): a
// Substrate actor's request reads the kit's home places (homePlaceView). The
// dispatch memo answers a repeat that reads the same places, read through
// another view of them, and judges again a request that reads other places;
// each answer is the one the call gets without the memo.
func TestTrustedDispatchMemoKeysGuestHomePlaces(t *testing.T) {
	gap0437Server(t, gap0437Packs[1], "openclaw", "action")
	home := t.TempDir()
	command := "cp -r ~/.ssh ~/sshbak"
	view := func(place string) homePlaceView {
		return (&substrateGuestClaims{homePlaces: map[string]bool{place: true}}).homePlaceView()
	}
	request := func(places homePlaceView) trustedActionRequest {
		return trustedActionRequest{
			Input:      actionfacts.Input{Tool: "exec", Command: command, CWD: home, ActiveHome: home},
			LegacyText: command, Connector: "openclaw", EnforcementCapable: true, StrictPolicy: true,
			budget: newTrustedActionBudget(false), guestHomePlaces: places,
		}
	}
	withoutMemo := func(places homePlaceView) []RuleFinding {
		trustedDispatchMemoOff.Store(true)
		defer trustedDispatchMemoOff.Store(false)
		return dispatchTrustedAction(context.Background(), request(places))
	}
	private, other := view(home+"/sshbak"), view(home+"/elsewhere")
	wantPrivate, wantOther := withoutMemo(private), withoutMemo(other)

	memo := &trustedDispatchMemo{}
	ctx := context.WithValue(context.Background(), trustedDispatchMemoKey{}, memo)
	bucket := "exec\x00" + command + "\x00" + command
	shared := request(private)
	judge := func(places homePlaceView) ([]RuleFinding, int) {
		before := len(memo.entries[bucket])
		call := shared
		call.guestHomePlaces = places
		findings := dispatchTrustedAction(ctx, call)
		return findings, len(memo.entries[bucket]) - before
	}
	first, stored := judge(private)
	if stored == 0 {
		t.Fatal("the memo kept no run of the call; the test needs a call the memo keeps")
	}
	again, stored := judge(view(home + "/sshbak"))
	if stored != 0 {
		t.Errorf("the memo judged again a repeat that reads the same home places (%d new runs)", stored)
	}
	elsewhere, stored := judge(other)
	if stored == 0 {
		t.Error("the memo answered a request that reads other home places with another request's run")
	}
	for _, c := range []struct {
		name      string
		got, want []RuleFinding
	}{{"first", first, wantPrivate}, {"repeat", again, wantPrivate}, {"other places", elsewhere, wantOther}} {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: memo answer %+v, without the memo %+v", c.name, c.got, c.want)
		}
	}
}
