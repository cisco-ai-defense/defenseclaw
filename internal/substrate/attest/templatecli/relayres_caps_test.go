// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package templatecli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0458: a published template of an image whose root relay starts the
// agent as its own user gives the actor's container exactly SETUID, SETGID
// and KILL on Substrate (its default AUDIT_WRITE, KILL, NET_BIND_SERVICE
// minus drop plus add); the template of any other image asks for nothing.
// The dry run shows the same.
func TestPublishGivesASeparatedRelayExactlyItsCapabilities(t *testing.T) {
	for _, sep := range []bool{true, false} {
		r := newRig(t)
		r.separated = sep
		if code, out, errText := publish(t, "--template", "team/kit"); code != ExitOK {
			t.Fatalf("separated=%v: exit %d: %s %s", sep, code, out, errText)
		}
		got, err := r.fake.GetActorTemplate(context.Background(), ateapi.Ref("team", "kit"))
		if err != nil {
			t.Fatal(err)
		}
		sc := got.GetContainers()[0].GetSecurityContext()
		eff := kit.ActorCapabilities(sc.GetCapabilities().GetAdd(), sc.GetCapabilities().GetDrop())
		switch {
		case sep && strings.Join(eff, ",") != "KILL,SETGID,SETUID":
			t.Errorf("a separated relay's actor gets %v, want KILL, SETGID, SETUID", eff)
		case !sep && sc != nil:
			t.Errorf("an unseparated image's template asks for %v", sc)
		}
		_, tmpl, err := dryRunResult(&templatePlan{Atespace: "team", Name: "kit", Separated: sep}, r.image)
		if err != nil || (tmpl.GetContainers()[0].GetSecurityContext() != nil) != sep {
			t.Errorf("dry run, separated=%v: %v %v", sep, tmpl.GetContainers()[0].GetSecurityContext(), err)
		}
	}
}
