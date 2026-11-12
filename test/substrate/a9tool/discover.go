// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type objMeta struct {
	Atespace   string    `json:"atespace"`
	Name       string    `json:"name"`
	UID        string    `json:"uid"`
	CreateTime time.Time `json:"createTime"`
}

type templateList struct {
	ActorTemplates []struct {
		Metadata   objMeta `json:"metadata"`
		Containers []struct {
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"actorTemplates"`
}

type actorList struct {
	Actors []struct {
		Metadata      objMeta `json:"metadata"`
		ActorTemplate struct {
			Atespace string `json:"atespace"`
			Name     string `json:"name"`
		} `json:"actorTemplate"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
		State string `json:"state"`
	} `json:"actors"`
}

// discover reads `kubectl ate get actor-template -o json` and `get actor -o
// json` (any number of each), verifies every template image, and prints one
// JSON line per signal and per template_unverified event. It is the lane's
// stand-in for the controller's inventory loop (A3 owns the real one).
func discover(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	var templates, actors, managed, plain multi
	fs.Var(&templates, "templates", "kubectl ate get actor-template -o json output (repeatable)")
	fs.Var(&actors, "actors", "kubectl ate get actor -o json output (repeatable)")
	fs.Var(&managed, "managed", "atespace/name of an actor DefenseClaw registered (repeatable)")
	fs.Var(&plain, "insecure-registry", "registry host:port reached over plain HTTP (repeatable)")
	anchors := fs.String("anchors", "", "trust anchors")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *anchors == "" {
		fmt.Fprintln(os.Stderr, "discover needs --anchors")
		return 2
	}
	ta, err := attest.LoadAnchors(*anchors)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	reg := attest.NewRegistry(attest.RegistryOptions{PlainHTTP: plain})
	ver := attest.NewVerifier(reg, func() attest.Policy { return attest.Policy{Anchors: ta} })
	now := time.Now().UTC()
	enc := json.NewEncoder(os.Stdout)

	attested := map[string]bool{} // atespace/template → admitted
	for _, f := range templates {
		var l templateList
		if err := readJSON(f, &l); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		for _, t := range l.ActorTemplates {
			image := ""
			if len(t.Containers) > 0 {
				image = t.Containers[0].Image
			}
			obs := attest.TemplateObservation{Atespace: t.Metadata.Atespace, Name: t.Metadata.Name, Image: image, FirstSeen: t.Metadata.CreateTime}
			v, verr := ver.Verify(ctx, image)
			key := t.Metadata.Atespace + "/" + t.Metadata.Name
			if verr == nil {
				attested[key] = true
				_ = enc.Encode(map[string]any{"kind": "signal", "signal": attest.TemplateSignal(obs, v, nil, now)})
				continue
			}
			rej, ok := attest.AsRejection(verr)
			if !ok {
				rej = &attest.Rejection{Code: "error", Detail: verr.Error()}
			}
			_ = enc.Encode(map[string]any{"kind": "signal", "signal": attest.TemplateSignal(obs, nil, rej, now)})
			_ = enc.Encode(map[string]any{"kind": "event", "event": attest.NewTemplateUnverified(obs, rej, now)})
		}
	}
	isManaged := map[string]bool{}
	for _, m := range managed {
		isManaged[m] = true
	}
	for _, f := range actors {
		var l actorList
		if err := readJSON(f, &l); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		for _, a := range l.Actors {
			tpl := a.ActorTemplate.Atespace + "/" + a.ActorTemplate.Name
			state := a.Status.State
			if state == "" {
				state = a.State
			}
			key := a.Metadata.Atespace + "/" + a.Metadata.Name
			sig := attest.ActorSignal(attest.ActorObservation{
				Atespace: a.Metadata.Atespace, Name: a.Metadata.Name, UID: a.Metadata.UID, State: state, Template: tpl,
				Managed: isManaged[key], TemplateAttested: attested[tpl], Owner: ownerOf(isManaged[key]), FirstSeen: a.Metadata.CreateTime,
			}, now)
			_ = enc.Encode(map[string]any{"kind": "signal", "signal": sig})
		}
	}
	return 0
}

func ownerOf(managed bool) string {
	if managed {
		return "person-a9"
	}
	return ""
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// kubectl ate prints a warning line before the JSON on stderr only, but
	// be lenient about leading text.
	if i := strings.Index(string(b), "{"); i > 0 {
		b = b[i:]
	}
	return json.Unmarshal(b, v)
}
