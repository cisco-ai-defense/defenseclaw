// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// checkedFields are, per message of an ActorTemplate's containers and
// volumes, the fields DefenseClaw knows and checks (GAP-0371). The check is
// default-deny over fields: a field set that is not listed here (a field a
// newer vendored API adds), or a field the vendored API does not know at
// all (protobuf unknown fields, a newer Substrate server), refuses the
// template until DefenseClaw checks it. The template is passed on to the
// actor as the server holds it, so a field DefenseClaw does not read would
// reach the actor unchecked.
var checkedFields = map[protoreflect.FullName][]protoreflect.Name{
	// image: attestation; command, args, env: ContainerSpecRefusal;
	// volume_mounts: MountRefusal; security_context: securityContextRefusal;
	// wakeup_probe and resources change neither the process nor its files.
	"substrate.ateapi.v1.Container":       {"name", "image", "command", "args", "env", "wakeup_probe", "volume_mounts", "security_context", "resources"},
	"substrate.ateapi.v1.EnvVar":          {"name", "value"},
	"substrate.ateapi.v1.VolumeMount":     {"name", "mount_path"},
	"substrate.ateapi.v1.SecurityContext": {"capabilities"},
	"substrate.ateapi.v1.Capabilities":    {"add", "drop"},
	// durable_dir, external: MountRefusal; system_info: only at /run/ate;
	// image: digest-pinned and in volume_images.
	"substrate.ateapi.v1.Volume": {"name", "durable_dir", "external", "system_info", "image"},
}

// FieldRefusal says which field of tmpl DefenseClaw does not check
// (GAP-0371), "" when every set field is one it checks. Unknown fields are
// refused anywhere in the containers and volumes; the template's metadata
// and status are the server's and are not looked at.
func FieldRefusal(tmpl *ateapi.ActorTemplate) string {
	if len(tmpl.ProtoReflect().GetUnknown()) > 0 {
		return "the template carries fields DefenseClaw does not know (a newer Substrate API); DefenseClaw admits only fields it checks"
	}
	for i, c := range tmpl.GetContainers() {
		if why := fieldRefusal(c.ProtoReflect(), fmt.Sprintf("containers[%d]", i)); why != "" {
			return why
		}
	}
	for i, v := range tmpl.GetVolumes() {
		if why := fieldRefusal(v.ProtoReflect(), fmt.Sprintf("volumes[%d]", i)); why != "" {
			return why
		}
	}
	return ""
}

func fieldRefusal(m protoreflect.Message, at string) string {
	if len(m.GetUnknown()) > 0 {
		return at + " carries fields DefenseClaw does not know (a newer Substrate API); DefenseClaw admits only fields it checks"
	}
	known, checked := checkedFields[m.Descriptor().FullName()]
	why := ""
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := at + "." + string(fd.Name())
		if checked && !slices.Contains(known, fd.Name()) {
			why = name + " is a field DefenseClaw does not check; remove it from the template"
			return false
		}
		switch {
		case fd.Message() == nil:
		case fd.IsList():
			l := v.List()
			for j := 0; j < l.Len() && why == ""; j++ {
				why = fieldRefusal(l.Get(j).Message(), fmt.Sprintf("%s[%d]", name, j))
			}
		case fd.IsMap():
		default:
			why = fieldRefusal(v.Message(), name)
		}
		return why == ""
	})
	return why
}

// relayNeeds are the capabilities a separated relay cannot run without
// (relay.separate: it refuses to start).
var relayNeeds = []string{"SETUID", "SETGID", "KILL"}

// securityContextRefusal says why a container's security_context does not
// keep what was attested (GAP-0371), "" when it does. A kit actor needs no
// added capability (PLAN 6.4), so any capabilities.add is refused: it would
// give the relay, or an agent of a relay that is not separated, a power the
// attested image does not have. Dropping capabilities is hardening and is
// admitted, except, for an image whose root relay starts the agent as its
// own user, ALL or one the relay needs (it would refuse to start).
func securityContextRefusal(c *ateapi.Container, v *attest.Verified) string {
	caps := c.GetSecurityContext().GetCapabilities()
	if len(caps.GetAdd()) > 0 {
		return "security_context.capabilities.add adds capabilities; DefenseClaw actors need none, remove it from the template"
	}
	if !relaySeparated(v) {
		return ""
	}
	for _, d := range caps.GetDrop() {
		n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(d)), "CAP_")
		if n == "ALL" || slices.Contains(relayNeeds, n) {
			return "security_context.capabilities.drop drops " + n + ", which DefenseClaw's relay needs to start the agent as its own user and to stop it (CAP_SETUID, CAP_SETGID, CAP_KILL); it keeps only those it needs by itself"
		}
	}
	return ""
}

// relaySeparated reports whether the image's relay runs as root and starts
// the agent as its own user (GAP-0116): the relay is the entrypoint and the
// image USER is root, which the template build of 1.0.10 and later admits
// only with relay.agent_user set. A kit image built before 1.0.10 runs the
// relay as the agent's user.
func relaySeparated(v *attest.Verified) bool {
	if v == nil || len(v.Entrypoint) == 0 || v.Entrypoint[0] != kit.RelayBinary {
		return false
	}
	u := strings.TrimSpace(v.User)
	return u == "" || u == "0" || u == "root" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:")
}

// UnseparatedReason is the note on a template whose relay and agent share a
// user (GAP-0372).
const UnseparatedReason = "the image's relay runs as the agent's own user (a kit image built before DefenseClaw 1.0.10, or an image USER other than root), so the agent can stop the relay and the terminal it serves; rebuild the template with DefenseClaw 1.0.10 or later (template build)"
