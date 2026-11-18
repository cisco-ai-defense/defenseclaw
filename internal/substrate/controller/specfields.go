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

// linuxCapabilities are the capability names Substrate takes in
// security_context.capabilities: upper case, without CAP_.
var linuxCapabilities = map[string]bool{
	"CHOWN": true, "DAC_OVERRIDE": true, "DAC_READ_SEARCH": true, "FOWNER": true, "FSETID": true, "KILL": true,
	"SETGID": true, "SETUID": true, "SETPCAP": true, "LINUX_IMMUTABLE": true, "NET_BIND_SERVICE": true,
	"NET_BROADCAST": true, "NET_ADMIN": true, "NET_RAW": true, "IPC_LOCK": true, "IPC_OWNER": true,
	"SYS_MODULE": true, "SYS_RAWIO": true, "SYS_CHROOT": true, "SYS_PTRACE": true, "SYS_PACCT": true,
	"SYS_ADMIN": true, "SYS_BOOT": true, "SYS_NICE": true, "SYS_RESOURCE": true, "SYS_TIME": true,
	"SYS_TTY_CONFIG": true, "MKNOD": true, "LEASE": true, "AUDIT_WRITE": true, "AUDIT_CONTROL": true,
	"SETFCAP": true, "MAC_OVERRIDE": true, "MAC_ADMIN": true, "SYSLOG": true, "WAKE_ALARM": true,
	"BLOCK_SUSPEND": true, "AUDIT_READ": true, "PERFMON": true, "BPF": true, "CHECKPOINT_RESTORE": true,
}

// capabilitySpelling says why a capability name of a template is not
// Substrate's spelling, "" when it is: a known capability, upper case,
// without CAP_ or padding (ALL in drop). Admission then reads the list as
// Substrate does: a "cap_setuid" or "all" that admission normalised and
// Substrate read otherwise would leave the container another set
// (GAP-0576).
func capabilitySpelling(field, c string, drop bool) string {
	if linuxCapabilities[c] || (drop && c == "ALL") {
		return ""
	}
	return fmt.Sprintf("security_context.capabilities.%s names %q, which is not a capability as Substrate spells it (upper case, no CAP_ prefix, for example SETUID)", field, c)
}

// securityContextRefusal says why a container's security_context does not
// fit the attested image (GAP-0371, GAP-0458), "" when it does. Substrate
// gives an actor container its default capabilities minus drop plus add
// (kit.ActorCapabilities).
//   - An image whose root relay starts the agent as its own user must end
//     with exactly SETUID, SETGID and KILL (the relay refuses to start
//     without them, and needs no other; GAP-0509) and may add only those
//     (template publish adds SETUID and SETGID and drops the other defaults:
//     kit.RelayCapabilitiesAdd and Drop).
//   - Any other image may add nothing: its agent runs as the relay's user,
//     so a capability added to the container would be the agent's.
//
// Dropping capabilities is hardening and is admitted otherwise.
func securityContextRefusal(c *ateapi.Container, v *attest.Verified) string {
	caps := c.GetSecurityContext().GetCapabilities()
	add, drop := caps.GetAdd(), caps.GetDrop()
	for _, a := range add {
		if why := capabilitySpelling("add", a, false); why != "" {
			return why
		}
	}
	for _, d := range drop {
		if why := capabilitySpelling("drop", d, true); why != "" {
			return why
		}
	}
	if !v.RelaySeparated() {
		if len(add) > 0 {
			return "security_context.capabilities.add adds capabilities, which the agent of this image (it runs as the relay's user) would get; remove it from the template"
		}
		return ""
	}
	for _, a := range add {
		if !slices.Contains(kit.RelayCapabilities, a) {
			return "security_context.capabilities.add adds " + a + "; DefenseClaw's relay needs only SETUID and SETGID added (template publish sets it)"
		}
	}
	got := kit.ActorCapabilities(add, drop)
	for _, need := range kit.RelayCapabilities {
		if !slices.Contains(got, need) {
			return "security_context.capabilities does not give the container " + need + ", which DefenseClaw's relay needs to start the agent as its own user and to stop it; publish the template with defenseclaw substrate template publish (it adds SETUID and SETGID)"
		}
	}
	for _, c := range got {
		if !slices.Contains(kit.RelayCapabilities, c) {
			// A Substrate default the relay does not need, kept by a template
			// that adds SETUID and SETGID without the drop (GAP-0509).
			return "security_context.capabilities leaves the container " + c + ", which DefenseClaw's relay does not need; drop it (template publish drops " + strings.Join(kit.RelayCapabilitiesDrop, " and ") + ")"
		}
	}
	return ""
}

// UnseparatedReason is the note on a template whose relay and agent share a
// user (GAP-0372).
const UnseparatedReason = "the image's relay runs as the agent's own user (a kit image built before DefenseClaw 1.0.10, or an image USER other than root), so the agent can stop the relay and the terminal it serves; rebuild the template with DefenseClaw 1.0.10 or later (template build)"
