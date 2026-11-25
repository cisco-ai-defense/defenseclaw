// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

// CheckRelayTLS is the check id of the gateway-to-relay transport (B3.5).
const CheckRelayTLS = "relay_tls"

// RelayCA is what verify read of the relay CA Secret (setup's relay-session
// step creates it). Note says why it could not be read ("" when it was).
type RelayCA struct {
	Secret  string
	Present bool
	Note    string
}

// CheckRelayTLSReady reports how the gateway reaches the actors' relays.
// substrate.relay_tls (RelayTLS, the effective value: auto, required or off)
// and the relay CA decide it:
//   - off: relays that serve TLS are still reached over TLS (they refuse plain
//     text); older relays are reached in plain text without an audit row. Pass,
//     no warning (an administrator's choice).
//   - auto: TLS where the relay serves it, plain text with a
//     substrate.relay.plain audit row elsewhere. Pass with the CA; without it
//     no relay can get a serving certificate, so actors on templates built by
//     this version cannot be attached: warn.
//   - required: plain text is refused (relay_tls_required). Without the CA
//     nothing can be attached: fail.
func CheckRelayTLSReady(o Observed) Check {
	ca := o.RelayCA
	mode := o.RelayTLS
	if mode == "" {
		mode = "auto"
	}
	switch {
	case mode == "off":
		return result(CheckRelayTLS, Pass, "", "substrate.relay_tls is off: relays that serve TLS are reached over TLS, "+
			"relays on older templates in plain text, without an audit row")
	case ca == nil:
		return result(CheckRelayTLS, Skip, "", "the relay CA Secret was not read")
	case ca.Note != "":
		return result(CheckRelayTLS, Skip, "", "could not read the relay CA Secret %s: %s", ca.Secret, ca.Note)
	case ca.Present && mode == "required":
		return result(CheckRelayTLS, Pass, "", "substrate.relay_tls is required: every attach uses TLS; actors on templates "+
			"built before this version are refused (relay_tls_required) until their template is built again")
	case ca.Present:
		return result(CheckRelayTLS, Pass, "", "substrate.relay_tls is auto: relays that serve TLS are reached over TLS, "+
			"relays on older templates in plain text with a substrate.relay.plain audit row")
	case mode == "required":
		return result(CheckRelayTLS, Fail, "", "substrate.relay_tls is required but the relay CA Secret %s is missing, so "+
			"no relay gets a serving certificate and no actor can be attached. Run setup again (its relay-session step "+
			"creates the Secret), then restart the gateway", ca.Secret)
	}
	return result(CheckRelayTLS, Warn, "", "the relay CA Secret %s is missing, so relays on templates built by this "+
		"version get no serving certificate and cannot be attached (relay_ca_missing). Run setup again (its "+
		"relay-session step creates the Secret), then restart the gateway", ca.Secret)
}
