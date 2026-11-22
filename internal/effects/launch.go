// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// LaunchedArgv reads one command's argv with the wrapper rows of the program
// table (env, sudo, nohup, timeout, setsid, nice, chroot, ...) and returns the
// argv of the program the launchers start, with the launchers peeled off. It
// is the same reading Extract applies to a command, for callers that see an
// argv and need the program it runs rather than its effects (the host plane's
// exec classifier, rel-1-0-10 GAP-1190).
//
// known is false when a launcher carries an option its row does not account
// for, or a word in the launcher part is dynamic ($VAR, a substitution): the
// child is then not certain and the caller must not treat the returned argv
// as the whole story. A word holding $ or ` is dynamic. An argv with no
// launcher comes back unchanged.
func LaunchedArgv(argv []string, flavor Flavor) (child []string, wrappers []string, known bool) {
	words := make([]Word, len(argv))
	for i, a := range argv {
		words[i] = Word{Value: a, Static: !strings.ContainsAny(a, "$`")}
	}
	w := newWalker(&Result{}, Options{Flavor: flavor})
	inner, wrappers, _, _, unaccounted := w.stripWrappers(words)
	known = !unaccounted
	if len(wrappers) > 0 && len(inner) > 0 && !inner[0].Static {
		known = false // the program after the launchers is dynamic
	}
	child = make([]string, len(inner))
	for i, wd := range inner {
		child[i] = wd.Value
	}
	return child, wrappers, known
}

// ModeledProgram reports whether the program table has a row for a program
// word (a path or a bare name), in the flavor's table: the table then accounts
// for what its operands are, so a word that only names something is data to
// it. A launcher row is not a program row (LaunchedArgv reads those).
func ModeledProgram(program string, flavor Flavor) bool {
	_, ok := lookupProgram(programBasename(program, flavor), flavor, DialectNone, false)
	return ok
}
