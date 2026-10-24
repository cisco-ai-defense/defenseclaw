// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"encoding/base64"
	"strings"
)

// pyShim is a root-owned Python module a Python harness's tool environment
// imports at every interpreter start, through a .pth file next to it in the
// environment's site-packages. The shims adjust how the pinned harness
// behaves in a sandbox where its own code cannot (a suspend the sandbox
// refuses, a notice its TUI never shows); none of them touches a hook's
// verdict.
type pyShim struct {
	// name is the module name (and the .py and .pth file names).
	name string
	// source is the module.
	source string
}

// pyOnImport is the helper a shim that patches a harness module uses:
// _defenseclaw_on_import(name, patch) runs patch(module) once the module
// named name has been executed, before any other code can import from it.
// The .pth runs before the harness imports anything, so the module is found
// through a one-shot entry at the front of sys.meta_path: it asks the path
// finder for the module's spec and wraps that module's own loader's
// exec_module (the loader object, and so __loader__, stays the one the path
// finder made). A patch that fails, or a module that is missing or not
// loaded from a file, leaves the harness exactly as it was.
const pyOnImport = `import sys


def _defenseclaw_on_import(name, patch):
    class _Finder:
        @staticmethod
        def find_spec(fullname, path=None, target=None):
            if fullname != name:
                return None
            try:
                sys.meta_path.remove(_Finder)
            except ValueError:
                pass
            from importlib.machinery import PathFinder
            spec = PathFinder.find_spec(fullname, path)
            loader = getattr(spec, "loader", None)
            exec_module = getattr(loader, "exec_module", None)
            if exec_module is None:
                return spec

            def _exec_module(module):
                exec_module(module)
                try:
                    patch(module)
                except Exception:
                    pass

            loader.exec_module = _exec_module
            return spec

    sys.meta_path.insert(0, _Finder)
`

// pyShimInstall is the install-step fragment that writes shims, root-owned
// and read-only, into the site-packages of the tool environment whose
// interpreter is python, which must lie under root. It leaves the directory
// in $site for what follows it.
func pyShimInstall(python, root, displayName string, shims ...pyShim) string {
	var b strings.Builder
	b.WriteString(`site="$(` + shellQuote(python) + ` -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; `)
	b.WriteString(`case "$site" in ` + root + `/*) ;; *) echo "` + displayName + ` site-packages $site is outside the install root" >&2; exit 1 ;; esac`)
	for _, s := range shims {
		b.WriteString(`; printf '%s' ` + shellQuote(base64.StdEncoding.EncodeToString([]byte(s.source))) + ` | base64 -d >"$site/` + s.name + `.py"; `)
		b.WriteString(`printf 'import ` + s.name + `\n' >"$site/` + s.name + `.pth"; `)
		b.WriteString(`chown root:root "$site/` + s.name + `.py" "$site/` + s.name + `.pth"; `)
		b.WriteString(`chmod 0644 "$site/` + s.name + `.py" "$site/` + s.name + `.pth"`)
	}
	return b.String()
}
