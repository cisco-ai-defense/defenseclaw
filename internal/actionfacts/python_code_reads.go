// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// PythonCodeOnlyReads reports inline Python code that provably writes
// nothing (rel-1-0-10:GAP-0104, GAP-0244). It is an allowlist read of the
// code's tokens, not a search for spelled write calls: anything the reader
// does not recognise counts as a possible write, so a new form can only add
// findings, never hide one.
//
// The code is read only if every name it uses is reviewed:
//   - a call is a builtin read function, a standard-library module function
//     (pythonCallables), or a method on the allowlist (pythonMethods);
//   - a callable is accepted only where it is called: a reference to one that
//     is not called (an alias, a value passed along, a subscripted or
//     parenthesised callee, a computed callee) is a possible write;
//   - open, io.open, gzip.open, Path.open and the like need a literal read
//     mode, os.open needs os.O_RDONLY alone;
//   - an import names an allowlisted module (no alias, no star import);
//   - no dunder name, lambda, def, class, del, global, yield, getattr, exec,
//     eval, compile, __import__, attribute assignment or decorator.
//
// Python puts the working directory first on sys.path for -c and stdin
// code, so a module that is not on the allowlist is never imported.
func PythonCodeOnlyReads(code string) bool {
	tokens, ok := pythonTokens(code, 0)
	if !ok || len(tokens) == 0 {
		return false
	}
	return pythonTokensRead(tokens)
}

// pythonWordSet is the set of the space-separated names in text. The names
// are one text, not one literal each.
func pythonWordSet(text string) map[string]bool {
	set := map[string]bool{}
	for _, name := range strings.Fields(text) {
		set[name] = true
	}
	return set
}

var (
	// pythonModules are the standard-library modules a read-only script uses.
	pythonModules = pythonWordSet("os sys json pathlib hashlib re io codecs base64 binascii struct zlib gzip bz2 lzma " +
		"datetime time math statistics pprint textwrap unicodedata shlex platform getpass copy collections csv " +
		"configparser tomllib glob fnmatch plistlib stat difflib pwd grp")

	// pythonCallables are the module functions and classes that read, print
	// or compute: each is accepted only where it is called.
	pythonCallables = pythonWordSet("json.load json.loads json.dumps " +
		"hashlib.md5 hashlib.sha1 hashlib.sha224 hashlib.sha256 hashlib.sha384 hashlib.sha512 hashlib.blake2b hashlib.blake2s " +
		"hashlib.sha3_256 hashlib.sha3_512 hashlib.file_digest " +
		"os.path.join os.path.basename os.path.dirname os.path.exists os.path.lexists os.path.isfile os.path.isdir " +
		"os.path.islink os.path.isabs os.path.getsize os.path.getmtime os.path.getatime os.path.getctime os.path.abspath " +
		"os.path.realpath os.path.expanduser os.path.expandvars os.path.normpath os.path.normcase os.path.splitext " +
		"os.path.split os.path.relpath os.path.commonpath os.path.commonprefix os.path.samefile " +
		"os.getcwd os.getenv os.listdir os.scandir os.walk os.stat os.lstat os.readlink os.fspath os.getpid os.getppid " +
		"os.getuid os.getgid os.geteuid os.getegid os.getlogin os.cpu_count os.access os.fsencode os.fsdecode os.uname " +
		"os.get_terminal_size os.environ.get os.environ.items os.environ.keys os.environ.values os.open os.fdopen " +
		"sys.exit sys.stdout.write sys.stderr.write sys.stdout.flush sys.stderr.flush sys.getdefaultencoding sys.getsizeof " +
		"re.compile re.search re.match re.fullmatch re.findall re.finditer re.sub re.subn re.split re.escape " +
		"io.open io.StringIO io.BytesIO io.FileIO codecs.open " +
		"gzip.open gzip.decompress gzip.compress bz2.open bz2.decompress bz2.compress lzma.open lzma.decompress lzma.compress " +
		"base64.b64decode base64.b64encode base64.urlsafe_b64decode base64.urlsafe_b64encode base64.b32decode base64.b32encode " +
		"base64.b16decode base64.b16encode base64.standard_b64decode base64.standard_b64encode " +
		"binascii.hexlify binascii.unhexlify binascii.crc32 binascii.b2a_hex binascii.a2b_hex " +
		"struct.unpack struct.unpack_from struct.calcsize struct.pack zlib.crc32 zlib.adler32 zlib.decompress zlib.compress " +
		"datetime.datetime datetime.datetime.now datetime.datetime.utcnow datetime.datetime.fromtimestamp " +
		"datetime.datetime.utcfromtimestamp datetime.datetime.strptime datetime.datetime.fromisoformat datetime.date " +
		"datetime.date.today datetime.date.fromtimestamp datetime.date.fromisoformat datetime.timedelta datetime.timezone " +
		"time.time time.time_ns time.monotonic time.perf_counter time.strftime time.localtime time.gmtime time.mktime " +
		"time.ctime time.asctime " +
		"math.floor math.ceil math.sqrt math.log math.log2 math.log10 math.exp math.pow math.fabs math.isnan math.isinf " +
		"math.isfinite math.gcd math.hypot math.trunc statistics.mean statistics.median statistics.stdev " +
		"pprint.pprint pprint.pformat textwrap.dedent textwrap.fill textwrap.wrap textwrap.indent textwrap.shorten " +
		"unicodedata.normalize unicodedata.category unicodedata.name shlex.split shlex.quote shlex.join " +
		"platform.system platform.platform platform.node platform.machine platform.release platform.version " +
		"platform.python_version platform.uname getpass.getuser copy.copy copy.deepcopy " +
		"collections.Counter collections.OrderedDict collections.defaultdict collections.deque " +
		"csv.reader csv.DictReader csv.field_size_limit configparser.ConfigParser configparser.RawConfigParser " +
		"tomllib.load tomllib.loads glob.glob glob.iglob glob.escape fnmatch.fnmatch fnmatch.fnmatchcase fnmatch.filter " +
		"fnmatch.translate plistlib.load plistlib.loads stat.S_ISREG stat.S_ISDIR stat.S_ISLNK stat.S_IMODE stat.S_IFMT " +
		"stat.filemode difflib.unified_diff difflib.ndiff difflib.get_close_matches difflib.SequenceMatcher " +
		"pwd.getpwnam pwd.getpwuid pwd.getpwall grp.getgrnam grp.getgrgid grp.getgrall " +
		"pathlib.Path pathlib.PurePath pathlib.PurePosixPath pathlib.PureWindowsPath")

	// pythonValues are the module values a read-only script uses.
	pythonValues = pythonWordSet("sys.argv sys.stdin sys.stdout sys.stderr sys.platform sys.version sys.version_info " +
		"sys.maxsize os.sep os.linesep os.name os.environ os.curdir os.pardir os.O_RDONLY os.path.sep " +
		"math.pi math.e math.inf math.nan datetime.timezone.utc")

	// pythonMethods are the methods that read, search, format or compute on
	// a value. copy (no argument), replace (two or more) and open (read
	// mode) are judged by their arguments in pythonMethodReads.
	pythonMethods = pythonWordSet("read readline readlines read_text read_bytes read_file read_string strip lstrip rstrip " +
		"split rsplit splitlines partition rpartition startswith endswith join format format_map lower upper title " +
		"capitalize casefold swapcase get keys values items encode decode hex fromhex from_bytes to_bytes hexdigest digest " +
		"find rfind rindex count index isdigit isalpha isalnum isspace isupper islower zfill ljust rjust center expandtabs " +
		"removeprefix removesuffix translate match search fullmatch findall finditer sub subn group groups groupdict " +
		"start end span exists is_file is_dir is_symlink is_absolute iterdir glob rglob resolve absolute expanduser " +
		"relative_to with_name with_suffix joinpath stat lstat readlink samefile owner as_posix as_uri isoformat strftime " +
		"timestamp total_seconds append extend add pop setdefault sort reverse insert update clear seek tell close flush " +
		"getvalue sections options has_section has_option getint getfloat getboolean")

	// pythonAttrs are the attributes that hold plain values.
	pythonAttrs = pythonWordSet("name stem suffix suffixes parent parents parts anchor drive root st_size st_mode st_mtime " +
		"st_atime st_ctime st_uid st_gid st_ino st_nlink st_dev real imag days seconds year month day hour minute second " +
		"microsecond pw_name pw_dir pw_uid pw_gid pw_shell gr_name gr_gid gr_mem sysname nodename release version machine " +
		"pattern flags fieldnames")

	pythonAllowedKeywords = pythonWordSet("as for in if elif else while not and or is with try except finally raise pass " +
		"break continue assert")
	pythonForbiddenKeywords = pythonWordSet("lambda def class del global nonlocal yield async await return")

	// pythonBuiltinCallables are the builtins that read, print or compute:
	// open is judged by its mode in pythonCalleeReads.
	pythonBuiltinCallables = pythonWordSet("print len str int float bool bytes bytearray list dict set frozenset tuple " +
		"sorted reversed enumerate zip range min max sum any all abs round repr isinstance hex oct bin ord chr format iter " +
		"next divmod pow ascii hash open")

	// pythonBuiltinValues are the builtin names that may be named without a
	// call: constants and the value types. Calling one of these only builds
	// a value.
	pythonBuiltinValues = pythonWordSet("True False None Ellipsis NotImplemented str bytes int float bool dict list tuple set " +
		"frozenset bytearray")

	// pythonBuiltinNames is every name of the builtins table that is not a
	// reviewed value: a bare reference to one is a callable named without a
	// call (print = ..., map(open, ...), key=len), or a dangerous builtin.
	pythonBuiltinNames = pythonWordSet("ArithmeticError AssertionError AttributeError BaseException BlockingIOError " +
		"BrokenPipeError BufferError BytesWarning ChildProcessError ConnectionAbortedError ConnectionError " +
		"ConnectionRefusedError ConnectionResetError DeprecationWarning EOFError Ellipsis EncodingWarning EnvironmentError " +
		"Exception False FileExistsError FileNotFoundError FloatingPointError FutureWarning GeneratorExit IOError " +
		"ImportError ImportWarning IndentationError IndexError InterruptedError IsADirectoryError KeyError KeyboardInterrupt " +
		"LookupError MemoryError ModuleNotFoundError NameError None NotADirectoryError NotImplemented NotImplementedError " +
		"OSError OverflowError PendingDeprecationWarning PermissionError ProcessLookupError RecursionError ReferenceError " +
		"ResourceWarning RuntimeError RuntimeWarning StopAsyncIteration StopIteration SyntaxError SyntaxWarning SystemError " +
		"SystemExit TabError TimeoutError True TypeError UnboundLocalError UnicodeDecodeError UnicodeEncodeError UnicodeError " +
		"UnicodeTranslateError UnicodeWarning UserWarning ValueError Warning ZeroDivisionError abs aiter all anext any ascii " +
		"bin bool breakpoint bytearray bytes callable chr classmethod compile complex copyright credits delattr dict dir " +
		"divmod enumerate eval exec exit filter float format frozenset getattr globals hasattr hash help hex id input int " +
		"isinstance issubclass iter len license list locals map max memoryview min next object oct open ord pow print " +
		"property quit range repr reversed round set setattr slice sorted staticmethod str sum super tuple type vars zip")

	pythonAssignOps = pythonWordSet("= += -= *= /= //= %= **= >>= <<= &= |= ^=")
)

// pythonExceptionName reports a builtin exception class: naming or calling
// one only builds a value (except OSError:, raise ValueError("x")).
func pythonExceptionName(name string) bool {
	if !pythonBuiltinNames[name] {
		return false
	}
	return strings.HasSuffix(name, "Error") || strings.HasSuffix(name, "Exception") ||
		strings.HasSuffix(name, "Warning") || name == "SystemExit" || name == "KeyboardInterrupt" ||
		name == "StopIteration" || name == "GeneratorExit"
}

// pyTok is one token: a name ('i'), a number ('n'), a string ('s', its source
// text), an operator or bracket ('o') or the end of a statement (';').
type pyTok struct {
	kind byte
	text string
}

func pythonTokensRead(t []pyTok) bool {
	from := map[string]string{}
	for i := 0; i < len(t); i++ {
		switch tok := t[i]; tok.kind {
		case 'o':
			next, ok := pythonOperatorReads(t, i)
			if !ok {
				return false
			}
			i = next
		case 'i':
			next, ok := pythonNameReads(t, i, from)
			if !ok {
				return false
			}
			i = next
		}
	}
	return true
}

// pythonOperatorReads judges an operator the main loop reaches: a decorator
// or backtick, a call of a computed value (f()(), x[0](), "s"()), and an
// attribute of a value (f().name, x[0].name), which is read like the
// attribute of a name.
func pythonOperatorReads(t []pyTok, i int) (next int, ok bool) {
	text := t[i].text
	switch {
	case strings.HasPrefix(text, "@") || text == "`":
		return i, false
	case text == "(":
		if i > 0 {
			prev := t[i-1]
			if prev.kind == 's' || prev.kind == 'n' || prev.kind == 'o' && (prev.text == ")" || prev.text == "]" || prev.text == "}") {
				return i, false
			}
		}
	case text == ".":
		if i+1 >= len(t) || t[i+1].kind != 'i' || strings.HasPrefix(t[i+1].text, "__") {
			return i, false
		}
		ok := pythonAttributeReads(t, i+1, t[i+1].text)
		return i + 1, ok
	}
	return i, true
}

// pythonAttributeReads judges the attribute name at t[at] of a value: a
// method on the allowlist when called, a plain-value attribute when not, and
// never the target of an assignment.
func pythonAttributeReads(t []pyTok, at int, name string) bool {
	if at+1 < len(t) && t[at+1].kind == 'o' && t[at+1].text == "(" {
		args, _, ok := pythonCallArgs(t, at+1)
		return ok && pythonMethodReads(name, args)
	}
	return pythonAttrs[name] && !pythonAssigns(t, at+1)
}

// pythonAssigns reports an assignment (plain or augmented) to the target that
// ends before t[k], whatever subscripts follow it.
func pythonAssigns(t []pyTok, k int) bool {
	for k < len(t) && t[k].kind == 'o' && t[k].text == "[" {
		depth := 0
		for ; k < len(t); k++ {
			if t[k].kind != 'o' {
				continue
			}
			switch t[k].text {
			case "[", "(", "{":
				depth++
			case "]", ")", "}":
				depth--
			}
			if depth == 0 {
				k++
				break
			}
		}
	}
	return k < len(t) && t[k].kind == 'o' && pythonAssignOps[t[k].text]
}

// pythonCallArgs splits the arguments of the call whose "(" is t[open]: the
// source text of each, at top-level commas. end is the index of the ")".
func pythonCallArgs(t []pyTok, open int) (args []string, end int, ok bool) {
	depth := 0
	var current strings.Builder
	empty := true
	for k := open; k < len(t); k++ {
		tok := t[k]
		if tok.kind == 'o' {
			switch tok.text {
			case "(", "[", "{":
				depth++
				if depth == 1 {
					continue
				}
			case ")", "]", "}":
				depth--
				if depth == 0 {
					if !empty {
						args = append(args, current.String())
					}
					return args, k, tok.text == ")"
				}
			case ",":
				if depth == 1 {
					args = append(args, current.String())
					current.Reset()
					empty = true
					continue
				}
			}
		}
		current.WriteString(tok.text)
		empty = false
	}
	return nil, 0, false
}

// pythonStatementStart reports that t[i] begins a statement.
func pythonStatementStart(t []pyTok, i int) bool {
	return i == 0 || t[i-1].kind == ';' || t[i-1].kind == 'o' && t[i-1].text == ":"
}

// pythonNameReads judges the name at t[i] and the attribute chain after it.
// next is the index of the last token it consumed.
func pythonNameReads(t []pyTok, i int, from map[string]string) (next int, ok bool) {
	name := t[i].text
	if strings.HasPrefix(name, "__") {
		return i, false
	}
	switch {
	case name == "import":
		return pythonImportReads(t, i, from)
	case name == "from" && pythonStatementStart(t, i):
		return pythonFromImportReads(t, i, from)
	case pythonAllowedKeywords[name] || name == "from":
		return i, true
	case pythonForbiddenKeywords[name]:
		return i, false
	}
	chain := []string{name}
	j := i
	for j+2 < len(t) && t[j+1].kind == 'o' && t[j+1].text == "." && t[j+2].kind == 'i' {
		if strings.HasPrefix(t[j+2].text, "__") {
			return j, false
		}
		chain = append(chain, t[j+2].text)
		j += 2
	}
	called := j+1 < len(t) && t[j+1].kind == 'o' && t[j+1].text == "("
	var args []string
	if called {
		var good bool
		if args, _, good = pythonCallArgs(t, j+1); !good {
			return j, false
		}
	}
	if len(chain) == 1 {
		return j, pythonBareNameReads(name, called, args, from)
	}
	if full, imported := from[chain[0]]; imported {
		chain = append(strings.Split(full, "."), chain[1:]...)
	}
	if pythonModules[chain[0]] {
		path := strings.Join(chain, ".")
		if called {
			return j, pythonCalleeReads(path, args)
		}
		return j, pythonValues[path] && !pythonAssigns(t, j+1)
	}
	if pythonBuiltinNames[chain[0]] && !pythonBuiltinValues[chain[0]] {
		return j, false
	}
	for k := 1; k < len(chain)-1; k++ {
		if !pythonAttrs[chain[k]] {
			return j, false
		}
	}
	last := chain[len(chain)-1]
	if called {
		return j, pythonMethodReads(last, args)
	}
	return j, pythonAttrs[last] && !pythonAssigns(t, j+1)
}

// pythonBareNameReads judges a name with no attribute after it.
func pythonBareNameReads(name string, called bool, args []string, from map[string]string) bool {
	full, imported := from[name]
	if called {
		switch {
		case name == "open":
			return pythonReadMode(args, 1)
		case pythonBuiltinCallables[name] || pythonExceptionName(name):
			return true
		case imported:
			return pythonCalleeReads(full, args)
		}
		return false
	}
	switch {
	case pythonBuiltinNames[name]:
		return pythonBuiltinValues[name] || pythonExceptionName(name)
	case pythonModules[name]:
		return false
	case imported:
		return pythonValues[full]
	}
	return true
}

// pythonCalleeReads judges a call of a standard-library function.
func pythonCalleeReads(path string, args []string) bool {
	switch path {
	case "os.open":
		return len(args) == 2 && args[1] == "os.O_RDONLY"
	case "io.open", "codecs.open", "gzip.open", "bz2.open", "lzma.open", "io.FileIO", "os.fdopen":
		return pythonReadMode(args, 1)
	}
	return pythonCallables[path]
}

// pythonMethodReads judges a call of a method on a value. replace with fewer
// than two arguments is Path.replace (a rename), copy with arguments is
// Path.copy (a copy onto disk), open needs a read mode.
func pythonMethodReads(name string, args []string) bool {
	switch name {
	case "open":
		return pythonReadMode(args, 0)
	case "copy":
		return len(args) == 0
	case "replace":
		return len(args) >= 2
	}
	return pythonMethods[name]
}

// pythonImportPath reads a dotted name at t[i] and returns its parts and the
// index after it.
func pythonImportPath(t []pyTok, i int) (parts []string, next int, ok bool) {
	for i < len(t) && t[i].kind == 'i' && !strings.HasPrefix(t[i].text, "__") {
		parts = append(parts, t[i].text)
		i++
		if i+1 < len(t) && t[i].kind == 'o' && t[i].text == "." && t[i+1].kind == 'i' {
			i++
			continue
		}
		return parts, i, true
	}
	return nil, i, false
}

// pythonAllowedPath reports a dotted path the allowlists name, or a prefix of
// one (a module or a submodule).
func pythonAllowedPath(path string) bool {
	if pythonCallables[path] || pythonValues[path] {
		return true
	}
	for _, set := range []map[string]bool{pythonCallables, pythonValues} {
		for known := range set {
			if strings.HasPrefix(known, path+".") {
				return true
			}
		}
	}
	return false
}

// pythonImportReads reads "import a, b.c": modules on the allowlist, no alias.
func pythonImportReads(t []pyTok, i int, from map[string]string) (int, bool) {
	k := i + 1
	for {
		parts, next, ok := pythonImportPath(t, k)
		if !ok || !pythonModules[parts[0]] || !pythonAllowedPath(strings.Join(parts, ".")) {
			return i, false
		}
		k = next
		if k < len(t) && t[k].kind == 'o' && t[k].text == "," {
			k++
			continue
		}
		break
	}
	if k < len(t) && t[k].kind != ';' {
		return i, false // as, or anything else
	}
	return k - 1, true
}

// pythonFromImportReads reads "from m import a, b": names on the allowlist, no
// alias, no star, no relative import. The names become callables the code may
// call by their bare name.
func pythonFromImportReads(t []pyTok, i int, from map[string]string) (int, bool) {
	parts, k, ok := pythonImportPath(t, i+1)
	if !ok || !pythonModules[parts[0]] || k >= len(t) || t[k].kind != 'i' || t[k].text != "import" {
		return i, false
	}
	module := strings.Join(parts, ".")
	k++
	if k < len(t) && t[k].kind == 'o' && t[k].text == "(" {
		k++
	}
	imported := 0
	for k < len(t) && t[k].kind == 'i' && !strings.HasPrefix(t[k].text, "__") {
		full := module + "." + t[k].text
		if !pythonAllowedPath(full) {
			return i, false
		}
		from[t[k].text] = full
		imported++
		k++
		if k < len(t) && t[k].kind == 'o' && t[k].text == "," {
			k++
		}
	}
	if k < len(t) && t[k].kind == 'o' && t[k].text == ")" {
		k++
	}
	if imported == 0 || k < len(t) && t[k].kind != ';' {
		return i, false
	}
	return k - 1, true
}

// pythonIdentStart accepts ASCII identifier starts only. Python NFKC-normalises
// identifiers, so a compatibility spelling of a builtin or module name (a
// full-width letter) is that name; the reader does not normalise, so a
// non-ASCII byte outside a string or comment ends the read
// (rel-1-0-10:GAP-0269).
func pythonIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func pythonIdentChar(c byte) bool {
	return pythonIdentStart(c) || c >= '0' && c <= '9'
}

// pythonStringPrefix reports a string prefix: r, u, b, f, t (the template
// string, whose fields Python evaluates like an f-string) and their pairs.
func pythonStringPrefix(word string) bool {
	switch strings.ToLower(word) {
	case "r", "u", "b", "f", "t", "br", "rb", "fr", "rf", "tr", "rt":
		return true
	}
	return false
}

// pythonOperator is the operator or bracket at the start of rest.
func pythonOperator(rest string) string {
	for _, op := range []string{"**=", "//=", ">>=", "<<=", "...", "->", "**", "//", ">>", "<<", "==", "!=", "<=", ">=",
		":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "@="} {
		if strings.HasPrefix(rest, op) {
			return op
		}
	}
	return rest[:1]
}

// pythonTokens splits code into tokens. Comments and string contents are
// dropped, but the expressions of an f-string or t-string are read as code of their own
// (depth bounds the nesting). A newline ends a statement outside brackets.
func pythonTokens(code string, depth int) ([]pyTok, bool) {
	if depth > 3 || len(code) > 1<<16 {
		return nil, false
	}
	var out []pyTok
	brackets := 0
	for i := 0; i < len(code); {
		c := code[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			i++
		case c == '\n':
			if brackets == 0 {
				out = append(out, pyTok{kind: ';'})
			}
			i++
		case c == '\\':
			switch {
			case i+1 < len(code) && code[i+1] == '\n':
				i += 2
			case i+2 < len(code) && code[i+1] == '\r' && code[i+2] == '\n':
				i += 3
			default:
				return nil, false
			}
		case c == '#':
			for i < len(code) && code[i] != '\n' {
				i++
			}
		case c == ';':
			out = append(out, pyTok{kind: ';'})
			i++
		case c == '\'' || c == '"':
			next, tokens, ok := pythonStringTokens(code, i, i, "", depth)
			if !ok {
				return nil, false
			}
			out, i = append(out, tokens...), next
		case pythonIdentStart(c):
			j := i
			for j < len(code) && pythonIdentChar(code[j]) {
				j++
			}
			word := code[i:j]
			if j < len(code) && (code[j] == '\'' || code[j] == '"') && pythonStringPrefix(word) {
				next, tokens, ok := pythonStringTokens(code, i, j, word, depth)
				if !ok {
					return nil, false
				}
				out, i = append(out, tokens...), next
				continue
			}
			if j < len(code) && (code[j] == '\'' || code[j] == '"') {
				// A name glued to a quote is a string prefix this reader does not
				// know (or a keyword written against its string): not read
				// (rel-1-0-10:GAP-0269).
				return nil, false
			}
			out, i = append(out, pyTok{'i', word}), j
		case c >= '0' && c <= '9' || c == '.' && i+1 < len(code) && code[i+1] >= '0' && code[i+1] <= '9':
			j := i + 1
			for j < len(code) && (pythonIdentChar(code[j]) || code[j] == '.' ||
				(code[j] == '+' || code[j] == '-') && (code[j-1] == 'e' || code[j-1] == 'E')) {
				j++
			}
			out, i = append(out, pyTok{'n', code[i:j]}), j
		case c >= 0x80:
			return nil, false
		default:
			op := pythonOperator(code[i:])
			switch op {
			case "(", "[", "{":
				brackets++
			case ")", "]", "}":
				if brackets > 0 {
					brackets--
				}
			}
			out, i = append(out, pyTok{'o', op}), i+len(op)
		}
	}
	return out, true
}

// pythonStringTokens reads the string whose quote is at code[quote] (its
// prefix starts at start). The result is the tokens of its f-string
// expressions, in parentheses, then one string token with the source text.
func pythonStringTokens(code string, start, quote int, prefix string, depth int) (next int, tokens []pyTok, ok bool) {
	q := code[quote]
	triple := quote+2 < len(code) && code[quote+1] == q && code[quote+2] == q
	body, closeLen := quote+1, 1
	if triple {
		body, closeLen = quote+3, 3
	}
	j := body
	for {
		if j >= len(code) {
			return 0, nil, false
		}
		if code[j] == '\\' {
			j += 2
			continue
		}
		if code[j] == q && (!triple || j+2 < len(code) && code[j+1] == q && code[j+2] == q) {
			break
		}
		if !triple && code[j] == '\n' {
			return 0, nil, false
		}
		j++
	}
	if strings.ContainsAny(prefix, "fFtT") {
		exprs, good := pythonFStringExprs(code[body:j], depth)
		if !good {
			return 0, nil, false
		}
		for index, expr := range exprs {
			inner, good := pythonTokens(expr, depth+1)
			if !good {
				return 0, nil, false
			}
			if index > 0 {
				// Not a comma: it would split the arguments of an enclosing call.
				tokens = append(tokens, pyTok{kind: ';'})
			}
			tokens = append(tokens, pyTok{'o', "("})
			tokens = append(tokens, inner...)
			tokens = append(tokens, pyTok{'o', ")"})
		}
	}
	end := j + closeLen
	return end, append(tokens, pyTok{'s', code[start:end]}), true
}

// pythonFStringExprs lists the expressions of an f-string body, those nested
// in format specs included. An unbalanced brace is not read.
func pythonFStringExprs(content string, depth int) ([]string, bool) {
	if depth > 3 {
		return nil, false
	}
	var exprs []string
	for i := 0; i < len(content); i++ {
		switch content[i] {
		case '{':
			if i+1 < len(content) && content[i+1] == '{' {
				i++
				continue
			}
			end, ok := pythonFieldEnd(content, i+1)
			if !ok {
				return nil, false
			}
			expr, spec := pythonSplitField(content[i+1 : end])
			if strings.TrimSpace(expr) == "" {
				return nil, false
			}
			exprs = append(exprs, expr)
			if strings.Contains(spec, "{") {
				more, ok := pythonFStringExprs(spec, depth+1)
				if !ok {
					return nil, false
				}
				exprs = append(exprs, more...)
			}
			i = end
		case '}':
			if i+1 < len(content) && content[i+1] == '}' {
				i++
				continue
			}
			return nil, false
		}
	}
	return exprs, true
}

// pythonFieldEnd returns the index of the "}" that closes the field whose
// text starts at from, past nested braces and quoted text.
func pythonFieldEnd(content string, from int) (int, bool) {
	depth := 1
	for i := from; i < len(content); i++ {
		switch c := content[i]; c {
		case '\'', '"':
			for i++; i < len(content) && content[i] != c; i++ {
				if content[i] == '\\' {
					i++
				}
			}
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// pythonSplitField cuts a field at its top-level "!" (a conversion, not !=)
// or ":" (the format spec).
func pythonSplitField(field string) (expr, spec string) {
	depth := 0
	for i := 0; i < len(field); i++ {
		switch c := field[i]; c {
		case '\'', '"':
			for i++; i < len(field) && field[i] != c; i++ {
				if field[i] == '\\' {
					i++
				}
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '!':
			if depth == 0 && (i+1 >= len(field) || field[i+1] != '=') {
				return field[:i], field[i+1:]
			}
		case ':':
			if depth == 0 {
				return field[:i], field[i+1:]
			}
		}
	}
	return field, ""
}

// pythonReadMode reports open arguments whose mode (the positional at index,
// or mode=) is absent or a literal read mode, with no opener of its own.
func pythonReadMode(args []string, index int) bool {
	mode, positional := "", 0
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if key, value, keyword := strings.Cut(arg, "="); keyword && pythonIdentifier(strings.TrimSpace(key)) {
			switch strings.TrimSpace(key) {
			case "mode":
				mode = strings.TrimSpace(value)
			case "opener":
				return false
			}
			continue
		}
		if strings.HasPrefix(arg, "*") {
			return false
		}
		if positional == index {
			mode = arg
		}
		positional++
	}
	if mode == "" {
		return true
	}
	if len(mode) < 2 || mode[0] != mode[len(mode)-1] || mode[0] != '\'' && mode[0] != '"' {
		return false
	}
	return strings.Trim(mode[1:len(mode)-1], "rbtU") == ""
}

func pythonIdentifier(text string) bool {
	if text == "" {
		return false
	}
	for index, char := range text {
		letter := char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
		digit := index > 0 && char >= '0' && char <= '9'
		if !letter && !digit {
			return false
		}
	}
	return true
}
