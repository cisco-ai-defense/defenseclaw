# Central Redaction Contract

## 1. Security Objective

The projection system must apply the configured privacy choice consistently while
preserving structure for debugging, correlation, alerting, and aggregation. The v8
default choice is `none` (unredacted); when a redacting profile is selected, its
transformations must be centralized, destination-aware, deterministic, idempotent,
and fail closed.

Redaction is not authorization. A destination must still be explicitly routed to
receive a record.

## 2. Processing Boundary

All collected logs and all exported trace attributes/events MUST pass through the
central redaction engine after route selection and before destination serialization.
For traces this boundary also covers link attributes, status descriptions,
exception messages/stack traces, GenAI/OpenInference aliases, and vendor wrappers.
Content aliases MUST be generated from one already-redacted typed value; no alias
may retain a less restrictive projection.

Metrics MUST be designed to contain no content-bearing attributes. The redaction
engine validates metric attribute classes but does not attempt expensive free-text
scanning of every metric sample.

The following are prohibited:

- A destination adapter reading an unredacted producer object directly.
- A producer pre-serializing an opaque JSON payload that bypasses field
  classification.
- Copying raw inbound HEC/OTLP bodies into reserved hidden fields.
- Applying redaction after HMAC/signature generation.
- Mutating the canonical record while preparing one destination.

## 3. Built-in Profiles

### 3.1 `none`

- No content redaction.
- Structural validation, size limits, and safe serialization still apply.
- Catalog default for built-in local persistence and capability-default optional
  delivery.
- Valid in defaults, bucket policy, concise sends, advanced routes, and local
  projection resolution.
- Does not produce a warning merely because it is active; configuration mutations
  remain compliance activity.

### 3.2 `sensitive`

- Detect and replace sensitive substrings inside ordinary content strings.
- Remove credential-class fields.
- Preserve non-sensitive surrounding text and structured shape.
- Hash or normalize paths according to the field contract.
- Intended as an explicit opt-in for local operational logs and controlled security
  destinations that need partial content.

### 3.3 `content`

- Replace complete content-bearing fields rather than inspecting substrings.
- Applies to prompts, responses, tool arguments/results, evidence bodies, judge
  bodies, full reasons derived from user content, and equivalent dynamic fields.
- Preserve metadata such as length, content type, hash, rule IDs, status, duration,
  token counts, and correlation IDs where those values are independently safe.
- Intended as an explicit opt-in for destinations that need operational metadata
  but not content.

### 3.4 `strict`

- Allow only fields explicitly classified as safe metadata or safe identifiers.
- Remove all content, reason, evidence, error, path, credential, and
  unknown dynamic-string fields.
- Intended for compliance summaries, health logs, and broadly accessible consoles.

The following matrix is the authoritative resolved definition. It is compiled as
immutable profile data; prose above is descriptive and cannot override a cell:

| Field class | `none` | `sensitive` | `content` | `strict` |
|---|---|---|---|---|
| `metadata` | `preserve` | `preserve` | `preserve` | `preserve` |
| `identifier` | `preserve` | `preserve` | `preserve` | `preserve` |
| `content` | `preserve` | `detect` | `whole` | `remove` |
| `reason` | `preserve` | `detect` | `whole` | `remove` |
| `evidence` | `preserve` | `detect` | `whole` | `remove` |
| `error` | `preserve` | `detect` | `whole` | `remove` |
| `path` | `preserve` | `hash` | `hash` | `remove` |
| `credential` | `preserve` | `remove` | `remove` | `remove` |
| Detector groups | none | `credentials`, `secrets`, `pii` | `credentials`, `secrets`, `pii` | `credentials`, `secrets`, `pii` |

The built-in `strict` profile still declares all three groups so a custom profile
that extends it has one deterministic inherited group set; its built-in modes do
not execute detectors. Similarly, `content` executes no detector for a class whose
mode is `whole`, `hash`, or `remove`. The group declaration never causes scanning
when the resolved field mode does not use `detect`.

For the `path` field class, the built-in `sensitive` and `content` profiles use
`hash-v1` as defined in §7.6; `strict` removes the path field. A schema may expose a
separately classified safe basename or destination class, but it cannot relabel the
original path as metadata. This behavior is fixed profile data, not an
implementation-language default.

### 3.5 `legacy-v7`

`legacy-v7` is an immutable built-in route projection used only to preserve the
effective redacting behavior of an upgraded v7 installation. It is not the default
for a fresh v8 source and it is not a synonym for `sensitive`, `content`, or
`strict`:

- Safe metadata is preserved.
- General strings, model/tool content, errors, paths, credentials, and other v7
  whole-field surfaces use the existing v7 length/hash placeholder behavior.
- Entity/identifier fields retain the v7 entity-placeholder rules, including the
  reviewed long-value prefix threshold.
- Reasons retain the v7 bounded token-aware behavior that preserves reviewed rule
  IDs and safe enum/key glue while whole-redacting dynamic values.
- Evidence retains the v7 evidence placeholder and bounded match-coordinate
  metadata.
- Existing v7 placeholder recognition, idempotence, spoof resistance, short-value
  handling, and SHA-256 compatibility token grammar are preserved exactly by
  generated golden vectors.

The profile is selected explicitly on migration-generated local/bucket/destination
routes when v7 redaction was effective. When v7 redaction was globally disabled,
migration selects the ordinary `none` behavior instead. `legacy-v7` is implemented
in the central Phase 2 projection engine; it does not keep a second v7 fan-out or
producer-side redaction path alive.

## 4. Custom Profile Composition

A custom redacting profile MUST extend exactly one of `sensitive`, `content`, or
`strict`; neither `none` nor `legacy-v7` can be extended or aliased. `none` has no
transformations to compose, while `legacy-v7` is a fixed migration-compatibility
contract rather than an authoring base. A custom profile MAY change only:

- Enabled built-in detector groups.
- Per-field-class transformation mode.

Detector work limits, output limits, replacement-token lengths, and report limits
are fixed catalog-v1 security bounds. They are not v8 configuration fields. A
future change to one of those limits requires a detector-catalog/specification
version change; it cannot be introduced as an unreviewed per-profile size or
excerpt knob.

Allowed field-class modes are:

- `preserve`
- `detect`
- `whole`
- `hash`
- `remove`

Profile-strength validation prevents a custom profile from becoming an unlabelled
raw bypass:

- `metadata` and schema-approved `identifier` MUST remain `preserve`; a custom
  profile cannot remove or rewrite truthfulness, correlation, or generated safe
  envelope fields.
- `preserve` is allowed only for schema-approved `metadata` and `identifier`
  classes.
- `credential` may use only `remove` or `whole`.
- `detect` requires at least one effective detector group.
- `content`, `reason`, `evidence`, `error`, and `path` cannot be set to `preserve`.
- A profile that needs raw dynamic fields must use the built-in `none` profile and
  therefore receives the ordinary unredacted behavior.

Custom profiles MUST NOT contain arbitrary regex, executable scripts, expressions,
network calls, or model prompts. Unknown detector groups, field classes, or modes
are startup errors.

Profiles are resolved at configuration load. Inheritance is deliberately
single-level: a custom profile extends one built-in redacting profile, so cycles
and multiple inheritance are not representable.

## 5. Field Classes

Every dynamic body field is assigned one of:

| Class | Examples | Redacting-profile behavior |
|---|---|---|
| `metadata` | version, duration, count, mode, protocol, bounded enum | Preserve |
| `identifier` | request ID, trace ID, scan ID, stable rule ID | Preserve if schema-approved |
| `content` | prompt, response, tool args/result, message, raw body | Detect or whole by profile |
| `reason` | policy reason, operator reason, decision explanation | Detect |
| `evidence` | matched excerpt, detector context, judge evidence | Detect or whole |
| `error` | external/provider error text and causes | Detect |
| `path` | file paths, workspace paths, URLs with path/query | Hash/normalize |
| `credential` | token, password, secret, auth header, private key | Remove or whole |

Unknown keys in dynamic objects are classified as `content`. Schema-owned fields
must declare classes in the event contract. A field name alone is insufficient to
upgrade an unknown field to safe metadata.

## 6. Built-in Detector Catalog v1

Detector catalog version 1 exposes exactly three operator-facing groups and the
following ordered membership. This table is authoritative for configuration,
overlap resolution, replacement IDs, Go detector conformance, and shared
Go/Python catalog/configuration parsing:

The canonical machine source is
`schemas/telemetry/v8/redaction/detector-catalog-v1.yaml`. It MUST contain catalog
version, ordered group membership, ordered detector entries, lexical grammar or
parser ID, semantic validator ID, input class/context, candidate bound,
replacement-interval rule, and fixture-set ID. The generated Go catalog and the
Python configuration/catalog constants consume that file; neither language keeps a
hand-maintained membership or ordering list. The file validates against
`schemas/telemetry/v8/redaction/detector-catalog.schema.json`, and generated-artifact
drift is part of `make check-schemas`.

| Order | Group token | Detector ID | Exact v1 recognition contract |
|---:|---|---|---|
| 1 | `credentials` | `credentials.api_token` | The literal-prefix, alphabet, and bounded-length provider formats in the audited subcatalog below, considered longest-prefix first and with token boundaries. |
| 2 | `credentials` | `credentials.private_key` | A complete ASCII PEM private-key block whose BEGIN/END label is one of `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`, or `OPENSSH PRIVATE KEY`; a public key or certificate alone is excluded. The lexical candidate is bounded at 64 KiB and follows the exact PEM rules below. |
| 3 | `credentials` | `credentials.authorization` | A case-insensitive ASCII header assignment whose name is exactly `Authorization` or `Proxy-Authorization`, followed by optional ASCII space/tab, `:` or `=`, optional space/tab, one of `Bearer`, `Basic`, `Digest`, `Token`, or `ApiKey`, at least one space/tab, and a nonempty credential ending at the line boundary. The complete line is bounded at 8 KiB; only the credential interval is selected. Bare schemes, prose, and other header names are excluded. |
| 4 | `credentials` | `credentials.cookie` | A complete bounded ASCII `Cookie` or `Set-Cookie` header line parsed by the exact grammar below. Values whose case-insensitive member names are `session`, `sessionid`, `sid`, `auth`, `authorization`, `token`, `access_token`, `refresh_token`, `jwt`, or `csrf` are selected. Attributes and unrelated members are excluded. |
| 5 | `credentials` | `credentials.connection_string` | An absolute hierarchical URI or bounded key/value DSN parsed by the exact grammar below and containing a nonempty password or cataloged credential query/member value. Credential material is selected, not a username, host, or host-only DSN. Supported schemes are the explicit catalog set `postgres`, `postgresql`, `mysql`, `mariadb`, `mongodb`, `mongodb+srv`, `redis`, `rediss`, `amqp`, `amqps`, `kafka`, `sqlserver`, and `snowflake`. |
| 6 | `secrets` | `secrets.assignment` | A bounded assignment parsed by the exact grammar below with one of the case-insensitive keys `password`, `passwd`, `pwd`, `secret`, `client_secret`, `api_key`, `apikey`, `access_token`, `refresh_token`, `private_key`, and `signing_key`. Empty values, booleans, null, and the exact placeholder set below are excluded. |
| 7 | `secrets` | `secrets.high_entropy` | A standalone 20-256 byte ASCII candidate from base64/base64url/hex alphabets with Shannon entropy `-sum(p(c)*log2(p(c)))` of at least 3.5 bits per character, no whitespace, and—for non-hex candidates—characters from at least three of uppercase, lowercase, digit, and `+/_-=` symbol classes. UUIDs, trace/span IDs, record IDs, all-one-character values, a 1-8 byte unit repeated to make the complete candidate, case-insensitive `example|sample|dummy|changeme|redacted` repetitions, hashes in schema-approved identifier fields, and candidates already claimed by a credential detector are excluded. |
| 8 | `secrets` | `secrets.url_query` | A query value for one of the exact case-insensitive keys below. Percent-decoding is used only for semantic validation; replacement offsets, length, and HMAC input use the exact original encoded value bytes. Empty decoded values are excluded. Parsing follows §7.6 URI rules and never reorders the source string during detection. |
| 9 | `secrets` | `secrets.cloud_account_identifier` | An AWS, Azure, or GCP identifier present in one of the exact inline labels or resource-name positions below. Unlabelled 12-digit numbers, UUIDs, and DNS-like strings are excluded. |
| 10 | `pii` | `pii.email` | An ASCII dot-atom local part and DNS host candidate using the exact grammar below, maximum 254 bytes and maximum 64-byte local part, with at least one host dot, valid 1-63 byte labels, and alphabetic 2-63 byte final label. Quoted local parts, comments, Unicode email, and IDNA inference are excluded in v1. Reserved domains are the required positive synthetic fixtures, avoiding live personal data. |
| 11 | `pii` | `pii.telephone` | North American 10-digit numbers using consistent spaces, dots, or hyphens, optional parentheses around the area code, plus international `+1` forms with the same separators. Area and exchange must start with 2-9. Unseparated 10-digit strings, extensions, non-`+1` international formats, dates, versions, and longer digit runs are excluded in v1. |
| 12 | `pii` | `pii.national_identifier` | U.S. Social Security numbers in `DDD-DD-DDDD` form. Reject area `000`, `666`, or `900`-`999`, group `00`, serial `0000`, the exact synthetic/example denylist below, all-identical digits, and a candidate embedded in a longer digit run. Other national identifiers require a future catalog version. |
| 13 | `pii` | `pii.payment_card` | A 13-19 digit candidate with optional consistent spaces or hyphens, digit boundaries, and a valid Luhn checksum. Reject all-identical digits, mixed separators, and every Luhn-negative candidate. |
| 14 | `pii` | `pii.ip_address` | A token-boundary candidate accepted by Go `net/netip.ParseAddr`, using IPv4 or IPv6 syntax. Ports, CIDRs, zones, and malformed/leading-zero IPv4 are excluded; the implementation may not silently repair a rejected candidate. |

The `credentials.api_token` provider subcatalog is exact:

| Provider/form | Prefix and suffix contract |
|---|---|
| AWS access/session/principal IDs | One of `AKIA`, `ASIA`, `AROA`, `AGPA`, `AIDA`, `AIPA`, `ANPA`, `ANVA`, followed by exactly 16 `[A-Z0-9]`. |
| GitHub classic/OAuth/server/refresh | One of `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, followed by exactly 36 `[A-Za-z0-9]`. |
| GitHub fine-grained PAT | `github_pat_`, then exactly 22 `[A-Za-z0-9]`, `_`, and exactly 59 `[A-Za-z0-9]`. |
| GitLab PAT | `glpat-` followed by 20-255 `[A-Za-z0-9_-]`. |
| Slack bot | `xoxb-`, 10-13 digits, `-`, 10-13 digits, `-`, and 24-128 `[A-Za-z0-9]`. |
| Other Slack token | One of `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, followed by 24-200 `[A-Za-z0-9-]`. |
| Stripe | One of `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `pk_live_`, `pk_test_`, followed by 20-128 `[A-Za-z0-9]`. Publishable forms are still credential-class telemetry and are protected. |
| Google API key | `AIza` followed by exactly 35 `[A-Za-z0-9_-]`. |
| OpenAI/Anthropic/OpenRouter | Longest-prefix-first `sk-proj-`, `sk-ant-`, `sk-or-`, or `sk-`; total token length 24-256 bytes and suffix alphabet `[A-Za-z0-9_+=.-]`. |
| JWT | Three dot-separated base64url segments, first segment beginning `eyJ`, each segment 2-1,024 characters, and total candidate at most 3,074 bytes; header and payload must decode to bounded JSON objects and an empty signature is rejected. No claim validation is performed. |

All provider formats require ASCII token boundaries. Prefix, alphabet, length, or
provider-form additions require a detector-catalog/specification version change.
Fixtures use reserved synthetic variants only; no live token is permitted.

### 6.1 Detector input and replacement intervals

A detector invocation receives only a valid UTF-8 string, its resolved field class,
and the immutable catalog entry. It does not receive a JSON key, pointer,
destination, bucket, or producer-supplied trust hint. A structured schema field
known to be a credential is classified `credential` and is handled by its profile
mode; it is not made safe by contextual detector heuristics. Consequently, labels,
header names, URI structure, and resource-name positions required below MUST occur
inside the scanned string itself.

Recognizers report half-open UTF-8 byte intervals into the original string. Semantic
decoding never changes an interval. Unless a detector below says otherwise, its
replacement interval is its complete lexical candidate and `MATCH_BYTES`/`N` in
§7.5 are the original bytes/length in that interval. For quoted or percent-encoded
values, delimiters remain outside the interval and escapes remain in their original
encoded form. `credentials.authorization`, cookie, DSN/assignment, and URL-query
detectors select only the credential/value interval. Cloud detectors select only
the account/project/tenant/subscription component. PII detectors select the complete
candidate including accepted separators.

For provider tokens, an ASCII token boundary is the start/end of input or a byte
outside `[A-Za-z0-9_+=.-]`. For the remaining detectors the manifest carries the
literal left/right boundary grammar; no Unicode `\w`, locale, or implementation
word-boundary behavior is permitted.

### 6.2 Exact structured grammars

The machine catalog encodes these closed parser contracts:

- **PEM private keys:** the candidate starts at a line boundary with exactly
  `-----BEGIN LABEL-----`, uses one consistent LF or CRLF line ending, contains one
  or more base64 payload lines of 4-64 characters, permits `=` padding only at the
  end of the final payload line, decodes successfully with standard padded base64,
  and ends with exactly `-----END LABEL-----` using the same allowed label. The
  decoded body must be nonempty. Headers, blank payload lines, unmatched labels,
  trailing characters on delimiter lines, and candidates over 65,536 bytes are
  rejected.
- **Authorization:** the exact 8 KiB line grammar and selected credential interval
  are in the detector table. Embedded CR/LF, control bytes other than horizontal
  tab in allowed whitespace, and credentials longer than the remaining line bound
  are rejected.
- **Cookies:** a complete line is at most 8 KiB, begins case-insensitively with
  `Cookie:` or `Set-Cookie:`, and contains no embedded CR/LF/control byte. Members
  are semicolon-separated `name=value` pairs with optional ASCII space/tab around
  delimiters. A name uses ASCII token characters. A value is either nonempty visible
  ASCII excluding semicolon, comma, double quote, and backslash, or a double-quoted
  sequence in which backslash escapes exactly the next visible ASCII byte. For
  `Cookie`, every member is eligible; for `Set-Cookie`, only the first pair is the
  cookie and later pairs are attributes. Only a value whose member name is in the
  detector-table set is selected, excluding its quote delimiters.
- **Connection strings:** a URI is ASCII, hierarchical, and uses one listed scheme.
  Userinfo is eligible only in `user:password` form and selects the nonempty raw
  password component; username-only userinfo is excluded. Query values use the
  URL-query key set below. A non-URI DSN is at most 8 KiB and is a sequence of
  `key=value` pairs separated by semicolon or one-or-more ASCII whitespace bytes.
  A key matches `[A-Za-z_][A-Za-z0-9_.-]*`; a value is a nonempty unquoted run up to
  a separator or a JSON double-quoted string with valid JSON escapes. Eligible keys
  are `password`, `passwd`, `pwd`, `pass`, `secret`, `client_secret`, `api_key`,
  `apikey`, `access_token`, `refresh_token`, `token`, `signature`, and `credential`.
  Only the original value bytes, excluding quote delimiters, are selected.
- **Assignments:** the complete lexical candidate is at most 8 KiB. It is either
  `KEY OWS ("="|":") OWS VALUE` with an ASCII identifier key, or JSON member
  `"KEY" OWS ":" OWS JSON_STRING`; `OWS` is zero or more ASCII space/tab bytes.
  An unquoted value ends at ASCII whitespace, comma, semicolon, `}`, or `]`; a
  quoted value must have valid JSON escapes. The original value bytes excluding
  quote delimiters are selected. After JSON unescaping for validation only, an
  empty value, case-insensitive `true`, `false`, `null`, `example`, `sample`,
  `dummy`, `changeme`, or `redacted`, a value made only of `*`, or a complete
  `${...}` placeholder is excluded.
- **URL query:** parsing uses the §7.6 URI parser. Eligible case-insensitive keys are
  exactly `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `key`,
  `secret`, `client_secret`, `password`, `passwd`, `pwd`, `signature`, `sig`,
  `x-amz-signature`, `x-goog-signature`, `code`, and `credential`. The value is
  percent-decoded only to decide whether it is empty and valid UTF-8. The selected
  interval and correlation input are the nonempty original encoded bytes between
  that `=` and the next `&`, `;`, `#`, or end of input. Key order and duplicates are
  retained.
- **Cloud identifiers:** accepted inline labels are exactly `aws_account_id`,
  `azure_tenant_id`, `azure_subscription_id`, `gcp_project_number`, and
  `gcp_project_id`, followed by optional ASCII space/tab, `:` or `=`, and optional
  space/tab. AWS values are exactly 12 digits or the 12-digit account component in
  a syntactically valid six-component ARN. Azure values are lowercase-insensitively
  labeled UUIDs or UUIDs immediately following `/subscriptions/` or `/tenants/` in
  an Azure resource ID. GCP project numbers are 6-19 digits; project IDs match
  `[a-z][a-z0-9-]{4,28}[a-z0-9]` and are accepted when labeled, immediately after
  `projects/`, or as the project portion of
  `NAME@PROJECT.iam.gserviceaccount.com`. No other surrounding key name or path
  grants context.
- **Email:** the local part is one or more ASCII `atext` atoms separated by single
  dots, where `atext` is alphanumeric or one of ``!#$%&'*+-/=?^_`{|}~``; leading,
  trailing, or repeated dots are invalid. DNS labels contain only ASCII letters,
  digits, and interior hyphens, cannot begin/end with a hyphen, and obey the table's
  length/final-label bounds.
- **Telephone:** accepted forms are `AAA SEP EEE SEP NNNN`,
  `(AAA) SEP EEE SEP NNNN`, `+1 SEP AAA SEP EEE SEP NNNN`, and
  `+1 SEP (AAA) SEP EEE SEP NNNN`, where `SEP` is one consistently reused byte from
  space, dot, or hyphen. Area and exchange start with 2-9. No other whitespace,
  punctuation, extension, or digit count is accepted.
- **National identifier:** the exact denied synthetic values are `078-05-1120`,
  `111-11-1111`, `123-45-6789`, `219-09-9999`, and `987-65-4321`, in addition to
  the structural exclusions in the table.
- **JWT:** base64url segments contain only `[A-Za-z0-9_-]` with optional valid
  terminal padding removed before matching. Header and payload decode to UTF-8 JSON
  objects with at most 8 KiB decoded bytes, depth 16, 256 members, and no duplicate
  keys. Trailing JSON data, non-object roots, invalid encoding, and empty signatures
  are rejected.

Any grammar, key/label set, parser bound, or replacement-interval change is a new
detector-catalog version. Implementations may optimize these rules but may not
accept a superset.

The group tokens remain exactly `pii`, `credentials`, and `secrets`. A custom
profile selects groups, never individual detector IDs. Omitted `detectors` inherits
the built-in base set; a present nonempty list replaces it; an empty or unknown
list is invalid. `sensitive`, `content`, and `strict` enable all groups, although a
whole/remove mode can prevent detector execution. `none` runs no detector.

All lexical recognizers MUST compile under Go's RE2-compatible regular-expression
semantics: no backreferences, lookaround, recursion, or catastrophic-backtracking
engine is permitted. Lexical matching produces bounded candidates only; the
semantic validator in the table decides acceptance. Every detector has a synthetic
positive, near-miss, boundary, Unicode-adjacent, overlap, and oversized corpus in
the Go detector package. Python validates the same versioned group/member manifest
and configuration tokens but MUST NOT carry a second detector implementation.
Fixtures use reserved/example data and MUST contain no live credential or personal
identifier. Cross-language execution parity applies to `hash-v1` (§7.6), not to
detector matching.

Overlap resolution is deterministic and cannot expose the non-overlapping tail of
a lower-priority match. Accepted intervals are sorted into transitive overlap
clusters; every cluster is replaced across the union from its minimum start through
maximum end. The cluster's token identity is selected by `credential > secret >
pii`, then catalog order, earlier start, and longer interval. Adjacent intervals do
not overlap and remain separate. Replacement proceeds from the end of the string
toward the beginning so original byte offsets remain valid.

## 7. Central Projection and Transformation Semantics

### 7.1 Immutable boundary and exact projection metadata

The central engine accepts an immutable canonical `Record` and produces a distinct
immutable `Projection` plus a `SafeReport`. It MUST NOT mutate, share mutable maps or
slices with, or serialize directly from the canonical record. One projection is
created independently per selected route/profile.

Projected JSON is the canonical envelope plus exactly one added top-level member:

```json
{
  "projection": {
    "redaction_profile": "sensitive",
    "detector_catalog_version": 1,
    "state": "transformed",
    "transformed_fields": 3,
    "removed_fields": 1,
    "oversize_fields": 0,
    "failure_count": 0,
    "failures_truncated": false
  }
}
```

The phrase "canonical envelope" describes the envelope field vocabulary, not a
requirement to copy stale classification entries. The canonical `Record` retains
its complete immutable `field_classes` map. A delivery `Projection` emits the
surviving subset of that original classification provenance: an entry is retained
only when its original pointer still resolves to the corresponding projected leaf.
An object property removed by `remove`, including an empty-container property, and
all of its classification entries are absent from the delivery map. An exact
classified array leaf removed to JSON `null` retains its index and classification
entry because that original pointer still exists. A structural `null` created by
pruning a descendant-empty container has no original class at the container pointer
and receives no synthesized entry. No removed property name or presence signal may
survive only in `field_classes`. This filtering intentionally means a delivery map
need not classify a newly created structural `null`; it does not mutate or weaken
the pre-projection complete-map validation in §7.2.

To prevent the same disclosure through a surviving parent key, a nonempty
container that becomes empty solely because every descendant was removed is
pruned as part of the same removal. When that prunable container is an object
property, the property is omitted; when it occupies an array slot, the slot becomes
JSON `null`. A container that was empty in the canonical input is not auto-pruned
merely for being empty, but its own exact leaf classification and configured mode
still apply. A container that retains any preserved or transformed descendant
remains present. Thus pruning neither invents key classification nor collapses
array indices. An exact classified leaf removed in an array retains that pointer's
classification on the delivered `null`; a container made prunable only through
descendant removal has no class at the container pointer, so its array `null` keeps
the index but receives no synthesized classification entry.

This `projection` object is delivery metadata and is not part of the canonical
envelope. It is included in the final projected serialization and its destination
integrity HMAC/signature. Its member set is exact: profile name, integer catalog
version, `raw|inspected|transformed|failed_closed` state, nonnegative counters, and
a Boolean truncation flag. `transformed_fields` counts changed serialized leaves other than
removed leaves; `removed_fields` counts removed properties/array slots;
`oversize_fields` is the subset of transformed leaves protected for scan size; and
`failure_count` counts field/sample/record processing failures independently.
Each configured leaf removal increments `removed_fields`. If recursive pruning
additionally omits a parent object property or nulls a parent array slot, each such
extra structural removal increments `removed_fields` once as well; pruning is not
hidden from the aggregate counters.
`raw` means `none` intentionally made no content transformation; `inspected` means
a redacting profile completed without a match, whole/hash/remove/oversize action,
or processing failure; `transformed` means at least one
detect/whole/hash/remove/oversize action and no processing failure; any processing
failure makes the aggregate state
`failed_closed`, even when safe output remains deliverable.

`SafeReport` is in-memory diagnostic data, not serialized into the projection. It
contains the same aggregate counters and at most 32 failure entries in deterministic
traversal order. An entry contains only field class, configured mode, result enum,
and stable error code. It contains no record value, substring, token, key material,
destination credential, endpoint, filesystem/URI path, JSON pointer, or exception
text. Additional entries set `failures_truncated` and increment the aggregate
failure count. The engine returns this report to the caller; the caller may emit a
rate-limited `platform.health / redaction.failed_closed` record. The engine MUST NOT
recursively route health telemetry itself.

### 7.2 Field-map resolution

P2 records provide an explicit complete JSON-pointer-to-class map for every dynamic
leaf in `body`; inherited parent classes and key-name upgrades are forbidden. The
builder assigns a newly encountered unknown dynamic member the explicit `content`
class. Before value traversal, the projector performs a shape-only comparison of
the immutable body leaf inventory and the field map. A missing, stale, ambiguous,
duplicate, extra, or unresolved pointer is a record-level projection failure with
`classification_failed`: no scalar value is passed to a detector or serializer, no
partial projection is delivered, and §9.2 applies. Because containers do not inherit
a field class, the engine MUST NOT guess a containing class or synthesize a
class-specific replacement token for an invalid map. A name such as `duration`,
`id`, or `status` can never upgrade an unknown value to `metadata` or `identifier`.

P5-generated family builders may inject a trusted generated `ClassResolver` from
the telemetry schema registry. That resolver is version-bound, covers aliases from
one canonical typed value, and produces the same explicit leaf decisions before
projection. No producer, destination adapter, or free-form heuristic can claim
schema-derived trust.

### 7.3 Scalar and container modes

- Objects are traversed in canonical key order; arrays retain semantic order.
- `remove` omits an object property. In an array it replaces the slot with JSON
  `null`, preserving indices and shape. Empty objects/arrays are retained unless
  that exact leaf is removed or a previously nonempty container becomes empty
  solely because all descendants were removed, in which case §7.1 recursively
  prunes that container using the same object-versus-array rule. The projected
  `field_classes` map is filtered under §7.1: omitted object leaves disappear from
  the map, while an exact classified leaf delivered as array `null` remains
  classified at its stable index. A descendant-pruned container `null` has no
  invented class entry. Every additional property omission or array-slot null caused
  by recursive pruning is a separate `removed_fields` action.
- `preserve` retains strings, canonical JSON booleans/numbers, and null exactly.
- `detect` scans strings only. Non-string scalars and null are preserved.
- `whole` and `hash` transform strings and the canonical JSON scalar text for
  booleans/numbers; null is preserved.
- Binary inputs are already represented by an explicitly classified canonical JSON
  string; the projection engine accepts no new opaque binary type.
- Metrics accept only `metadata` and schema-approved `identifier` leaves. Any other
  class or unresolved metric attribute fails that sample; detector scanning is
  never run on metric samples.

For logs/traces, a per-field failure after successful field-map validation replaces
the complete affected scalar safely and continues other fields. A container
traversal failure or any classification failure is record-level, delivers no
projection, and follows §9.2. No guessed container token or partially scanned raw
middle is emitted.

### 7.4 Fixed work and size limits

The canonical payload (`body` or `instrument_data`) is at most 1,048,576 bytes and
the complete canonical record is at most 4,194,304 bytes. A projected payload
remains limited to 1,048,576 bytes. The complete serialized projected record may be
at most 4,198,400 bytes: the canonical-record maximum plus exactly 4 KiB reserved
for the bounded top-level `projection` object. The projection object itself MUST fit
inside that 4 KiB headroom; destination wrappers are bounded separately by their
adapter contracts. This permits an exact-maximum valid `none` record to receive its
required projection metadata without weakening the canonical payload bound.

Projection depth, member count, and individual string limits remain within the
canonical bounds. Transformation expansion that would exceed the projected payload
or complete projected-record bound fails closed under `output_limit`. Additional
detector-catalog-v1 limits are fixed:

| Limit | Value | Required exhaustion behavior |
|---|---:|---|
| Bytes scanned per string | 256 KiB | Do not scan a prefix/suffix. Replace the whole field with the `oversize.CLASS` token. |
| Lexical candidates per field | 512 | Stop detection and replace the whole field with `failed_closed`/`candidate_limit`. |
| Accepted matches per field | 256 | Replace the whole field with `failed_closed`/`field_match_limit`. |
| Accepted matches per record | 4,096 | Replace the current and every subsequently detectable field with `failed_closed`/`record_match_limit`; preserve already transformed safe fields. |
| Safe-report entries | 32 | Omit further entries and set `failures_truncated`; never omit aggregate counts. |

Invalid UTF-8, depth/member/output overflow, regex/validator error, key failure, or
candidate/match-limit exhaustion is fail-closed for the affected field/sample. The
separate scan-byte limit intentionally uses the safe keyed `oversize.CLASS`
transformation and `transformed`/`truncated` state rather than reporting a processing
failure. Neither case permits a scanned prefix plus an unscanned raw middle or
suffix. Go uses RE2 only. These limits are not configurable in v8.

### 7.5 Replacement tokens and correlation domains

All correlation tokens use the installation key in §7.7 and HMAC-SHA-256 with
separate ASCII domain strings and NUL separators. There is no unkeyed fallback.
Detected substring replacement is exactly:

`<redacted type=DETECTOR_ID v=1 key=KEY_ID len=N hmac=16HEX>`

`16HEX` is the first 16 lowercase hexadecimal characters of
`HMAC-SHA-256(key, "defenseclaw-redaction-detect-v1" || NUL || DETECTOR_ID || NUL || MATCH_BYTES)`.
`N` is the original matched UTF-8 byte count. Whole-field replacement uses the same
grammar with `type=field.CLASS` and domain
`defenseclaw-redaction-whole-v1`; oversize replacement uses
`type=oversize.CLASS` and domain `defenseclaw-redaction-oversize-v1`. For whole and
oversize, input bytes are the original string or canonical JSON scalar text and
`N` is that byte length.

A processing failure that cannot safely compute a keyed correlation token is
exactly `<redacted type=failed_closed v=1 code=CODE>`. `CODE` is a bounded registered
token such as `key_unavailable`, `invalid_utf8`, `candidate_limit`,
`field_match_limit`, `record_match_limit`, `unicode_repertoire`,
`projection_context_mismatch`, or `output_limit`; it contains
no length, digest, value, or exception text.

The correlation scope is installation-wide. For the same key, detector/class,
catalog version, and exact value, tokens correlate across profiles and
destinations. Domain and detector/class input prevent correlation across different
types. Key rotation intentionally ends future correlation with old tokens.

### 7.6 `hash` mode and path/URI normalization

`hash` is a deterministic non-reversible field-class transformation. Go and Python
implement `hash-v1` byte-for-byte:

1. Reject invalid UTF-8 and any Unicode scalar whose Derived Age is unassigned or
   later than Unicode 13.0; otherwise normalize text to Unicode 13.0 NFC. The
   generated compact range table at
   `schemas/telemetry/v8/redaction/unicode-age-13.0.json` is the shared accepted
   repertoire and is embedded in both implementations. Runtime Go/Python Unicode
   library versions are not authority and startup/tests assert the embedded table's
   version and digest. A rejected scalar fails with `unicode_repertoire`; it is not
   silently passed through. Do not trim, case-fold ordinary text, expand environment
   variables/`~`, consult the filesystem, or resolve symlinks.
2. Recognize a Windows drive path before attempting URI parsing. A drive-absolute
   root is `c:/` after lowercasing only the drive letter; `..` cannot cross it. A
   UNC root is exactly `//server/share` only when both nonempty server and share
   segments are present; preserve their case and prevent `..` from crossing that
   root. A leading `//server` without share is not an absolute UNC root. Convert
   backslashes to slash, collapse separators after the root, remove `.`, resolve
   `..` against an ordinary segment, retain unresolved leading `..` only for a
   relative path, and remove a trailing slash except for a root.
3. Treat only an ASCII RFC-3986 absolute hierarchical URI with `scheme://authority`
   as a URI. Opaque URIs (`urn:`, `mailto:`, `data:`) are ordinary lexical text.
   Text with a syntactically valid scheme followed by `://` but an invalid,
   non-ASCII, or empty host fails closed; v8 performs no IDNA conversion or repair.
   Split the URI first, validate every percent escape, uppercase escape hex, and
   decode percent-encoded unreserved bytes in each component. Then lowercase the
   ASCII scheme and host, remove path dot segments (so decoded `%2e` participates in
   dot-segment processing), and discard the fragment after validating it. A nonempty
   explicit port contains decimal ASCII digits only. Numeric `080` is the HTTP
   default and numeric `0443` is the HTTPS default, so any zero-padded spelling with
   numeric value 80/443 is removed for that scheme; every other port spelling is
   preserved. Preserve query item order, duplicates, delimiters, and values. Invalid
   percent escapes fail closed. Userinfo participates in normalized hash input but
   is never emitted in diagnostics or metadata.
4. Compute HMAC-SHA-256 over
   `"defenseclaw-redaction-hash-v1" || NUL || FIELD_CLASS || NUL || NORMALIZED_VALUE`.
5. Emit all 64 lowercase digest hex characters in
   `<hashed class=CLASS v=1 key=KEY_ID len=N hmac=HEX>`, where `N` is the original
   UTF-8 byte length.

The hash domain is distinct from detect/whole/oversize domains. Cross-language
golden vectors use one shared success/error fixture and cover ordinary text, POSIX,
drive-relative/absolute Windows paths, valid/invalid UNC roots, relative parents,
Unicode 13.0 NFC and rejected newer/unassigned scalars, hierarchical/opaque/invalid
URIs, encoded dot segments, invalid percent escapes, query duplicates, userinfo,
and zero-padded default/nondefault ports. Every success entry contains normalized
text and the exact token; every failure entry contains only its expected safe error
code. Both implementations MUST consume every entry rather than duplicating an
independent malformed-input list.

The HMAC is over `NORMALIZED_VALUE`, while token `len=N` is the original UTF-8 byte
length. Equivalently normalized inputs therefore have the same `(class, key,
hmac)` correlation identity but may have different complete presentation tokens
when their original byte lengths differ. Downstream correlation uses the parsed
`(class, key, hmac)` tuple, never string equality of the complete token.

### 7.7 Correlation-key custody and rotation

The only v8 key location is `${data_dir}/redaction-correlation.key`. There is no
YAML/environment key material or path override. On first writable initialization,
the owner creates exactly 32 cryptographically random raw bytes using an atomic
exclusive-create, file sync, directory sync, and rename/link-safe sequence with
mode `0600`. Existing keys are opened without following symlinks and rejected if
they are a symlink, non-regular file, not owned by the effective service user, have
any group/other permission bit, or are not exactly 32 bytes. `KEY_ID` is the first
12 lowercase hex characters of SHA-256 over the raw key.

Future CLI integration rotates by atomically installing a newly generated valid
key at the fixed path and auditing the old/new safe key IDs. Historical projections
are never rewritten. The built-in `none` profile can operate when the key is absent
or invalid because it computes no correlation token. A redacting profile fails
each affected field closed with `code=key_unavailable` and returns a safe report;
it never falls back to raw or unkeyed hashing.

### 7.8 Trusted idempotence and legacy exception

A `Projection` carries unexported engine-origin, profile, key ID, detector version,
and transformed-node provenance. Re-projecting a projection made by the same engine
with the same profile/key/catalog is a no-op deep immutable clone. Any profile, key,
catalog, or engine-origin mismatch is rejected without output as
`projection_context_mismatch`; the caller must create the new projection from the
immutable canonical `Record`. A projection never retains hidden raw values merely
to support reprojection. The exact `Record` parser rejects a serialized projection's
extra delivery member, while token-shaped user text inside a new canonical record is
untrusted and processed normally. Token grammar alone never grants idempotence or
bypass trust.

The sole scoped exception is `legacy-v7`: for the v8 migration-compatibility
window—the lifetime of the shipped `legacy-v7` profile—it recognizes the exact old
v7 placeholder grammars needed by that immutable profile. Recognition is
unavailable to every other profile and may be removed only with the profile in a
future major-version migration/spec amendment. The extracted v7 string/entity/content/
reason/evidence helpers are pure and state-free: no `DisableAll`, reveal flag,
environment read, mutable package switch, or producer-side branch. A trusted schema
resolver supplies evidence match coordinates when they exist; otherwise the legacy
evidence helper emits its old safe placeholder without inventing coordinates.

### 7.9 Producer reporting truthfulness

Projection never rewrites producer availability. If the producer supplied an
input/output/arguments/result value, its safe `reported` metadata remains `true`
even when the value is partially transformed, wholly replaced, hashed, oversized,
removed, or failed closed. If the producer did not supply it, `reported` remains
`false`; the projector must not fabricate a value merely to redact it.

The P5 telemetry adapter derives the content `state` defined in 11 §12.2 from the
trusted projection result: `preserved` for `none`, `partially_redacted` for detect,
`whole_redacted` for whole/hash/remove (the removed value remains omitted),
`truncated` for a wholly protected oversize value, `failed_closed` for processing
failure, and `not_reported` only for genuinely absent producer data. Thus `reported`
answers whether data existed, while `state` answers what the projection did to it.

## 8. Evidence and Remediation

- Finding evidence summaries are `content`.
- Evidence excerpts are `evidence`.
- Remediation text is always `reason`, including bounded catalog remediation. A
  stable remediation template ID may be a separately classified `identifier`, but
  the human-readable text is never upgraded to `metadata`.
- Evidence fingerprints and stable rule IDs are identifiers.
- Complete prompts, responses, and tool data MUST NOT be stored as finding evidence
  merely because a stricter route can later redact them.

## 9. Failure Behavior

### 9.1 Field processing failure

After the complete field map passes §7.2 preflight, if detection, scalar
transformation, encoding, or field-size handling fails for a dynamic field:

1. Replace the complete field with the exact §7.5 `failed_closed` token, or the
   keyed whole/oversize token when that result was computed safely.
2. Continue processing the rest of the projection.
3. Mark projection state `failed_closed`, update its counters, and add a bounded
   value-free `SafeReport` entry when capacity remains.
4. Return the report to the caller. The caller emits a bounded, rate-limited
   `platform.health / redaction.failed_closed` signal containing profile,
   destination name, field class, and stable error code, but no field value,
   destination secret/endpoint/path, exception text, or recursive redaction report.

Field-map/classification failure is never handled by this field-level path. It is
the record-level `classification_failed` outcome in §7.2/§9.2; unresolved metric
classification rejects the complete sample under §7.3.

### 9.2 Record processing failure

If a complete projection cannot be safely serialized:

- Do not deliver the unsafe projection.
- Emit a rate-limited health transition.
- Preserve delivery to other destinations whose projections succeed.
- For SQLite, write a minimal mandatory failure record; inability to write that
  record changes SQLite health to failed and follows the local-integrity failure
  path.

An incomplete/stale/ambiguous field map, container traversal failure, mismatched
trusted projection tuple, or complete projected-record limit failure is a complete
projection failure under this section. No class is guessed and no partial payload is
eligible for delivery.

### 9.3 Profile-faithful failure behavior

There is no environment variable or runtime error path that changes the selected
profile. Under `sensitive`, `content`, `strict`, `legacy-v7`, or a custom redacting
profile, redaction errors fail closed and never fall back to raw output. Under the
selected `none` profile, raw content is intentional and no detector is expected to
run; the projection still enforces schema, type, size, and serialization
constraints.

The v7 `DEFENSECLAW_DISABLE_REDACTION` behavior is removed from both Go and Python
surfaces during migration. `DEFENSECLAW_REVEAL_PII` may remain only as an
authorized, local, display-time reveal control: it MUST NOT alter collection,
redaction, SQLite persistence, judge-body retention, or any exported projection.
Any existing coupling between that variable and retention must be removed.

## 10. Local Forensic Judge Bodies

Raw judge response retention remains an explicit local forensic feature, separate
from ordinary log routing. Requirements:

- Judge bodies are stored only in the configured judge-body SQLite database.
- They are never copied into canonical logs or remote destination projections.
- Retention follows the global local event/evidence retention age.
- Access paths must be authenticated/locally authorized and must make raw-content
  display explicit.
- Enabling or disabling raw judge retention is compliance activity.
- The observability migration must remove the current global redaction bypass from
  this path; forensic retention is a scoped exception, not a universal one.

## 11. Verification Properties

The redaction implementation MUST be tested for:

- Nested objects and arrays.
- Unicode and invalid byte handling at input boundaries.
- Multiple and overlapping detector matches.
- Luhn-positive and Luhn-negative payment-card candidates.
- Credential fields regardless of key casing.
- User-supplied fake placeholders.
- Idempotence.
- Determinism under map ordering differences.
- Oversize and deeply nested values.
- Malformed structured strings.
- Independent outputs for two destinations using different profiles.
- No mutation of the canonical record.
- Failure-closed behavior and recursion protection.
- Cross-language `hash-v1` golden vectors, path/URI normalization edge cases, key
  rotation, and unavailable-key fail-closed behavior.
- `legacy-v7` golden vectors for each v7 string/entity/content/reason/evidence
  helper, placeholder grammar, repeated application, spoofed placeholders, and
  globally disabled versus redacting migration outcomes.
- GenAI, OpenInference, legacy, span-event, link, exception, and Galileo projection
  aliases all receive equal-or-stronger redaction from one canonical value.
- Input/output `reported` and redaction-state metadata remain truthful after whole,
  partial, truncation, missing-data, and fail-closed projection.
