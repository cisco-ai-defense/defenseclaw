# Command reading budget

Every shell reader of a hook call (the parsers, the statement split, the
analysers, the hook client) works inside one budget, defined in
`internal/shellparse/budget.go` and checked before any of them runs:
`shellparse.BudgetExceeded` (also `TooDeep`, `Reader`, `Parse`). An agent
controls the text of its tool calls, so without a bound the text is a denial
of service against the gateway (GAP-0254: a 67 KB pipeline held the hook past
6 GiB; GAP-0255: a 499 KB left-deep list overflowed the goroutine stack in the
copy of the parse cache, a fatal error that kills the process).

## The two stages

1. **One linear pass over the raw bytes**, independent of the grammar and of
   whether the text parses. It counts nesting of `(`, `{`, `[`; the `|` and
   `&&` bytes; and tokens (words plus separator and operator bytes). It counts
   twice: *aware of data* (single-quoted text, comments and the bodies of
   here-documents that expand no command are not counted: the shell does not
   parse them as commands, and base reads a here-document of shell code in
   full) and *raw* (every byte, with a bound eight times and four times the
   aware one). The aware count is this pass's reading of the grammar, not the
   parser's: where the two differ, the raw bound still limits what the parser is
   given, and the tree measure below counts what it really holds.
2. **A tree measure**, for a text past a soft bound (more than 2,048 bytes or
   512 chain bytes): the text is parsed once and the tree is counted with an
   iterative walk (explicit stack, no recursion): nodes, depth and chain
   operators. A chain past the soft bound that does not parse has no tree to
   measure and is over the budget (GAP-0284).

The copy of the parse cache (`cloneFile`) is iterative as well, so a tree of
any depth costs heap, not goroutine stack. The remaining recursive readers
(`syntax.Walk` and the analysers) recurse once per level of a tree the budget
has already bounded to `MaxTreeDepth` levels.

Every parser site goes through the one entry: the 37 that read through
`shellparse.Reader`, and the eight that used a raw reader, which do now. The nested
body measure and the budget's own measuring parse are the only parsers on
text the first stage has bounded in another way.

## Values

| Bound | Value | Largest real call | p99.99 | Why this value |
|---|---|---|---|---|
| `MaxNestingDepth` | 512 | | | unchanged (GAP-2537) |
| `MaxCommandBytes` | 1 MiB | 97,371 | 25,175 | the hook body cap |
| `MaxChainOperators` (tree) | 512 | 38 | 10 | 64 to 270 ms and 24 MiB at the cap on the costliest family (a pipeline of command substitutions: 64 ms on a quiet box, 149 to 268 ms measured by the review on a loaded one); 4096 cost 1.6 to 4.2 s |
| `MaxChainBytes` (text, aware) | 16,384 | 1,600 | 176 | parsing a chain costs about 2 KB per byte |
| `MaxTokens` (text, aware) | 131,072 | about 15,000 | | a flat command at the bound costs 60 MiB and 40 ms |
| `MaxParsedNodes` (tree) | 32,768 | 13,559 | 375 | 100 to 165 ms and 67 MiB for a flat command at the bound |
| `MaxTreeDepth` (tree) | 2,048 | | | an arithmetic chain of 2,048 additions costs 66 ms and 23 MiB |

"Largest real call" is over 3.13 million calls of the owner traces (Claude
Code and Codex on Linux, macOS and Windows). Nothing real comes near a bound:
0 calls are past one, and 36 calls (0.001%) are within 10x of the chain-byte
bound.

## An over-budget call

A call past the budget is opaque to the readers, so it takes the unknown tier
of the hook, the existing evaluation limit (`ACTION-COMPOUND-LIMIT`), with the
reason `parse_budget_exceeded`: an alert outside the strict profile, a block in
strict, managed strict included (managed non-strict alerts, by the owner rule
of rel-1-0-6:GAP-0675). It never reads as allowed.

It keeps the check that works on the raw text. A call whose text may name the
active DefenseClaw state (`hookpaths.MayNameState`: quotes, escapes, case and
patterns do not hide it) is judged as a proven mutation of it, which blocks in
every mode, including observe, as the readers' proof of a state write did
before the budget refused to read the call (GAP-0281). The hook client sends
the incomplete-evidence header for such a call; the gateway does not depend on
it.

## A block proven beside a cap (the cap floor)

The unknown tier is a floor, not the verdict. A call past any reading cap of
the trusted-action path (nesting, this budget, the statement budget, the
nested-body bound: every call that carries `ACTION-COMPOUND-LIMIT`) is also cut
into pieces in `internal/gateway/cap_floor.go` (`withCapFloor`, one place, run
after every dispatch path). The cut reads the text once and never parses: it
splits at `;`, `&`, `|`, `&&`, `||`, `(`, `)`, `$(`, a backquote, a line end
and the `{` and `}` words, never inside a quoted string, a comment or a
here-document body. The static script of a shell (`bash -c` with a
single-quoted script, a here-document fed to a shell on standard input) is a
piece of its own. A piece whose text may name a protected target or the
DefenseClaw state (`hookpaths.BoundCallMayNameProtected`) is judged by every
reader as the call it is, and a finding a reader proves there (an
authoritative proof that is not itself an evaluation limit or a parse failure)
counts for the whole call, rule id included. So a write that blocks alone
still blocks before, after or inside the padding that hit the cap, in every
tier, and a state write still blocks in observe (rel-1-0-10:GAP-0312,
GAP-0360, GAP-0435, GAP-0381).

The action analysis has a bound of its own: a syntax tree deeper than 64
levels or past its node bound (`actionfacts` `limit_exceeded`, issue
`depth_limit` or `node_limit`) yields no path facts, which on rel let a state
write inside 30 to 512 nested subshells through in every tier
(rel-1-0-10:GAP-0547). Such a call is truncated in the sense of the bound
rule: it gets the evaluation-limit finding with the reason
`bounded_truncated cap=depth` (or `nodes`), so at least the unknown tier of
the pack, and its pieces are judged as above.

A call that names no protected target or state gets no piece and keeps the
evaluation-limit verdict, so a cap alone is not a new block. Reads beside a
cap stay reads: a piece is judged by the same rules as the call it is.

A here-document fed to a shell is that shell's script whether or not a cap is
hit; its body is judged as a piece of every such call (GAP-0532: a state write
in it was allowed at any size).

The floor has bounds of its own, each of which leaves the call at the unknown
tier it already has: 16 pieces per hook call (half from the start of the call,
half from its end, bodies included), a statement of at most 4 KiB, a shell
body of at most 256 KiB, a body cut again at most twice, and of a call over
96 KiB only the first 64 KiB and the last 32 KiB are cut. The pieces that name
a target are found by halving, so a call of thousands of statements costs a
pass over its text per level of the halving.

## Cost curve

Hook decision, default tier, median of three, on the gate box. The caps are
set from this table: a call at a cap stays under 64 MiB, and under about 100 ms on a quiet box (up to 270 ms on the costliest family on a loaded one, 2 to 4 times slower). A row past
a cap is refused before any reader runs. Regenerate it with
`PARSE_BUDGET_CURVE=1 go test -run TestParseBudgetCostCurve -v ./internal/gateway`
(`PARSE_BUDGET_SHAPE=<shape>` for one family).

```
pipe           n=32      bytes=65    ms=11.4    MiB=26   action=allow
pipe           n=64      bytes=129   ms=12.0    MiB=8    action=allow
pipe           n=128     bytes=257   ms=6.1     MiB=1    action=alert
pipe           n=256     bytes=513   ms=10.0    MiB=2    action=alert
pipe           n=512     bytes=1025  ms=31.0    MiB=4    action=alert
pipe           n=1024    bytes=2049  ms=2.1     MiB=0    action=alert
pipe           n=2048    bytes=4097  ms=2.9     MiB=1    action=alert
pipe           n=4096    bytes=8193  ms=4.2     MiB=2    action=alert
and            n=32      bytes=97    ms=11.4    MiB=5    action=allow
and            n=64      bytes=193   ms=14.7    MiB=9    action=allow
and            n=128     bytes=385   ms=4.2     MiB=1    action=alert
and            n=256     bytes=769   ms=10.1    MiB=2    action=alert
and            n=512     bytes=1537  ms=39.3    MiB=4    action=alert
and            n=1024    bytes=3073  ms=3.7     MiB=1    action=alert
and            n=2048    bytes=6145  ms=5.5     MiB=2    action=alert
and            n=4096    bytes=12289 ms=8.3     MiB=4    action=alert
or             n=32      bytes=97    ms=9.1     MiB=5    action=allow
or             n=64      bytes=193   ms=15.7    MiB=9    action=allow
or             n=128     bytes=385   ms=4.3     MiB=1    action=alert
or             n=256     bytes=769   ms=12.9    MiB=2    action=alert
or             n=512     bytes=1537  ms=25.4    MiB=4    action=alert
or             n=1024    bytes=3073  ms=2.6     MiB=0    action=alert
or             n=2048    bytes=6145  ms=2.2     MiB=1    action=alert
or             n=4096    bytes=12289 ms=3.8     MiB=3    action=alert
mixed          n=32      bytes=257   ms=22.9    MiB=11   action=allow
mixed          n=64      bytes=513   ms=7.8     MiB=1    action=alert
mixed          n=128     bytes=1025  ms=16.2    MiB=3    action=alert
mixed          n=256     bytes=2049  ms=2.7     MiB=0    action=alert
mixed          n=512     bytes=4097  ms=3.8     MiB=1    action=alert
mixed          n=1024    bytes=8193  ms=6.0     MiB=2    action=alert
mixed          n=2048    bytes=16385 ms=10.6    MiB=5    action=alert
mixed          n=4096    bytes=32769 ms=19.5    MiB=11   action=alert
subst-pipe     n=32      bytes=161   ms=27.3    MiB=20   action=allow
subst-pipe     n=64      bytes=321   ms=7.3     MiB=2    action=alert
subst-pipe     n=128     bytes=641   ms=21.0    MiB=6    action=alert
subst-pipe     n=256     bytes=1281  ms=65.4    MiB=16   action=alert
subst-pipe     n=512     bytes=2561  ms=64.4    MiB=24   action=alert
subst-pipe     n=1024    bytes=5121  ms=3.3     MiB=1    action=alert
subst-pipe     n=2048    bytes=10241 ms=4.9     MiB=2    action=alert
subst-pipe     n=4096    bytes=20481 ms=8.6     MiB=5    action=alert
group-pipe     n=32      bytes=129   ms=8.0     MiB=4    action=allow
group-pipe     n=64      bytes=257   ms=15.6    MiB=8    action=allow
group-pipe     n=128     bytes=513   ms=5.1     MiB=1    action=alert
group-pipe     n=256     bytes=1025  ms=11.3    MiB=3    action=alert
group-pipe     n=512     bytes=2049  ms=50.6    MiB=6    action=alert
group-pipe     n=1024    bytes=4097  ms=3.2     MiB=1    action=alert
group-pipe     n=2048    bytes=8193  ms=4.2     MiB=2    action=alert
group-pipe     n=4096    bytes=16385 ms=6.8     MiB=4    action=alert
block-pipe     n=32      bytes=225   ms=8.5     MiB=5    action=allow
block-pipe     n=64      bytes=449   ms=15.8    MiB=9    action=allow
block-pipe     n=128     bytes=897   ms=8.0     MiB=1    action=alert
block-pipe     n=256     bytes=1793  ms=16.4    MiB=3    action=alert
block-pipe     n=512     bytes=3585  ms=37.4    MiB=6    action=alert
block-pipe     n=1024    bytes=7169  ms=4.1     MiB=1    action=alert
block-pipe     n=2048    bytes=14337 ms=6.4     MiB=2    action=alert
block-pipe     n=4096    bytes=28673 ms=11.1    MiB=5    action=alert
redirect-pipe  n=32      bytes=129   ms=18.1    MiB=7    action=allow
redirect-pipe  n=64      bytes=257   ms=26.0    MiB=13   action=allow
redirect-pipe  n=128     bytes=513   ms=5.0     MiB=1    action=alert
redirect-pipe  n=256     bytes=1025  ms=11.8    MiB=3    action=alert
redirect-pipe  n=512     bytes=2049  ms=52.9    MiB=6    action=alert
redirect-pipe  n=1024    bytes=4097  ms=2.4     MiB=1    action=alert
redirect-pipe  n=2048    bytes=8193  ms=5.4     MiB=2    action=alert
redirect-pipe  n=4096    bytes=16385 ms=6.2     MiB=5    action=alert
assign-pipe    n=32      bytes=193   ms=8.6     MiB=5    action=allow
assign-pipe    n=64      bytes=385   ms=15.8    MiB=9    action=allow
assign-pipe    n=128     bytes=769   ms=8.3     MiB=1    action=alert
assign-pipe    n=256     bytes=1537  ms=12.7    MiB=3    action=alert
assign-pipe    n=512     bytes=3073  ms=38.5    MiB=6    action=alert
assign-pipe    n=1024    bytes=6145  ms=3.7     MiB=1    action=alert
assign-pipe    n=2048    bytes=12289 ms=5.6     MiB=2    action=alert
assign-pipe    n=4096    bytes=24577 ms=6.0     MiB=5    action=alert
unparsed-pipe  n=32      bytes=66    ms=3.2     MiB=2    action=allow
unparsed-pipe  n=64      bytes=130   ms=4.3     MiB=3    action=allow
unparsed-pipe  n=128     bytes=258   ms=6.1     MiB=5    action=allow
unparsed-pipe  n=256     bytes=514   ms=13.2    MiB=11   action=allow
unparsed-pipe  n=512     bytes=1026  ms=15.5    MiB=21   action=allow
unparsed-pipe  n=1024    bytes=2050  ms=2.5     MiB=1    action=alert
unparsed-pipe  n=2048    bytes=4098  ms=1.9     MiB=2    action=alert
unparsed-pipe  n=4096    bytes=8194  ms=4.2     MiB=4    action=alert
arith          n=32      bytes=75    ms=4.7     MiB=2    action=allow
arith          n=64      bytes=139   ms=6.4     MiB=2    action=allow
arith          n=128     bytes=267   ms=9.0     MiB=2    action=allow
arith          n=256     bytes=523   ms=7.9     MiB=4    action=allow
arith          n=512     bytes=1035  ms=22.1    MiB=6    action=allow
arith          n=1024    bytes=2059  ms=35.4    MiB=12   action=allow
arith          n=2048    bytes=4107  ms=3.8     MiB=1    action=alert
arith          n=4096    bytes=8203  ms=4.2     MiB=2    action=alert
flat-words     n=256     bytes=517   ms=19.5    MiB=7    action=allow
flat-words     n=1024    bytes=2053  ms=41.9    MiB=22   action=allow
flat-words     n=4096    bytes=8197  ms=78.9    MiB=29   action=alert
flat-words     n=16384   bytes=32773 ms=9.8     MiB=10   action=alert
flat-words     n=65536   bytes=131077 ms=45.6    MiB=39   action=alert
flat-stmts     n=256     bytes=513   ms=4.2     MiB=3    action=alert
flat-stmts     n=1024    bytes=2049  ms=12.5    MiB=6    action=alert
flat-stmts     n=4096    bytes=8193  ms=45.0    MiB=28   action=alert
flat-stmts     n=16384   bytes=32769 ms=19.5    MiB=16   action=alert
flat-stmts     n=65536   bytes=131073 ms=21.1    MiB=12   action=alert
heredoc-lines  n=256     bytes=1564  ms=11.2    MiB=3    action=allow
heredoc-lines  n=1024    bytes=6172  ms=26.7    MiB=13   action=allow
heredoc-lines  n=4096    bytes=24604 ms=117.1   MiB=51   action=allow
heredoc-lines  n=16384   bytes=98332 ms=231.0   MiB=103  action=allow
heredoc-lines  n=65536   bytes=393244 ms=808.4   MiB=354  action=allow
__CURVE2_DONE__                                           
```

The `bytes` dimension is not a structure and is not in this table. A benign
here-document of ordinary text costs the rule engine about 2.5 ms and 1 MiB
per KB (98 KB: 250 ms and 103 MiB), whatever its structure; that is the same
cost as before the budget, bounded by `MaxCommandBytes`, and tracked as its own
gap.

## Tests

- `internal/shellparse/budget_test.go`: the exact bound of each dimension for
  every shape family, the unparsed chain, every tree kind, the data-aware
  counts (here-documents, quotes, comments), the hard bounds, probe sizes
  with bounded time and memory, linear growth, iterative copy and measure
  under a 1 MiB stack limit, and `FuzzBudget` (a large-input generator over
  the family table; it also checks that the first stage never counts fewer
  chain operators than the tree holds).
- `internal/gateway/parse_budget_test.go`: the verdicts through both
  connectors, per user and managed, default and strict tiers, observe and
  action modes; the state-write proof at and past every bound; bounded
  allocation and time. Inputs come from the generators of `budget_gen_test.go`.
- `internal/gateway/cap_floor_test.go`: the cut (`TestCapFloorPieces`); a
  write proven alone (fixtures by case id) keeps its block and rule id beside
  every cap family in all five tiers, the state write in observe, and a cap
  alone or a script that writes nothing keeps its rel verdict.
- `internal/actionfacts/pipeline_scope_test.go`: the statement split of a
  pipeline is linear.
