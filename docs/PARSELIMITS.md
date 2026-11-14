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

A call past the budget is truncated in the sense of the bound rule
(`internal/guardrail/bounded`): it takes the
unknown tier of the hook, the existing evaluation limit
(`ACTION-COMPOUND-LIMIT`), through `withBoundedTruncation`. The reason is
`bounded_truncated cap=<kind>` and `parse_budget_exceeded` (bytes: `bytes`;
nesting and tree depth: `depth`; tree nodes: `nodes`; chain operators, tokens,
brace expansion, an unparsed chain: `items`). It alerts outside the strict
profile, a managed install with a pack that is not strict included (the owner
ruling of rel-1-0-6:GAP-0675), and blocks in strict, managed strict included.
It never reads as allowed.

It keeps the check that works on the raw text. A call whose statements may
write the active DefenseClaw state (`hookpaths.BudgetMayWriteState`: a
statement that may name it, however quotes, escapes, case or patterns spell
it, and is not proven read-only) is judged as a proven mutation of it, which
blocks in every mode, including observe, as the readers' proof of a state write
did before the budget refused to read the call (GAP-0281). That holds for a
state write before the cap (GAP-0312: a write before 513 nested subshells) and
after it. A call that only reads or prints what names the state (the owner
traces name the tree in most scripts) is not blocked. The hook client sends the
incomplete-evidence header for such a call, listing the state it may write
(`hookpaths.BudgetStateReading`); the gateway does not depend on it.

A brace expansion past its bound and nested shell bodies past
`MaxNestedBodyBytes` keep the evaluation-limit-only verdict the owner ruled for
them (rel-1-0-6:GAP-0675, GAP-0677).

A shell call over the string limit of the analysis (64 KiB) leaves the
analysers no command to judge. When its padding is white space or comments the
bounded twin reads the whole call; otherwise (one word of that size) it is
truncated like the rest, bytes cap (GAP-0382). A trailing comment never takes a
block away (GAP-0381). Two of 3,134,337 real calls are over 64 KiB.

## Every cap counts work, never time

No bound of a shell reader counts wall-clock time: the walks of the active
state, the linked-tree walks and the state-glob expansion end at an entry or
work bound, so one call has one verdict whatever the load of the box
(GAP-0339, tests under full CPU load, 50 runs per call and tier).

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

### Share of real calls near a bound

Over the 3,134,337 calls of the owner traces: 0 are past a bound of this
budget (220 are past the older brace-expansion bound, unchanged); the largest
chain has 38 nodes (7% of the cap), the deepest tree 52 levels (3%), the
largest 13,559 nodes (41%; 1 call is within 10x of the cap, none within 2x),
the largest call 97,371 bytes (9% of the cap). The hook p95 on 20,000 owner
trace calls and 20,000 s3 calls is unchanged against the base (see the review
notes of the commit), with identical verdicts on every call.

### What the budget does not bound: the bytes of benign text

A benign here-document of ordinary text is one node, so no structural bound
applies to it, and the readers pay a per-byte cost on its text: about 2.5 ms
and 1 MiB per KB (98 KB, the largest real call: 250 ms and 103 MiB; extrapolated
1 MiB: about 2.3 s and 900 MiB). It is the same cost as before the budget
(rel-1-0-10:GAP-0299, P3). It is spread over about ten readers (the patch
target reader, the whole-call fallback, the nested-body weight, the rule scan),
so there is no single input to bound. The one lever is a cap on the command
size. A cap at the 64 KiB analysis limit would turn benign text rows into
alerts, and would bypass the over-limit reading of padded calls
(`actionfacts/over_limit_command_layout.go`), which proves protected writes in a
call past 64 KiB; that would be a downgrade of the kind GAP-0281 describes. So
`MaxCommandBytes` stays at the hook body cap until that reading can be done
without the per-byte cost.

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
- `internal/actionfacts/pipeline_scope_test.go`: the statement split of a
  pipeline is linear.
