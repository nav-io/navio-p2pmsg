# Contributing

## Before you tag a release

`prepublishOnly` runs `typecheck` and `build` — it verifies the artifact being
uploaded, not the behaviour of the code. Run the suites yourself first:

```
npm test         # 566 unit tests, ~3 min on an idle machine
npm run test:int # 62 integration tests against a real naviod, ~11 min
```

Both must be green on the commit you intend to tag.

The tests are deliberately not in the publish gate. They are dominated by
BLS12-381 operations, so on a workstation that is also compiling a node they
slow by an order of magnitude — a group test that takes 5 seconds idle has been
measured at over 60 — and vitest's own worker RPC starts timing out. Gating an
upload on that turns a deterministic check into a coin flip about what else the
machine happens to be doing, and the failures land on whichever test was
waiting rather than on anything real. Tests belong on a machine that is only
running tests.

## Running the integration suite

It needs a `naviod` built from nav-io/navio-core #474, at
`~/dev/navio-fmd/build/bin/naviod` or wherever `$NAVIOD` points. The suite runs
its files one at a time (`--fileParallelism=false`): each spawns real regtest
daemons, and eleven files at once means roughly twenty of them competing.
