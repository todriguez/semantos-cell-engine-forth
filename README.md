# Semantos Cell Engine Forth

A compact Forth implementation of the Semantos cell engine.

This package contains a self-contained 1KB semantic-cell runtime:

- packed 1024-byte cells with a 256-byte header and 768-byte payload
- main and auxiliary 2-PDA stacks for semantic cells
- linear, affine, relevant, and debug resource rules
- little-endian cell header accessors
- type-hash parity helpers
- BSV-oriented sighash parsing helpers
- a Bitcoin Script data-stack executor with standard opcode coverage

It is intentionally small: load `bootstrap.fs`, get the cell engine.

## Requirements

- `gforth`
- `make` for the convenience test target

On macOS with Homebrew:

```sh
brew install gforth
```

On Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y gforth
```

## Quick Start

```sh
gforth bootstrap.fs
```

After loading, useful words include:

- `SCELL-ALLOC` - allocate a staging cell
- `CELL-DEFAULT` - zero a cell and set magic/version/ref-count defaults
- `SCELL-PUSH` / `SCELL-POP` - push and pop semantic cells on the main 2-PDA stack
- `OP-TOALTSTACK` / `OP-FROMALTSTACK` - move cells between the main and auxiliary stacks
- `CELL-DUMP` - inspect a cell header
- `.LINEARITY-STATUS` - show resource enforcement mode
- `VERIFY-TYPE-HASH-PARITY` - run the type-hash parity check

## Tests

Run all tests:

```sh
make test
```

Or run individual suites:

```sh
gforth tests/run-m1.fs -e bye
gforth tests/run-executor.fs -e bye
gforth tests/run-sighash.fs -e bye
```

Current local result at packaging time:

```text
M1:       PASS 18 / FAIL 0
Executor: PASS 37 / FAIL 0
Sighash:  PASS 38 / FAIL 0
```

## Layout

```text
bootstrap.fs             Load order and banner
core/constants.fs        Protocol constants and header offsets
core/cell.fs             1024-byte cell accessors and staging pool
core/2pda.fs             Main and auxiliary semantic-cell stacks
core/linearity.fs        Linear/affine/relevant enforcement
core/type-hash.fs        Type-hash parity helpers
core/sighash.fs          BSV sighash context helpers
core/executor.fs         Bitcoin Script data-stack executor
opcodes/standard.fs      Standard opcode dispatch
tests/                   GForth test entrypoints
```

## Status

Prototype, but a runnable one. Crypto opcodes are stubbed unless a compatible
crypto module is loaded. `OP_2ROT` and wider `OP_ROLL` cases intentionally
abort for now rather than pretending to be complete.

## License

No license has been selected yet.
