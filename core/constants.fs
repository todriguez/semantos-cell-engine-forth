\ constants.fs — Semantos cell-engine protocol constants
\ Auto-sync target: semantos-core/core/cell-engine/src/constants.zig
\ All integers little-endian on the wire. Offsets are byte positions in
\ the packed 1024-byte cell. Do not edit offsets by hand — run compare-constants
\ against the Zig source if anything changes.

[DEFINED] SCELL-CONSTANTS-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-CONSTANTS-LOADED

\ ── Protocol ─────────────────────────────────────────────────────────────────

1024 CONSTANT SCELL-SIZE          \ packed cell = 1024 bytes
 256 CONSTANT HEADER-SIZE         \ header occupies first 256 bytes
 768 CONSTANT PAYLOAD-SIZE        \ payload occupies last 768 bytes
   2 CONSTANT SCELL-VERSION       \ current wire format version
   8 CONSTANT CONT-HEADER-SIZE    \ continuation-cell header size
1016 CONSTANT CONT-PAYLOAD-SIZE   \ continuation-cell payload size

\ ── Stacks ───────────────────────────────────────────────────────────────────

1024 CONSTANT MAIN-STACK-CELLS    \ 1024 cells = 1 MB
 256 CONSTANT AUX-STACK-CELLS     \  256 cells = 256 KB

\ ── Magic bytes (raw, not endian-converted) ──────────────────────────────────
\ DEADBEEF CAFEBABE 13371337 42424242
\ Use bare C, so bytes land directly at HERE (= SCELL-MAGIC); no ALLOT.

CREATE SCELL-MAGIC
HEX
  0DE C, 0AD C, 0BE C, 0EF C,
  0CA C, 0FE C, 0BA C, 0BE C,
  013 C, 037 C, 013 C, 037 C,
  042 C, 042 C, 042 C, 042 C,
DECIMAL

\ ── Linearity values ─────────────────────────────────────────────────────────

1 CONSTANT LINEARITY-LINEAR       \ must be consumed exactly once
2 CONSTANT LINEARITY-AFFINE       \ may be discarded, not duplicated
3 CONSTANT LINEARITY-RELEVANT     \ may be duplicated, not discarded
4 CONSTANT LINEARITY-DEBUG        \ unchecked — for test scaffolding only

\ ── Commerce phase ───────────────────────────────────────────────────────────

0 CONSTANT PHASE-SOURCE
1 CONSTANT PHASE-PARSE
2 CONSTANT PHASE-AST
3 CONSTANT PHASE-TYPECHECK
4 CONSTANT PHASE-OPTIMISE
5 CONSTANT PHASE-CODEGEN
6 CONSTANT PHASE-ACTION
7 CONSTANT PHASE-OUTCOME
HEX FF DECIMAL CONSTANT PHASE-UNKNOWN

\ ── Taxonomy dimension ───────────────────────────────────────────────────────

0 CONSTANT DIM-COMPOSITE
1 CONSTANT DIM-WHAT
2 CONSTANT DIM-HOW
3 CONSTANT DIM-INSTRUMENT

\ ── Cell type (in flags or payload discriminant) ──────────────────────────────

1 CONSTANT CTYPE-BUMP
2 CONSTANT CTYPE-ATOMIC-BEEF
3 CONSTANT CTYPE-ENVELOPE
4 CONSTANT CTYPE-DATA
5 CONSTANT CTYPE-STATE
6 CONSTANT CTYPE-POINTER

\ ── Header field offsets (byte position in packed 1024-byte cell) ─────────────

 0 CONSTANT OFF-MAGIC             \  16 bytes — raw
16 CONSTANT OFF-LINEARITY         \   4 bytes LE u32
20 CONSTANT OFF-VERSION           \   4 bytes LE u32
24 CONSTANT OFF-FLAGS             \   4 bytes LE u32
28 CONSTANT OFF-REF-COUNT         \   2 bytes LE u16
30 CONSTANT OFF-TYPE-HASH         \  32 bytes raw SHA256
62 CONSTANT OFF-OWNER-ID          \  16 bytes raw
78 CONSTANT OFF-TIMESTAMP         \   8 bytes LE u64
86 CONSTANT OFF-CELL-COUNT        \   4 bytes LE u32
90 CONSTANT OFF-PAYLOAD-TOTAL     \   4 bytes LE u32
94 CONSTANT OFF-RESERVED          \ 162 bytes — structured below
96 CONSTANT OFF-PARENT-HASH       \  32 bytes raw (within reserved)
128 CONSTANT OFF-PREV-STATE-HASH  \  32 bytes raw (within reserved)
224 CONSTANT OFF-DOMAIN-ROOT      \  32 bytes raw (within reserved; RM-023)
256 CONSTANT OFF-PAYLOAD          \ payload begins here

\ ── Opcode dispatch ranges ────────────────────────────────────────────────────

  0 CONSTANT OP-STANDARD-MIN
175 CONSTANT OP-STANDARD-MAX
176 CONSTANT OP-MACRO-MIN          \ Craig extended macros
191 CONSTANT OP-MACRO-MAX
192 CONSTANT OP-PLEXUS-MIN         \ Plexus / payment opcodes
207 CONSTANT OP-PLEXUS-MAX
208 CONSTANT OP-HOSTCALL-MIN       \ host-boundary syscalls
223 CONSTANT OP-HOSTCALL-MAX
224 CONSTANT OP-ROUTING-MIN        \ OP_BRANCHONOUTPUT etc.
239 CONSTANT OP-ROUTING-MAX

\ Routing opcodes (0xE0..)
HEX 0E0 DECIMAL CONSTANT OP-BRANCHONOUTPUT

\ ── Domain flags ─────────────────────────────────────────────────────────────

HEX
00000001 CONSTANT DFLAG-EDGE-CREATION
00000002 CONSTANT DFLAG-SIGNING
0000000A CONSTANT DFLAG-METERING
0001FE01 CONSTANT DFLAG-COMMERCE-V1
0001FE02 CONSTANT DFLAG-ANCHOR-ATTEST-V1
0001FE03 CONSTANT DFLAG-SCG-RELATION-V1
DECIMAL

\ ── Extension pages (in flags field) ─────────────────────────────────────────

HEX
00010000 CONSTANT PAGE-LOOM-SHELL
00010100 CONSTANT PAGE-ODDJOBZ
00010200 CONSTANT PAGE-BSV-ANCHOR
0001FE00 CONSTANT PAGE-SUBSTRATE-SCHEMA
00010400 CONSTANT PAGE-TESSERA
DECIMAL

\ ── BCA (Blockchain-anchored Cell Address) ────────────────────────────────────

 8 CONSTANT BCA-SUBNET-PREFIX-SIZE
16 CONSTANT BCA-MODIFIER-SIZE
16 CONSTANT BCA-IPV6-ADDR-SIZE
33 CONSTANT BCA-PUBKEY-SIZE
 2 CONSTANT BCA-COLLISION-MAX

\ ── Binding ──────────────────────────────────────────────────────────────────

32 CONSTANT BIND-TXID-SIZE
 4 CONSTANT BIND-VOUT-SIZE
 8 CONSTANT BIND-ANCHOR-HEIGHT-SIZE
 4 CONSTANT BIND-DERIV-INDEX-SIZE
48 CONSTANT BIND-TOTAL-SIZE
