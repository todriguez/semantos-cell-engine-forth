\ type-hash.fs — Canonical 4-segment typeHash construction (T5.a)
\ Zig source: semantos-core/core/cell-engine/src/type_hash.zig
\
\ The typeHash is a 32-byte identifier that is *identical* across every
\ conforming runtime: TypeScript, Zig, Rust, Go, and now Forth.  If your
\ implementation produces the same 32 bytes as the parity vectors at the
\ bottom of this file, you are wire-compatible.
\
\ Algorithm — structured |8|8|8|8| (T5.a, 2026-05-25):
\
\   typeHash[ 0: 8] = sha256(s1)[0:8]   ← namespace
\   typeHash[ 8:16] = sha256(s2)[0:8]   ← domain
\   typeHash[16:24] = sha256(s3)[0:8]   ← sub-type
\   typeHash[24:32] = sha256(s4)[0:8]   ← qualifier / version
\
\ The 32 bytes are four truncated inner hashes, concatenated directly —
\ NO outer hash wrapper.  The structure is intentionally preserved:
\   - Relays peek bytes [0:8] to filter by namespace in O(1).
\   - LMDB cellsByType is range-scannable by prefix.
\   - Each segment is independently verifiable.
\
\ The wildcard sentinel (8 raw zero bytes at position 0) signals
\ "promiscuous fan-out — any subscriber may consume this cell."
\
\ Dependency: crypto/crypto.fs must provide SHA256-INTO before VERIFY-TYPE-HASH-PARITY
\ is called.  SHA256-INTO ( src-addr src-len dst-addr -- ) writes 32 bytes at dst-addr.
\ A stub is defined below so this file compiles without crypto loaded — calling
\ BUILD-TYPE-HASH before loading crypto will abort with a clear error.

[DEFINED] SHA256-INTO [IF] [ELSE]
  : SHA256-INTO ( src-addr src-len dst-addr -- )
    DROP 2DROP
    CR ." SHA256-INTO: load crypto/crypto.fs before using BUILD-TYPE-HASH" CR ABORT ;
[THEN]

[DEFINED] SCELL-TYPE-HASH-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-TYPE-HASH-LOADED

REQUIRE constants.fs

\ ── Type-hash constants ───────────────────────────────────────────────────────

32 CONSTANT TYPE-HASH-SIZE           \ 32 bytes total
 4 CONSTANT TYPE-HASH-SEGMENTS       \ 4 segments
 8 CONSTANT TYPE-HASH-SEG-BYTES      \ 8 bytes per segment

\ Wildcard sentinel — 8 zero bytes at position 0 means "promiscuous routing".
CREATE TYPEHASH-WILDCARD TYPE-HASH-SEG-BYTES ALLOT
TYPEHASH-WILDCARD TYPE-HASH-SEG-BYTES 0 FILL

\ Scratch buffers for SHA256 output (one per segment to allow nesting).
CREATE TH-SHA-BUF0 32 ALLOT
CREATE TH-SHA-BUF1 32 ALLOT
CREATE TH-SHA-BUF2 32 ALLOT
CREATE TH-SHA-BUF3 32 ALLOT

\ ── Core computation ─────────────────────────────────────────────────────────

\ Hash one segment and write its first 8 bytes into out+offset.
\ Requires: SHA256-INTO ( src-addr src-len dst-addr -- )
: TH-SEGMENT ( src-addr src-len scratch-buf out-addr offset -- )
  >R                          \ save offset
  >R                          \ save out-addr
  -ROT                        \ scratch-buf src-addr src-len
  SWAP >R SWAP                \ src-addr src-len  R:scratch
  R@  SHA256-INTO             \ ( scratch-buf src-addr src-len -- )
  R>                          \ scratch-buf
  R>  R>  +                   \ out-addr+offset
  SWAP  TYPE-HASH-SEG-BYTES MOVE ;  \ copy 8 bytes from scratch into out

\ Compute the canonical typeHash from four string segments into out-addr.
\ ( s1a s1l s2a s2l s3a s3l s4a s4l out-addr -- )
: BUILD-TYPE-HASH ( s1a s1l s2a s2l s3a s3l s4a s4l out-addr -- )
  \ Stash out-addr, then process each segment.
  >R                          \ R: out-addr
  2>R 2>R 2>R                 \ stash s2 s3 s4
  TH-SHA-BUF0 R@ 0  TH-SEGMENT   \ s1 → out[0:8]
  2R> TH-SHA-BUF1 R@  8  TH-SEGMENT   \ s2 → out[8:16]
  2R> TH-SHA-BUF2 R@ 16  TH-SEGMENT   \ s3 → out[16:24]
  2R> TH-SHA-BUF3 R@ 24  TH-SEGMENT   \ s4 → out[24:32]
  R> DROP ;

\ Static result buffer — overwritten on each TYPE-HASH-OF call.
CREATE TH-RESULT-BUF 32 ALLOT

\ Compute into TH-RESULT-BUF; returns its address.  Not re-entrant.
: TYPE-HASH-OF ( s1a s1l s2a s2l s3a s3l s4a s4l -- out-addr )
  TH-RESULT-BUF  BUILD-TYPE-HASH
  TH-RESULT-BUF ;

\ ── Queries on a computed hash ───────────────────────────────────────────────

: TH-NAMESPACE-ADDR  ( th-addr -- addr )  ;           \ bytes 0:8  (identity)
: TH-DOMAIN-ADDR     ( th-addr -- addr )  8  + ;       \ bytes 8:16
: TH-SUBTYPE-ADDR    ( th-addr -- addr )  16 + ;       \ bytes 16:24
: TH-QUALIFIER-ADDR  ( th-addr -- addr )  24 + ;       \ bytes 24:32

: TH-WILDCARD? ( th-addr -- flag )
  \ True when namespace prefix (bytes 0:8) is the all-zero sentinel.
  TYPEHASH-WILDCARD SWAP  TYPE-HASH-SEG-BYTES COMPARE 0= ;

: TH-SAME-NAMESPACE? ( a-th b-th -- flag )
  \ True when both hashes share the same 8-byte namespace prefix.
  \ This is the O(1) relay routing decision.
  TYPE-HASH-SEG-BYTES COMPARE 0= ;

\ ── Parity vectors (from type_hash.zig test suite) ───────────────────────────
\ To verify: load this file in gforth, then run:  VERIFY-TYPE-HASH-PARITY
\
\ Each vector: BUILD-TYPE-HASH(s1,s2,s3,s4) must produce exactly the
\ 32 bytes listed.  Byte-identical to TypeScript (protocol-types/src/type-hash.ts)
\ and Zig (cell-engine/src/type_hash.zig) test suites.

\ Static scratch buffers for parity checking (top-level, not inside words).
CREATE TH-PARITY-BUF  32 ALLOT
CREATE TH-HEX-BUF     64 ALLOT

\ Hex-encode N bytes from src-addr into dst-addr (dst must have 2*N bytes).
\ Pure Forth, no external dependency.
: HEX-ENCODE ( src-addr dst-addr n -- )
  0 ?DO
    OVER I + C@               \ byte value
    DUP  4 RSHIFT             \ high nibble
    DUP 10 < IF [CHAR] 0 ELSE 10 - [CHAR] a THEN + OVER I 2 * + C!
    15 AND                    \ low nibble
    DUP 10 < IF [CHAR] 0 ELSE 10 - [CHAR] a THEN + OVER I 2 * 1 + + C!
  LOOP
  2DROP ;

\ Run one parity vector.  Expects SHA256-INTO to be loaded (from crypto/crypto.fs).
: PARITY-CHECK ( s1a s1l s2a s2l s3a s3l s4a s4l exp-addr exp-len -- )
  2>R                          \ save expected addr+len
  TH-PARITY-BUF BUILD-TYPE-HASH
  TH-PARITY-BUF TH-HEX-BUF 32 HEX-ENCODE
  2R>                          \ expected addr+len
  TH-HEX-BUF SWAP COMPARE 0= IF
    ." PASS" CR
  ELSE
    ." FAIL" CR
    ." Expected: " 2R> TYPE CR
    ." Got:      " TH-HEX-BUF 64 TYPE CR
  THEN ;

: VERIFY-TYPE-HASH-PARITY ( -- )
  CR ." ── typeHash parity vectors (T5.a) ─────────────────────" CR
  S" " S" " S" " S" "
    S" e3b0c44298fc1c14e3b0c44298fc1c14e3b0c44298fc1c14e3b0c44298fc1c14"
    PARITY-CHECK
  S" a" S" b" S" c" S" d"
    S" ca978112ca1bbdca3e23e8160039594a2e7d2c03a9507ae218ac3e7343f01689"
    PARITY-CHECK
  S" mnca" S" tile" S" injection" S" "
    S" 09e9fe981010c9b48b668b8994aa8451545a70019936cf88e3b0c44298fc1c14"
    PARITY-CHECK
  S" tessera" S" batch" S" mint" S" v1"
    S" 2f1e83d30fff12f14bb24efc9641afc5dc6f17bbec824fff3bfc269594ef6492"
    PARITY-CHECK
  S" oddjobz" S" job" S" worktrack" S" v2"
    S" c4cf2fd44009863e5e8c9902207afaeb822965fc3debc30dfb04dcb6970e4c3d"
    PARITY-CHECK
  S" chess" S" stake" S" " S" v1"
    S" ac739dccd121f712f4caf4ff95731a23e3b0c44298fc1c143bfc269594ef6492"
    PARITY-CHECK
  CR ." ── done ─────────────────────────────────────────────" CR ;
