\ opcodes/standard.fs — Bitcoin Script standard opcodes 0x61–0xAF
\ Overrides the EXEC-STANDARD stub in core/executor.fs.

[DEFINED] SCELL-STANDARD-OPS [IF] EXIT [THEN]
TRUE CONSTANT SCELL-STANDARD-OPS

\ ── Arithmetic dispatch helpers ───────────────────────────────────────────────
\ OP-ARITH-2: pops b (TOS) then a, computes a xt b, pushes int result.
\ OP-BOOL-2:  same but pushes bool result.

: OP-ARITH-1 ( xt -- )
  SDS-POP-INT  SWAP EXECUTE  SDS-PUSH-INT ;

: OP-ARITH-2 ( xt -- )
  SDS-POP-INT  SDS-POP-INT  SWAP ROT EXECUTE  SDS-PUSH-INT ;

: OP-BOOL-2 ( xt -- )
  SDS-POP-INT  SDS-POP-INT  SWAP ROT EXECUTE  SDS-PUSH-BOOL ;

\ ── OP_DEPTH ──────────────────────────────────────────────────────────────────

: DO-OP-DEPTH ( -- )  SDS-DEPTH SDS-PUSH-INT ;

\ ── OP_SIZE ───────────────────────────────────────────────────────────────────
\ Leaves the item on the stack and pushes its byte length.

: DO-OP-SIZE ( -- )  SDS-PEEK NIP SDS-PUSH-INT ;

\ ── OP_CAT ────────────────────────────────────────────────────────────────────

CREATE OP-CAT-BUF  MAX-SDS-ITEM 2 * ALLOT
VARIABLE OP-CAT-LEN

: DO-OP-CAT ( -- )
  SDS-POP>A  SDS-POP>B           \ A=TOS  B=2nd
  SDS-TMP-B-LEN @ SDS-TMP-A-LEN @ + DUP
  MAX-SDS-ITEM > IF ." OP_CAT result too large" CR ABORT THEN
  OP-CAT-LEN !
  SDS-TMP-B SDS-TMP-B-LEN @ OP-CAT-BUF SWAP MOVE
  SDS-TMP-A SDS-TMP-A-LEN @ OP-CAT-BUF SDS-TMP-B-LEN @ + SWAP MOVE
  OP-CAT-BUF OP-CAT-LEN @ SDS-PUSH ;

\ ── OP_SPLIT ──────────────────────────────────────────────────────────────────

CREATE OP-SPLIT-L MAX-SDS-ITEM ALLOT
CREATE OP-SPLIT-R MAX-SDS-ITEM ALLOT

: DO-OP-SPLIT ( -- )
  SDS-POP-INT                         \ n (split position)
  SDS-POP>A                           \ A = item, TMP-A-LEN = total len
  DUP 0< OVER SDS-TMP-A-LEN @ > OR IF ." OP_SPLIT out of range" CR ABORT THEN
  DUP >R
  SDS-TMP-A R@ OP-SPLIT-L SWAP MOVE               \ left: first n bytes
  SDS-TMP-A R@ + SDS-TMP-A-LEN @ R@ - OP-SPLIT-R SWAP MOVE  \ right: rest
  OP-SPLIT-L R@ SDS-PUSH
  OP-SPLIT-R SDS-TMP-A-LEN @ R> - SDS-PUSH ;

\ ── OP_NUM2BIN / OP_BIN2NUM ───────────────────────────────────────────────────

CREATE OP-N2B-BUF MAX-SDS-ITEM ALLOT
VARIABLE N2B-N  VARIABLE N2B-SZ  VARIABLE N2B-I

: DO-OP-NUM2BIN ( -- )
  SDS-POP-INT N2B-SZ !   \ desired byte length
  SDS-POP-INT N2B-N !    \ integer value
  N2B-SZ @ MAX-SDS-ITEM > IF ." NUM2BIN too large" CR ABORT THEN
  OP-N2B-BUF N2B-SZ @ 0 FILL          \ zero the buffer
  N2B-N @ ABS 0 N2B-I !
  BEGIN DUP 0<> WHILE
    DUP $FF AND  OP-N2B-BUF N2B-I @ + C!
    1 N2B-I +!  8 RSHIFT
  REPEAT DROP
  N2B-N @ 0< IF
    OP-N2B-BUF N2B-SZ @ 1- + DUP C@ $80 OR SWAP C!
  THEN
  OP-N2B-BUF N2B-SZ @ SDS-PUSH ;

: DO-OP-BIN2NUM ( -- )  SDS-POP SCRIPT-INT@ SDS-PUSH-INT ;

\ ── OP_INVERT / OP_AND / OP_OR / OP_XOR ─────────────────────────────────────
\ Operate byte-by-byte on byte strings.

VARIABLE BWA-LEN  CREATE BWA-A MAX-SDS-ITEM ALLOT
VARIABLE BWB-LEN  CREATE BWB-B MAX-SDS-ITEM ALLOT
CREATE BWC-C MAX-SDS-ITEM ALLOT

: DO-OP-INVERT ( -- )
  SDS-POP BWA-LEN ! BWA-A SWAP MOVE
  BWA-LEN @ 0 DO  BWA-A I + DUP C@ 255 XOR SWAP C!  LOOP
  BWA-A BWA-LEN @ SDS-PUSH ;

: DO-OP-BW2 ( xt -- )   \ bitwise op on two equal-length byte strings
  >R
  SDS-POP BWA-LEN ! BWA-A SWAP MOVE     \ TOS → A
  SDS-POP BWB-LEN ! BWB-B SWAP MOVE     \ 2nd → B
  BWA-LEN @ BWB-LEN @ <> IF ." bitwise op length mismatch" CR ABORT THEN
  BWA-LEN @ 0 DO
    BWA-A I + C@  BWB-B I + C@  R@ EXECUTE
    BWC-C I + C!
  LOOP
  R> DROP
  BWC-C BWA-LEN @ SDS-PUSH ;

\ ── OP_EQUAL / OP_EQUALVERIFY ────────────────────────────────────────────────

VARIABLE EQ-LA  CREATE EQ-A MAX-SDS-ITEM ALLOT
VARIABLE EQ-LB  CREATE EQ-B MAX-SDS-ITEM ALLOT

: DO-OP-EQUAL ( -- )
  SDS-POP EQ-LA !  EQ-A EQ-LA @ MOVE
  SDS-POP EQ-LB !  EQ-B EQ-LB @ MOVE
  EQ-LA @ EQ-LB @ <> IF 0 SDS-PUSH-BOOL EXIT THEN
  EQ-A EQ-LA @  EQ-B EQ-LB @  COMPARE 0= SDS-PUSH-BOOL ;

: DO-OP-EQUALVERIFY ( -- )
  DO-OP-EQUAL
  SDS-POP SDS-TRUTHY? 0= IF ." OP_EQUALVERIFY failed" CR ABORT THEN ;

\ ── OP_WITHIN ────────────────────────────────────────────────────────────────

VARIABLE OW-MAX  VARIABLE OW-MIN  VARIABLE OW-X

: DO-OP-WITHIN ( -- )
  SDS-POP-INT OW-MAX !
  SDS-POP-INT OW-MIN !
  SDS-POP-INT OW-X !
  OW-X @ OW-MIN @ >=  OW-X @ OW-MAX @ <  AND  SDS-PUSH-BOOL ;

\ ── Crypto stubs ─────────────────────────────────────────────────────────────
\ These ABORT; load crypto/crypto.fs to override with real implementations.

: DO-OP-RIPEMD160   ( -- )  ." OP_RIPEMD160: load crypto/crypto.fs"     CR ABORT ;
: DO-OP-SHA1        ( -- )  ." OP_SHA1: load crypto/crypto.fs"           CR ABORT ;
: DO-OP-SHA256      ( -- )  ." OP_SHA256: load crypto/crypto.fs"         CR ABORT ;
: DO-OP-HASH160     ( -- )  ." OP_HASH160: load crypto/crypto.fs"        CR ABORT ;
: DO-OP-HASH256     ( -- )  ." OP_HASH256: load crypto/crypto.fs"        CR ABORT ;
: DO-OP-CHECKSIG    ( -- )  ." OP_CHECKSIG: load crypto/crypto.fs"       CR ABORT ;
: DO-OP-CHECKMSIG   ( -- )  ." OP_CHECKMULTISIG: load crypto/crypto.fs"  CR ABORT ;
: DO-OP-CODESEP     ( -- )  ;   \ OP_CODESEPARATOR — no-op in this engine

\ ── Main dispatcher — wired into executor's DEFER via IS ─────────────────────

: -EXEC-STANDARD-IMPL ( opcode -- )

  \ ── Flow control ──────────────────────────────────────────────────────────
  DUP $61 = IF DROP EXIT THEN                            \ OP_NOP
  DUP $62 = IF DROP ." OP_VER reserved" CR ABORT THEN   \ OP_VER
  DUP $63 = IF      EXEC-HANDLE-IF   EXIT THEN           \ OP_IF
  DUP $64 = IF      EXEC-HANDLE-IF   EXIT THEN           \ OP_NOTIF
  DUP $65 = IF DROP ." OP_VERIF"  CR ABORT THEN
  DUP $66 = IF DROP ." OP_VERNOTIF" CR ABORT THEN
  DUP $67 = IF DROP EXEC-HANDLE-ELSE  EXIT THEN          \ OP_ELSE
  DUP $68 = IF DROP EXEC-HANDLE-ENDIF EXIT THEN          \ OP_ENDIF

  DUP $69 = IF DROP
    EXEC-EXECUTING @ IF
      SDS-POP SDS-TRUTHY? 0= IF ." OP_VERIFY failed" CR ABORT THEN
    THEN  EXIT THEN                                       \ OP_VERIFY

  DUP $6A = IF DROP ." OP_RETURN" CR ABORT THEN          \ OP_RETURN

  \ ── From here, skip execution when inside a false branch ─────────────────
  EXEC-EXECUTING @ 0= IF DROP EXIT THEN

  \ ── Alt stack ─────────────────────────────────────────────────────────────
  DUP $6B = IF DROP  SDS-POP SDS-ALTPUSH  EXIT THEN      \ OP_TOALTSTACK
  DUP $6C = IF DROP  SDS-ALTPOP SDS-PUSH  EXIT THEN      \ OP_FROMALTSTACK

  \ ── Stack ops ─────────────────────────────────────────────────────────────
  DUP $6D = IF DROP  SDS-2DROP  EXIT THEN                 \ OP_2DROP
  DUP $6E = IF DROP  SDS-2DUP   EXIT THEN                 \ OP_2DUP
  DUP $6F = IF DROP  SDS-3DUP   EXIT THEN                 \ OP_3DUP
  DUP $70 = IF DROP  SDS-2OVER  EXIT THEN                 \ OP_2OVER
  DUP $71 = IF DROP  SDS-2ROT   EXIT THEN                 \ OP_2ROT
  DUP $72 = IF DROP  SDS-2SWAP  EXIT THEN                 \ OP_2SWAP
  DUP $73 = IF DROP  SDS-IFDUP  EXIT THEN                 \ OP_IFDUP
  DUP $74 = IF DROP  DO-OP-DEPTH EXIT THEN                \ OP_DEPTH
  DUP $75 = IF DROP  SDS-DROP   EXIT THEN                 \ OP_DROP
  DUP $76 = IF DROP  SDS-DUP    EXIT THEN                 \ OP_DUP
  DUP $77 = IF DROP  SDS-NIP    EXIT THEN                 \ OP_NIP
  DUP $78 = IF DROP  SDS-OVER   EXIT THEN                 \ OP_OVER
  DUP $79 = IF DROP  SDS-POP-INT SDS-PICK  EXIT THEN      \ OP_PICK
  DUP $7A = IF DROP  SDS-POP-INT SDS-ROLL  EXIT THEN      \ OP_ROLL
  DUP $7B = IF DROP  SDS-ROT    EXIT THEN                 \ OP_ROT
  DUP $7C = IF DROP  SDS-SWAP   EXIT THEN                 \ OP_SWAP
  DUP $7D = IF DROP  SDS-TUCK   EXIT THEN                 \ OP_TUCK

  \ ── BSV-restored splice ops ───────────────────────────────────────────────
  DUP $7E = IF DROP  DO-OP-CAT     EXIT THEN              \ OP_CAT
  DUP $7F = IF DROP  DO-OP-SPLIT   EXIT THEN              \ OP_SPLIT
  DUP $80 = IF DROP  DO-OP-NUM2BIN EXIT THEN              \ OP_NUM2BIN
  DUP $81 = IF DROP  DO-OP-BIN2NUM EXIT THEN              \ OP_BIN2NUM
  DUP $82 = IF DROP  DO-OP-SIZE    EXIT THEN              \ OP_SIZE

  \ ── BSV-restored bitwise ops ──────────────────────────────────────────────
  DUP $83 = IF DROP  DO-OP-INVERT                  EXIT THEN  \ OP_INVERT
  DUP $84 = IF DROP  ['] AND  DO-OP-BW2            EXIT THEN  \ OP_AND
  DUP $85 = IF DROP  ['] OR   DO-OP-BW2            EXIT THEN  \ OP_OR
  DUP $86 = IF DROP  ['] XOR  DO-OP-BW2            EXIT THEN  \ OP_XOR

  \ ── Equality ──────────────────────────────────────────────────────────────
  DUP $87 = IF DROP  DO-OP-EQUAL        EXIT THEN         \ OP_EQUAL
  DUP $88 = IF DROP  DO-OP-EQUALVERIFY  EXIT THEN         \ OP_EQUALVERIFY
  DUP $89 = IF DROP  ." OP_RESERVED1" CR ABORT THEN
  DUP $8A = IF DROP  ." OP_RESERVED2" CR ABORT THEN

  \ ── Arithmetic ────────────────────────────────────────────────────────────
  DUP $8B = IF DROP  ['] 1+     OP-ARITH-1  EXIT THEN    \ OP_1ADD
  DUP $8C = IF DROP  ['] 1-     OP-ARITH-1  EXIT THEN    \ OP_1SUB
  DUP $8D = IF DROP  ['] 2*     OP-ARITH-1  EXIT THEN    \ OP_2MUL
  DUP $8E = IF DROP  ['] 2/     OP-ARITH-1  EXIT THEN    \ OP_2DIV
  DUP $8F = IF DROP  ['] NEGATE OP-ARITH-1  EXIT THEN    \ OP_NEGATE
  DUP $90 = IF DROP  ['] ABS    OP-ARITH-1  EXIT THEN    \ OP_ABS
  DUP $91 = IF DROP  SDS-POP-INT 0= SDS-PUSH-BOOL EXIT THEN  \ OP_NOT
  DUP $92 = IF DROP  SDS-POP-INT 0<> SDS-PUSH-BOOL EXIT THEN \ OP_0NOTEQUAL

  DUP $93 = IF DROP  ['] +   OP-ARITH-2  EXIT THEN       \ OP_ADD
  DUP $94 = IF DROP  ['] -   OP-ARITH-2  EXIT THEN       \ OP_SUB
  DUP $95 = IF DROP  ['] *   OP-ARITH-2  EXIT THEN       \ OP_MUL
  DUP $96 = IF DROP  ['] /   OP-ARITH-2  EXIT THEN       \ OP_DIV
  DUP $97 = IF DROP  ['] MOD OP-ARITH-2  EXIT THEN       \ OP_MOD
  DUP $98 = IF DROP  ['] LSHIFT OP-ARITH-2  EXIT THEN    \ OP_LSHIFT
  DUP $99 = IF DROP  ['] RSHIFT OP-ARITH-2  EXIT THEN    \ OP_RSHIFT

  DUP $9A = IF DROP
    SDS-POP-INT 0<>  SDS-POP-INT 0<>  AND  SDS-PUSH-BOOL EXIT THEN  \ OP_BOOLAND
  DUP $9B = IF DROP
    SDS-POP-INT 0<>  SDS-POP-INT 0<>  OR   SDS-PUSH-BOOL EXIT THEN  \ OP_BOOLOR

  DUP $9C = IF DROP  ['] =  OP-BOOL-2  EXIT THEN         \ OP_NUMEQUAL
  DUP $9D = IF DROP                                       \ OP_NUMEQUALVERIFY
    SDS-POP-INT SDS-POP-INT = 0= IF ." OP_NUMEQUALVERIFY" CR ABORT THEN
    EXIT THEN
  DUP $9E = IF DROP  ['] <> OP-BOOL-2  EXIT THEN         \ OP_NUMNOTEQUAL
  DUP $9F = IF DROP  ['] <  OP-BOOL-2  EXIT THEN         \ OP_LESSTHAN
  DUP $A0 = IF DROP  ['] >  OP-BOOL-2  EXIT THEN         \ OP_GREATERTHAN
  DUP $A1 = IF DROP  ['] <= OP-BOOL-2  EXIT THEN         \ OP_LESSTHANOREQUAL
  DUP $A2 = IF DROP  ['] >= OP-BOOL-2  EXIT THEN         \ OP_GREATERTHANOREQUAL

  DUP $A3 = IF DROP  SDS-POP-INT SDS-POP-INT MIN SDS-PUSH-INT EXIT THEN  \ OP_MIN
  DUP $A4 = IF DROP  SDS-POP-INT SDS-POP-INT MAX SDS-PUSH-INT EXIT THEN  \ OP_MAX
  DUP $A5 = IF DROP  DO-OP-WITHIN  EXIT THEN              \ OP_WITHIN

  \ ── Crypto ────────────────────────────────────────────────────────────────
  DUP $A6 = IF DROP  DO-OP-RIPEMD160  EXIT THEN           \ OP_RIPEMD160
  DUP $A7 = IF DROP  DO-OP-SHA1       EXIT THEN           \ OP_SHA1
  DUP $A8 = IF DROP  DO-OP-SHA256     EXIT THEN           \ OP_SHA256
  DUP $A9 = IF DROP  DO-OP-HASH160    EXIT THEN           \ OP_HASH160
  DUP $AA = IF DROP  DO-OP-HASH256    EXIT THEN           \ OP_HASH256
  DUP $AB = IF DROP  DO-OP-CODESEP    EXIT THEN           \ OP_CODESEPARATOR
  DUP $AC = IF DROP  DO-OP-CHECKSIG   EXIT THEN           \ OP_CHECKSIG
  DUP $AD = IF DROP  DO-OP-CHECKSIG                       \ OP_CHECKSIGVERIFY
    SDS-POP SDS-TRUTHY? 0= IF ." OP_CHECKSIGVERIFY" CR ABORT THEN
    EXIT THEN
  DUP $AE = IF DROP  DO-OP-CHECKMSIG  EXIT THEN           \ OP_CHECKMULTISIG
  DUP $AF = IF DROP  DO-OP-CHECKMSIG                      \ OP_CHECKMULTISIGVERIFY
    SDS-POP SDS-TRUTHY? 0= IF ." OP_CHECKMULTISIGVERIFY" CR ABORT THEN
    EXIT THEN

  . ." : unimplemented opcode" CR ABORT ;

' -EXEC-STANDARD-IMPL IS EXEC-STANDARD
