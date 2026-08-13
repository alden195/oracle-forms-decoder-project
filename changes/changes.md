# Changes

Running log of changes made to the extension. Newest entries at the top.

Each entry records what changed and why, so that the reasoning survives past the point where anyone
remembers it. Keep `architecture/architecture.md` and `features/features.md` in sync when an entry
here invalidates them.

## Format

```
## YYYY-MM-DD — short title

What changed, in a sentence or two.

**Why:** the reason, especially if the change is not self-evident from the diff.
**Affects:** files, or the architecture/feature docs that needed updating alongside it.
```

---

## 2026-08-13 — Prepared for publication: identifiers redacted

The project was put under version control for upload to a git remote, which meant deciding what to do
about real data from the tested system embedded in the docs and tests: the target hostname, four
captured `JSESSIONID` values, the WebLogic route ids and the server instance names.

All of it has been **replaced with synthetic values of identical shape**, consistently across every
file, so that a value appearing in two places is still the same value. Nothing about the
documentation's meaning changes — what those examples demonstrate is the *structure* of the cookies
(which one rotates, which one carries a route suffix, which message assigns the new one), never the
literal bytes. The tests exercise parsing behaviour and are equally unaffected; all 104 still pass.

**Why bother:** session identifiers from a production system have no business in a published
repository even once expired, and naming the specific institution under test is not something to do
by accident. Doing it before the first commit matters — once real values are in git history,
removing them means rewriting history rather than deleting a file.

`.gitignore` was also extended to cover the two export features that write secrets to disk
(`oracle-forms-keys.json`, `oracle-forms-fixtures.json`) and the default fixture directory, plus
machine-local tool configuration. The README, still the untouched PortSwigger template until now, was
replaced.

**Affects:** `.gitignore`, `README.md`, `architecture/architecture.md`, `changes/changes.md`,
`session/SessionId.java`, `burp/FormsDetector.java`, `session/SessionIdTest.java`,
`session/EndToEndDecodeTest.java`, `session/KeyStoreJsonTest.java`,
`session/NullPostFramingTest.java`.

## 2026-08-13 — Regression: retroactive key recovery broken for the applet client

Found while surveying the code, not by a test — which is the point of the entry.

The session-attribution fix earlier today correctly moved the applet client's `ifcmd=getinfo` GET
into the session its response establishes. But that GET is numbered **Pragma 1**, the same as the
`GDay` handshake POST, and it arrives *first*. `RetroactiveKeyScanner.collect` took the first Pragma 1
request it saw, so it latched onto the GET's empty body and every applet-client session came back as
"handshake incomplete in history, no key derived". Live capture was unaffected — `FormsHttpHandler`
reads the body directly — so only retroactive recovery, the feature for traffic captured before the
extension was installed, was broken.

`PragmaHistorySource` had the same collision and was fixed at the time by indexing POSTs only; the
scanner was missed because nothing tests it. The scanner now selects the body that actually carries
the `GDay`/`Mate` magic rather than the first one to turn up, which is immune to both arrival order
and request method.

**Why it escaped:** the `burp/` package has almost no test coverage — 104 tests, nearly all in
`codec/` and `session/`. That gap is now the top item on the improvements list.

**Affects:** `burp/history/RetroactiveKeyScanner.java`, `session/KeyDerivationTest.java`.

## 2026-08-13 — Key derivation can be validated after all

The project has said since the start that validating `GdayMateKeyDerivation` was blocked on the
4-byte FHT opening constant, and that learning that constant meant decoding a session by hand.

**That premise was wrong.** The constant is a 32-bit oracle. The parser is a much stronger one: a
correct key turns a Pragma 3 body into well-formed FHT — valid headers, property ids from the
470-entry table, type markers from a small set, string lengths that land inside the buffer — and a
wrong key yields uniform random bytes. Asking "does it parse, and are the ids real?" tests hundreds
of bits of structure rather than 32, and needs nothing known in advance. The constant then falls out
for free, as the first four bytes of a message that parsed, so it is a *result* of validation rather
than a prerequisite.

`KeyValidation` implements this with a **control group**: 32 random keys per session, same
ciphertext, same parser. The verdict is comparative — the derived key must beat every control
outright — so there is no hand-tuned threshold standing between a wrong answer and a pass. Measured
separation: a correct key scores 100% known property ids, a wrong one 16–24%, indistinguishable from
random.

Two measures were tried and rejected on the way, both recorded in the code because they look
plausible and are not:

- **Bytes consumed** is a poor discriminator. The parser is deliberately lenient, so random bytes
  routinely walk *further* through a body than a short well-formed message does.
- **Hit rate alone** is noisy at small denominators: a control that stumbles onto one real id scores
  a perfect 1.0 and ties a genuine decryption that found seven of seven. Ranking is on the count.

**The real blocker was tooling, not protocol.** Validation needs byte-exact bodies, and the Burp MCP
renders them as escaped text that is lossy for binary — an 8-byte handshake can arrive as seven
visible characters, so the randoms cannot be recovered through it. The Sessions tab now has an
*Export validation fixtures…* action that dumps the handshake and Pragma 3 bodies straight from the
JVM, and `RealCaptureValidationTest` runs the check against that file, skipping with instructions
when it is absent.

**Verified end to end**, not just unit-tested: generated one fixture file with sessions encrypted
under the derived key and another with a session under an unrelated key, and confirmed the suite
passes on the first and fails on the second with a per-session report.

**Also fixed**, found while wiring the export: `PragmaHistorySource` indexed every message including
the control GETs. Since the applet client numbers its `ifcmd=getinfo` GET as Pragma 1 — the same
number as the `GDay` handshake POST — and yesterday's session-attribution fix correctly moved that
GET into the new session, the GET's empty body would have displaced the handshake in the index and
lost the key material. Only POSTs carry FHT bodies, so only POSTs are indexed now.

**Still unvalidated until someone exports a fixture.** Nothing here proves the derivation is right;
it builds the thing that *can* prove it, and shows that thing is capable of failing.

**Affects:** new `session/KeyValidation.java`, new `session/ValidationFixtures.java`, new
`session/KeyValidationTest.java` and `session/RealCaptureValidationTest.java`,
`burp/ui/SessionsTab.java`, `burp/history/PragmaHistorySource.java`, `session/KeyStoreJson.java`
(object reader made package-visible for reuse), `build.gradle.kts`,
`architecture/architecture.md` §8, `features/features.md`.

## 2026-08-13 — NULLPOST and oversized-response fragmentation

First run against live traffic with the extension loaded. Pragma 8 and 9 responses decoded to
garbage. Two protocol facts were missing, both discovered from the fresh proxy history and both
absent from the reference implementation as well.

**The client sends a literal, cleartext `NULLPOST`.** When the server owes more data than fits in one
HTTP response, the client keeps the exchange going by POSTing the eight ASCII bytes `NULLPOST`. It
never passes through the client's RC4 cipher, so it must advance the request keystream by *zero*
bytes. We were advancing by 8. In the captured session pragmas 8, 9 and 10 are all NULLPOSTs, so
every request from pragma 11 onward was decrypting 24 bytes out of position — silently, as noise.

**An oversized response is split across several pragmas.** The three NULLPOSTs above drew responses
of exactly 66000, 66000 and 20892 bytes: one 218 892-byte logical message flushed in fragments. The
RC4 replay was already right here — the stream is continuous, so each fragment decrypts correctly —
but *parsing a fragment on its own* is not, because every fragment after the first begins in the
middle of an FHT structure. That is what produced convincing-looking garbage rather than an obvious
failure, and it is why the symptom read as "not properly decrypted" when decryption was fine.

Fragments are now rejoined before the parser sees them. The grouping rule keys on the NULLPOST
sentinel — "response N+1 continues response N iff request N+1 is a NULLPOST" — rather than on the
66000-byte size, so it does not depend on how the server's response buffer happens to be configured.
`ReplayResult.FragmentGroup` carries which pragmas were joined, and the editor states it, because the
user clicked one pragma and is being shown the parse of four.

**The session-establishing GET is not always Pragma 0.** Found while reading the same session. The
Web Start launcher (`Java/11.0.31`) sends the servlet-info GET as Pragma 0, but the applet client
(`Java/1.8.0_461`) sends it as Pragma 1 — and sends the `GDay` handshake as Pragma 1 too. Since that
GET's request cookie still names the *previous* session, keying only on the pragma number filed it
under the wrong one. It is now recognised by `ifcmd=getinfo` in the URL as well, which is safe to key
on where a bare `Set-Cookie` check would not be: every encrypted message is a POST to the bare
servlet path, so no message carrying FHT data can match it. Also fixed `PragmaHistorySource`'s
history filter, which matched on the request alone and so excluded that GET before the loop's own
response-aware check could see it.

**Verified by mutation.** Both fixes were reverted in turn to confirm the new tests fail without
them: reverting the NULLPOST stream length fails 2 tests, reverting fragment reassembly fails 3.

**Still not validated:** key derivation. These fixes are about framing, and they are proven against a
synthetic session shaped like the real one, not against byte-exact fixtures. The stream-symmetry
check did pass by inspection on the fresh session — the pragma 3 request and response ciphertexts
share their first four bytes — which is real evidence for the one-key/both-directions/offset-0 model.

**Affects:** `session/PragmaBody.java` (the sentinel, `streamLength`), `session/StreamReplayer.java`
(zero-length advance, fragment grouping, group-aware SESSION-scope dictionary), `session/ReplayResult.java`
(`NullPost`, `FragmentGroup`), `session/SessionId.java`, `burp/history/PragmaHistorySource.java`,
`burp/DecodeService.java`, `burp/FhtRenderer.java`, new `session/NullPostFramingTest.java`,
`architecture/architecture.md` §1 and §7, `features/features.md`.

## 2026-08-13 — Pre-use review: display corruption and unload crashes

Final pass before running the extension in Burp for the first time. The audit so far had covered
protocol logic; this one covered the parts that only fail when the thing is actually loaded — and
those had no test coverage at all, which is why they held the remaining bugs.

**The editor would have rendered its own decoration as `?`.** `FormsEditorPane.setText` encoded with
ISO-8859-1, which cannot represent `─` (U+2500), `—` (U+2014) or `…` (U+2026) — every one becomes a
literal `?`. Each separator line would have appeared as `????????????????` and every header as
`Oracle Forms ? session … ? pragma 3`. Worse than cosmetic: FHT string properties are decoded from
UTF-8 on the wire, so *any* decoded value outside Latin-1 was being silently corrupted too. Fixed on
both sides — the editor now emits UTF-8 so real values survive, and the renderer's own decoration is
plain ASCII so the layout holds whatever display charset Burp is set to.

**Unloading with an editor tab open threw on the EDT.** `CompletableFuture.supplyAsync` throws
`RejectedExecutionException` *synchronously* when its executor is shut down, so the `.exceptionally()`
handler attached to it never sees it. Same exposure on every Sessions tab button. This is not an edge
case: CLAUDE.md tells the user to reload by Ctrl-clicking the Loaded checkbox, so it sits directly on
the normal development loop. Both paths now degrade to a message telling the user to reload.

**Swing components were built off the Event Dispatch Thread.** Burp calls `initialize` on a background
thread; `SessionsTab` was constructed there. That is the class of violation that works repeatedly and
then deadlocks on someone else's machine. Now built via `invokeAndWait`, with the EDT case handled so
it cannot deadlock on itself, and a failed tab no longer takes the whole extension down — decoding
works without it.

**A refused persistence write would have lost keys silently.** `PersistedKeyStore` re-reads after
`setChildObject` (the API does not promise the instance handed in is the one stored) but did not check
the re-read for null, so a refusing store would NPE inside `put` — called from the proxy response
path, where the only symptom is captured keys quietly never appearing. Now throws with an explicit
message.

`tearDown` was also made null-safe and idempotent, since Burp can unload an extension that failed
partway through loading.

**New coverage.** `ExtensionLifecycleTest` drives load, unload, double-unload and a three-times reload
cycle against a reflective stub of the Montoya API — no mocking library, so the project stays
dependency-free (criterion 4). It asserts every registration is made, and that no `oracle-forms-*`
thread survives unload, having first proved those threads existed. The built jar was additionally
loaded by class name outside Gradle and taken through a full initialize, confirming the shipped
artifact works and not merely the classes directory.

**Why:** every previous check tested logic in isolation. Loading is the one path that has to work
before any of that matters, and it was the one path nothing exercised.
**Affects:** `burp/ui/FormsEditorPane.java`, `burp/FhtRenderer.java`, `burp/DecodeService.java`,
`burp/ui/SessionsTab.java`, `burp/OracleFormsDecoder.java`, `burp/persistence/PersistedKeyStore.java`,
`session/ReplayResult.java`, `session/Pragma3SelfTest.java`, `burp/ExtensionLifecycleTest.java`

## 2026-08-13 — Bugs found by auditing the implementation against the live capture

Re-read the proxy history looking specifically for assumptions the code gets wrong. Three fixes, plus
several assumptions confirmed sound.

**Pragma 0 was attributed to the wrong session.** The Pragma 0 GET is what *establishes* the session,
so its request still carries the **previous** session's `JSESSIONID` while its response hands out the
new one. Observed directly: a Pragma 0 request sent `JSESSIONID=A5bnVY0l…` and its response replied
`Set-Cookie: JSESSIONID=HpCezl7m…` — the id every later pragma of that session then used. Reading the
request cookie therefore filed Pragma 0 under a stale, unrelated session. `SessionId.fromSetCookieHeader`
had been written for exactly this and was never called. Now `SessionId.resolveForPragma` applies the
rule, and it applies it *only* to Pragma 0 — following a `Set-Cookie` on any other pragma would look
like a session change and shatter a stream that is in fact continuous. Harmless to replay (pragma 0 is
cleartext and the keystream starts at 3), but it mislabelled messages and polluted the wrong session's
index.

**The checkpoint cache could corrupt session-scoped decoding.** Under `DictionaryScope.SESSION`, the
checkpoint stored at the target pragma was snapshotted from the dictionary *before* the target's own
strings were absorbed. Resuming from that checkpoint to decode the next pragma resolved every
back-reference into the target's slots to an empty string — reintroducing the §7.2 failure mode
through the *cache* rather than through the scope setting, which is worse, because the setting is the
thing you would think to check. Latent today (`PACKET` is the default) but it would have fired the
moment anyone flipped the scope to answer the open question, and it would have looked like evidence
*for* packet scoping. `SessionScopeReplayTest` pins it down; the tests were confirmed to fail against
the pre-fix code before being kept.

**`SessionId.fromUrl` could throw on Unicode.** Index arithmetic done on a lower-cased copy, whose
length can differ from the original. Vanishingly unlikely in a URL, but it is attacker-influenced
input.

Assumptions checked and **confirmed** against the capture, so they need no code change:

- `lservlet` responses carry no `Content-Encoding` and no `Transfer-Encoding` — plain `Content-Length`,
  HTTP/1.1. So `body()` really is raw ciphertext; there is no compression layer to undo.
- All 22 sessions have **distinct** `JSESSIONID` values, so it is safe as a bare store key and no
  session's pragma numbering is shared with another's.
- The two cookies appear in **both orders** across the capture, confirming name-based rather than
  positional matching was necessary.
- Pragma 3 request and response do open with identical ciphertext (`Âúaë`, `Nl1Ï` in two sessions),
  so `checkStreamSymmetry` will pass on real data.
- Two client User-Agents and two WebLogic backends both appear, as documented.

**Why:** the implementation was written from the docs, and the docs were written from a reading of the
history rather than from running code against it. Re-reading the traffic with the code in hand is a
different exercise and found things neither pass would have.
**Affects:** `session/SessionId.java`, `session/StreamReplayer.java`, `burp/FormsDetector.java`,
`burp/history/PragmaHistorySource.java`, `burp/history/RetroactiveKeyScanner.java`,
`burp/ui/FormsRequestEditor.java`, `burp/ui/FormsResponseEditor.java`,
`session/SessionScopeReplayTest.java`, `session/SessionIdTest.java`

## 2026-08-13 — The Pragma 3 self-test was vacuous; replaced with two checks that discriminate

While writing unit tests for `Pragma3SelfTest`, the "wrong key must fail" case passed when it should
have failed. The check specified in architecture §1 cannot work:

> Decrypt the first 4 bytes of the Pragma 3 request and of the Pragma 3 response. If they do not
> match each other, the key or the stream start is wrong.

The premise is that the two *ciphertext* prefixes are identical. Both are decrypted with the same
keystream at the same offset, so their plaintexts are identical **for any key whatsoever**. A totally
wrong key yields two identical wrong prefixes and the check passes. It has no discriminating power,
and the plan had it as build order step 2's first task — the thing everything else was to be
validated against.

Replaced with the two checks the observation actually supports:

- `checkStreamSymmetry(req, resp)` compares the **raw ciphertext** prefixes and needs no key. This is
  the real content of the original observation: it validates that both directions share one key and
  both start at Pragma 3 offset 0, which is the assumption the whole replay model rests on.
- `checkKey(key, body, expectedConstant)` compares a decrypted prefix against the known opening
  constant. This can falsify a key, but needs the constant, which is still unknown.
- `recoverOpeningConstant(key, body)` bridges the gap: run it over all 22 captured sessions, and a
  correct derivation must make every session agree despite different keys. That is real evidence and
  it can actually fail.

`RetroactiveKeyScanner` runs the symmetry check per session and reports failures rather than storing
keys silently.

**Why:** the whole point of the self-test was to validate `GdayMateKeyDerivation` before the parser
existed. Shipping it as specified would have produced a green check on every session including
broken ones, and the derivation would then have been trusted on the strength of a test that cannot
fail. Identifying the opening constant is now the explicit blocker for key validation (§8).
**Affects:** `session/Pragma3SelfTest.java`, `session/Pragma3SelfTestTest.java`,
`burp/history/RetroactiveKeyScanner.java`, `architecture/architecture.md` (§1, §8),
`features/features.md`

## 2026-08-13 — Extension implemented: codec, session, and Burp wiring (build order 1–5)

Built the decoder end to end. The extension now loads into Burp, captures keys from live handshakes,
persists them to the project file, and decodes any captured message on demand by replaying the RC4
stream from proxy history. 73 unit and integration tests, all passing.

- **`codec/`** was already present; completed and tested it. Fixed a real gap found by testing: a
  truncation partway through a message discarded every property already recovered, so a partial
  decode rendered as empty despite `FhtPacket`'s documented promise that partial results are a
  first-class outcome. `readProperties` now appends into a caller-owned list and `readMessage`
  registers the partial message before rethrowing.
- **`session/`** — `Direction`, `PragmaBody`, `PragmaSource`, `Handshake`, `SessionId`, `SessionKey`,
  `SessionKeyStore` (+ in-memory implementation), `Checkpoint`, `CheckpointCache`, `StreamReplayer`,
  `ReplayResult`, `KeyStoreJson`, `DictionaryScope`. No Burp imports, so all of it is unit-tested
  directly (criterion 12).
- **`burp/`** — `FormsDetector`, `PersistedKeyStore`, `PragmaHistorySource`, `RetroactiveKeyScanner`,
  `FormsHttpHandler`, `DecodeService`, `FhtRenderer`, request and response editor tabs, `SessionsTab`,
  and `OracleFormsDecoder` wiring with a full unloading handler.

Design points worth recording:

- **`CheckpointCache` thins rather than truncates.** When a stream exceeds its bound it drops every
  second checkpoint, doubling the effective interval while keeping coverage across the session.
  Evicting the oldest would discard exactly the checkpoints that make the start of a session cheap to
  reach and are the most expensive to rebuild.
- **`DecodeService` retries once through a rebuilt history index on a gap**, because a "missing
  pragma" often just means the cached index predates traffic proxied since.
- **Editor tabs use a generation counter** so a slow decode of a 28 KB Pragma 3 response cannot
  overwrite whatever the user navigated to in the meantime.
- **`PACKET` dictionary scope lets replay skip intervening packets entirely** — only the stream
  length matters, so no decryption or parsing happens for them. `SESSION` scope must decrypt and
  parse each one. The performance gap is large and follows directly from §7.2's open question.

**Why:** this is build order steps 1–5. The order was kept because each step is independently
verifiable and the risky protocol work sits behind a testable seam — which is what caught the
self-test problem above.
**Affects:** all of `src/main/java/oracleforms/`, `src/main/java/Extension.java`,
`src/test/java/oracleforms/`, `build.gradle.kts`, `architecture/architecture.md`,
`features/features.md`, `CLAUDE.md`

## 2026-08-13 — Build targets Java 21 by cross-compilation rather than a toolchain

Replaced the `java { toolchain { languageVersion = 21 } }` block with `options.release = 21`.

**Why:** the toolchain block hard-fails when no JDK of exactly that version is installed. This
machine has a Java 21 *JRE* (no `javac`) and a Temurin 25 JDK, so the build could not run at all.
`options.release = 21` produces identical Java 21 bytecode (verified: class file major version 65)
from any JDK 21 or newer, which is strictly more portable and loses nothing.
**Affects:** `build.gradle.kts`

## 2026-08-13 — Protocol assumptions validated against the live capture

Read the project's Burp proxy history through the `burp` MCP server (~1,100 encrypted pragma POSTs
across 22 sessions against `forms.example.edu/forms/lservlet`) and folded the findings into the
docs. Three of the five §8 open questions are now answered; a new §1 subsection records what was
confirmed, and §8 is split into "resolved" and "still open".

Substantive changes rather than just annotations:

- **Session id is `JSESSIONID`, not `JSESSIONID_FORMS`.** Both cookies are present; the latter
  rotates mid-session (observed moving `anQtg` → `anQ0T` within one session). The docs previously
  said only "check the URL and the Cookie header", which would not have stopped anyone from keying on
  the wrong cookie and fragmenting every RC4 stream. Now a table in §3.
- **A key-derivation self-test that needs no plaintext.** The first four ciphertext bytes of the
  Pragma 3 request and response are identical within a session and differ across sessions — verified
  on two independent sessions. Because both directions are seeded from the same key and both sit at
  keystream position 0 at Pragma 3, that means the FHT message opens with a shared 4-byte constant.
  Decrypt both and compare: a mismatch proves the key or the stream start is wrong. This is now build
  order step 2's first task.
- **Keystream start pinned to Pragma 3, offset 0**, in both directions — previously implied but never
  stated.
- **Pragma numbering confirmed contiguous** (sampled 100–111 consecutively; Pragma 2 absent across
  the whole history), so gap detection can be strict rather than tolerant.
- Recorded that the MCP tools render bodies as escaped text and are lossy for binary, so fixtures
  must be exported from Burp directly.

**Why:** the architecture was written from the reference implementation's research alone and labelled
its protocol section "a starting hypothesis to verify against your own target". Verifying it before
writing code is cheap; discovering the wrong session-id choice after building the replayer would look
like an intermittent decryption bug rather than a lookup-key mistake. The Pragma 3 oracle in
particular removes the chicken-and-egg problem of needing a working parser to know whether the key is
right.
**Affects:** `architecture/architecture.md` (§1, §3, §4, §7.3, §8, §9), `CLAUDE.md`,
`features/features.md`

## 2026-08-13 — Architecture designed against the reference implementation

Read the [3erk1n/oracle-forms-decoder](https://github.com/3erk1n/oracle-forms-decoder) Jython
extension in full and rewrote `architecture/architecture.md` around it: protocol facts, the
on-demand-replay decoding model, the persisted key store, component layout, and a list of the
reference's bugs. Rewrote `features/features.md` to match, and replaced CLAUDE.md's speculative
protocol description with the confirmed FHT/RC4 details.

**Why:** the earlier architecture guessed at the protocol ("may be compressed and/or encrypted…
proprietary Java-serialized"). It is actually RC4 with a 5-byte key derived from a cleartext
handshake, and the keystream is continuous across the session. That last fact is load-bearing: it
means a stored key alone cannot decrypt an arbitrary message, so the whole decode path had to be
designed around replaying the stream from proxy history rather than decoding live. Verified the
Montoya persistence and proxy-history signatures against `montoya-api-2026.7.jar` with `javap`
rather than assuming them.
**Affects:** `architecture/architecture.md`, `features/features.md`, `CLAUDE.md`

## 2026-08-13 — Documentation scaffolding

Added the `architecture/`, `features/`, and `changes/` folders with their initial documents.
`architecture/architecture.md` records the proposed layering for the decoder, and
`features/features.md` records the planned feature set — both are forward-looking, since no decoder
code exists yet.

**Why:** the project's direction (an Oracle Forms decoder for JNLP-launched Java 8 client traffic)
was captured in CLAUDE.md but had no room to hold design detail. Splitting it out keeps CLAUDE.md
short enough to stay read.
**Affects:** `architecture/architecture.md`, `features/features.md`, `changes/changes.md`, `CLAUDE.md`

## 2026-08-13 — Project context recorded in CLAUDE.md

Rewrote CLAUDE.md to describe the Oracle Forms decoder goal rather than the generic template, and
corrected the stated Montoya API version from 2025.10 to 2026.7 to match `build.gradle.kts`.

**Why:** the documented version disagreed with the build file, which would mislead anyone checking
API availability against the wrong javadoc.
**Affects:** `CLAUDE.md`
