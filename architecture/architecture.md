
# Architecture

Architecture for the Oracle Forms traffic decoder Burp extension (Java / Montoya API).

Reference implementation: [3erk1n/oracle-forms-decoder](https://github.com/3erk1n/oracle-forms-decoder) —
a single-file Jython extension (`oracle_forms_burp.py`, 1140 lines) against Burp's legacy API. We take
its protocol research, which is the valuable part, and rebuild the structure around it. Deviations are
listed in [Corrections to the reference](#corrections-to-the-reference).

> **Status: build order steps 1–5, 6a–6e and 6h.0–6h.4 implemented** (2026-08-18). 245 unit and integration
> tests. The extension builds, loads, decodes read-only, persists keys — and now sends: a captured
> message can be drafted into Repeater as plaintext, edited property by property, and re-encrypted at
> the live session's keystream position on Send, with the real client's session surviving intact.
>
> The send path has been **verified against a loaded extension in a running Burp** (2026-08-14): key
> capture, offset and tail encryption, keystream continuity across sends, `Pragma` rewriting,
> `NULLPOST` pass-through, fail-closed refusal and the marker trust rule all check out against an
> independent RC4 implementation. What remains unverified is the *application* layer of §6.1 —
> a message **has** now been sent to a real Forms server, and it was rejected — see §6.11. The one
> bug that diagnosis turned up regardless of the cause, a silently guessed offset after an untracked
> send, is **fixed**.
>
> **The cause of that rejection has since been found by reading the code (2026-08-18): the proxy
> advanced the four-stream ledger but never applied it to any bytes**, so the real client's first
> message after an injection reached the server at the wrong keystream offset and killed the runtime
> — after which every send answers `FRM-93618`. Fixed; see §6.2 and §6.11.
>
> **Bisection step 2 has since been run (2026-08-18) and passed**: an *unedited* Mode A draft was
> accepted by the live Forms server. The cryptographic and transport rows of §6.1 are therefore
> confirmed for the request direction against a real target. **Steps 3–5 — whether an *edit*
> survives — are unrun, and are now the whole open question.**
>
> **Mode D is built** (§6.12, 2026-08-18): a request held in the Intercept tab can be decoded,
> edited in a property table or as raw bytes, and re-encrypted at the session's live keystream
> position on Forward. It carries §6.2's own "proxied request edited to P′" row, which needed no new
> crypto. **It has not been run against a live target** — 6h.5 is bisection steps 3–5, and that is
> now the whole open question of §6.
>
> **Its first use on a live session found a bug, and the pre-flight FHT check is what caught it**
> (2026-08-19, §6.12 *The message being held is already in history*): **Burp records a request in
> proxy history when it intercepts it, not when it forwards it**, so a tail measurement counted the
> very message being held and the ledger sat one whole message too far along the keystream. Fixed by
> measuring the position *before* the held pragma, and by checking the ledger against the traffic and
> correcting it when the traffic proves itself. A second live session then showed that an
> edited *value* was reaching the server inside a message that contradicted it — see
> §6.3's *A string is not always the only thing that describes itself*. 266 tests.
>
> **Bisection step 5 has now been run through Mode D, and it passed** (2026-08-19): a length-changing
> edit was accepted by the live Forms server, the application acted on the new value, and the session
> — **diverged** by that edit — kept working for every message after it. That is §6.1's application
> row reached for the first time, and the live counterpart of `DivergedForwardingTest`. See §6.11.
>
> Remaining: **6h.5** (live-target edit), **6d.2, 6d.3, 6d.5** (§6.10 — 6d.1 and 6d.4 were built as
> Mode D prerequisites), **6f** (Mode B session bootstrap, gated on §6.7 question 1), **6g**
> (response editing) and **step 7** (rules tab). The protocol questions in §8 are still open pending
> byte-exact fixtures.

---

## 1. Protocol facts

Established from the reference implementation and its README. Everything in this section is
**reverse-engineered, not documented by Oracle** — treat it as a starting hypothesis to verify against
your own target, not as ground truth.

Oracle Forms HTTP Transport (FHT), Forms 10g/11g:

- The Java client (launched from a `.jnlp`, running on Java 8) POSTs to the Forms listener servlet,
  path containing `lservlet`.
- Every message carries a `Pragma: N` sequence header:

  | Pragma | Method | Content |
  | --- | --- | --- |
  | 0 | GET | servlet info, cleartext |
  | 1 | POST | `GDay`/`Mate` handshake, cleartext, **carries the key material** |
  | 3+ | POST | RC4-encrypted FHT binary |

  Pragma 2 does not exist.

- **Key derivation.** A 5-byte (40-bit) RC4 key is derived from two 4-byte randoms sent in cleartext:
  `client_random` after the `GDay` magic (`0x47446179`) in the Pragma 1 request, `server_random` after
  the `Mate` magic (`0x4d617465`) in the response. Using Java arithmetic right-shift on the randoms
  read as signed big-endian int32:

  ```
  key[0] = (client_random >> 8)  & 0xFF
  key[1] = (server_random >> 4)  & 0xFF
  key[2] = 0xAE                       // constant
  key[3] = (client_random >> 16) & 0xFF
  key[4] = (server_random >> 12) & 0xFF
  ```

- **The RC4 keystream is continuous across the whole session**, not reset per message. Each direction
  has its own stream, both seeded from the same key. This single fact drives most of the design below.
- The plaintext is a proprietary binary format ("FHT") of messages, each an action + class id +
  handler id + a property list, with a 256-slot string dictionary for back-references.

### Confirmed against a live capture

> **Note on identifiers.** Every hostname, `JSESSIONID`, `JSESSIONID_FORMS` value — including its
> rotating suffix — server instance name and WebLogic route id in this document and in the test suite
> has been **replaced with a synthetic value of the same shape** before publication. The observations
> and the structural properties they demonstrate are real; the literal bytes are not, and cannot be
> correlated with any live system. Replacement is consistent throughout, so a value that appears in
> two places is still the same value.
>
> The rotating suffix was **added to this list on 2026-08-14**, having been missed by the original
> pass: the values after the `|` were real. A synthetic suffix now reads `rot01`, `rot02`, and so on,
> which is deliberately impossible to mistake for a captured one. If you add a fixture, invent the
> suffix too — the rule is that no literal byte in this repository came off a real wire.

Read from the Burp proxy history of the current project on 2026-08-13 (target
`forms.example.edu/forms/lservlet`, Forms 11g, ~1,100 encrypted pragma POSTs across 22
sessions). This moves several §8 items from hypothesis to fact **for this deployment** — it does not
make them universal.

- **`GDay`/`Mate` is the scheme in use.** Pragma 1 request body is exactly 8 bytes (`GDay` + 4-byte
  client random); the response is exactly 8 bytes (`Mate` + 4-byte server random). So the §1
  derivation is the right first implementation.
- **Pragma 0 is a GET with `?ifcmd=getinfo&iflocale=…&ifhost=…&ifip=…`**, responding `text/plain`
  with the servlet path. Its **response** carries the `Set-Cookie: JSESSIONID=…` that the rest of the
  session uses. A session therefore begins at its Pragma 0 response, not at Pragma 1.
- **Pragma 2 is absent** — zero matches across the entire history.
- **Pragma numbering is contiguous.** Sampled 100–111 within one session: strictly consecutive, no
  skips. Gap detection can treat any missing number as genuinely uncaptured.
- **The keystream starts at Pragma 3, offset 0, in both directions.** See the self-test below.
- **Encrypted bodies range from 2 bytes to ~28 KB.** The Pragma 3 response is the large initial-UI
  payload (28,296 bytes in one session); steady-state traffic is 8–12 byte requests against
  100–400 byte responses. Size bounds must accommodate both ends.
- **Two client User-Agents both speak the protocol**: `Java/11.0.31` (the Web Start launcher) and
  `Mozilla/4.0 (…) Java/1.8.0_461` (the Forms applet client). Detection must not filter on
  User-Agent.

### `NULLPOST` and oversized responses (2026-08-13)

Two framing rules, both learned the hard way from live traffic and **neither present in the
reference implementation**. Missing either produces garbage that looks like a decryption failure.

- **The client posts a cleartext `NULLPOST`.** When the server owes more data than fits in one HTTP
  response, the client continues the exchange by POSTing the eight ASCII bytes `NULLPOST`. It is
  written straight to the socket, *not* through the RC4 request cipher, so it **contributes zero
  bytes to the request keystream**. Advancing over its 8 bytes desynchronises every later request in
  the session. Observed at pragmas 8, 9 and 10 of one session, and at 29 and 30 of another.

- **A large response is fragmented across pragmas.** Those three NULLPOSTs drew responses of exactly
  66000, 66000 and 20892 bytes — one 218 892-byte logical message flushed in buffer-sized pieces. The
  RC4 stream runs continuously across them, so each fragment *decrypts* correctly; but every fragment
  after the first starts mid-structure, so **parsing one alone yields plausible nonsense**. Fragments
  must be rejoined before parsing.

  The grouping rule keys on the sentinel, not on the size: **response N+1 continues response N iff
  request N+1 is a `NULLPOST`.** That is exactly what the client means by it, and it keeps the rule
  independent of the server's response-buffer configuration. `ReplayResult.FragmentGroup` records
  which pragmas were joined so the editor can say so.

- **The session-establishing GET is not always Pragma 0.** The launcher sends the servlet-info GET as
  Pragma 0; the applet client sends it as Pragma 1 — and sends the `GDay` handshake as Pragma 1 as
  well. Since that GET's request cookie names the *previous* session (§3), it must be recognised by
  `ifcmd=getinfo` in the URL rather than by its pragma number. This is safe where a bare `Set-Cookie`
  check would not be: every encrypted message is a POST to the bare servlet path, so nothing carrying
  FHT data can match the marker and no continuous stream can be fragmented by it.

#### What the Pragma 3 observation actually buys

Within a session, the **first four ciphertext bytes of the Pragma 3 request and the Pragma 3 response
are identical**, and they differ from session to session. Verified on two independent sessions.

Since each direction has its own stream but both are seeded from the same key and both sit at
keystream position 0 at Pragma 3, identical ciphertext implies identical plaintext. So the FHT
message opens with the same 4-byte constant in both directions.

> **Correction (2026-08-13).** An earlier version of this section proposed the check "decrypt the
> first 4 bytes of both directions; if they do not match, the key is wrong." **That check is
> vacuous and has been removed.** The two ciphertext prefixes are *already known to be equal*, and
> both are decrypted with the same keystream, so their plaintexts are equal for *any* key — a
> completely wrong key produces two identical wrong prefixes and passes. It has no discriminating
> power. This was caught by a unit test written against a synthetic session
> (`Pragma3SelfTestTest.demonstratesWhyTheOriginalCheckWasVacuous`).

The observation still carries real information, but it splits into two different checks, which is
how `Pragma3SelfTest` is now built:

1. **`checkStreamSymmetry(pragma3Request, pragma3Response)`** — compares the **raw ciphertext**
   prefixes. Needs no key at all. It validates the architectural assumption that both directions
   share one key and both start at Pragma 3 offset 0. If it fails, the replay model itself is wrong,
   which is the single most valuable thing to learn early. This is the real content of the original
   observation, and it was never about decryption.
2. **`checkKey(key, pragma3Body, expectedConstant)`** — compares a *decrypted* prefix against the
   known opening constant. This is the only check that can falsify a key, and it is unavailable
   until the constant's value is learned by decoding one session by hand.

Until then, `recoverOpeningConstant(key, body)` gives the constant a key implies. Run it across all
22 captured sessions: **if the derivation is correct, every session must recover the same constant**,
despite having different randoms and therefore different keys. That cross-session agreement is
genuine evidence for the derivation formula — and unlike the original check, it can actually fail.

*Caveat:* the four-byte match was read off the MCP's escaped-text rendering, not raw bytes, so it is
strong evidence rather than proof — a lossy rendering could in principle collapse two distinct bytes
onto the same character. Re-confirm on exported bytes when the fixtures land. If it does not hold,
the likely culprits are the streams not both starting at Pragma 3 or the two directions not sharing
a key, and both are worth knowing early.

**Version risk.** The derivation above is specific to the `oracle/forms/net/HTTPConnection` bytecode
the reference author examined. Forms 12c, or a deployment with `INITIAL_ENCRYPTKEY` (property 271) in
play, may differ. Isolate key derivation behind an interface (§4) so a second scheme can be added
without touching anything else.

---

## 2. The central design decision

**The reference decodes live and only live. We decode on demand.** This is the most important
difference, and it is what makes your headline feature possible.

The reference decrypts inside its proxy listener and stores the *formatted text* in module-level
dicts. The editor tab is a lookup into that dict. The consequences:

- Traffic that did not flow through the proxy while the extension was loaded can never be decoded.
- Reloading the extension, or reopening the project, loses every key and every decode. Existing proxy
  history becomes permanently opaque.

You asked for key session storage so that previously captured encrypted traffic stays readable. That
requires inverting the model:

> Capture keys eagerly and **persist** them. Decode lazily, on demand, by **replaying** the RC4
> keystream from the session's start.

### Why storing the key is necessary but not sufficient

Because the keystream is continuous, the key alone does not let you decrypt Pragma 42. RC4 at that
point has consumed every byte of Pragmas 3–41 in that direction. To read Pragma 42 you must
re-derive the stream position by running the cipher over all preceding bodies in order.

So the decode path is: **stored key → replay preceding pragmas in order → decrypt the target.**

This is workable because the ordering key is explicit and reliable — the `Pragma` header number — and
because proxy history retains the bodies. It also gives a genuinely useful diagnostic the reference
cannot produce: if a pragma is *missing* from history, we know precisely which one, and can report
"Pragma 17 not captured — cannot decode 18 and later" instead of a blank tab.

### Checkpointing

Naive replay is O(n) per message and O(n²) to browse a session. Cache a **checkpoint** at intervals
(every ~25 pragmas) and at each decoded message:

```
Checkpoint = { rc4 S-box (256 bytes) + i + j , string dictionary (256 slots) }
```

The string dictionary is in the checkpoint because it may be session-scoped rather than per-packet
(see §7, open question). Decoding then means: find nearest checkpoint ≤ target, replay forward from
there, store a new checkpoint. Checkpoints live in a bounded LRU, in memory only — they are
reconstructible from the key, so they are never persisted.

---

## 3. Key session store

The persistence layer is confirmed present in Montoya 2026.7: `api.persistence().extensionData()`
returns a `PersistedObject` supporting nested `getChildObject`/`setChildObject`, `setByteArray`,
`setString`, `setLong`, and key enumeration via `childObjectKeys()`. That maps cleanly onto a session
table:

```
extensionData()
  └── "oracleForms"
        └── "sessions"
              └── <jsessionid>
                    ├── key        : ByteArray(5)
                    ├── host       : String
                    ├── firstSeen  : Long (epoch millis)
                    ├── lastSeen   : Long
                    ├── label      : String   (user-editable note)
                    └── source     : String   ("derived" | "manual" | "imported" | "bootstrap")
        ├── "streams"
        │     └── <jsessionid>          absent until this session's streams diverge (§6.2)
        │           ├── clientRequestBytes  : Long
        │           ├── serverRequestBytes  : Long
        │           ├── serverResponseBytes : Long
        │           ├── clientResponseBytes : Long
        │           └── nextPragma          : Long
        └── "desync"
              └── <jsessionid>          absent until this session's position becomes unrecoverable
                    └── reason          : String   (shown verbatim in the refusal, §6.11)
```

`extensionData()` is scoped to the Burp project, which is the right lifetime: keys belong to the
traffic captured in that project, and they survive both extension reload and Burp restart.

The `streams` collection is what lets an edited or injected session survive an extension reload. RC4
state is a pure function of the key and the bytes consumed, so four counters reconstruct all four
ciphers with one `skip` each; `nextPragma` rides along because after an injection the session has a
sequence number the capture has never seen. It is written **only once the four counters stop being
equal** — before the first length-changing edit or Repeater injection they are derivable from proxy
history, and writing them on every message would touch the project file for nothing. See §6.2.

The `desync` collection is the durable half of the refusal in §6.11: it records that traffic reached
the server which proxy history never captured, so this session can never be appended to again. It is
durable rather than in-memory because the *server's* state is — its request cipher stays ahead across
an extension reload and a Burp restart, and a marker that did not survive them would let a later send
encrypt at an offset this extension had already detected as wrong, which is worse than never having
detected it.

> **Correction (2026-08-14, on building it).** These counters were originally drawn as a *child* of
> each session entry. They are a **sibling collection** instead, because `PersistedKeyStore.put`
> replaces a session's entry wholesale — anything nested inside would be destroyed silently every
> time a key was re-derived. Keeping them apart makes that impossible rather than merely avoided.
>
> **`desync` is a third sibling for the same reason, one level down** (2026-08-14): `save()` replaces
> a session's *stream* entry wholesale, so a marker nested inside it would be destroyed by the next
> checkpoint. The two are independent anyway — a session can be desynchronised without ever having
> diverged, which is in fact the common case.

### Which cookie is the session id

The capture shows **two** session cookies, and picking the wrong one silently destroys the replay:

| Cookie | Behaviour | Use as session id? |
| --- | --- | --- |
| `JSESSIONID` | Constant for the life of the session | **Yes** |
| `JSESSIONID_FORMS` | Rotates mid-session via `Set-Cookie`, often every few messages | **No** |

Observed directly: one session held `JSESSIONID=X43xQtj1…` while `JSESSIONID_FORMS` moved from
`formsapp_rs1|rot01` at Pragma 1 to `formsapp_rs1|rot02` by Pragma 65. Keying on `JSESSIONID_FORMS`
would shatter a single RC4 stream into dozens of fragments, each missing the Pragma 1 that carries
its key — the failure would look like "no key for this session" on almost every message.

Two further details:

- **The session id never appears in the URL** on this deployment; it is Cookie-only. The reference's
  URL-only extractor (§7.3) would do nothing here. Read the `Cookie` header, and **match by cookie
  name, not position** — the two cookies appear in both orders across the capture.
- `JSESSIONID` embeds a WebLogic route suffix (`…!-1111111111`) and the capture contains a second
  backend (`…!-2222222222`, serving `formsapp_rs2`). The value is therefore unique across servers and
  is safe to use as a bare store key without qualifying it by host. Confirmed across all 22 captured
  sessions: every one has a distinct `JSESSIONID`, so no two sessions can collide in the store.
- **Pragma 0 is the exception: its request cookie names the *previous* session.** The Pragma 0 GET is
  what establishes the session, so its request still carries whatever `JSESSIONID` the client had
  while its response assigns the new one. Seen directly: request `JSESSIONID=A5bnVY0l…`, response
  `Set-Cookie: JSESSIONID=HpCezl7m…`, and every later pragma of that session used the latter. So a
  Pragma 0 must be identified from its response's `Set-Cookie`, and **only** a Pragma 0 — treating a
  `Set-Cookie` on any other message as a session change would fragment a continuous stream. This is
  `SessionId.resolveForPragma`.

**Ways a key enters the store**, in priority order:

1. **Derived live** from an observed Pragma 1 handshake. The normal path.
2. **Derived retroactively** by scanning proxy history for Pragma 1 messages. This recovers sessions
   captured before the extension was installed — run it on demand from the Sessions tab, never
   automatically at load (criterion 9: history can be enormous).
3. **Entered manually** — paste a 5-byte key hex for a session captured elsewhere, or one recovered by
   other means.
4. **Imported** from a JSON export of another project's store.

**Security note.** These keys are session secrets and the Burp project file is not encrypted. That is
an acceptable tradeoff for a pentest tool, but it should be stated in the README, and the store should
offer a "forget session" and "clear all keys" action. The keys protect traffic that already contains
plaintext credentials, so the marginal risk is low — but it should be a documented choice, not an
accident.

---

## 4. Component structure

The dependency arrow points one way: `ui` and `http` depend on `session` and `codec`; `codec` depends
on nothing in this project. Keeping the codec free of `burp.api.montoya.*` is what makes it testable
without a running Burp (BApp criterion 12) and fuzzable against captured samples.

```
oracleforms/
  Extension.java                    BurpExtension entry point; wiring; unload handler

  codec/                            pure, no Burp imports, unit-tested
    Rc4Stream.java                    keystream state; apply(byte[]) advances it; copyable
    KeyDerivation.java                interface — deriveKey(clientRandom, serverRandom)
      GdayMateKeyDerivation.java      the 10g/11g scheme from §1
    FhtReader.java                    bounded cursor; throws on truncation, never over-reads
    FhtParser.java                    bytes -> FhtPacket, recording byte offsets per property
    FhtWriter.java                    FhtPacket -> bytes (re-encode)
    PropertyIds.java                  the 470+ id table, plus a prebuilt reverse map
    model/
      FhtPacket.java, FhtMessage.java, FhtProperty.java, PropertyValue.java
      ParseOutcome.java               complete | truncated-at-offset | failed, with partial results

  session/                          stateful, no Burp imports
    SessionId.java                    jsessionid extraction (Cookie header *and* URL; see §3)
    SessionKey.java                   the 5 key bytes + provenance metadata
    SessionKeyStore.java              interface: get/put/list/forget
    StreamReplayer.java               key + ordered pragma bodies -> plaintext at pragma N
    Checkpoint.java                   RC4 state + string dictionary snapshot
    CheckpointCache.java              bounded LRU, in-memory only
    SessionStreams.java               the four ciphers + byte counters for one session (§6.2)
    StreamRegistry.java               bounded LRU of SessionStreams; rebuilds from history on miss
    SessionTail.java                  where a session's streams have got to; refuses on a gap
    InjectionPlan.java                the send decision: ciphertext + pragma, or a refusal

  burp/                             the only package that touches Montoya
    persistence/PersistedKeyStore.java    SessionKeyStore and StreamPositionStore over PersistedObject
    history/PragmaHistorySource.java      pulls a session's pragmas from proxy history, filtered
    handler/FormsHttpHandler.java         observes traffic; captures handshakes; keeps the ledger level
    repeater/
      SendToRepeaterMenu.java             context menu: send the decoded message to Repeater (§6.5)
      DraftMarkers.java                   the X-OracleForms-* contract
      RepeaterSendInterceptor.java        encrypts marked outbound bodies; strips the markers
    ui/
      FormsRequestEditorProvider.java  + FormsRequestEditor  (ExtensionProvidedHttpRequestEditor)
      FormsResponseEditorProvider.java + FormsResponseEditor
      SessionsTab.java                   the key store UI
      RulesTab.java                      auto-modification rules
```

Everything under `session/` stays free of Montoya imports, including the new stream ledger: the
arithmetic that keeps four ciphers consistent across an edit is the subtlest code in step 6 and has
to be testable against a synthetic session with no running Burp.

### Why `StreamReplayer` and `PragmaHistorySource` are separate

`StreamReplayer` takes an ordered list of bodies and a key. It has no idea where the bodies came
from. `PragmaHistorySource` knows about `api.proxy().history(filter)` and nothing about RC4. This
split is what lets you unit-test replay against a recorded fixture, which is the single most valuable
test in the project — it is where the subtle bugs will be.

`api.proxy().history(ProxyHistoryFilter)` takes a filter, so we never materialize the full history
(criterion 9). Filter on: URL contains `lservlet`, has a numeric `Pragma` header, matching session id.

---

## 5. Message flow

**Detection** (cheapest check first — this runs on every proxied request): path contains `lservlet`
→ numeric `Pragma` header present → session id extractable. Only then does anything else happen.

**Live capture.** `FormsHttpHandler` watches for Pragma 1. On the request it stashes `client_random`
after the `GDay` magic; on the response it reads `server_random` after `Mate`, derives the key, and
writes it to the store. **This is the only work done on the proxy hot path** — no decryption, no
parsing, no formatting. That is a deliberate departure from the reference (criterion 5).

**On-demand decode.** When an editor tab is asked to display a message, it resolves session id and
pragma number, then hands off to a background executor:

```
key from store ─┬─ absent ──> "no key for this session" + offer manual entry / retro-scan
                └─ present ─> nearest checkpoint ≤ pragma
                              └─> replay intervening pragmas from history
                                    ├─ gap detected ──> "Pragma N missing, cannot decode"
                                    └─ complete ─────> decrypt target -> FhtParser -> render
```

The tab shows a pending state on a cache miss and repaints when the result arrives. Nothing slow
happens on the EDT.

**Outbound (step 6, §6).** The mirror image, and it runs in the opposite order: the editor holds
plaintext and the handler encrypts at send time, because the correct keystream offset is not known
until the moment the request actually leaves. Detection gains one case — a request carrying the
`X-OracleForms-*` markers is a plaintext draft, not ciphertext — and the handler gains one rule: a
marked request either encrypts successfully or never leaves Burp. See §6.5.

**One addition to the hot-path budget.** The handler now also keeps an *already open* session ledger
level with the traffic the real client is still generating, because otherwise a session goes stale
the moment the client sends anything after a Repeater send, and the next send would encrypt at an
offset the server has left behind. The cost is one hash lookup per Forms message and nothing at all
for other traffic; the cipher only advances for a session the user has already sent into. Sessions
nobody sends to never get past the lookup.

**Failure is a first-class result.** `ParseOutcome` distinguishes a clean parse from one truncated at
a byte offset, and the tab renders partial results *plus* an explicit "parsing stopped at offset N"
line, falling back to a hex view. A malformed message from an untrusted target must never produce a
blank tab or a silent partial decode.

---

## 6. Editing, and sending from Repeater

The goal this section designs for: **send a captured Forms message to Repeater, change a value, press
Send, and have the server accept it.** Everything below exists to make that one sentence true, and to
be honest about where it stops being true.

### 6.1 Three independent things must hold

A Repeater send that "works" needs three separate properties. They are worth naming separately
because every one of them fails the same way — the server returns an error page, or stalls, or tears
the session down — while the fix for each is completely different.

| Layer | Requirement | Who can guarantee it |
| --- | --- | --- |
| **Cryptographic** | The body must be RC4'd at exactly the keystream offset the server's request cipher currently sits at for this session. One byte out and the entire message is noise. | The extension, fully |
| **Transport** | Cookies must name a session the server still holds, and the `Pragma` header must be the number it expects next. | The extension, fully |
| **Application** | The Forms runtime is a state machine. A message referring to handler ids or UI objects that no longer exist is rejected even when it decrypts perfectly. | Nobody, in general — only mitigated (§6.4, Mode B) |

The first two are engineering. The third is inherent to replaying against a stateful application, and
the design's job is to make it *visible* rather than to pretend it away.

### 6.2 The four-stream model

The reference documents a real limitation: changing a string's length shifts the RC4 stream position
for every later message in the session, breaking it. **This is fixable, and we should fix it.**

The reference keeps one RC4 state per direction. But Burp is a man in the middle with *two*
independent cipher relationships — one with the client, one with the server. Keep **four** states per
session:

| State | Used for |
| --- | --- |
| `clientRequestStream` | decrypting what the client sends |
| `serverRequestStream` | encrypting what we forward to the server |
| `serverResponseStream` | decrypting what the server sends |
| `clientResponseStream` | encrypting what we forward to the client |

They start identical and stay identical until the first length-changing edit, after which the
positions diverge and each side remains internally consistent:

- Client encrypts P4 at its position `L3`; we decrypt with `clientRequestStream`, also at `L3`. ✓
- We forward `P4'` encrypted with `serverRequestStream` at `L3'`; the server decrypts at `L3'`. ✓

**A Repeater injection is the same problem with the length going 0 → n.** That is the key
realisation, and it is why Repeater support is not a separate mechanism: an injected message is a
message the real client never sent, so from the client's point of view its length was zero and from
the server's it was `n`. The four-stream ledger absorbs the difference exactly as it absorbs an edit.

> **Correction (2026-08-18, and it is the cause of the first live-target failure).** Everything above
> describes bytes being *carried across* the two relationships, and for a year the implementation
> only ever carried the *counters*. `FormsHttpHandler` advanced all four legs correctly and then
> forwarded each proxied message unchanged, which is right only while the two legs of a direction sit
> at the same offset. After an injection they do not — and the client's very next message reached the
> server encrypted at an offset `n` bytes behind where the server's cipher was, which is `FRM-93618`
> (§6.11). **A ledger that only counts is not a four-stream proxy.**
>
> `SessionStreams.forward` is the missing half: for a diverged direction it decrypts on the leg facing
> the sender and re-encrypts on the leg facing the receiver, and the handler puts the result on the
> wire. Undiverged sessions still take the counter-only path, because there the translation provably
> returns its input.
>
> Worth naming why the suite missed it: every test in `SessionStreamsTest` and step 6 of
> `RepeaterInjectionEndToEndTest` performs the translation *in the test* and then checks the far side
> can read it. They verify the model, which was never wrong. Nothing drove the production call with a
> real party on the other end until `DivergedForwardingTest`.

> An earlier version of this section said "replaying a single message out of sequence from Repeater
> still desyncs the real session (inherent, not fixable)". **That is true only of replaying into the
> middle of a session, which the four streams cannot help with because the server has already
> consumed that stream position and will never return to it.** Appending to the *tail* of a session
> is a different operation and is fully supported — see Mode A below. The two were conflated.

What advances which stream:

| Event | `clientRequest` | `serverRequest` | `serverResponse` | `clientResponse` |
| --- | --- | --- | --- | --- |
| Proxied request `P`, unmodified | +len(P) | +len(P) | — | — |
| Proxied request `P`, edited to `P′` | +len(P) | +len(P′) | — | — |
| Proxied request is `NULLPOST` | 0 | 0 | — | — |
| Proxied response `R`, unmodified | — | — | +len(R) | +len(R) |
| Proxied response `R`, edited to `R′` | — | — | +len(R) | +len(R′) |
| **Repeater injection `X`** | **0** | **+len(X)** | **+len(reply)** | **0** |

The Repeater row *is* the feature. The real client's ciphers never move, so the live session keeps
working after an injection; the server's ciphers move, so the server keeps working too. Both sides
stay internally consistent and neither can tell.

**The four streams are cheap to persist and cheap to rebuild.** RC4 state is a pure function of the
key and the number of bytes consumed, so the ledger is four `long` counters, not four 256-byte
S-boxes. Rebuilding a stream is one `Rc4Stream.skip(n)`, which is milliseconds even for a session of
several megabytes. So the "if the extension is unloaded mid-session the streams are lost" caveat is
also removable: persist the counters under the session (§3) and the divergence survives a reload.
Write them **only once a divergence exists** — before the first edit or injection all four are equal
and reconstructible from proxy history, and writing on every message would hammer the project file
for nothing.

### 6.3 Structural editing, not byte scanning

The reference patches strings by scanning the plaintext for a two-byte header pattern, which can
match arbitrary bytes inside string contents or image data and silently corrupt the message. Instead,
`FhtParser` records the byte offset and length of every property value it reads, so an edit is applied
at a known-good offset.

> **Correction (2026-08-14, on building it).** This section previously added "— or, better, the
> packet is re-serialized from the model via `FhtWriter`". **That option does not exist, because
> `FhtParser` is deliberately lossy.** It discards the delta-index byte on `ACTION_5`/`ACTION_6`
> messages, keeps only the subtype and byte length of an `ExtValue` rather than its payload, resolves
> back-references into plain strings without recording which dictionary slots produced them, and
> never records the slot a literal string was stored into. Rebuilding a packet from that model would
> silently rewrite bytes nobody asked to change — on a shared, continuous keystream, where a wrong
> byte damages every message after it.
>
> So `FhtWriter` **splices**: it copies the original packet verbatim and replaces only the byte ranges
> recorded for the properties actually edited. Everything untouched is untouched *by construction*,
> which is a stronger guarantee than any test can give. Where the model is missing something the
> encoding needs — a string's dictionary slot, a back-reference's slot pair, the type marker itself —
> the writer reads it back out of the original bytes.

**The identity gate.** Splicing is only as safe as the encoder producing the replacement, so before
any edit is applied the writer re-encodes that property with its **unchanged** value and checks the
result is byte-identical to what is already there. If the encoder cannot reproduce bytes it can read,
it does not get to replace them.

That check runs on every edit at runtime, not only in tests, and it is what lets the writer be honest
about types it only partly understands: a property this codec gets subtly wrong shows up as a refused
edit with a reason, not as a corrupted session. It also catches lossy *decoding* — a string whose
bytes are not valid UTF-8 comes back through `FhtReader` as a replacement character, would re-encode
to different bytes, and is therefore locked.

**One promotion is deliberate.** Editing a back-referenced string rewrites it as a literal stored into
the same destination slot. A back-reference's only effect besides its own value is that dictionary
write, and a literal into the same slot performs exactly it, so any later property reading that slot
sees the new text — which is what a user changing a string means. Nothing is promoted unless the value
actually changes.

#### A string is not always the only thing that describes itself

> **Learned from a live edit that the application ignored** (2026-08-19).

A Forms client does not send a text item's value on its own. It sends the value **together with the
caret and the selection**, and both of those are indices into that very string:

```
UPDATE handler=113
    ID_99            = "elevenchars"     <- the text
    SELECTION        = (11, 11)          <- caret at the end of it
    CURSOR_POSITION  = 11
```

Splice a seven-character value in and the message now says the text is seven characters long and the
caret is at eleven. **No client can produce that**, and the Forms runtime is under no obligation to
make sense of it — which is what an edit that reaches the server and changes nothing looks like.
Confirmed on three consecutive live edits: `SELECTION` and `CURSOR_POSITION` held the length of the
text the client had, every time.

So `TextIndexEdits` adds the companion edits, through the same splice and the same identity gate. The
rule is narrow on purpose, because this is the one place the writer is allowed to change something
the user did not type:

- **Only an index that now points past the end of the edited text moves, and only to the end of it.**
  A caret the user left in the middle of the string is a position a client could genuinely send.
- **An explicit edit outranks the inference** — a caret the user typed is never touched.
- **Two changed strings in one message adjust nothing**, because the caret indexes one of them and
  nothing here can say which. A stale value the user can see beats a confident wrong one.
- **The raw surface is exempt.** It is unrestricted by design; the user is writing bytes and nothing
  is entitled to add any of its own.
- **Nothing is silent.** The adjustment is named in the status line as the cell is committed, and
  logged again on the way out.

This does not generalise into "the codec understands the application". It is one relationship,
between a string and the indices into it, that is visible in the bytes and provable from them.

### 6.4 Four send modes

The extension cannot know which of these the user wants, and they have very different consequences,
so the mode is chosen explicitly — at "Send to Repeater" time, and changeable in the tab afterwards.
Mode D is the exception, and only because it cannot be ambiguous: it is chosen by *where the message
is*, since a request held in the Intercept tab admits exactly one sensible position.

#### Mode A — append to the tail of a live session

The default when the target session is known and its history has no gaps.

- **Position**: the session's tail. Taken from the persisted `serverRequest` counter if a divergence
  is on record, otherwise computed by replaying history to the highest captured pragma — the same
  machinery `StreamReplayer` already uses to decode.
- **Pragma**: rewritten to `highest + 1`. The captured number is kept only as provenance.
- **Cookies**: rewritten to the session's most recently observed values. This matters specifically
  for `JSESSIONID_FORMS`, which rotates every few messages (§3) — a stale value may route to a
  backend that has never heard of the session.
- **Effect**: the message lands in a live application session and the Forms runtime acts on it. This
  is not a sandbox, and the UI must say so.
- **Concurrency**: sends against one session must be **serialised**, because each one advances the
  shared server-side stream. A consequence worth stating plainly: *Intruder with more than one thread
  is broken by construction in this mode* — parallel payloads interleave into a single keystream and
  destroy each other. Force single-threaded, or refuse.
- **Gaps**: if history is missing a pragma, the tail offset is unknown. **Refuse the send; never
  guess.** A wrong offset does not produce a polite error — it feeds the server bytes it reads as
  garbage, and can take the user's live session down with it.

#### Mode B — bootstrap a fresh session

The repeatable one, and the honest answer to "I want to send this again tomorrow".

1. `GET …?ifcmd=getinfo&…` → the response's `Set-Cookie` gives a new `JSESSIONID`.
2. `POST` Pragma 1 with `GDay` + a fresh 4-byte random → `Mate` + server random → derive the key and
   store it with `source = "bootstrap"`.
3. Optionally **replay a captured prefix**: pragmas 3…N−1 from the source session, re-encrypted under
   the *new* key, in order, honouring the `NULLPOST` rule outbound (send cleartext, advance nothing)
   and consuming each response so the response stream keeps pace.
4. Send the edited target message.

Every request goes through `api.http().sendRequest()` (BApp criterion 7), on a background executor,
cancellable. Because extension-issued requests re-enter registered `HttpHandler`s as
`ToolType.EXTENSIONS`, the bootstrap must tag its own traffic so the handler's capture path does not
recurse into it.

The prefix replay is what makes the application layer (§6.1) tractable: it walks the server-side
runtime into the state the target message assumes. Whether the server *accepts* a replayed prefix is
an open question with a cheap experiment — see §6.7.

#### Mode C — fixed offset, for inspection only

Encrypt at the offset the message originally occupied. Correct for a live send only in the degenerate
case where the target already *is* the tail. It exists for diffing ciphertext and exporting to other
tools, and the UI must label it as not-for-sending rather than quietly offering it as an equal.

#### Mode D — edit a request in flight, from the Intercept tab

Decrypt the request Burp is holding, let the user edit it, and re-encrypt it at the session's live
`serverRequest` position on Forward. The client's own `clientRequest` leg advances by the length it
actually sent, so the two part company exactly as they do for a Repeater injection — this is §6.2's
"proxied request `P`, edited to `P′`" row, the one the ledger was designed for and the only one never
exercised.

Unlike Mode A it invents nothing: the `Pragma` number and the cookies are the client's own and stay
untouched, the message is in sequence by construction, and no tail has to be guessed at while a live
client is still talking. It is also the only mode that can **verify its own keystream offset before
the user edits anything**, because it decrypts a message whose plaintext it can then check for
well-formed FHT.

Fully designed in **§6.12**, including the capability token that lets a marker be trusted from the
Proxy without weakening rule 1 of §6.5.

### 6.5 Where the plaintext lives: the marker-header contract

The Repeater tab has to hold *something*, and the choice determines everything else.

**Rejected: hold the ciphertext, re-encrypt in `getRequest()`.** Burp calls `getRequest()` whenever it
needs the message, not only at Send, so the send offset would have to be frozen at edit time — and by
the time the user presses Send the session tail may have moved. It also leaves the raw tab showing
ciphertext that no longer matches what the editor is displaying.

**Chosen: the Repeater tab carries the FHT *plaintext*, plus marker headers. The HTTP handler
encrypts at send time and strips the markers.** The handler is then the single owner of the crypto
and the only place that needs to know a stream position, and it learns that position at the instant
it is actually correct. As a bonus the raw tab becomes a usable hex editor for bytes the parser does
not yet understand.

```
X-OracleForms-Session:  <jsessionid>         which session's key and streams to use
X-OracleForms-Send:     tail | bootstrap | offset=<n> | intercept
X-OracleForms-Origin:   <captured pragma>    provenance, for display only
X-OracleForms-Original: <byte length>        Mode D only: what the client actually sent (§6.12)
X-OracleForms-Token:    <128 random bits>    Mode D only: the capability that makes a Proxy-origin
                                             marker trustworthy, single-use (§6.12)
X-OracleForms-Position: <keystream offset>   Mode D only: where the client's leg stood when the edit
                                             was decoded, re-checked at Forward (§6.12)
```

Handler rules, in order:

1. **Honour the markers only from Burp's own tools** — `toolSource().isFromTool(REPEATER, INTRUDER,
   EXTENSIONS)`. A marker on a proxied request was set by the client, and the client is the
   application under test; treat it as untrusted, strip it, and ignore it (criterion 3). The check
   sits behind the existing `lservlet` detection gate, so it adds nothing to the hot path for traffic
   that is not ours.

   **Mode D is an exception to the tool list and not to the rule** (§6.12). An intercept edit
   necessarily arrives *from the Proxy*, so it carries a single-use `X-OracleForms-Token` this
   extension minted and has never put on the wire. A Proxy-origin marker without a valid token is
   still ignored and stripped, exactly as before; the token is what is trusted, not the origin.
2. **Strip all three headers before the request leaves Burp, on every path including failures.**
3. **Fail closed.** No key, no session, unknown position, encryption impossible — return
   `RequestToBeSentAction.spoof(…)` with a synthetic response explaining why. The request never
   leaves Burp, and the explanation appears in Repeater's response pane, which is where the user is
   already looking. Silently sending a marked request unencrypted would put readable FHT — including
   any credentials in it — on the wire.
4. **`NULLPOST` outbound.** A plaintext body of exactly those eight bytes is sent cleartext and
   advances nothing, mirroring the decode rule.
5. **No `Content-Length` fixup is needed after encryption.** RC4 is length-preserving; the only
   length change is the user's own edit, which Burp already accounts for when the editor hands back a
   modified request.

**The response leg.** Repeater responses never enter proxy history, so the replay-from-history path
cannot reach them. The handler decrypts the reply against `serverResponseStream`, advances it, and
puts the plaintext in a bounded LRU keyed by a hash of the ciphertext; the response editor checks
that cache before falling back to replay. Hashing the ciphertext, rather than keying on (session,
pragma), keeps repeated sends of different bodies from colliding.

**Detection needs one addition.** A plaintext draft still looks like an encrypted message to
`FormsDetector` — `lservlet` path, `Pragma ≥ 3`, a `JSESSIONID` — so the editor would try to replay
and decode bytes that are already clear. `FormsTarget` gains a flag set from the marker, and the pane
renders the body directly when it is set.

### 6.6 Component additions

As built (2026-08-14). Names marked ▲ were not in the original sketch; the reasons are below.

```
codec/                              pure, no Burp imports
  FhtWriter.java                    splices edited properties into a packet; the identity gate (§6.3)
  FhtEdit.java                    ▲ one pending change, bound to the parsed property not to an offset
  FhtUnwritableException.java     ▲ checked: the caller must say what happens instead
  PropertyValues.java             ▲ text <-> PropertyValue, shape-preserving, for editable cells

session/                            stateful, no Burp imports
  StreamLeg.java                  ▲ the four cipher relationships
  SessionStreams.java               the four Rc4Streams + byte counters + next pragma
  StreamPositions.java            ▲ the durable form: four longs and a sequence number
  StreamPositionStore.java        ▲ persistence seam, so session/ stays Montoya-free
  StreamRegistry.java               bounded LRU of SessionStreams; rebuilds from history on miss
  SessionTail.java                ▲ measures a session's position, and refuses on an interior gap
  StreamPositionUnknownException  ▲ the refusal supertype: nothing can be encrypted for this session
  StreamGapException.java         ▲ names the missing pragma, so a refusal is actionable
  StreamDesyncException.java      ▲ the server is ahead of the capture, unrecoverably (§6.11)
  InjectionPlan.java              ▲ the send decision: bytes, pragma and offset, or a refusal
  CookieHeader.java               ▲ refreshes the rotating cookie without discarding the user's

burp/
  DecodedBodyCache.java           ▲ plaintext for bodies history cannot reach (a Repeater reply)
  repeater/
    SendMode.java                 ▲ tail | offset, never defaulted
    DraftMarkers.java             ▲ the X-OracleForms-* contract: parse, apply, strip
    RepeaterSendInterceptor.java    the marker-header half of FormsHttpHandler
    SendToRepeaterMenu.java         context menu: "Send decoded to Repeater (…)"
  ui/
    FhtDraftPanel.java            ▲ the property table; editability from FhtWriter.editRefusal
    FormsRequestEditor              editable when EditorCreationContext.editorMode() is not READ_ONLY
```

**`OutboundEncoder` was not built.** It would have been a single method wrapping one call plus the
`NULLPOST` rule, and that rule belongs next to the state it protects: it lives in
`SessionStreams.apply` instead, beside the counters it must not advance.

**`SessionBootstrap` was not built** — Mode B is still designed only, gated on §6.7 question 1.

#### Built for Mode D (§6.12), 2026-08-18

```
session/                            stateful, no Burp imports
  InterceptEditPlan.java          ▲ the in-flight edit decision: advance clientRequest by the length
                                    the client sent, encrypt the edited body on serverRequest, or
                                    refuse. Kept out of burp/ for the same reason InjectionPlan is —
                                    it is ledger arithmetic, and it has to be testable against a
                                    synthetic session with two independent parties
  SessionTail.before(…)           ▲ where the ciphers stood *before* a pragma, which is what an
                                    in-flight edit needs and is not the tail (2026-08-19)
  StreamRegistry.openBefore(…)    ▲ opens the ledger there
  StreamRegistry.measureBefore(…) ▲ a detached second opinion, built without disturbing the live
                                    ledger, so a candidate offset can be verified before it is
                                    believed
  StreamRegistry.resynchronise(…) ▲ adopts a verified correction; refuses a diverged session, whose
                                    counters are the only record of traffic history never saw

burp/
  proxy/
    InterceptTokens.java          ▲ mints, validates and consumes the single-use capability that
                                    lets a Proxy-origin marker be trusted (§6.12). Bounded; nothing
                                    it holds ever reaches the wire
  repeater/
    SendMode.java                   gains INTERCEPT
    DraftMarkers.java               gains X-OracleForms-Original and X-OracleForms-Token, and strips
                                    both like the rest
  handler/
    FormsHttpHandler.java           gains one branch: a token-bearing Proxy request takes the
                                    intercept path *instead of* forward(), never both — and it is
                                    dispatched ahead of RepeaterSendInterceptor, which would
                                    otherwise strip the markers and forward the plaintext (§6.12)
    FormsHttpHandler.EditRoute    ▲ the routing decision, split out and free of Burp objects so a
                                    test can drive it: RequestToBeSentAction's factories need a
                                    running Burp, so a test going through the handler could not
                                    assert on what came back
  proxy/
    InterceptEditService.java       prepares a held request: opens the ledger *before* it, decodes
                                    with a detached cipher, and reconciles the ledger against the
                                    captured traffic when the decode does not verify (2026-08-19)
  ui/
    FhtDraftPanel.java              gains the Raw surface, the toggle and the cell commit (6d.1,
                                    6d.4 — prerequisites, see §6.12's build order)
    FormsRequestEditor.java         gains the intercept path: decode with a detached cipher, verify
                                    the offset reads as FHT, then offer editing and return
                                    plaintext + markers + token from getRequest()
```

**A separate `InterceptEditPlan` rather than a third method on `InjectionPlan`.** They answer
different questions. `InjectionPlan` decides what a message *this extension is sending* should look
like, and owns the sequence number; Mode D is rewriting a message *the client sent*, keeps that
message's own number, and has to move a second leg by a length only the editor knows. Folding the two
together would put an unused pragma decision in one path and an unused length in the other.

Everything in `session/` and `codec/` stays free of Montoya imports, for the same reason
`StreamReplayer` does: the ledger arithmetic in §6.2 is the subtlest code in the feature and has to be
testable against a synthetic session with no running Burp. That is what makes
`RepeaterInjectionEndToEndTest` possible — it runs decode → edit → inject → *server reads it* → client
carries on, with nothing stubbed but Burp itself.

`RepeaterSendInterceptor` is a collaborator of `FormsHttpHandler`, not a second registered handler, so
the ordering between key capture and send interception is deterministic rather than dependent on
registration order.

Editability is gated on `editorMode()`, which Burp already sets to `READ_ONLY` for proxy history.
Proxy history therefore stays read-only for free, and the editable path only ever appears where an
edit can mean something.

### 6.7 Open questions, and the experiments that settle them

All five need a live target, and all five are cheap once Mode B exists.

1. **Does the server accept a replayed prefix in a fresh session?** The question Mode B rests on.
   Bootstrap, replay pragmas 3…N from a capture, and compare each response structurally against the
   captured one. Decisive either way.
2. **Are handler ids stable across sessions?** If they are, a captured message can be sent into a
   bootstrapped session without replaying the whole prefix, which turns Mode B from expensive into
   cheap. Compare decoded property values across two captured sessions performing the same action.
3. **Is the `Pragma` number validated or advisory?** Send one with a deliberately wrong number into a
   bootstrapped session. Determines whether the tail number must be exact.
4. **Does `JSESSIONID_FORMS` actually affect routing,** or does the route suffix inside `JSESSIONID`
   carry it? Omit it in a bootstrapped session and see.
5. **Does the server tolerate a length change?** It should — an FHT message is self-describing — but
   the whole four-stream model is only worth building if it does.

### 6.8 Build order for step 6

Revised from the single line in §9, which predates all of the above. Each step is independently
verifiable and the ones that can damage a live session come last.

| | Step | Gate | Status |
| --- | --- | --- | --- |
| **6a** | `FhtWriter` + round-trip tests | decode→encode reproduces captured bytes exactly. Nothing below starts until this passes | **done** — per-property identity gate, enforced at runtime as well as in tests |
| **6b** | `SessionStreams`, `StreamRegistry`, the four-stream ledger | unit tests over synthetic sessions, including an injected message and a length-changing edit. No UI, no Burp | **done** — `SessionStreamsTest` simulates client and server as separate parties |
| **6c** | Marker-header contract and `RepeaterSendInterceptor`, Mode C only | a marked request encrypts to the same bytes as the capture it came from | **done** — `InjectionPlanTest.offsetModeReproducesTheOriginalCiphertext` |
| **6d** | Editable request editor in Repeater, `FhtWriter`-backed | edit a property, see the plaintext change; markers survive the round trip | **reopened** — the property table works, but is unreachable from `Ctrl+R`, drops an uncommitted cell, and covers only round-trippable values. See §6.10 |
| **6e** | Mode A tail append, per-session serialisation, refuse-on-gap | a modified message is accepted by a live session *and* the real client keeps working afterwards | **reopened, then repaired** (2026-08-18). The second half of the gate was never implemented: the proxy advanced the ledger but forwarded traffic unchanged, so the real client stopped working immediately after an injection (§6.2, §6.11). `SessionStreams.forward` fixes it and `DivergedForwardingTest` covers it. Still not verified against a live target |
| **6f** | Mode B bootstrap and prefix replay | once experiment 1 in §6.7 has an answer | not built |
| **6g** | Response editing, client-facing response leg | last, because fragment groups (§1) only bite here | not built |
| **6h** | **Mode D — editing a request in flight from the Intercept tab** | an edited intercepted request is accepted by the server *and* the real client keeps working. Broken into 6h.0–6h.5 in **§6.12**; depends on §6.10's 6d.1 and 6d.4 | **done** — 6h.0–6h.4 built 2026-08-18, repaired 2026-08-19 (the first live use hit the tail-includes-the-held-message bug, §6.12). **6h.5 run 2026-08-19: a length-changing edit was accepted by the live server, the application acted on it, and the diverged session kept working** (§6.11). Steps 3 and 4 of the bisection, both strictly easier, remain formally unrun |

> **What "done" means for 6e.** Two levels of evidence, and neither is the application layer.
>
> *In simulation:* every claim in §6.2 is verified against a simulated client and server holding
> their own continuous ciphers, including that the real client keeps working after an injection.
>
> *Against a live Burp* (2026-08-14): the deployed extension was driven through Burp's own HTTP stack
> at a local listener standing in for the servlet, and the ciphertext it produced was checked against
> an independent RC4 implementation. Key derivation, offset and tail encryption, keystream continuity
> across consecutive sends, `Pragma` rewriting, `NULLPOST` pass-through, the fail-closed refusal and
> the marker trust rule all hold. This is what found the `Content-Length` bug in the refusal response
> that no simulation could reach.
>
> *Still unverified:* whether the Forms runtime **accepts** an appended message. That is the
> application layer of §6.1 and it needs the real target — exactly what §6.7 cannot answer from
> here.

Two notes on ordering. **Request editing is unaffected by response fragmentation** — requests are
small and are never split — so the concern raised in `features/improvements.md` about fragment
groups applies only to 6g, and does not hold up the Repeater feature at all. And **6e is the first
step that can perturb someone's live session**, which is the natural place to stop and reconsider
rather than a thing to slide into.

### 6.9 Honest limits

- Mode A acts on a live application session. It is not a sandbox, and undoing it means restarting the
  session.
- Mode A needs the extension loaded, and needs the session's stream position known. Gaps in history
  mean refusal, not a best guess.
- The application layer (§6.1) cannot be guaranteed by anything the extension does. A message can be
  cryptographically perfect and still be rejected because the runtime has moved on.
- Repeater tabs and the project file will contain FHT **plaintext**, which is the point but is also a
  new place for credentials to sit unencrypted. Same tradeoff as the key store (§3), and it belongs
  in the README next to it.
- Intruder is supported only as a consequence of the same contract, and only Mode B is safe to run
  concurrently.
- **After an injection, the session depends on the extension.** A diverged session's traffic has to
  be translated between the two cipher relationships on every message, in order, for the rest of that
  session's life (§6.2). Unloading the extension, bypassing the proxy, or losing a message means the
  client and the server are talking at different keystream offsets and neither can recover. The
  counters are persisted so a reload survives, but nothing can replace traffic the extension did not
  see. This is inherent to appending to a live session, not an implementation gap — but before
  2026-08-18 it was not implemented at all, which is what `FRM-93618` was.
- **Mode A cannot hold a session still while a send is in flight.** The tail is a snapshot taken from
  history; a client that is still talking moves the server's cipher between the measurement and the
  packet's arrival. Leaving the application idle avoids it, but nothing can reserve a keystream
  position against a live client. See §6.11.
- **Mode A's tail counts a request that is being intercepted.** Burp puts a request into proxy
  history when it holds it, not when it forwards it (§6.12), and history cannot tell a held request
  from one that is merely waiting for its response — both simply have no response yet. So a Repeater
  append made *while* a request sits in the Intercept tab is that request's length too far along the
  keystream. Mode D is immune, because it knows which message is being held: it is the one being
  edited. Mode A is not, and cannot be from history alone. Turn interception off before appending, or
  expect the intercept path to notice and repair the ledger afterwards — by which time the Mode A
  message has already gone.
- **Sending captured ciphertext from Repeater — without the draft markers — spends the session.**
  Those bytes reach the server but never enter proxy history, so every later tail measurement would
  be short by their length. Since 2026-08-14 this is **detected and refused** rather than guessed at
  (§6.11): the session is marked unrecoverable, durably, and Mode A explains why. The session is
  still spent — nothing can recover an offset the capture never saw — but the failure is now a
  message instead of a dead application.
- **A refusal can be a false positive, deliberately.** The mark is set when the request is about to
  leave Burp, not when the server acknowledges it, so ciphertext sent to a host that refuses the
  connection still spends the session. Fail-closed is the right way round here: the cost of a wrong
  refusal is restarting the application, and the cost of a wrong permission is a corrupted live
  session that gives no sign of it.
- **Mode D refuses by dropping, and a dropped request probably ends the session.** The proxy path has
  no way to explain itself to a client — `ProxyRequestToBeSentAction` has no `spoof` — so the only
  fail-closed answer available is to send nothing. That is the deliberate choice (§6.12), and its
  price is an application restart. It is mitigated by checking the key, the ledger and the offset
  *before* an edit is offered, not by softening what happens when the check was not enough.

---

### 6.10 Why a Repeater tab is not editable in practice, and what makes it editable

> **Status: 6d.1 and 6d.4 built** (2026-08-18) as prerequisites of Mode D (§6.12) — the cell commit
> and the raw plaintext surface. **6d.2, 6d.3 and 6d.5 remain designed only.** Note that 6d.3's
> conversion bar now exists in a Mode D form: a held Proxy request gets one button, because the mode
> there cannot be ambiguous. The Repeater ciphertext tab still has no route to a draft.
>
> Originally raised from use (2026-08-14): a message sent to Repeater cannot be
> manipulated. 6d is marked **done** above and the property table does work — but it is reachable
> only by a route most users will not take, it drops the edit they just typed, and it covers a
> minority of a real message. This section is the diagnosis and the fix; the build order is at the
> end of it.

#### The four reasons, which are independent

Worth separating, because "I can't edit it" has four different causes here and three of them are
defects rather than limits. Fixing any one alone still leaves the feature looking broken.

**1. The entry point is one nobody uses.** `Ctrl+R` — Burp's own *Send to Repeater* — copies the
message as it stands, which is **ciphertext**. Only the extension's own *Send decoded to Repeater*
context items produce a draft. A ciphertext tab carries no `X-OracleForms-*` markers, so
`DraftMarkers.from` is empty, `FormsRequestEditor` falls to the read-only decode pane, and **there is
no route from that tab to an editable one**. This is almost certainly what a user hits first, and it
is the one that makes the feature look absent rather than merely limited.

**2. A typed value is discarded unless the user presses Enter.** Swing's default is that a `JTable`
leaves its cell editor open when focus moves elsewhere: `setValueAt` never fires, the model still
holds the old value, `isModified()` returns false and `getRequest()` returns the unedited body. So
typing into a cell and then clicking **Send** sends the *original* message, silently. From the
outside that is indistinguishable from "editing does nothing", and it is the most damaging of the
four because it looks like it worked.

**3. The table is the only surface, and it offers only what the writer can round-trip.** Everything
else is shown locked: extended payloads, implicit zeros, voids, unrecognised type markers,
structural pseudo-properties. Nothing can be added, deleted or reordered, and the message header is
untouchable. For a *decoder* that is exactly right. For a *manipulation* tool it is the wrong
default, because in a protocol this incompletely understood the interesting bytes are
disproportionately the ones the codec cannot yet name.

**4. A failed edit fails open.** `FormsRequestEditor.getRequest` catches a splice failure, logs it,
and returns the **unedited** plaintext — so a refused edit sends the original message with nothing on
screen to say so. §6.5's rule 3 says a draft that cannot be *encrypted* never leaves Burp. The same
has to hold for a draft that cannot be *assembled*; there is no principled difference between the two.

#### A. Two ways into an editable tab, and `Ctrl+R` is one of them

The context menu stays as it is. What is added is a route from a ciphertext Repeater tab to a draft,
because that is the tab the user will actually be looking at.

When the Forms request tab is created with `editorMode() == DEFAULT` — Repeater and Intruder, never
proxy history — over a message that is still ciphertext with a resolvable session, it renders the
read-only decode as now, **plus a conversion bar**: two buttons, one per send mode, worded exactly as
the menu items are. The mode is still never chosen on the user's behalf (§6.4).

Pressing one runs the same background replay the menu item runs, and on success the panel swaps to
the draft view holding plaintext.

**The conversion reaches Burp through the contract that already exists.** `isModified()` becomes
true and `getRequest()` returns the plaintext body with the marker headers added. That is not a new
mechanism — it is precisely how a table edit already reaches the wire today. If Burp does not honour
it, the current edit path does not work either, so this adds no new unknown to the design. Where it
differs from an edit is that headers change as well as the body, which `HttpRequest.withAddedHeader`
covers.

Three properties this must have:

- **Nothing is sent.** Conversion rewrites the tab; the user still presses Send.
- **It is visible.** The banner changes and the raw tab's bytes change underneath the user, which is
  a large enough change that it must never happen without an explicit press.
- **It is one-way.** Converting back would mean re-encrypting at an offset chosen for display, which
  is Mode C wearing a disguise. A user who wants the ciphertext back has it in proxy history.

One related correction: the *Send decoded to Repeater* items are currently offered on a message that
is **already a draft** — plaintext with `Pragma ≥ 3` passes `isEncrypted()` — and would decode
plaintext as though it were ciphertext, producing garbage. Suppress them when `DraftMarkers.isMarked`
holds.

#### B. Commit the cell before anything reads the model

Two changes, deliberately redundant:

- `table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE)`, which handles the ordinary case.
- An explicit `stopCellEditing()` at the top of `editedPlaintext()` and `isModified()`.

The client property alone would do in most cases, but it is a Swing implementation detail and the
*read* path is the one that has to be right: the invariant is "the model is current whenever anybody
asks it a question", and that belongs where the question is answered, not only where focus is lost.

The test goes through the table model and the editor component — not through the renderer, which is
where a test can pass while the real path drops the value.

#### C. A raw plaintext surface beside the table

The table stays primary; it is the safe, structural, identity-gated surface and most edits belong
there. Beside it sits **Raw**: Burp's own editable `RawEditor` over the decoded plaintext, giving
text and hex views over byte-exact content.

Everything the table refuses is reachable there — extended payloads, unknown markers, the message
header, inserting and deleting properties, and length changes of any size.

```
        ┌──────────── one buffer: the draft plaintext ────────────┐
        │                                                          │
   [ Structured ]  ──switch: splice pending edits──▶  [ Raw ]
   property table  ◀──switch: re-parse the bytes───   hex + text
   identity-gated                                     unrestricted
        │                                                          │
        └───────────────▶ getRequest() ◀───────────────────────────┘
```

**One authoritative surface at a time**, chosen by a toggle, and switching commits. Table → Raw
splices the pending edits and loads the result; Raw → Table re-parses the bytes and rebuilds the
rows. There is never pending state in the hidden view. Two live editors over one buffer is the
classic way to lose a user's work, and the only reliable defence is that one of them is not live.

**The raw view warns; it does not block.** Edited bytes are re-parsed on every switch and before
send. If they no longer parse as FHT the banner says so and names the offset, and the send proceeds
anyway. Refusing here would be wrong: sending what the parser thinks is malformed is the entire
point of a manipulation tool, and this parser's opinion is a hypothesis about someone else's
protocol (§1), not an authority.

That is deliberately the opposite of the identity gate in §6.3, and the difference is *who is
asserting*. The writer refuses a splice when **it** cannot prove the change is faithful — that is the
codec doubting itself, and it should fail closed. The raw view sends what the **user** wrote, having
said plainly what it thinks of it. Conflating the two would either make the table unsafe or make the
raw view useless.

**The ledger already absorbs it.** A raw edit of any length is, to §6.2, the same length-changing
edit the four-stream model was built for. Nothing downstream needs to know a raw edit happened — which
is why this is cheap to add now and would have been a redesign before 6b.

#### D. Fail closed when an edit cannot be assembled

A fourth marker, honoured before any other:

```
X-OracleForms-Refuse: <reason>
```

Set by the editor when `FhtWriter.applyEdits` throws. `RepeaterSendInterceptor` checks it first,
refuses with that reason, and strips it like the rest.

The reason it travels as a header rather than a dialog is that `getRequest()` is called by Burp
whenever it wants the message, on threads of its choosing — a modal dialog there would be a bug, and
throwing would surface as a broken tab. The refusal has to ride along with the request and be
answered by the machinery that already exists for it, which puts the explanation in Repeater's
response pane where the user is looking anyway.

This closes the last fail-open path in the send route. Every other one was closed on 2026-08-14; this
one was missed because it lives in the editor rather than the interceptor.

#### Component additions

```
burp/ui/
  ConvertToDraftBar.java        ▲ the two-button conversion bar on a ciphertext Repeater tab
  FhtDraftPanel.java              gains the Raw view, the surface toggle, and cell-commit
  FormsRequestEditor.java         gains the conversion path and the refusal marker

burp/repeater/
  DraftMarkers.java               gains REFUSE_HEADER and its strip
  RepeaterSendInterceptor.java    honours the refusal marker before anything else
  SendToRepeaterMenu.java         suppressed on a message that is already a draft
```

No new package, no new class in `codec/` or `session/`. That is the useful signal here: every one of
these is a UI or contract defect, and none of them reaches the protocol layer. The crypto built in
6a–6e is not what is wrong.

#### Build order

Reopens 6d. Each step is independently verifiable, and the ordering is by how much of the complaint
each one removes.

| | Step | Gate |
| --- | --- | --- |
| **6d.1** | Cell commit on focus loss and on read | type a value, click Send without pressing Enter, and the edit is in the body. Tested through the model |
| **6d.2** | Fail closed on an unassemblable edit (`X-OracleForms-Refuse`) | a draft whose splice throws is answered with the refusal response and never leaves Burp |
| **6d.3** | Conversion bar: ciphertext Repeater tab → draft | `Ctrl+R` on a captured message, then one press, gives an editable draft with correct markers |
| **6d.4** | Raw plaintext surface and the one-live-surface toggle | an edit made in either surface survives a switch to the other and back; nothing is lost either way |
| **6d.5** | Suppress the draft menu items on an existing draft | right-clicking a draft offers no item that would re-decode plaintext |

6d.1 and 6d.2 are the correctness ones and go first — they are small, and until 6d.1 lands every
other test of this feature is testing a surface that silently discards its input. 6d.3 is the one
that removes the reported symptom. 6d.4 is the largest and the only one with real design risk in it,
which is why it is not first despite being the most visible.

#### What this still does not do

- **No property can be added or deleted structurally.** The raw view is the escape hatch, and it
  works at the byte level with no help from the codec. A structural insert needs the parser to record
  what it currently discards (§6.3), which is a `codec/` change and a separate piece of work.
- **The raw view can produce bytes the server will misparse**, and will say so rather than prevent
  it. That is intended, but it means a raw edit can put a live Mode A session into a state nothing
  can recover — the same standing risk as §6.9's first line, with a sharper edge on it.
- **None of this touches the application layer** (§6.1). A perfectly edited message is still subject
  to whether the runtime still has the objects it names.

---

### 6.11 The first live-target send, and what it found

**2026-08-14.** An edited message was sent to the real Forms server in Mode A. The server answered:

```
ifError:0/FRM-93618: fatal error reading data from runtime process
```

This is the first time anything from this project has reached a live Forms runtime, and it moves the
whole of §6 from "verified in simulation" to "tried, and rejected".

> **The first suspect below has since been fixed** (2026-08-14, *poison the ledger*). That does not
> mean it was the cause — it was worth fixing whether or not it was, because it was the one place in
> the design that guessed. The bisection is still unrun, and step 2 is still the decisive experiment.

#### Reading the error

FRM-93618 is the Forms **servlet** reporting that it could not read a coherent message from the
`frmweb` runtime process. That is the signature of the runtime being handed bytes it cannot parse —
not of a well-formed message being logically refused. The distinction matters because it points at a
different layer of §6.1: a stale handler id produces a Forms-level error inside the application, and
garbage produces this. So the **cryptographic** layer is the place to look, not the application one.

#### Ruled out

**A length-changing edit does not leave a stale length field behind.** FHT is terminator-delimited
and self-describing — messages end at `0xF0`, properties carry their own type markers, and there is
no packet-level or message-level byte count anywhere in `FhtParser`. So splicing a longer string
cannot desynchronise the structure the way it would in a length-prefixed format. This was the first
thing worth checking and it is not the cause.

#### The leading suspect: a silent ledger desync

`FormsHttpHandler.trackForwarded` ignores any Forms message that did not come from the Proxy:

```java
if (!isFromProxy(message)) return;
```

A **non-draft Repeater tab holding captured ciphertext is a valid Forms message.** It passes
detection, carries no markers so `RepeaterSendInterceptor` leaves it alone, and reaches the server
unchanged — where the server's request cipher consumes its bytes. But `api.proxy().history()` is
proxy-only, so the send is never recorded. Every subsequent tail measurement for that session is then
short by exactly that body's length, permanently.

This is very easy to do by accident. Sending a captured message to Repeater and pressing Send is the
first thing anyone tries, and it is what the §6.10 conversion bar exists to make unnecessary — but
until that lands, the ciphertext tab is what a user gets, and pressing Send on it quietly destroys
the session's offset.

> **This is an inconsistency in the design, not just an unlucky user.** §6.9 records that such an
> offset is "deliberately not modelled". Everywhere else — a gap in history, an unknown position, a
> missing key — the design **refuses and says why**. Here alone it carries on with a number it has no
> right to, and the failure surfaces as a dead application session rather than as a message. Not
> modelling something is a reason to refuse, not a licence to guess.

**The fix: poison the ledger rather than ignore the traffic.** When Forms ciphertext for a session
leaves Burp from a non-proxy tool without being a draft, mark that session's stream position
*unknowable*. Mode A then refuses with a reason the user can act on, which is exactly the treatment a
history gap already gets (§6.4, Mode A, *Gaps*). It converts silent corruption into a refusal.

##### As built (2026-08-14)

`trackForwarded`'s early return became `noteUntrackedSend`, and the refusal rides the type system so
it cannot be forgotten at a call site:

```
StreamPositionUnknownException        abstract; "nothing can be encrypted for this session"
  ├── StreamGapException              history has a hole      — isRecoverable() == true
  └── StreamDesyncException           the server is ahead     — isRecoverable() == false
```

`StreamRegistry.open` now declares the parent, so every caller that previously handled only a gap had
to be widened to handle both — the compiler found them rather than a reviewer. The distinction the
subclasses carry is the *remedy*: a gap might be closed by capturing the missing pragma, a desync
never can be, because the bytes the server consumed are gone.

Five decisions in it that are not obvious from the diff:

- **The desync is checked before the live ledger, not after.** An already-open ledger is exactly as
  wrong as a freshly measured one once untracked bytes have reached the server, and it is the more
  dangerous of the two because it looks authoritative. Marking a session also drops any open ledger.
- **Responses and `NULLPOST`s do not spend a session.** Only a request advances the server's request
  cipher, and a `NULLPOST` is written to the socket without being encrypted at all (§1), so resending
  one moves nothing. Getting either wrong would make the refusal fire on traffic that costs nothing.
- **Drafts never reach the check.** `RepeaterSendInterceptor` runs first in
  `handleHttpRequestToBeSent` and returns, which *is* the distinction being drawn: a draft is
  encrypted at send time and accounted for in the ledger; a plain resend is forwarded unchanged and
  is not.
- **Only the first mark per session writes.** `markDesynced` returns whether the mark was news, so an
  Intruder run over a spent session logs once and writes to the project file once, rather than once
  per payload.
- **An unreadable marker is not treated as absent**, unlike every other read in `PersistedKeyStore`.
  A record that exists but will not parse still proves something was marked, and the safe reading of
  "this session was broken, but I cannot recall why" is to keep refusing. Elsewhere a corrupt entry
  costs a rebuild; here it would cost a live application session.

**What it does not do.** It does not adjust the offset by the bytes it saw leave, and deliberately
so: the correct offset is *not knowable* rather than merely unrecorded. Traffic can reach the server
from a second Burp instance, from curl, or from the application with the proxy bypassed, and none of
that is visible here. Adjusting by the part we happened to observe would turn a detectable failure
into an undetectable one.

Covered by `StreamDesyncTest` (8 tests): the refusal, its survival across a registry rebuild, the
mark-once contract, that other sessions are unaffected, and that `forget` clears it.

#### The actual cause (2026-08-18): the proxy never re-encrypted forwarded traffic

Found by reading the send path rather than by running the bisection, and it is not any of the three
suspects below — it is a fourth, and it was in plain sight.

`FormsHttpHandler.trackForwarded` called `SessionStreams.observeUnmodified`, which advances both legs
of a direction and returns nothing; the handler then forwarded the message unchanged. That is correct
only while the two legs agree. **A Mode A send is precisely the thing that makes them disagree.** So
the moment an injection landed, the real client's next message was passed to the server still
encrypted at the client's offset, `n` bytes behind where the server's request cipher now sat — and
`FRM-93618` is the servlet saying it could not read a coherent message from `frmweb`. The response
direction has the mirror of it: the server's next reply was `m` bytes ahead of the client.

Because FRM-93618 is fatal, the runtime dies at that point and *every* later send into the session
answers the same way, however perfectly encrypted. That is the shape of a session that appears to
reject an edited message and then rejects everything.

`CLIENT_REQUEST` and `CLIENT_RESPONSE` were, until this was fixed, never used to transform a single
byte anywhere in `src/main/` — they appeared only in counter arithmetic and in the persistence key
map. The four-stream model was implemented as bookkeeping and never as a proxy.

The fix is `SessionStreams.forward` and is described in §6.2. Two notes on what it does not do:

- **It does not exonerate the first send.** It explains the second onwards with certainty. Whether
  the *first* injection was itself well-formed is still what step 2 of the bisection below measures,
  and that step is still unrun. Fixing a bug is not evidence it was the only one — the same caution
  the desync fix above earned.
- **It raises the stakes on Mode A rather than lowering them.** A diverged session now depends on the
  extension staying loaded and seeing every message in order, for the rest of that session's life.
  See §6.9.

#### The second suspect: the live client racing the send

The ledger is measured from proxy history at the instant of the first send. Any message the real
client sends between that measurement and our packet arriving moves the server's request cipher, and
Forms clients poll. §5 keeps an *already open* ledger level with live traffic, but that only starts
once the ledger exists — the measurement that creates it is a snapshot, and nothing holds the session
still while the request is in flight.

Unlike the first suspect this one is transient and avoidable (leave the application idle), but it is
not *fixable* in general: there is no way to reserve a keystream position against a client that is
still talking. It is a genuine limit of Mode A and belongs in §6.9.

#### The third suspect: the edit itself

Least likely given the error's shape, but not excluded. The specific thing to distrust is the
**back-reference → literal promotion** (§6.3), which the design already flags as an inference from
the client's parser rather than something observed on the wire.

Worth stating plainly, because it is easy to over-read what the identity gate proves: **it verifies
that re-encoding an *unchanged* value reproduces the original bytes. It says nothing about whether a
*changed* one is well-formed.** That is the correct scope for it — it is a check on the encoder, not
on the protocol — but it means a passing gate is not evidence that an edited message is acceptable.

#### Step 2, run (2026-08-18): the request was accepted

An **unedited** Mode A draft was sent to the live target on a session the forwarding fix above was
loaded for. The server answered with a normal encrypted FHT response — **not** `FRM-93618`.

That is the result the whole of §6 was waiting for. It retires every cryptographic and transport
hypothesis for the request direction at once: the tail measured from history, the keystream offset,
the `Pragma` rewrite and the rotating-cookie refresh are all correct against a real Forms server.
Rows *Cryptographic* and *Transport* of the §6.1 table are, for an appended message, confirmed.

The reply decoded to noise, and that turned out to be a separate and narrower problem — the response
leg, not the request leg.

##### Why the response tail is systematically short

Proxy history is asymmetric about traffic in flight, and the Forms client makes that asymmetry
permanent rather than occasional. The client **long-polls**: the capture shows requests held open for
28 seconds. So at almost any instant Burp has recorded a request whose response has not yet come
back, and `SessionTail` measures:

- the **request** leg correctly — the server really has consumed those bytes, which is why the send
  is accepted;
- the **response** leg short by exactly the outstanding response's length.

Answering an injected message is precisely what makes the runtime flush its pending output down the
waiting poll. The server emits that response first, advancing its response cipher, and only then
answers us — so the reply arrives one whole response further on than the ledger believes.

**The length of a response that has not arrived is not knowable when the message is sent.** No amount
of care at send time recovers it; this is structural, not a race, and not something a snapshot taken
more carefully would fix.

##### Solving for the offset, which is not the same as guessing one

`ReplyOffsetRecovery` searches forward from the ledger's position for the offset at which the body
parses as FHT. The distinction from the guessed offset this section spent so long condemning is that
the answer is **verified before it is believed**, by the same oracle §8 uses on a candidate key:
every property id must be in the table, and the parse must reach the terminator. A guess is an answer
nothing can check. This one is checked, refuses on a tie, refuses on a body too short to carry
evidence, and searches forward only — the ledger can be behind the server but never ahead of it.

The gap it reports *is* the missing response's length, so the ledger is resynchronised and the error
does not accumulate into the next send.

The threshold is set by the number of chances a wrong answer gets, not by how unlikely one is in
isolation: at three properties with all ids known, pure noise found a "clean" offset 133,417 bytes
away, because a quarter of a million candidates is a lot of chances. Demanding a complete parse
closed it, across eight randomised full-window trials.

> **A consequence of the incomplete id table, predicted rather than observed** (2026-08-19). This
> search demands that *every* property id be known, and the capture has since shown that a real
> message can carry one the table has no name for (§6.12). A reply containing such an id therefore
> cannot be verified here at all, and the recovery refuses rather than resynchronising. That is the
> safe direction and the gate is deliberately not relaxed — 250,000 candidates is a great many
> chances for a wrong answer — but it means the remedy for such a reply is to *name the id*, not to
> lower the bar.

#### The bisection that settles it

Each step changes exactly one variable, and the first failure names the cause. FRM-93618 is fatal, so
the runtime process is gone and every run starts from a restarted application.

| | Step | If it fails here |
| --- | --- | --- |
| **0** | Fresh session; let the app settle, then leave it idle | — |
| **1** | Close every plain ciphertext Repeater tab for the session; send none | — |
| **2** | Newest captured pragma, **unedited**, tail mode | Cryptographic or transport. The edit is innocent; suspects 1 and 2 — **run 2026-08-18: PASSED, the server accepted it.** See above |
| **3** | Same message, edit an **integer** (no length change) | The writer's value encoding |
| **4** | Same message, edit a **string to the same byte length** | String encoding or the back-reference promotion |
| **5** | Same message, **length-changing** string edit | The four-stream ledger's length handling, or the runtime rejecting a resized message — **run 2026-08-19 through Mode D: PASSED.** See below |

Step 2 was the decisive one, and it separated every crypto and transport hypothesis from every edit
hypothesis with a single send, clearing the former.

#### Step 5, run through Mode D (2026-08-19): the edit survived, and so did the session

A text item's value was edited in the Intercept tab from four characters to seven — the client's own
message 34 bytes, 37 forwarded — and:

- **the server accepted it and the application acted on the new value**, which is the first time
  anything in this project has reached §6.1's *application* row and been answered properly;
- **the client's session carried on**: the next three pragmas went by as ordinary encrypted traffic
  with ordinary responses.

That second half is the one worth dwelling on. A length-changing edit **diverges** the session by
construction — the client's request leg advanced by 34 and the server's by 37 — so from that moment
every message had to be decrypted on one leg and re-encrypted on the other by
`SessionStreams.forward`. Three real messages later, both parties were still reading each other. The
half of §6.2 that only ever ran in tests, and whose absence *was* `FRM-93618`, now has a live target
behind it.

Steps 3 and 4 remain formally unrun, and they are the easier two: an integer edit and a same-length
string edit disturb strictly less than a length change, which moves the ledger as well as the bytes.

#### What the same run showed about the *content* of an edit

Two edits, one ignored and one obeyed, differing in exactly one thing — a natural experiment:

| | text | caret / selection | result |
| --- | --- | --- | --- |
| earlier edit | 11 characters → 7 | left at 11, **past the end** | reached the server, application ignored it |
| this edit | 4 characters → 7 | at 4, still inside the text | applied |

That is what §6.3's *A string is not always the only thing that describes itself* is about, and it is
why `TextIndexEdits` exists. **The clamp itself is not yet confirmed against the target**: the edit
that worked had an in-range caret already, so nothing needed clamping. What is confirmed is the
failure mode it removes.

The extension's own output line — `sending N plaintext bytes as pragma P … keystream offset O` —
compared against the pragma number of the client's last real message, shows directly whether the
offset was stale.

#### What this does not yet tell us

Nothing about §6.7's five open questions. A rejected message at the cryptographic layer says nothing
about whether the runtime would accept a correctly-encrypted appended one, which is still the
question Mode A rests on and still needs an answer from the target.

---

### 6.12 Mode D — editing in flight, from the Proxy Intercept tab

> **Status: built** (2026-08-18), 6h.0–6h.4, **repaired 2026-08-19**. 266 tests. The goal: intercept
> a Forms request in Burp's **Intercept** tab, edit it in the Oracle Forms tab, press **Forward**, and
> have the server act on the edited message and answer normally — with the client's session carrying
> on afterwards.
>
> **Unverified against a live target.** 6h.5 — bisection steps 3, 4 and 5 — is the remaining work,
> and the two UI assumptions at the end of this section are still assumptions.
>
> Building it changed the design in three ways, all recorded below where they belong: the dispatch
> order in the handler turned out to be a safety property rather than a preference; the ledger is
> re-measured from fresh history on first open; and the "at most one request in flight" assumption
> is now **enforced** rather than merely documented.
>
> **Using it found a fourth, and it is the one this section was most wrong about:** the tail is not
> where an in-flight edit belongs, because Burp puts a held request into proxy history before it is
> sent. See *The message being held is already in history*, below.

#### The observation that makes this cheap

This is not a new mechanism. It is **§6.2's table row that has never once been exercised**:

| Event | `clientRequest` | `serverRequest` | `serverResponse` | `clientResponse` |
| --- | --- | --- | --- | --- |
| Proxied request `P`, edited to `P′` | +len(P) | +len(P′) | — | — |

The four-stream ledger was designed for exactly this and then built for the Repeater case first,
because §6.2 recognised that an injection is the same problem with the length going 0 → n. Mode D is
the original problem, at its original length. Everything downstream of the edit already exists and is
already tested:

- **Divergence** is created the same way and persisted the same way (`StreamRegistry.checkpoint`).
- **Every subsequent client message** is carried across the divergence by `SessionStreams.forward`,
  which is what `DivergedForwardingTest` covers.
- **The response leg needs nothing at all.** A request-length edit moves only the two request legs,
  so `serverResponse` and `clientResponse` stay equal, and `forward` keeps taking its undiverged path
  for every response — unchanged bytes, both counters advanced. The reply to an edited request is
  therefore readable by the client with no intervention and readable by us at the ledger's own
  position, with `ReplyOffsetRecovery` never involved.

So "the server gives a response back" requires no new work: it is already the cheap path.

A consequence worth stating early: **a same-length edit diverges nothing.** The two legs stay equal
and all later traffic keeps forwarding unchanged. Only a length change creates the divergence, and
that maps exactly onto the difference between bisection steps 3–4 and step 5 (§6.11).

#### Why this is the best case for the application layer

§6.1's third row — whether the Forms runtime accepts the message — is the one nobody can guarantee,
and Mode D is the most favourable position it will ever be in:

| | Mode A (tail) | Mode D (intercept) |
| --- | --- | --- |
| Sequence position | appended after the capture | **in sequence, by construction** |
| Runtime state | whatever it has moved to since | exactly what the client believes it is |
| Handler ids | may have been destroyed | the ones the client just used |
| Races a live client | yes (§6.9) | no — the client is blocked on this request |

Mode A asks the runtime to accept a message it was not expecting. Mode D changes a message it *is*
expecting. That is a different question, and a much easier one.

#### How the two modes differ on the wire

| | Mode A — tail | Mode C — offset | **Mode D — intercept** |
| --- | --- | --- | --- |
| Keystream offset | measured tail | the captured pragma's offset | the ledger's live `serverRequest` |
| `Pragma` header | rewritten to tail + 1 | kept | **kept — it is the client's own** |
| Cookies | `JSESSIONID_FORMS` refreshed | as captured | **untouched — the client's own live header** |
| `clientRequest` leg | untouched | untouched | **advanced by the original length** |
| Creates divergence | always (0 → n) | never | only on a length change (n → m) |
| Needs a tail measurement | every send | to pragma − 1 | only to open the ledger the first time |

Rewriting the `Pragma` or the cookies here would be actively wrong. In Mode A the message is ours and
the sequence number has to be invented; in Mode D the message is the client's, and its number and its
cookies are already the ones the session is using. Touching them would desynchronise the client's own
sequence against the server.

#### The dispatch order is a safety property

> **Found while building (2026-08-18), and it is the sharpest edge in this feature.**

A Mode D draft must be dispatched **before** `RepeaterSendInterceptor`, not after. The interceptor
sees the markers, correctly judges that a marker on *proxied* traffic was set by the client, and
strips them and forwards the body — which is right for every other mode and catastrophic for this
one, because a Mode D body is FHT **plaintext**. The first working version had it second, and would
have put decoded traffic on the wire.

The general rule, which is worth stating because it is not obvious from §6.5: **whoever handles a
marked request must be the one that owns its body.** The trust rule and the body format have to be
decided together, and Mode D is the first mode where they disagree.

So the routing decision is one function with one invariant — *a request carrying intercept markers is
never left to another path*. Every outcome is an encrypt or a drop; there is no fall-through. That
covers three cases that cannot be told apart from outside and all want the same answer: the extension
was reloaded since the conversion so the token no longer exists, Burp called the handler twice and it
was already spent, or the application under test invented the markers. Only the last is an attack,
but forwarding is unsafe in the first two and pointless in the third.

#### The offset, and why displaying must not move it

Two operations, at two different moments:

```
  display   plaintext = streams.cipherAt(CLIENT_REQUEST).applied(ciphertext)   ledger UNTOUCHED
  forward   streams.advance(CLIENT_REQUEST, len(P))                            ledger committed
            ciphertext′ = streams.apply(SERVER_REQUEST, plaintext′)
```

**Display must use a detached cipher**, which is precisely what `SessionStreams.cipherAt` was built
for — "a detached cipher at a leg's current position, for an encryption that may not happen". Burp
calls `setRequestResponse` whenever the tab is shown, not only when the user intends to edit, so a
display that advanced the ledger would double-advance on a second look at the same message and would
advance for a message the user goes on to drop. The tab must be free to render as often as Burp
likes.

The forward step needs len(P), the **original** ciphertext length, which the editor knows and the
handler does not — by then it is holding the edited body. It travels in a marker (below).

#### A self-verifying offset, which Mode A never had

The intercept path can check its own offset before it lets anybody edit anything, and this is the
strongest guarantee in the whole of §6.

We decrypt the intercepted message at the offset we believe. If that offset is right the plaintext is
well-formed FHT with property ids drawn from the table; if it is wrong it is uniform noise.
`KeyValidation.signalsOf` already scores exactly this, and `RepeaterSendInterceptor.readsAsFht`
already uses it for the same question on a reply. So:

> **The tab offers editing only when the message it just decoded reads as FHT.** Otherwise it stays
> read-only and says why.

That converts the entire "wrong keystream offset" failure class — the one that produced `FRM-93618`
and cost a live session — from something the server discovers into something the tab refuses. Mode A
has no equivalent: its offset is only ever tested by the server's reaction, after the bytes have
gone. Here the evidence is in hand before the user is offered a cell to type in.

#### Trust: markers from the Proxy, and the capability token

Rule 1 of §6.5 says draft markers are honoured **only** from Repeater, Intruder and Extensions, and
never from the Proxy, because a marker on proxied traffic was put there by the client and the client
is the application under test (criterion 3). Mode D needs a marked request to arrive *from the
Proxy*, which is exactly what that rule forbids.

**Do not relax the rule.** Bind the marker to a capability token instead:

```
X-OracleForms-Session:  <jsessionid>
X-OracleForms-Send:     intercept
X-OracleForms-Origin:   <the client's own pragma>
X-OracleForms-Original: <length in bytes of the ciphertext the client sent>
X-OracleForms-Token:    <128 random bits, minted per edit>
```

The handler honours a Proxy-originated marker set **only** when the token is present and matches one
the extension minted, and **consumes it on use**. The token is added by the editor and stripped
before the request leaves Burp, so the client never observes one; it is single-use, so a leaked one
cannot be replayed. Rule 1 therefore stands unchanged for markers alone — the token is what makes the
exception safe, and it is unforgeable rather than merely unlikely.

Worth being concrete about what a forged marker would otherwise buy, because it is not "nothing": the
handler would treat the client's own ciphertext as plaintext and encrypt it a second time, sending
the server garbage, while diverging the ledger by a length the client chose. It gains an attacker no
capability against the server — the client can already send whatever it likes to its own server — but
it corrupts the tester's view of the session and steers a crypto operation from attacker-controlled
input, which is what criterion 3 exists to prevent.

*Alternative considered:* correlate on `messageId()` instead, recording the edit in an in-process map
keyed by the id. Rejected as the primary mechanism because the API documents `InterceptedRequest`
and `HttpRequestToBeSent` ids only as unique per request/response pair, and does not promise the two
are the same number for one message. The token needs no such promise.

#### Failing closed, and why it is `drop`

`ProxyRequestToBeSentAction` offers only `continueWith` and `drop` — **there is no `spoof` on the
proxy path**, so a refusal cannot be explained to the client the way §6.5 explains one to the user in
Repeater's response pane. Three options, and none of them is pleasant:

| | Result |
| --- | --- |
| Forward the original ciphertext | session survives, the edit is silently discarded |
| **`drop`** | **nothing is sent; the client sees a connection error and the session most likely dies** |
| Spoof a 599 to the client | the Forms client receives `text/plain` it cannot parse; the session dies anyway |

**Chosen: `drop`.** It is the same instinct as everywhere else in the send path — a message that
cannot be encrypted correctly does not go — and it is the only one of the three that never lets a
wrong outcome look like a right one. The cost is stated plainly rather than hedged: **a dropped
intercept edit will probably end the session and need the application restarted.**

That cost is what the pre-flight check exists to make rare. By the time Forward is pressed, the key,
the ledger, and the offset have all been checked and the decode has been shown to read as FHT. The
only failure left is a splice the writer refuses, and the property table already refuses those
per-cell at type time (§6.10 B). A drop should be close to unreachable in practice; it is there so
that when it is reached, nothing worse happens.

`FormsHttpHandler` already drops a draft rather than forwarding it after an internal error. Mode D
inherits that path unchanged — with the difference that it is now the *intended* behaviour rather
than a backstop.

#### Opening the ledger before the first edit

An undiverged session has no materialised ledger: `StreamRegistry.forProxiedMessage` returns empty
and the handler forwards unchanged, which is correct. The first intercept edit is what creates the
divergence, so the ledger has to be opened at that point by `StreamRegistry.open`, which measures the
tail from proxy history and refuses on a gap or a desync. Two consequences:

- **Open it at display time, on the decode executor** — never on the proxy thread at forward time.
  Opening walks the session's history and may run the cipher over every byte of it. By the time
  Forward is pressed it is a cache hit, and a refusal has already been shown in the tab instead of
  being discovered with the client blocked.
- **The tail measured at display time is still right at forward time**, because the client is blocked
  on this very request and cannot advance its own request cipher while it waits.

That second point is where the long-poll asymmetry of §6.11 **does not** bite, and it is worth
saying why: that asymmetry is a property of the *response* leg — history holds a request whose
response has not come back — and Mode D only touches the request legs. The outstanding response moves
neither of them.

> **That assumption is now enforced rather than documented** (built 2026-08-18). It rested on a Forms
> client having at most one request in flight per session; if it can have two — a heartbeat alongside
> a poll, say — a second message forwarded while the first is being edited would advance the client's
> leg past the offset this edit was decoded against.
>
> So the decoded-at offset travels in `X-OracleForms-Position` and is **checked again at Forward**.
> If the ledger has moved, the edit is dropped and says so. An assumption that costs a comparison to
> verify should not be left as an assumption — and unlike the pre-flight FHT check, which runs before
> the edit, this one covers the window *during* it.

> **A second thing the build changed: the ledger is measured from fresh history.** A session's
> history index is cached, and on a live session it goes stale by one message for every message the
> client sends — so a tail measured from an index built twenty messages ago puts the ledger twenty
> messages behind. The FHT check would catch it, but as a baffling refusal rather than a working
> edit. The index is therefore refreshed on the **first** open for a session, and only then: once the
> ledger exists it is advanced by the forwarding path and history is not consulted again.

#### The message being held is already in history

> **Found on the first live use of Mode D** (2026-08-19), and the pre-flight check above is the only
> reason it was a refusal rather than another `FRM-93618`.

Everything above says "open the ledger by measuring the tail", and the tail is wrong here, for a
reason nothing in this design anticipated:

> **Burp records a request in the proxy history as soon as it *intercepts* it — not when it is
> forwarded.**

So while a request sits in the Intercept tab it is already in the capture, indistinguishable from one
the server has read. `SessionTail.measure` means "what the server's cipher has consumed" and it
summed in the very message being held, putting the ledger one whole message further along the
keystream than the client's cipher. The decode is then uniform noise, `KeyValidation.signalsOf` says
so, and the tab refuses.

Two consequences make it worse than a one-message error.

- **It is inherited.** Forwarding the held message advances the ledger over bytes the tail had
  already counted, so *every* later position in that session carries the same offset — including the
  ones Mode A would use.
- **A message too small to judge slips through it.** A steady-state Forms request is 8 to 12 bytes,
  below the bar at which a decode can be judged at all, so it comes back `UNVERIFIABLE` and editing
  is offered — at an offset now known to be wrong. That happened: an 8-byte pragma was edited and
  sent to the live server 283 bytes into the wrong part of the keystream. It survived only because
  RC4 preserves length, so the server's cipher stayed aligned for every later message and only that
  one message's content was noise.

**The measurement Mode D needs is not the tail.** It is `SessionTail.before(source, pragma)` — the
position the ciphers stood at *immediately before* this message — and it is exact rather than
cautious: the message at that pragma is the one being held, so by construction neither it nor
anything after it has reached the server. It also leaves `nextPragma` equal to the number the message
about to go out actually carries, where the tail claimed the one after it.

**And the ledger, once open, is checked against the traffic.** A ledger is an accumulation — one
measurement plus every message since — and the only way to check an accumulation is against something
measured independently. When a decode does not verify, `InterceptEditService.reconcile` measures the
position from captured traffic, decrypts there, and adopts it **only if the result reads as FHT**.
That is `ReplyOffsetRecovery`'s rule (§6.11) applied to the request leg, with no search needed:
there are two candidates and the message in hand decides between them. It is what repairs a session
already poisoned — by this bug, or by a Mode A send made while a request was held.

**When the two disagree and the message cannot settle it, editing is refused.** Both offsets are
named and the request can still be forwarded unchanged. Offering an edit at a disputed, unverifiable
offset is the thing that cost the pragma above, and §6.11's rule covers it exactly: not modelling
something is a reason to refuse, not a licence to guess.

`reconcile` stands down for a session that has **diverged**. History has no record of what this
extension injected, so a measurement of it is wrong by precisely the amount that matters; the
persisted counters are the only record there is, and a measurement that cannot see that traffic
cannot correct it.

##### The check must not require the id table to be complete

The pre-flight check asks "do these bytes read as FHT?", and until 2026-08-19 it answered by
requiring 90% of the property ids to be in the 466-entry table ported from the reference. **That is
requiring the table to be complete, and it is not.** An ordinary text-item update from the live
target carries the item's own value under **id 99**, which has no name here; with `SELECTION`,
`CURSOR_POSITION` and two `FOCUS` properties around it, a perfectly decoded message scores four out
of five — and would have been refused for a gap in someone else's research.

`KeyValidation.readsAsFht` now takes the structural signal as well, and that one owes the table
nothing: a parse that runs from the first byte to a terminator, over at least four properties, while
scoring ≥ 0.5 on ids. The bar sits between the two measured populations rather than at the top of one
— a wrong key or offset scores 16–24%, and the worst correct decode seen on the capture scores 80%.
The two signals are required together rather than either alone, because noise that stumbles into a
clean parse brings almost no recognisable ids with it.

Both callers — this check and the Repeater reply check — share the one method, so they cannot drift
apart again. `ReplyOffsetRecovery`'s gate is deliberately *not* relaxed: it searches a quarter of a
million candidate offsets, and a wrong answer there gets that many chances to look right.

#### The editing surface

The tab carries **plaintext**, as in §6.5, and offers both surfaces from §6.10 C — the identity-gated
property table and an unrestricted raw hex/text view over the same buffer, with one live surface at a
time and a commit on switch. Interception is where the raw view earns most: the interesting bytes in
a protocol this incompletely understood are disproportionately the ones the codec cannot yet name,
and a tester holding a live request wants at them.

The raw view **warns and does not block**, unchanged from §6.10 — but the bound on the damage is
better here than that section could claim, and it is worth being precise about why. The ledger counts
**lengths, not meanings**. A malformed edit costs the Forms runtime; it does not cost the keystream.
Both sides stay in step on bytes consumed whatever the bytes say, so a raw edit that the server
cannot parse leaves a session that is cryptographically intact and application-level broken — which
is recoverable by restarting the application, not by anything worse.

#### What must be confirmed before building 6h.3

Two UI assumptions carry the whole feature, and both are cheap to settle by loading the extension:

1. **Burp shows extension-provided message editors in the Intercept tab at all.** If it does not, the
   feature needs a different surface entirely and this design is the wrong one.
2. **`EditorCreationContext` reports `editorMode() == DEFAULT` and `toolSource()` naming the Proxy
   for that tab.** `toolSource()` is confirmed to exist on the interface; what it returns there is
   not. Those two together are the discriminator that turns on the intercept path without touching
   proxy history, which must stay read-only.

Neither is a protocol question, so neither belongs in §6.7 — but 6h.3 is guesswork until both are
answered.

#### Build order

Reuses §6.10's work rather than duplicating it, so two of its steps become hard prerequisites.

| | Step | Gate |
| --- | --- | --- |
| **6h.0** | §6.10's **6d.1** (commit a cell on focus loss and on read) and **6d.4** (raw surface and the one-live-surface toggle) | Prerequisites, not optional. 6d.1 especially: **Forward** is a different button in a different panel, so focus loss without Enter is guaranteed rather than likely, and today's table would silently discard the edit |
| **6h.1** | `InterceptEditPlan` and the ledger arithmetic. No UI, no Burp | Over a synthetic session: client encrypts P at T, we decrypt at T, we encrypt P′ at T, both parties read every subsequent message. The mirror of `SessionStreamsTest` for the edit row |
| **6h.2** | The token, and the marker extension | A Proxy-originated marker with no token is ignored and stripped; with a valid token it is honoured; a token works exactly once; markers never reach the wire |
| **6h.3** | The editable intercept tab, with pre-flight verification | An intercepted ciphertext request decodes, verifies its own offset, and offers editing — and stays read-only with a stated reason when the key, the ledger or the FHT check says no |
| **6h.4** | The handler branch and the fail-closed drop | An edited intercepted request reaches the server re-encrypted at `serverRequest`, **and the real client's next message still decodes** — the second half is the gate, and it is the half 6e originally missed |
| **6h.5** | Live target: bisection steps 3, 4 and 5 through Mode D | An integer edit, a same-length string edit, then a length-changing one |

> **6h.0–6h.4 are built** (2026-08-18). `InterceptEditTest` covers the ledger arithmetic against a
> simulated client and server, including the gate above: after an edit of any length the server reads
> what the user wrote and the client's next message still decodes. `InterceptEditRoutingTest` pins
> the dispatch invariant, and `InterceptTokensTest` the capability. **6h.5 is unrun**, and so are the
> two UI assumptions below.

**6h.5 is the reason to build this now.** Bisection steps 3–5 (§6.11) are the whole remaining open
question of §6, and Mode D is a **cleaner instrument for them than Mode A is**: it removes the tail
measurement, the invented pragma, the refreshed cookie and the race with a live client, so a failure
cannot be blamed on any of them. If an edit fails through Mode D, it is the edit.

#### Honest limits, specific to Mode D

- **A refused edit ends the session.** `drop` is the deliberate choice above, and this is its price.
- **The application is blocked while the tab is open**, because that is what interception is. The
  decode still runs off the EDT, but a large Pragma 3 response will keep the client waiting.
- **A length-changing edit binds the session to the extension for the rest of its life**, exactly as
  §6.9 already records for an injection. A same-length edit does not, because nothing diverges.
- **Editing an intercepted *response* is not this feature.** It is step 6g, and it is harder for the
  reason §6.9 gives: a length change moves the fragment-group boundaries the server chose.
- **The application layer is still not guaranteed** (§6.1). Mode D gives it the best odds available,
  which is not the same as a promise.

---

## 7. Corrections to the reference

You said the repo is not fully correct. Here is what I found reading it, roughly by severity.

### Correctness

1. **Dead code in the FHT message header** (`oracle_forms_burp.py:476-478`). `class_id = i & 0x3FF`
   yields 0–1023, then `if class_id >= 2000: class_id += 3000` can never fire. Either the mask should
   be `0x0FFF` or bits 10–11 are flags. Treat class-id extraction as unverified and check it against
   real captures.
2. **The string dictionary is reset per packet** (`parse_fht`, line 488) while the RC4 stream is
   explicitly continuous per session. If Oracle scopes the dictionary to the session, every
   back-reference (`tm == 0x9000`) resolves to an empty string and values silently vanish. **Open
   question — test both scopings against a real capture.** Our `Checkpoint` carries the dictionary so
   either answer is cheap to adopt.
3. **Session id is only read from the URL** (`get_jsessionid`). Confirmed fatal: on our capture the
   id is Cookie-only, so the reference does nothing at all against this target. Read both, and pick
   `JSESSIONID` rather than the rotating `JSESSIONID_FORMS` — see §3.
4. **The string patcher is a naive byte scan** (`_patch_string_prop`) — see §6.
5. **Sensitive-value detection regex-parses its own formatted output** (`_flag_sensitive`,
   `_extract_str_props`). A value containing a quote or newline breaks it. Work from the model.
6. **Parse errors are swallowed** (`parse_fht`'s bare `except: pass`) and return partial results
   indistinguishable from complete ones. See `ParseOutcome` in §4.

### BApp acceptance criteria the reference would fail

7. **Decryption, parsing and formatting all run inside the proxy listener** — the hot path
   (criterion 5). We do key capture only there.
8. **No unload handling at all** (criterion 6). No `IExtensionStateListener`; nothing is released.
   We register an `ExtensionUnloadingHandler` that shuts down the executor and clears caches.
9. **Every cache grows without bound** (criterion 9): `_decoded`, `_plain`, `_pre_state`, `_live_msgs`
   and `_tab_refs` are never pruned, and `_live_msgs` retains intercepted-message objects forever.
   Note `_pre_state` holds a 256-entry list per pragma per direction. All our caches are bounded LRUs
   and hold no Burp objects.
10. **All exceptions swallowed silently** at the top of `processProxyMessage`. Log to the extension's
    error stream instead.

### Efficiency

11. **Reverse property-name lookup is a linear scan of a 470-entry dict**, executed per property per
    message per render (`next((k for k, v in ID_MAP.items() ...))`, four call sites). Precompute the
    reverse map once — `PropertyIds` does.

### Missing from the reference entirely

12. **No `NULLPOST` handling.** The word does not appear in the file. It applies RC4 to every
    request body unconditionally (`pt = rc4_apply(sess.req_st, body)`), so the cleartext sentinel
    both decrypts to noise *and* advances the request keystream by 8 bytes it never consumed,
    desynchronising the rest of the session. See §1.
13. **No response fragmentation handling.** `parse_fht` treats whatever arrives as a complete unit.
    A message split across several pragmas is therefore parsed as several broken ones, with no
    buffering and no continuation logic. See §1.

Both are the bugs that made pragmas 8 and 9 decode to garbage on our first live run, so anything
ported from the reference should be assumed to share them.

### Carried over unchanged

The property-id table (470+ entries), the `ACTION_MAP`, the sensitive-id set, the GDay/Mate magics,
the key derivation formula, the property type-marker decoding (`tm` nibble → int/str/bool/point/…),
and the separate-stream-per-direction insight are all worth porting as-is. That table is the bulk of
the reference's real value and is tedious to reproduce.

---

## 8. Protocol questions

### Resolved by the capture (2026-08-13)

Answered from the proxy history — see §1. True of this deployment; keep the seams that let a second
answer be plugged in.

- **Session id location.** Cookie only, never the URL, and it is `JSESSIONID` — not the rotating
  `JSESSIONID_FORMS`. (§3)
- **Key derivation scheme.** `GDay`/`Mate` with 8-byte handshake bodies both ways, so the 10g/11g
  formula applies. `INITIAL_ENCRYPTKEY` is not in play here.
- **Pragma gaps.** Numbering is contiguous; Pragma 2 is the only absence. A missing number means
  genuinely uncaptured traffic, so gap detection can be strict.

### Still open

These need plaintext, so they cannot be settled until the first session decodes:

- String dictionary scope: per packet or per session? (§7.2) Both are implemented behind
  `DictionaryScope`; the default is `PACKET`, matching the reference. Decode one session each way
  and look for back-references resolving to empty strings.
- Class-id masking in the message header. (§7.1) `FhtParser` masks with `0x0FFF` and `FhtMessage`
  retains `rawHeader`, so the question can be settled from a decoded capture without re-decoding.
- The 4-byte constant that opens every FHT message in both directions — its value is unknown, though
  its *existence* is established (§1).

  > **Correction (2026-08-13).** This was previously called "the blocker for validating key
  > derivation at all". **It is not, and never was.** The constant is a 32-bit oracle; the *parser*
  > is a far stronger one. A correct key turns a Pragma 3 body into well-formed FHT — valid headers,
  > property ids drawn from the 470-entry table, type markers from a small set, string lengths that
  > land inside the buffer — while a wrong key yields uniform random bytes. Asking "does it parse,
  > and are the ids real?" tests hundreds of bits of structure instead of 32, and needs nothing known
  > in advance. Measured separation on synthetic sessions: a correct key scores 100% known property
  > ids, a wrong one 16–24%, the same as random keys.
  >
  > `KeyValidation` implements this, with a control group of 32 random keys per session so the check
  > is comparative and cannot rubber-stamp: the derived key must beat every control outright. The
  > constant then falls out for free — it is the first four bytes of a message that parsed — so
  > settling this question is now a *result* of validation rather than a prerequisite for it.

  What actually blocks it is **byte-exact fixtures**, which is a tooling gap, not a protocol one: the
  Burp MCP renders bodies as escaped text and is lossy for binary, so the handshake randoms cannot be
  recovered through it. The Sessions tab's *Export validation fixtures…* action closes that gap, and
  `RealCaptureValidationTest` runs the check against the exported file (skipping when absent).

---

## 9. Build order

Each step is independently verifiable, and the risky protocol work is front-loaded behind a testable
seam.

**Getting fixture bytes out first.** Steps 1 and 2 need byte-exact captured bodies. The Burp MCP
tools render message bodies as escaped text, which is lossy for binary — usable for reading headers
and locating messages, not for recovering the 4-byte handshake randoms or ciphertext. Export the
fixture sessions from Burp itself (or dump them from inside the extension once step 3 exists) rather
than reconstructing them from MCP output.

1. `codec/` with the property tables, `Rc4Stream`, `FhtReader`/`FhtParser`, driven entirely by unit
   tests against captured fixture bytes. No Burp involvement.
2. `session/` — key derivation, `StreamReplayer`, checkpointing. Still no Burp; test with a recorded
   sequence of pragma bodies. **Run the §1 Pragma 3 self-test across all 22 captured sessions before
   trusting `GdayMateKeyDerivation`** — it validates the key and the stream start position without
   needing the parser, so it can and should come first.
3. Minimal Burp wiring — `FormsHttpHandler` capturing keys, `PersistedKeyStore`, and a read-only
   request editor tab. First point the thing is usable.
4. `SessionsTab` — key list, manual entry, retroactive history scan, export/import.
5. Response editor tab, sensitive-value highlighting and proxy-history annotation.
6. **Editing and Repeater.** `FhtWriter` with round-trip tests, the four-stream ledger, the
   marker-header contract, and the three send modes. This is no longer one step — it is seven, and
   they are broken out with their gates in **§6.8**. Read that rather than this line.
7. `RulesTab` auto-modification. Depends on step 6: a rule is an edit applied without interception,
   so it needs the same `FhtWriter` and the same outbound encoder.
