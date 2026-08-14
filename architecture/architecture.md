
# Architecture

Architecture for the Oracle Forms traffic decoder Burp extension (Java / Montoya API).

Reference implementation: [3erk1n/oracle-forms-decoder](https://github.com/3erk1n/oracle-forms-decoder) —
a single-file Jython extension (`oracle_forms_burp.py`, 1140 lines) against Burp's legacy API. We take
its protocol research, which is the valuable part, and rebuild the structure around it. Deviations are
listed in [Corrections to the reference](#corrections-to-the-reference).

> **Status: build order steps 1–5 and 6a–6e implemented** (2026-08-14). 185 unit and integration
> tests. The extension builds, loads, decodes read-only, persists keys — and now sends: a captured
> message can be drafted into Repeater as plaintext, edited property by property, and re-encrypted at
> the live session's keystream position on Send, with the real client's session surviving intact.
>
> The send path has been **verified against a loaded extension in a running Burp** (2026-08-14): key
> capture, offset and tail encryption, keystream continuity across sends, `Pragma` rewriting,
> `NULLPOST` pass-through, fail-closed refusal and the marker trust rule all check out against an
> independent RC4 implementation. What remains unverified is the *application* layer of §6.1 —
> nothing has been sent to a real Forms server.
>
> Remaining: **6f** (Mode B session bootstrap, gated on §6.7 question 1), **6g** (response editing)
> and **step 7** (rules tab). The protocol questions in §8 are still open pending byte-exact
> fixtures.

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

> **Note on identifiers.** Every hostname, `JSESSIONID`, server instance name and WebLogic route id
> in this document and in the test suite has been **replaced with a synthetic value of the same
> shape** before publication. The observations and the structural properties they demonstrate are
> real; the literal bytes are not, and cannot be correlated with any live system. Replacement is
> consistent throughout, so a value that appears in two places is still the same value.

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
        └── "streams"
              └── <jsessionid>          absent until this session's streams diverge (§6.2)
                    ├── clientRequestBytes  : Long
                    ├── serverRequestBytes  : Long
                    ├── serverResponseBytes : Long
                    ├── clientResponseBytes : Long
                    └── nextPragma          : Long
```

`extensionData()` is scoped to the Burp project, which is the right lifetime: keys belong to the
traffic captured in that project, and they survive both extension reload and Burp restart.

The `streams` collection is what lets an edited or injected session survive an extension reload. RC4
state is a pure function of the key and the bytes consumed, so four counters reconstruct all four
ciphers with one `skip` each; `nextPragma` rides along because after an injection the session has a
sequence number the capture has never seen. It is written **only once the four counters stop being
equal** — before the first length-changing edit or Repeater injection they are derivable from proxy
history, and writing them on every message would touch the project file for nothing. See §6.2.

> **Correction (2026-08-14, on building it).** These counters were originally drawn as a *child* of
> each session entry. They are a **sibling collection** instead, because `PersistedKeyStore.put`
> replaces a session's entry wholesale — anything nested inside would be destroyed silently every
> time a key was re-derived. Keeping them apart makes that impossible rather than merely avoided.

### Which cookie is the session id

The capture shows **two** session cookies, and picking the wrong one silently destroys the replay:

| Cookie | Behaviour | Use as session id? |
| --- | --- | --- |
| `JSESSIONID` | Constant for the life of the session | **Yes** |
| `JSESSIONID_FORMS` | Rotates mid-session via `Set-Cookie`, often every few messages | **No** |

Observed directly: one session held `JSESSIONID=X43xQtj1…` while `JSESSIONID_FORMS` moved from
`formsapp_rs1|anQtg` at Pragma 1 to `formsapp_rs1|anQ0T` by Pragma 65. Keying on `JSESSIONID_FORMS`
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

### 6.4 Three send modes

The extension cannot know which of these the user wants, and they have very different consequences,
so the mode is chosen explicitly — at "Send to Repeater" time, and changeable in the tab afterwards.

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
X-OracleForms-Session: <jsessionid>          which session's key and streams to use
X-OracleForms-Send:    tail | bootstrap | offset=<n>
X-OracleForms-Origin:  <captured pragma>     provenance, for display only
```

Handler rules, in order:

1. **Honour the markers only from Burp's own tools** — `toolSource().isFromTool(REPEATER, INTRUDER,
   EXTENSIONS)`. A marker on a proxied request was set by the client, and the client is the
   application under test; treat it as untrusted, strip it, and ignore it (criterion 3). The check
   sits behind the existing `lservlet` detection gate, so it adds nothing to the hot path for traffic
   that is not ours.
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
  StreamGapException.java         ▲ names the missing pragma, so a refusal is actionable
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
| **6d** | Editable request editor in Repeater, `FhtWriter`-backed | edit a property, see the plaintext change; markers survive the round trip | **done** — property table, editability and its refusal reason per row |
| **6e** | Mode A tail append, per-session serialisation, refuse-on-gap | a modified message is accepted by a live session *and* the real client keeps working afterwards | **done** in simulation — `RepeaterInjectionEndToEndTest`. Not yet run against a live target |
| **6f** | Mode B bootstrap and prefix replay | once experiment 1 in §6.7 has an answer | not built |
| **6g** | Response editing, client-facing response leg | last, because fragment groups (§1) only bite here | not built |

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
