
# Architecture

Architecture for the Oracle Forms traffic decoder Burp extension (Java / Montoya API).

Reference implementation: [3erk1n/oracle-forms-decoder](https://github.com/3erk1n/oracle-forms-decoder) —
a single-file Jython extension (`oracle_forms_burp.py`, 1140 lines) against Burp's legacy API. We take
its protocol research, which is the valuable part, and rebuild the structure around it. Deviations are
listed in [Corrections to the reference](#corrections-to-the-reference).

> **Status: build order steps 1–5 implemented** (2026-08-13). `codec/`, `session/` and the Burp
> wiring are in place with 73 unit and integration tests; the extension builds, loads, decodes
> read-only, and persists keys. Steps 6 (`FhtWriter` and editing) and 7 (rules tab) remain, and the
> protocol questions in §8 are still open pending byte-exact fixtures.

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
                    └── source     : String   ("derived" | "manual" | "imported")
```

`extensionData()` is scoped to the Burp project, which is the right lifetime: keys belong to the
traffic captured in that project, and they survive both extension reload and Burp restart.

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

  burp/                             the only package that touches Montoya
    persistence/PersistedKeyStore.java    SessionKeyStore over PersistedObject
    history/PragmaHistorySource.java      pulls a session's pragmas from proxy history, filtered
    handler/FormsHttpHandler.java         observes traffic; captures handshakes; live re-encrypt
    ui/
      FormsRequestEditorProvider.java  + FormsRequestEditor  (ExtensionProvidedHttpRequestEditor)
      FormsResponseEditorProvider.java + FormsResponseEditor
      SessionsTab.java                   the key store UI
      RulesTab.java                      auto-modification rules
```

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

**Failure is a first-class result.** `ParseOutcome` distinguishes a clean parse from one truncated at
a byte offset, and the tab renders partial results *plus* an explicit "parsing stopped at offset N"
line, falling back to a hex view. A malformed message from an untrusted target must never produce a
blank tab or a silent partial decode.

---

## 6. Editing and the length problem

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

So arbitrary-length edits work **for live proxied traffic**, as long as the extension stays in the
path and re-encrypts every subsequent message in that session. Two honest caveats: replaying a single
message out of sequence from Repeater still desyncs the real session (inherent, not fixable), and if
the extension is unloaded mid-session the streams are lost.

**Structural editing, not byte scanning.** The reference patches strings by scanning the plaintext for
a two-byte header pattern, which can match arbitrary bytes inside string contents or image data and
silently corrupt the message. Instead, `FhtParser` records the byte offset and length of every
property value it reads, so an edit is applied at a known-good offset — or, better, the packet is
re-serialized from the model via `FhtWriter`. Ship read-only decoding first; enable editing only once
`FhtWriter` round-trips captured samples byte for byte.

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
6. `FhtWriter` with round-trip tests, then editing and the four-stream model from §6.
7. `RulesTab` auto-modification.
