# Features

Feature list for the Oracle Forms traffic decoder. Design detail lives in
`architecture/architecture.md`; this file tracks *what* we build and where each item stands.

See `features/improvements.md` for a survey of the extension as built and a prioritised backlog of
what should change next — including the test-coverage gap that has now let two bugs through.

> **Status: build order steps 1–5 done** (2026-08-13), **6a–6e done** (2026-08-14). Numbers in
> brackets map to the build order in architecture §9; step 6's letters map to the sub-build-order in
> architecture §6.8.
>
> **Step 6a–6e built** (2026-08-14, repaired 2026-08-18). Sending a modified message from Repeater
> works: draft a captured message into Repeater as plaintext, edit it property by property, and it is
> re-encrypted at the live session's keystream position on Send — with the real client's session
> surviving, which needed the forwarding fix below to be true at all.
>
> **Mode D built 2026-08-18** (6h.0–6h.4, architecture §6.12), **repaired 2026-08-19**: a request
> held in the Intercept tab can be decoded, edited as properties or as raw bytes, and re-encrypted at
> the session's live keystream position on Forward. 266 tests. It has **not** been run against a live
> target — that is bisection steps 3–5, and it is now the whole open question of §6. Mode B (6f) and
> response editing (6g) remain.
>
> **The first live use of Mode D found a bug, and the tab's own pre-flight check is what caught it**
> (2026-08-19): **Burp records a request in proxy history when it intercepts it, not when it forwards
> it**, so measuring the session's tail counted the very message being held and the ledger sat one
> whole message too far along the keystream. Mode D now measures the position *before* the held
> pragma, and checks the ledger against the captured traffic — adopting a corrected offset only when
> the message decodes as FHT there, and refusing when the two disagree and the message is too small
> to say which is right. Architecture §6.12.
>
> **An edited message has now been accepted by the live target, and the application acted on it**
> (2026-08-19, bisection step 5 through Mode D): a text item's value was changed from four characters
> to seven while the proxy held the request, the server accepted the 37 bytes in place of the client's
> 34, and the client's session carried on for every message afterwards — with the two request legs
> **diverged**, so each of those messages had to be translated across the four-stream ledger. That is
> the application row of architecture §6.1 reached for the first time, and the live counterpart of
> `DivergedForwardingTest`. Steps 3 and 4 (integer, same-length string) disturb strictly less and
> remain formally unrun.
>
> **An appended message has now been accepted by the live target** (2026-08-18). An unedited Mode A
> draft drew a normal encrypted response instead of `FRM-93618`, which confirms the cryptographic and
> transport layers of architecture §6.1 for the request direction against a real server. Getting
> there took two fixes: the proxy never re-encrypted forwarded traffic after an injection (§6.2), and
> the reply arrives one whole response further on than proxy history can show, because the client
> long-polls (§6.11). **What is still unrun is whether an *edit* survives** — bisection steps 3–5.

Status key: `planned` · `in progress` · `done` · `blocked`

## Core decoding

| Feature | Status | Notes |
| --- | --- | --- |
| Detect Oracle Forms messages | done | `lservlet` path + numeric `Pragma` header + resolvable session id, cheapest check first. Session id = `JSESSIONID` cookie, not `JSESSIONID_FORMS` (rotates). The session-establishing GET is found by `ifcmd=getinfo`, since the applet client numbers it Pragma 1 and the launcher Pragma 0 |
| RC4 keystream engine | done | Continuous per session, separate stream per direction [1] |
| FHT binary parser | done | Records byte offsets per property, so edits are structural not byte-scanned [1] |
| Property id table (470+) | done | Ported from the reference, plus a prebuilt reverse map [1] |
| Decode requests | done | [3] |
| Decode responses | done | [5] |
| Explicit parse outcomes | done | Clean / truncated-at-offset / failed — never a silent partial decode [1] |
| Raw hex fallback | done | On any decode failure, with the reason stated [3] |
| `NULLPOST` handling | done | The cleartext keep-alive body contributes zero bytes to the request keystream, and is shown as "no payload" rather than a failed decode. Missing this desynchronised every request after one |
| Oversized response reassembly | done | Responses split across pragmas are rejoined before parsing, grouped by the `NULLPOST` sentinel rather than the 66000-byte fragment size. Parsing a fragment alone produced convincing garbage |

## Key session storage

The headline feature. Persisting keys is what makes previously captured traffic readable — but the
key alone is not enough, because the RC4 stream is continuous. See architecture §2.

| Feature | Status | Notes |
| --- | --- | --- |
| Derive keys from live Pragma 1 handshakes | done | The only work done on the proxy hot path [3] |
| Pragma 3 stream-symmetry check | done | Compares the two directions' *raw ciphertext* prefixes; needs no key. Validates that both streams share a key and start at pragma 3 offset 0 [2] |
| Structural key validation | done | `KeyValidation` decrypts pragma 3 with the derived key and checks it parses into real property ids, against a control group of 32 random keys so it cannot rubber-stamp. Replaces the "needs the opening constant" approach, which was never actually necessary (architecture §8). **The id table is not complete**, so "does this read as FHT?" no longer rests on it alone: the live capture's ordinary text-item update carries the item's value under id 99, which has no name here, and scored 0.8 against a 0.9 bar. A parse that runs end to end over at least four properties, scoring ≥ 0.5 on ids, now counts too — one method, shared by the in-flight pre-flight check and the reply check, so they cannot drift apart (2026-08-19) |
| Export validation fixtures | done | Sessions tab action dumping the byte-exact handshake and pragma 3 bodies. Closes the tooling gap that actually blocked validation — the MCP renders bodies as lossy escaped text |
| Validate derivation on real capture | in progress | `RealCaptureValidationTest` is written and proven to pass on a correct derivation and fail on a wrong one; it skips until a fixture file is exported from Burp [2] |
| Persist keys across reload and restart | done | `PersistedObject` under `extensionData()`, project-scoped [3] |
| On-demand stream replay | done | Replay preceding pragmas to reach the target; what actually makes stored keys useful [3] |
| Checkpoint cache | done | RC4 state + string dictionary every ~25 pragmas; turns O(n²) browsing into O(n) [3] |
| Gap detection | done | Report *which* pragma is missing rather than failing blankly [3] |
| Sessions tab | done | List known sessions, keys, pragma counts, last seen [4] |
| Manual key entry | done | Paste a 5-byte key for traffic captured elsewhere [4] |
| Retroactive history scan | done | Recover keys from Pragma 1s already in proxy history; on demand only, never at load [4] |
| Export / import key store | done | JSON, for moving between projects [4] |
| Forget session / clear all keys | done | Keys are session secrets in an unencrypted project file [4] |

## Editing and Repeater

**The goal: send a captured message to Repeater, change a value, press Send, and have the server
accept it.** Designed in architecture §6 and built as 6a–6e. Sub-steps below are lettered to match
the sub-build-order in architecture §6.8, and each was gated on the one before it.

The gate on all of it was `FhtWriter` reproducing captured bytes exactly. Re-encoding before that is
verified produces a message that is cryptographically perfect and structurally wrong, which the
server will decrypt cleanly and then misparse — the worst failure mode available. What ships checks
that per property, at runtime, before every edit.

| Feature | Status | Notes |
| --- | --- | --- |
| FHT re-encoder | done | `FhtWriter`, **splicing** rather than re-serializing: the parser is lossy, so only the edited property's byte range is rewritten and everything else is untouched by construction [6a] |
| Keeping a text item's caret inside its text | done | A Forms client sends a text item's value together with `SELECTION` and `CURSOR_POSITION`, which are indices into that very string. Change the text's length and they describe the old one — a message no client can send, and one the runtime is free to ignore, which is what an edit that reaches the server and changes nothing looks like (seen live 2026-08-19). `TextIndexEdits` pulls an index that now points past the end back to the end, as an extra edit through the same splice and identity gate. Narrow on purpose: an in-range caret is left alone, an explicitly edited one outranks the inference, two changed strings in one message adjust nothing, the raw surface is exempt, and every adjustment is named in the status line and the log. Architecture §6.3 |
| Round-trip verification tests | done | Re-encoding a property with its *unchanged* value must reproduce the original bytes. Enforced at runtime before every edit, not only in tests — an encoding we get subtly wrong becomes a refused edit with a reason, never a corrupted session [6a] |
| Four-stream ledger | done | Separate client-facing and server-facing ciphers per direction, so a length change or an injected message leaves both sides internally consistent. Persisted as four byte counters plus a sequence number, so it survives a reload [6b] |
| Translating forwarded traffic across the divergence | done | Once a session has diverged, every proxied message is decrypted on the leg facing its sender and re-encrypted on the leg facing its receiver. Until 2026-08-18 the ledger counted the bytes and forwarded them unchanged, which is right only while the two legs agree — and an injection is exactly what makes them disagree. That was the cause of `FRM-93618`. Undiverged sessions still take the counter-only path, so the hot path is unchanged for a session nobody has sent into [6b] |
| Marker-header contract | done | The Repeater tab carries FHT *plaintext* plus `X-OracleForms-*` headers; the HTTP handler encrypts at send time, when the correct offset is finally known, and strips the markers. Fails closed: a refused draft gets a spoofed explanatory response and never leaves Burp [6c] |
| Send decoded message to Repeater | done | Context menu on proxy history and message editors, one item per send mode [6c] |
| Editable request tab | done | A property table with per-row editability and the *reason* when a property is locked. Editable only where Burp's `EditorMode` is not `READ_ONLY`, so proxy history stays read-only for free [6d] |
| Send mode A — append to session tail | done | Encrypts at the live session's current position, rewrites `Pragma` and refreshes the rotating `JSESSIONID_FORMS` without discarding the rest of the user's Cookie header. Sends per session are serialised; a gap in history means refuse, never guess. **Turn interception off before appending**: Burp puts a held request into proxy history before it is forwarded, and history cannot tell one from a request merely waiting for its response, so a tail measured while one is held is that request's length too far along (architecture §6.9). Mode D is immune because it knows which message is held — it is the one being edited [6e] |
| Reply decryption for sent messages | done | A Repeater reply never enters proxy history, so replay cannot reach it. The interceptor decrypts it against the ledger and caches the plaintext by ciphertext hash for the response editor [6e] |
| Reply keystream offset recovery | done | The client long-polls, so proxy history holds an outstanding request whose response has not arrived, and the response tail is short by exactly that response's length — which is not knowable at send time. The reply is checked against the id table and, if it reads as noise, the true offset is *searched for and verified* rather than assumed: every id must be known and the parse must reach the terminator, it refuses on a tie, and it searches forward only. The gap it measures resynchronises the ledger. Runs on the decode executor, never the Burp response thread. **Until 2026-08-18 none of it was observable**: the rendered text is cached per (session, direction, pragma) and never expired, and nothing repainted an open editor, so the correction landed in a cache the UI would not read again — reopening the message re-served the stale decode. A superseding decode now invalidates its rendering and notifies open panes. A refusal also reports its nearest miss, since "nothing in the window" and "rejected over one unknown id" need opposite fixes. **Showing a reading and trusting it are separate decisions**: resynchronising the ledger keeps the strict gate (all ids known, parse reaches a terminator, no tie), while displaying uses the same ≥ 0.9 bar the interceptor already applies to decide a reply decoded correctly — a candidate with 4/4 ids known but no terminator was being withheld while a 2/9 reading stayed on screen, which is the system contradicting itself. An unverified decode is labelled as such with its offset and gap [6e] |
| Refuse after an untracked send | done | Ciphertext sent from Burp's own tools without the draft markers reaches the server but never enters proxy history, so no later measurement can see the bytes it consumed. The session is marked unrecoverable — durably, because the server's cipher stays ahead across a restart — and Mode A refuses with the reason instead of encrypting at a guessed offset. Same treatment a history gap already got; the two now share a supertype so the send path catches one thing (architecture §6.11) |
| Send mode C — fixed offset | done | Encrypts at the captured position, touching no ledger. Verified the strongest way available: an unedited draft re-encrypts to the captured ciphertext byte for byte [6c] |
| Send mode D — edit a request in flight (Intercept tab) | done | Intercept a Forms request, edit it in the Oracle Forms tab, and it is re-encrypted at the session's live position on Forward. **This is the four-stream ledger's own "proxied request edited to P′" row** — the one case it was designed for and never exercised — so it needs no new crypto: divergence, forwarding and the whole response leg already exist. It is also the only mode that can verify its own keystream offset *before* an edit is offered, by checking that what it decoded reads as FHT. Refuses by dropping, because the proxy path cannot explain a refusal to the client. Conversion is explicit — a held request gets an "Edit this request" button, because Burp shows a tab whenever it likes and "shown" cannot mean "intended". Trusted by a single-use capability, not by origin, so §6.5's rule that a Proxy-set marker is untrusted stands. Dispatched ahead of the Repeater interceptor, which would otherwise strip the markers and forward the plaintext. **Positioned before the held message, not at the session tail**: Burp records an intercepted request in proxy history before it is forwarded, so a tail measurement counts a message the server has never read — which is what the first live use ran into, and what the pre-flight check caught (2026-08-19). The ledger is also reconciled against the captured traffic when a decode does not verify, adopting a corrected offset only if the message reads as FHT there, and refusing rather than guessing when the message is too small to tell. Architecture §6.12. **Built 2026-08-18, repaired 2026-08-19, and confirmed against the live target on 2026-08-19**: a length-changing edit was accepted, the application acted on it, and the diverged session kept working [6h.0–6h.5] |
| Send mode B — bootstrap a fresh session | planned | The extension performs its own `getinfo` GET and `GDay`/`Mate` handshake, optionally replays a captured prefix under the new key, then sends. The repeatable mode, and the only one safe to run concurrently. Gated on architecture §6.7 question 1 [6f] |
| Editable response tab | planned | Last, because response fragment groups only bite here — a length change moves the boundaries the server chose [6g] |
| Auto-modification rules tab | planned | `PROPERTY = value`, applied in transit without interception. Needs the same writer and outbound encoder as the rest of step 6 [7] |

### What the extension cannot guarantee

Three layers have to hold for a send to be accepted (architecture §6.1): cryptographic, transport, and
application. The extension owns the first two completely. The third — whether the Forms runtime still
has the handler ids and UI objects the message refers to — is inherent to replaying against a stateful
application, and mode B's prefix replay only mitigates it. Five open questions and the experiments
that settle them are listed in architecture §6.7.

**The cryptographic layer is verified twice over; the application layer not at all.** In simulation,
`RepeaterInjectionEndToEndTest` runs decode → edit → inject → server reads it → client carries on.
Against a running Burp (2026-08-14), the deployed extension was driven at a local listener and its
ciphertext checked against an independent RC4 implementation — key derivation, offset and tail
encryption, keystream continuity across sends, `Pragma` rewriting, `NULLPOST` pass-through,
fail-closed refusal and the marker trust rule all hold.

**An appended message was accepted by the live target on 2026-08-18** (bisection step 2: an
*unedited* Mode A draft, answered with a normal encrypted response). The cryptographic and transport
layers are therefore confirmed for the request direction against a real server, not just in
simulation. Steps 3–5 — integer edit, same-length string edit, length-changing string edit — are
unrun, so whether an **edit** survives is still open.

**First live-target send, 2026-08-14: rejected with `ifError:0/FRM-93618`** — the Forms servlet
could not read data from the runtime process, which is the signature of the runtime being fed bytes
it cannot parse. **The cause was found on 2026-08-18: the proxy never re-encrypted forwarded
traffic.** The ledger's counters diverged correctly on an injection, but `FormsHttpHandler` passed
each subsequent proxied message on unchanged, so the real client's next poll reached the server
encrypted at an offset the server had already moved past. The runtime dies on those bytes, and every
send afterwards — however well-formed — draws the same error. Fixed by `SessionStreams.forward`;
architecture §6.2 and §6.11. Two earlier suspects were also fixed on the way: a silent ledger desync
after an untracked ciphertext send, and a keystream offset guessed rather than refused. **None of
that proves the very first send was well-formed** — the bisection in §6.11 is still the way to
confirm it, and its step 2 (send an *unedited* draft on a fresh idle session) is still unrun.

Whether the runtime *accepts* an appended message
is the application layer, and no amount of the above reaches it.

**Intruder is supported only in mode A, and only single-threaded.** Each payload advances the shared
server-side keystream, so parallel requests interleave into one stream and destroy each other. Sends
are serialised per session, which makes concurrency slow rather than wrong — but the concurrency
buys nothing, and mode B is the mode that would.

## Usability

| Feature | Status | Notes |
| --- | --- | --- |
| Sensitive value highlighting | done | Credential properties, from the model rather than by regex over formatted text [5] |
| Proxy history annotation | done | Colour + comment so Forms traffic is findable in a large project [5] |
| Extension name and error logging | done | Replace the template's "My Extension"; never swallow exceptions silently [3] |
| Settings panel | planned | Endpoint override for non-default deployments, verbose logging |

## Quality gates

From `docs/bapp-store-requirements.md`. The reference implementation would fail items 1–4 of this
list, which is a large part of why we are restructuring rather than porting it directly.

| Requirement | Status | Notes |
| --- | --- | --- |
| No slow work on the proxy hot path or the EDT | done | Key capture only in the handler; decode on a background executor (criterion 5) |
| Clean unload | done | `ExtensionUnloadingHandler` shuts down the executor, clears caches (criterion 6) |
| Bounded caches, no retained Burp objects | done | All LRU; filtered `proxy().history()` calls (criterion 9) |
| Errors surfaced, not swallowed | done | Log to the extension error stream |
| Unit tests over `codec/` and `session/` | done | 266 tests, including a synthetic-session replay suite, the four-stream ledger simulated against independent client and server parties, and an end-to-end decode→edit→inject→server-reads-it chain. Possible because neither package imports Montoya (criterion 12). Still to do: re-run against byte-exact fixtures exported from the 22 captured sessions |
| Decoder hardened against malformed input | done | Bounded reads; bodies are untrusted (criterion 3) |
| GUI elements parented to the Burp frame | done | Criterion 10 |

## Explicitly out of scope

- **TLS decryption.** Burp's proxy already handles it. We decode Oracle's RC4 layer underneath.
- **WebSocket transport.** Only HTTP Transport (`lservlet`) is covered, matching the reference.
- **Supporting the Java 8 client runtime.** The *target application* runs on Java 8; the extension
  builds and runs on Java 21.
- **Jython compatibility.** The reference is Jython 2.7 on the legacy API; we are Java on Montoya.
