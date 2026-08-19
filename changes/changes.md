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

## 2026-08-19 — An edited text item sent a caret past the end of its own text

A value edited in the Intercept tab reached the server exactly as typed and the application ignored
it. The edit was never the problem; the message around it was.

Decoded from the wire (history item 2620, pragma 44), what went out was:

```
UPDATE handler=113
    ID_99            = "sevench"     <- the user's new value, 7 characters
    SELECTION        = (11, 11)
    CURSOR_POSITION  = 11
UPDATE handler=113 { FOCUS = false }
UPDATE handler=96  { FOCUS = true }
```

**Why:** a Forms client does not send a text item's value on its own. It sends the value together
with the caret and the selection, and both of those are *indices into that very string*. Shorten the
text and they still describe the old one, so the message says the text is seven characters long and
the caret is at eleven. No client can produce that, and the runtime is under no obligation to make
sense of it.

Confirmed across all three of the session's live edits, each one a different length change, and the
correlation is exact:

| pragma | client's bytes | sent | new value | old length | SELECTION / CURSOR_POSITION |
| --- | --- | --- | --- | --- | --- |
| 31 | 37 | 33 | `thr` (3) | 7 | 7 |
| 39 | 33 | 36 | `sixchr` (6) | 3 | 3 |
| 44 | 41 | 37 | `sevench` (7) | 11 | 11 |

**The fix: `codec/TextIndexEdits`.** When an edit changes a string's length, any
`CURSOR_POSITION` or `SELECTION` in the *same message* that now points past the end of that string
is pulled back to it, as an additional edit through the same splice and the same identity gate.

Four decisions in it that are not obvious from the diff, and all four are about not overreaching —
§6.3's guarantee is that everything the user did not edit is untouched *by construction*, and this
adds to what the user edited rather than weakening that:

- **Only an index that points past the end moves, and only to the end.** A caret the user left in the
  middle of the string is a position a client could genuinely send. Pragma 39 above is exactly that
  case — caret 3 into a 6-character value — and nothing is owed there.
- **An explicit edit outranks the inference.** A caret the user typed themselves is never touched.
- **Two changed strings in one message adjust nothing.** The caret indexes one of them and nothing
  here can say which; a stale value the user can see and correct beats a confident wrong one.
- **The raw surface is left alone entirely.** It is unrestricted by design, the user is writing
  bytes, and nothing is entitled to add any of its own to them.
- **Nothing is silent.** The status line names the adjustment the moment the cell is committed, and
  the send path logs it. Clamping also only ever makes a value smaller, so it cannot overflow the
  width the property was encoded at.

### The id table is not complete, and the FHT check assumed it was

Found while decoding the same message, and it is a latent "cannot edit this request" for exactly the
messages people want to edit. The text value of a text-item update is **id 99**, which the 466-entry
table ported from the reference has no name for. So a perfectly decoded message scores four known
ids out of five — 0.8, under the 0.9 bar that both the in-flight pre-flight check and the Repeater
reply check applied.

**Requiring 90% of ids to be named is requiring the table to be complete.** The structural signal
owes the table nothing, so it now counts as well: `KeyValidation.readsAsFht` accepts a reading that
either scores ≥ 0.9 on ids, or parses from the first byte to a terminator over at least four
properties while scoring ≥ 0.5. The second bar sits between the two measured populations rather than
at the top of one — a wrong key or offset scores 16–24%, the worst correct decode seen on the live
capture scores 80%. Both call sites now share the one method, so they cannot drift apart again.

**Confirmed the same day.** With the fix loaded, a text item's value was edited from four characters
to seven in the Intercept tab, forwarded, and **the application acted on the new value** — the first
time anything in this project has reached the application row of architecture §6.1 and been answered
properly. The session, **diverged** by the length change (client leg +34, server leg +37), kept
working for every message after it, which is the live counterpart of `DivergedForwardingTest` and the
half of §6.2 whose absence was `FRM-93618`. That is **bisection step 5** (§6.11), the hardest of
steps 3–5, and it closes the open question §6 has carried since 2026-08-14.

The pair also settles the diagnosis by natural experiment: the edit that was ignored left the caret
past the end of its text, the edit that was obeyed left it inside. **The clamp itself is still not
confirmed against the target** — the successful edit needed none — so what is proven live is the
failure mode it removes, not the remedy.

**And the verdict line reads `VERIFIED`**, which is what the relaxed rule predicts for this message
and what the old one could not have produced: five properties, one id with no name, a parse that runs
end to end. One loose end stays open and no longer affects anything: an edit made *before* that
change was converted at all, which the 0.9 bar should have refused. The behaviour it produced is now
the behaviour the rule specifies, rather than an accident.

**Affects:** `codec/TextIndexEdits.java` (new), `codec/TextIndexEditsTest.java` (new),
`session/KeyValidation.java`, `burp/proxy/InterceptEditService.java`,
`burp/repeater/RepeaterSendInterceptor.java`, `burp/ui/FhtDraftPanel.java`,
`burp/ui/FormsRequestEditor.java`, `session/KeyValidationTest.java`, architecture §6.3 and §6.12,
`features/features.md`. 266 tests.

---

## 2026-08-19 — Mode D was decoding at the session tail, one whole message too far

An intercepted request could not be edited: the tab refused with *"this message does not decode as
Oracle Forms data at the keystream offset this session is believed to be at"*. The ledger was opened
at the session's **tail**, and the tail counted the very message being held.

**Why:** **Burp records a request in the proxy history as soon as it intercepts it, not when it
forwards it.** So a request sitting in the Intercept tab is already in history, indistinguishable
from one the server has read, and `SessionTail.measure` — which means "what the server's cipher has
consumed" — summed it in. The in-flight decode was therefore one whole message further along the
keystream than the client's cipher, and the FHT check said so. That check is the only reason this
surfaced as a refusal rather than as another `FRM-93618`.

Confirmed against the live capture rather than reasoned about. In the session that reported it,
pragma 25 was in proxy history with no response and no annotation — Burp had recorded it but the
extension had never seen it leave — and an earlier edit's own marker gave the arithmetic away:
`X-OracleForms-Position: 991` on pragma 19, where the sum of request bodies for pragmas 3–18 is 708
and pragma 18's body is 283 bytes. 708 + 283 = 991. The ledger was one held message ahead, exactly.

**The error is inherited, which is why one bad measurement cost a whole session.** Forwarding the
held message advances the ledger over bytes the tail had already counted, so every later position in
that session carries the same offset. Pragma 19 was 8 bytes — below the 24-byte bar at which a decode
can be judged at all — so it came back `UNVERIFIABLE`, editing was offered anyway (as designed, since
refusing every small request would refuse most of the protocol), and the edit went to the server
encrypted 283 bytes into the wrong part of the keystream. The runtime survived it, but only by luck:
RC4 preserves length, so the server's cipher stayed aligned for every later message and only pragma
19's *content* was noise.

**The fix, in three parts.**

1. **`SessionTail.before(source, pragma)`** — the position the session's ciphers stood at
   *immediately before* a pragma, which is what an in-flight edit needs and is not the tail.
   `StreamRegistry.openBefore` opens the ledger there. This is exact rather than cautious: the
   message at that pragma is the one being held, so by construction neither it nor anything after it
   has reached the server. It also leaves `nextPragma` equal to the message about to go out, where
   the tail measurement claimed the one after it.
2. **The ledger is checked against the traffic, and corrected when the traffic wins.** A ledger is an
   accumulation — one measurement plus every message since — and the only way to check an
   accumulation is against something measured independently. When the decode does not verify,
   `InterceptEditService.reconcile` measures the position from captured traffic, decrypts there, and
   adopts it **only if the result reads as FHT** — `ReplyOffsetRecovery`'s rule applied to the
   request leg, with no search needed because there are only two candidates and the message in hand
   decides between them. This is what repairs a session already poisoned by the bug, including one
   poisoned by a Mode A send while a request was held.
3. **A disagreement too small to settle is refused, not guessed at.** If the two positions differ and
   the message is under the judgeable bar, editing is refused with both offsets named, rather than
   offered at whichever one happened to be in the ledger. That is the exact case that sent pragma 19
   to the server at a stale offset, and "not modelled is a reason to refuse, not a licence to guess"
   (§6.11) applies to it as much as to a history gap.

Two smaller things came with it. The history index is now rebuilt when it does not reach the message
*before* the held one — a precise staleness test, replacing "rebuild on first open", which was
already right about the hazard and could not see it recur. And `resynchronise` refuses a session that
has diverged: its counters are the only record of traffic history never saw, so a measurement that
cannot see that traffic cannot correct it.

**What this does not fix.** Mode A still measures the unbounded tail, so a Repeater append made
*while* a request is held in the Intercept tab is short by that request — the same root cause, and it
cannot be fixed the same way because history cannot tell a held request from one that is merely
awaiting its response. Recorded in architecture §6.9; the intercept path now repairs the ledger
afterwards, but the Mode A message itself would already have gone.

Also noted while reading the capture, and not fixed: `ProxyHttpRequestResponse.request()` and
`finalRequest()` are documented identically — both are "the request that was sent by Burp Proxy" —
so `PragmaHistorySource`'s comment about indexing "the client's bytes" is optimistic. What history
holds is the request as it left the Proxy stage, which after a Mode D conversion is FHT plaintext.
Lengths are unaffected for a same-length edit, and a length-changing one diverges the session, which
is precisely when `reconcile` stands down.

**Affects:** `session/SessionTail.java`, `session/StreamRegistry.java`,
`burp/proxy/InterceptEditService.java`, `burp/handler/FormsHttpHandler.java`,
`burp/proxy/InterceptEditServiceTest.java` (new), `session/StreamRegistryTest.java`,
architecture §6.9 and §6.12, `features/features.md`. 256 tests.

---

## 2026-08-18 — Built Mode D: editing a request in flight from the Intercept tab (6h.0–6h.4)

A Forms request held in Burp's **Intercept** tab can now be decoded, edited — in the property table
or as raw bytes — and re-encrypted at the session's live keystream position on **Forward**, with the
client's session carrying on afterwards. 245 tests. **Not yet run against a live target**: 6h.5 is
bisection steps 3–5, and that is now the whole open question of §6.

As §6.12 predicted, the crypto needed nothing new. `SessionStreams.editInFlight` advances the
client's leg by what the client wrote and encrypts the edit on the server's, which is §6.2's
"proxied request `P`, edited to `P′`" row; everything downstream — divergence, persistence,
`forward()` translation of later messages, the entire response leg — was already built and tested.
`InterceptEditTest` drives it against a simulated client and server and asserts the gate: after an
edit of any length the server reads what the user wrote and the client's next message still decodes.

**Three things the build changed, and the first is the sharp one.**

1. **The dispatch order is a safety property, not a preference.** The first working version ran Mode
   D *after* `RepeaterSendInterceptor`. That interceptor sees the markers, correctly judges that a
   marker on *proxied* traffic was set by the client, strips them and forwards the body — which is
   right for every other mode and catastrophic for this one, because a Mode D body is FHT
   **plaintext**. It would have put decoded traffic, credentials included, on the wire.

   The general rule, which §6.5 does not state because Mode D is the first mode where it bites:
   **whoever handles a marked request must be the one that owns its body.** The routing decision is
   now one function with one invariant — an intercept-marked request is never left to another path,
   every outcome is an encrypt or a drop, there is no fall-through. `InterceptEditRoutingTest` pins
   it, including the truth table where a bad token, a missing token, a replayed token and an
   unavailable edit path all still claim the request.

2. **The ledger is measured from fresh history on first open.** A session's history index is cached,
   and on a live session it goes stale by one message per message the client sends, so a tail
   measured from a twenty-message-old index puts the ledger twenty messages behind. The FHT check
   would have caught it, but as a baffling refusal rather than a working edit. Refreshed on the
   first open only: once the ledger exists the forwarding path advances it and history is not
   consulted again.

3. **"At most one request in flight" is enforced instead of documented.** §6.12 flagged it as an
   assumption it could not verify. The decoded-at offset now travels in `X-OracleForms-Position` and
   is re-checked at Forward; if something else on the session was forwarded while the request was
   being edited, the ledger has moved past the offset this edit was decoded against and the edit is
   dropped with that stated. An assumption that costs a comparison to verify should not stay an
   assumption — and unlike the pre-flight FHT check, which runs before the edit, this covers the
   window *during* it.

**Trust.** Rule 1 of §6.5 stands unchanged: a Proxy-origin marker is honoured only with a single-use
128-bit capability the extension minted and never puts on the wire, and `InterceptTokens` makes it
unforgeable rather than merely improbable. Eviction and `clear()` both fail closed — a refused edit,
never an accepted one.

**Fail-closed is `drop`,** as chosen. There is no `spoof` on the proxy path, so a refusal cannot be
explained to the client at all; the log is the only channel and it says so at length. The pre-flight
check makes it rare: by the time Forward is pressed the key, the ledger and the offset have all been
checked, and the decode has been shown to read as FHT.

**The offset verifies itself, which no other mode can do.** The tab decrypts at the offset it
believes and refuses to offer editing if the result does not parse as FHT — moving the wrong-offset
failure class, the one that produced `FRM-93618`, from something the server discovers to something
the tab refuses. Its limit is reported rather than hidden: steady-state Forms requests are 8–12 bytes
and carry no structure to judge, so those are marked `UNVERIFIABLE`, still editable, and labelled.

**Conversion is never automatic.** Returning plaintext from `getRequest()` the moment the tab is
looked at would rewrite an intercepted request because the user glanced at it — including one they
meant to forward untouched. Burp calls `setRequestResponse` whenever a tab is shown, so "shown"
cannot mean "intended"; the user presses a button.

**Prerequisites built with it:** §6.10's **6d.1** (commit a cell on focus loss *and* on every read)
and **6d.4** (raw plaintext surface, one live surface, commit on switch). 6d.1 was not optional —
Forward is a different button in a different panel, so focus loss without Enter is what always
happens, and the old table would have silently discarded the edit and forwarded the original.

**Affects:** `session/SessionStreams.java`, `session/InterceptEditPlan.java` (new),
`burp/proxy/InterceptTokens.java` and `burp/proxy/InterceptEditService.java` (new),
`burp/repeater/DraftMarkers.java`, `burp/repeater/SendMode.java`,
`burp/handler/FormsHttpHandler.java`, `burp/ui/FhtDraftPanel.java`,
`burp/ui/FormsRequestEditor.java`, `burp/ui/FormsEditorProviders.java`,
`burp/OracleFormsDecoder.java`; tests `session/InterceptEditTest.java`,
`burp/proxy/InterceptTokensTest.java`, `burp/handler/InterceptEditRoutingTest.java`,
`burp/repeater/DraftMarkersTest.java`. Docs: architecture §6.5, §6.6, §6.8, §6.10, §6.12 and the
status header; `features/features.md`.

---

## 2026-08-18 — Designed §6.12: Mode D, editing a request in flight from the Intercept tab

Designed, not built. The request: intercept a Forms request in Burp's **Intercept** tab, edit it in
the Oracle Forms tab, press Forward, and have the server act on it and answer normally.

**The finding that shapes it: this is §6.2's own table row, and the only one never exercised.** The
four-stream ledger's "proxied request `P`, edited to `P′` → `clientRequest` +len(P),
`serverRequest` +len(P′)" is precisely intercept editing. The ledger was designed for it and then
built for the Repeater case first, because §6.2 recognised an injection as the same problem with the
length going 0 → n. So Mode D needs **no new crypto**: divergence, persistence,
`SessionStreams.forward` translation of every later client message, and the whole response leg
already exist and are covered by `DivergedForwardingTest`.

That last point answers "the server should give a response back" for free. A request-length edit
moves only the two request legs, so `serverResponse` and `clientResponse` stay equal and every
response keeps taking `forward`'s undiverged path — unchanged bytes, both counters advanced, no
`ReplyOffsetRecovery` involved. A **same-length** edit diverges nothing at all.

Four decisions worth recording, because none is obvious from the section alone:

- **Displaying must not move the ledger.** Decode uses `SessionStreams.cipherAt` — a detached copy —
  because Burp calls `setRequestResponse` whenever the tab is shown, including for messages the user
  never edits and messages they go on to drop. Only Forward commits.
- **The offset verifies itself, which Mode A never could.** We decrypt at the offset we believe, and
  if it is right the plaintext parses as FHT with known property ids — `KeyValidation.signalsOf`
  already scores exactly this. So the tab offers editing *only* when the decode reads as FHT. That
  moves the entire wrong-offset failure class, the one that produced `FRM-93618`, from something the
  server discovers to something the tab refuses before the user types.
- **A capability token, not a relaxed trust rule.** Mode D needs a marked request arriving *from the
  Proxy*, which is what §6.5 rule 1 forbids — a marker on proxied traffic was set by the client. The
  rule stands: a Proxy-origin marker is honoured only with a single-use `X-OracleForms-Token` this
  extension minted and never put on the wire. Rejected `messageId()` correlation as the primary
  mechanism, because the API documents those ids only as unique per request/response pair and does
  not promise `InterceptedRequest` and `HttpRequestToBeSent` share a number.
- **Failing closed means `drop`,** chosen by the user over forwarding the original bytes.
  `ProxyRequestToBeSentAction` has no `spoof`, so a refusal cannot be explained to the client at all;
  sending nothing is the only answer that never lets a wrong outcome look like a right one. Its price
  is recorded plainly in §6.9 — a dropped edit will probably end the session — and the pre-flight
  check above exists to make it rare rather than to soften it.

**Prerequisites, not optional:** §6.10's **6d.1** (commit a cell on focus loss and on read) and
**6d.4** (raw plaintext surface and the one-live-surface toggle). 6d.1 especially — **Forward** is a
different button in a different panel, so focus loss without pressing Enter is guaranteed rather than
likely, and today's table would silently discard the edit. The raw surface was chosen over the
property table alone because interception is exactly where the bytes the codec cannot yet name are
the interesting ones.

**Why build this next.** Bisection steps 3–5 (§6.11) are the whole remaining open question of §6, and
Mode D is a cleaner instrument for them than Mode A: in-sequence, no tail measurement, no invented
pragma, no refreshed cookie, no race with a live client. If an edit fails through Mode D, it is the
edit.

**Two UI assumptions are unverified and carry the feature** (§6.12): that Burp shows
extension-provided editors in the Intercept tab at all, and that `EditorCreationContext` reports
`DEFAULT` plus a Proxy `toolSource()` there. `toolSource()` is confirmed to exist on the interface;
what it returns in that tab is not. Both are cheap to settle by loading the extension, and 6h.3 is
guesswork until they are.

Also corrected two stale claims in the document's own status header while editing it: the test count
(197 → 214) and "step 2 is still unrun", which §6.11 has recorded as run and passed since earlier the
same day.

**Affects:** `architecture/architecture.md` §6.4 (now four modes), §6.5 (marker list and rule 1),
§6.6 (planned components), §6.8 (step 6h), §6.9 (limits), **§6.12 (new)**, and the status header;
`features/features.md`. No code yet.

---

## 2026-08-18 — Showing a reply and trusting it are now separate decisions

The diagnostic added earlier today paid for itself on the first run. The refusal reported its nearest
miss, and the miss was **4 of 4 property ids known, 31 bytes consumed, no terminator reached** — a
candidate 61,196 bytes past the ledger. So the reply-offset search was finding the answer and
throwing it away, while the pane went on showing the ledger's reading of **2 of 9**.

That is a contradiction, not a conservative choice: `RepeaterSendInterceptor.readsAsFht` — the same
class's own test for "this reply decoded correctly" — passes at ≥ 0.9 known ids without asking for a
complete parse. It rejected the 2/9 reading, which is what triggered the search, and it would have
accepted the 4/4 one. The system was simultaneously calling a reading too weak to display and strong
enough to condemn the alternative.

**Split the two decisions.** Accepting an offset did two things at once — choose what to display, and
move the session's response ledger — and only the second is dangerous, because a wrong ledger sits
under the next send and puts bytes on a live application's wire. So:

- **Resynchronising the ledger** keeps the strict gate exactly as it was: every id known, the parse
  reaching a terminator, no tie, forward only. Nothing about that has been loosened.
- **Displaying** now uses `readsAsFht`, the bar this class already applies to the same question, so
  the two can no longer disagree. The decode is labelled `UNVERIFIED` in its header with the offset
  and the gap, and the log says plainly that the ledger was not moved and the next reply will be off
  by the same amount.

**Why not just loosen the gate:** completeness is what closed the false-positive hole the original
work found, where noise produced a "clean" offset 133,417 bytes away across a quarter-million
candidates. It earns its place for a decision that later reaches the wire. It does not earn its place
for deciding whether the user is allowed to read their own reply.

**Confirmed against the live capture.** The extension logged request offset 1197 and response offset
280,323; tabulating that session from proxy history reproduces both exactly. Pragma 40 — the client's
outstanding long-poll — is in history with `<no response>`, which is the §6.11 asymmetry visible
directly rather than inferred: the request leg is right, the response leg is short by exactly the
response that never came back.

**Affects:** `burp/DecodedBodyCache.java` (a `put` overload carrying a caveat),
`burp/DecodeService.java`, `burp/repeater/RepeaterSendInterceptor.java`,
`session/ReplyOffsetRecoveryTest.java`. 214 tests.

---

## 2026-08-18 — The reply-offset recovery could never be seen, whatever it found

A second live Mode A send reported "the same error": the response pane again showed a reply decoded
at the wrong keystream offset. Reading the proxy history for that session and then the display path
found that **the recovery built earlier the same day cannot reach the screen**, so it makes no
observable difference whether its search succeeds.

Three defects, in the order they bite:

1. **The rendered result is cached forever, and the correction is not.** `DecodeService.decode`
   caches rendered text under `(session, direction, pragma)` in a map that never expires within a
   project. The reply is rendered once from the ledger's offset, and the recovery — landing seconds
   later on the decode executor — writes only the *plaintext* cache. Reopening the message re-serves
   the stale rendering, so the corrected reading was unreachable through the UI permanently, not
   merely until a repaint.
2. **Nothing asks an open editor to paint again.** `FormsEditorPane.show` runs once per
   `setRequestResponse`. The search takes seconds and the user is looking at the pane the whole
   time.
3. **A write-ordering race.** `interceptResponse` cached the ledger's reading *after* `decryptReply`
   had already scheduled the recovery. Both write the same entry, so a fast search could publish the
   good plaintext and have it immediately overwritten by the unreadable one — permanently, since
   nothing runs a second time.

Fixed by making a superseding `put` invalidate the rendering it produced and notify open editors
(`DecodeService.DecodeUpdateListener`, held in a weak set so Burp discarding an editor needs no
deregistration it never announces), by having `FormsEditorPane` repaint on a matching update, and by
returning the recovery as a `Runnable` the caller runs *after* publishing the ledger's attempt.

Also: a refusal now reports its nearest miss. `ReplyOffsetRecovery.scan` returns the most FHT-like
offset it saw alongside the one it was willing to believe, and the log line quotes it.

**Why:** an empty `Optional` cannot distinguish "no offset in this window decrypts the body" from
"the right offset was rejected over one unknown property id", and those need opposite fixes — a
wider window versus a looser gate. Note the two thresholds currently disagree: `readsAsFht` treats
≥ 0.9 known ids as a good decode, while `ReplyOffsetRecovery.convincing` demands 1.0 *and* a parse
reaching the terminator. A reply carrying one id outside the 467-entry table is therefore
undiscoverable by a search that would have accepted it as correct had the ledger produced it. That
is left as-is pending a log line from a real run, because loosening it trades a false refusal for a
false answer, and this send path is deliberately built to prefer the former.

**Measured from the live capture** (session tabulated from proxy history, lengths taken from
`Content-Length` so the MCP's lossy body rendering does not matter): history was complete and
contiguous over pragmas 1 and 3–29 with no gaps, so Mode A was right not to refuse. At the send, the
request leg stood at 594 bytes and the response leg at 277,340 — the asymmetry being one 218,892-byte
logical response split across pragmas 6–9 by the `NULLPOST` rule (66,000 x3 + 20,892), which
confirms the architecture §1 fragmentation rule against a second session. No response carried
`Content-Encoding` or chunking, so the stored body lengths equal the wire lengths and the tail
arithmetic's inputs are sound. Worth noting against `DEFAULT_WINDOW`: at 256 KB the search window is
smaller than this session's own response offset, and only 17% larger than that single fragmented
response — one flush of that size and the answer is outside the window.

**Affects:** `burp/DecodeService.java`, `burp/ui/FormsEditorPane.java`,
`burp/repeater/RepeaterSendInterceptor.java`, `session/ReplyOffsetRecovery.java`,
`burp/SupersededDecodeTest.java` (new), `session/ReplyOffsetRecoveryTest.java`. 213 tests.

---

## 2026-08-18 — Bisection step 2 run: the request was accepted, and the reply leg was short

**The decisive experiment finally ran, and an appended message was accepted by a live Forms
runtime.** An unedited Mode A draft drew a normal encrypted response rather than `FRM-93618`. That
retires every cryptographic and transport hypothesis for the request direction: the tail measurement,
the keystream offset, the `Pragma` rewrite and the cookie refresh are all correct against a real
server. It is the first time anything from this project has been *acted on* by the target.

The reply, however, decoded to noise — five properties, none of their ids in the 467-entry table, and
a string length demanding 37,038 bytes from a 102-byte body. By the §8 oracle (a correct offset
scores ~100% known ids, a wrong one 16–24%) that is a clean decrypt of the wrong keystream position.

**Why the response tail is short, and why it is not a race.** Proxy history is asymmetric about
traffic in flight. A Forms client **long-polls** — the capture shows requests held open for 28
seconds — so at almost any moment Burp has recorded a request whose response has not come back.
`SessionTail` therefore measures the request leg correctly and the response leg short by exactly that
outstanding response's length. Sending is unaffected, because the server's *request* cipher really is
where we think it is. The reply is affected, because answering an injected message is what makes the
runtime flush its pending output down the waiting poll: the server emits that response first,
advancing its response cipher, and only then answers us.

**The length of a response that has not arrived cannot be known at send time.** That is structural.

**So it is solved rather than guessed.** `ReplyOffsetRecovery` searches forward from the ledger's
position for the offset at which the body parses, and the result is *verified* before it is believed
— every property id must be in the table and the parse must reach the terminator. That is the same
oracle §8 uses on a candidate key, and it is what distinguishes this from the guessed offset §6.11
forbids: a guess is an answer nothing can check. The gap it reports is the missing response's length,
so the ledger is resynchronised and the error does not carry into the next send.

**Three things the search does deliberately:**

- **Forward only.** The ledger can be behind the server but never ahead of it, because nothing
  removes bytes from a keystream. A backward search would be hunting for something that cannot be
  there, and every offset examined is another chance at a false positive.
- **Refuses on a tie, and on anything short.** Two equally clean offsets is a coincidence with a
  second opinion, not an answer. A 2-byte acknowledgement carries no evidence at all.
- **Demands a complete parse.** At three properties with all ids known, a body of pure noise found a
  "clean" offset 133,417 bytes away during development — a quarter of a million candidates is enough
  chances that merely-unlikely is not good enough. Requiring the parse to reach the terminator means
  every length and type marker in the body agreed with each other, which no wrong offset managed
  across eight randomised full-window trials.

It runs on `DecodeService`'s existing executor rather than the Burp response thread that delivered
the reply — the full window is a couple of seconds of work (criterion 5) — and the ledger's own
attempt is cached first, so the response pane always shows something and the recovery overwrites it.

**What is now known and not known.** The request direction is confirmed correct against the live
target. The response direction is correct once recovered, and the recovery is verified rather than
assumed. **Still unrun: bisection steps 3–5**, which are the ones that test whether an *edit*
survives — integer, same-length string, then length-changing string.

**Affects:** new `ReplyOffsetRecovery` and its tests, `KeyValidation.signalsOf` (extracted and made
public), `RepeaterSendInterceptor` (reply verification and recovery, new executor parameter),
`DecodeService.background()`, `OracleFormsDecoder`; architecture §6.11 and `features/features.md`.

---

## 2026-08-18 — The proxy never re-encrypted forwarded traffic, so an injection killed the session

`FormsHttpHandler` now carries each proxied message of a **diverged** session across the two cipher
relationships — decrypting it on the leg facing whoever sent it and re-encrypting it on the leg
facing whoever receives it — instead of forwarding the bytes unchanged. This is the cause of
`FRM-93618`, and it is a defect in the implementation rather than in the design.

**Why:** architecture §6.2 says Burp is a man in the middle with *two* cipher relationships, and that
after an injection the client-facing and server-facing legs sit at different keystream positions. The
ledger tracked that faithfully — four counters, correctly advanced — but **nothing ever applied it to
any bytes.** `CLIENT_REQUEST` and `CLIENT_RESPONSE` were never once used to transform a message in
`src/main/`; they only appeared in counter arithmetic. So a Mode A send left the server's request
cipher `n` bytes ahead of the client's, and the client's very next poll was forwarded verbatim: the
client encrypted at *T*, the server decrypted at *T + n*, and the Forms runtime was handed noise.
`FRM-93618` is the servlet reporting exactly that — it could not read a coherent message from
`frmweb`. Because that error is fatal, the runtime dies and every later send into the session,
including a perfectly encrypted one, answers the same way.

**Why the tests did not catch it.** `RepeaterInjectionEndToEndTest` step 6 and every helper in
`SessionStreamsTest` do the translation themselves — `apply(CLIENT_REQUEST)` then
`apply(SERVER_REQUEST)` — and then assert the server can read the result. They were testing the
model, and the model is right. Production called `observeUnmodified`, which advances both counters
and returns nothing, and no test ever drove *that* path with a party on the other end. A four-column
ledger is not a four-stream proxy, and the suite could not tell the difference.
`DivergedForwardingTest` now drives the production call and keeps an independent client and server
either side of it; its first test pins the old behaviour down as the failure.

**Three decisions in it that are not obvious from the diff:**

- **Undiverged sessions are not translated.** The two legs share a keystream position, so a
  round trip through both ciphers returns the input after two RC4 passes. `SessionStreams.forward`
  reports whether it rewrote anything, and the handler rebuilds the message only when it did — so a
  session nobody has ever sent into still costs one map lookup on the hot path, as §5 requires.
- **`StreamRegistry.forProxiedMessage` exists rather than reusing `peek`.** The live map is an LRU
  and it is empty after an extension reload, so it is not a trustworthy record of which sessions have
  diverged. Either would silently drop a session back to forwarding client-side ciphertext at a
  server that has moved on — the exact failure being fixed. The persisted counters are the durable
  record; the answer is cached both ways so the project file is read once per session, not once per
  message.
- **A translated message checkpoints immediately.** The counters moved, the divergence is still
  there, and a reload before the next message would otherwise resume from a position the session has
  left. Only diverged sessions reach it, which is what stops this becoming a project-file write per
  proxied message.

**One consequence, handled:** `PragmaHistorySource` now indexes `request()` rather than
`finalRequest()`. Proxy history is the *client's* view of the session — one continuous cipher from
pragma 3 — and that is what replay reconstructs by summing lengths. After a divergence
`finalRequest()` holds bytes from the server-facing stream, which replay does not follow, so every
message after an injection would have decoded to noise in the editor. Lengths are identical either
way, so the tail measurement is untouched.

**What this does not settle.** It explains a session that dies after the first injection and answers
`FRM-93618` for every send thereafter. It does **not** prove the first send was correct, and fixing
it is not evidence it was the only cause — the same trap §6.11 records for the desync fix. The
bisection in §6.11 is still unrun and its step 2 — an *unedited* draft on a fresh idle session — is
still the decisive experiment.

**Affects:** `SessionStreams` (new `forward`/`Forwarded`, `diverged(Direction)`), `StreamRegistry`
(new `forProxiedMessage`, divergence cache), `FormsHttpHandler` (rewrites forwarded bodies),
`PragmaHistorySource`, new `DivergedForwardingTest`; architecture §6.2, §6.8, §6.9, §6.11 and
`features/features.md`.

---

## 2026-08-14 — Refuse instead of guessing after an untracked send (the ledger desync)

`FormsHttpHandler` now marks a session's keystream position **unrecoverable** when Forms ciphertext
leaves Burp from one of its own tools without the draft markers, and Mode A refuses to send for that
session, durably and with the reason. This is the fix proposed in architecture §6.11 and it is the
first code change since the live-target rejection.

**Why:** the entry below records the diagnosis. The short form is that a plain Repeater resend of
captured ciphertext reaches the server and advances its request cipher, but `api.proxy().history()`
is proxy-only, so nothing later can see those bytes and every tail measurement is short by their
length — permanently, silently, and with the failure surfacing as a dead application session rather
than as a message. §6.9 had called that offset "not modelled"; in practice not-modelled meant
*guessed*, which is the one thing the rest of this design never does. Worth fixing whether or not it
caused FRM-93618, which the bisection has yet to say.

**The shape of it.** The refusal rides the type system so no call site can forget it:
`StreamPositionUnknownException` is a new abstract parent over the existing `StreamGapException` and
a new `StreamDesyncException`, and `StreamRegistry.open` declares the parent. Widening it that way
made the compiler find every caller that previously handled only a gap. The subclasses differ in
`isRecoverable()`, which is the honest distinction: a gap might be closed by capturing the missing
pragma, a desync never can be, because the bytes the server consumed are gone.

**Five decisions worth recording, because none is visible in the diff:**

- The desync is checked **before** the live ledger, not after — an already-open ledger is exactly as
  wrong as a freshly measured one once untracked bytes have landed, and more dangerous because it
  looks authoritative. Marking also drops any open ledger.
- **Responses and `NULLPOST`s do not spend a session.** Only a request moves the server's request
  cipher, and a `NULLPOST` is never encrypted at all, so resending one costs nothing.
- **Drafts never reach the check**, because `RepeaterSendInterceptor` runs first and returns. That is
  precisely the distinction being drawn: a draft is encrypted at send time and accounted for.
- **Only the first mark per session writes to the project file**, so an Intruder run over a spent
  session logs once rather than once per payload.
- **An unreadable marker is not treated as absent**, unlike every other read in `PersistedKeyStore`.
  A record that exists but will not parse still proves something was marked, and "I know this session
  was broken but not why" should keep refusing. Elsewhere a corrupt entry costs a rebuild; here it
  would cost a live application session.

**What it deliberately does not do:** adjust the offset by the bytes it saw leave. The correct offset
is *not knowable* rather than merely unrecorded — traffic can reach the server from another Burp
instance, from curl, or from the application with the proxy bypassed — so adjusting by the observed
part would turn a detectable failure into an undetectable one.

**A false positive is possible and is the right way round.** The mark is set as the request leaves
Burp, not when the server acknowledges it, so ciphertext sent to a refused connection still spends the
session. A wrong refusal costs an application restart; a wrong permission costs a corrupted live
session that gives no sign of itself.

**Affects:** `session/StreamPositionUnknownException.java` (new), `session/StreamDesyncException.java`
(new), `session/StreamGapException.java`, `session/StreamPositionStore.java`,
`session/StreamRegistry.java`, `burp/handler/FormsHttpHandler.java`,
`burp/repeater/RepeaterSendInterceptor.java`, `burp/persistence/PersistedKeyStore.java` (a third
sibling collection, `desync`, for the same reason `streams` is one), and
`architecture/architecture.md` §3, §6.6, §6.9, §6.11. Tests: `StreamDesyncTest` (new, 8),
`StreamRegistryTest` and `KeyChangeInvalidatesStreamsTest` updated for the widened store contract.
**193 tests, 0 failures**, up from 185.

**Not yet done:** the desync is not surfaced in the Sessions tab, so a user learns of it at Send time
from the refusal response. That is where they are looking, but a column would be better.

## 2026-08-14 — First live-target send: rejected with FRM-93618

An edited message was sent to the real Forms server in Mode A. The server answered
`ifError:0/FRM-93618: fatal error reading data from runtime process`. Documented as architecture
§6.11, with the ranked suspects and a five-step bisection; §6.9 gained two limits; `features.md` and
`CLAUDE.md` no longer claim nothing has been sent to a live target.

**No code changed.** This entry records a finding, not a fix — the decisive experiment (§6.11
step 2: send an *unedited* draft) has not been run, and changing the send path before it would be
guessing at which of three suspects is real.

**Why it matters more than one failed send.** FRM-93618 is the servlet failing to read from the
`frmweb` runtime process, which is what being fed unparseable bytes looks like — not what a
well-formed but stale message looks like. So it indicts the *cryptographic* layer of §6.1, the one
layer the design claims to own completely, rather than the application layer it has always been
honest about not owning.

**The suspect worth acting on regardless of the outcome.** `FormsHttpHandler.trackForwarded` ignores
any Forms message not from the Proxy. A non-draft Repeater tab holding captured ciphertext is a valid
Forms message: it reaches the server and advances the server's request cipher, but proxy history
never records it, so every later tail measurement for that session is short by its length —
permanently, and silently. §6.9 had already noted this offset was "not modelled"; what that turned
out to mean in practice was *guessed*, which is the one thing the rest of the design never does. The
proposed fix is to poison the ledger and refuse, the same treatment a gap in history already gets.

**What was ruled out, and how.** A length-changing edit cannot leave a stale length field behind:
FHT is terminator-delimited and self-describing, with no packet- or message-level byte count anywhere
in `FhtParser`. Worth recording because it is the first thing anyone will suspect of a splicing
writer.

**A caveat about the identity gate, stated because it is easy to over-read.** It proves that
re-encoding an *unchanged* value reproduces the original bytes. It says nothing about whether a
*changed* one is well-formed. That is the right scope — it is a check on the encoder, not on the
protocol — but a passing gate is not evidence that an edited message will be accepted.

**Affects:** `architecture/architecture.md` (§6.9, §6.11), `features/features.md`, `CLAUDE.md`.

## 2026-08-14 — Designed §6.10: making the Repeater tab editable in practice

Raised from use: a message sent to Repeater could not be manipulated. Diagnosed as four independent
causes and designed as architecture §6.10, build order 6d.1–6d.5. **Design only; nothing built.**

**Why 6d was marked done and still did not work.** The property table exists and functions. But it
is reachable only via the extension's own context items — `Ctrl+R` produces a ciphertext tab with no
route to an editable one; a typed cell is discarded unless Enter is pressed, because the `JTable`
never sets `terminateEditOnFocusLost`; the table covers only values `FhtWriter` can round-trip; and
`FormsRequestEditor.getRequest` fails *open*, sending the unedited body when a splice throws.

Each of those alone is enough to make the feature look absent, which is why "6d: done" was true of
the code and false of the experience. The gate for 6d was "edit a property, see the plaintext change"
— a gate written against the mechanism rather than against a user reaching it.

**Affects:** `architecture/architecture.md` (§6.8 table, §6.10).

## 2026-08-14 — Redacted the rotating cookie suffix, missed by the first pass

The 2026-08-13 redaction replaced every hostname, `JSESSIONID`, server instance name and WebLogic
route id. It did not replace the **suffix of `JSESSIONID_FORMS`** — the part after the `|` — because
that was never on the list. So while the server instance name became `formsapp_rs1`, the values
beside it were real: seven distinct suffixes across `SessionIdTest`, `CookieHeaderTest`,
`architecture.md` and one historical entry in this file. Two of them were confirmed real by comparing against live proxy
history while testing the send path.

All seven are now synthetic, and named so they cannot be mistaken for captured data: `rot01`,
`rot02`, and so on, with `rot07+` keeping the odd character a real value carried. Shape and the
rotation each test demonstrates are preserved, so nothing the suite proves has changed — 185 tests,
unchanged.

The list in §1's note on identifiers now names the rotating suffix explicitly, with the rule stated
plainly: no literal byte in this repository came off a real wire. The original list was an
enumeration of what had been noticed, and anything not enumerated was silently out of scope, which is
how these survived.

**Severity, honestly:** low. These are five-character WebLogic routing tokens from sessions that
expired months ago, sitting beside a server instance name that was already fake. They unlock nothing
and identify nobody on their own. The reason to fix them is that "we redact captured identifiers" is
either a rule or it is not.

**This does not remove them from history.** They are in `411af92`, which is published on a public
remote, so the fix cleans the tip and nothing before it. Removing them from history means rewriting
it and force-pushing over a published branch — a separate decision, not something to fold into a
routine change.

**Affects:** `session/SessionIdTest.java`, `session/CookieHeaderTest.java`,
`architecture/architecture.md`, `changes/changes.md`.

## 2026-08-14 — Two fail-safe holes found by review

A multi-agent review of the send path raised three findings. One was a false positive; the other two
were real, and both had the same shape: a guarantee stated unconditionally in the design that the
code only delivered conditionally.

**1. The fail-closed contract rested on one method's error handling.**
`FormsHttpHandler` wraps its work in `catch (RuntimeException)` and falls through to
`continueWith(request)` — correct for ordinary traffic, and exactly wrong for a draft, whose body is
FHT plaintext and whose markers have not yet been stripped. `RepeaterSendInterceptor.intercept` did
catch around its own send, but the trust check ahead of it was *outside* that try, so a throw from
`toolSource()` or `DraftMarkers.strip()` escaped to the handler and the draft went out as readable
FHT with its markers attached. Architecture §6.5 states rules 2 and 3 with no exceptions in them.

Fixed on both sides. Everything after the marked-request check now sits inside the interceptor's try;
its refusal path can no longer throw either, falling back to `drop()` if even building the
explanation fails. And the handler now checks for markers in its own catch and drops rather than
forwards, so the guarantee no longer depends on one method being complete.

**2. Stream counters outlived the key that produced them.**
Persisting the counters in a collection *beside* the session entry, rather than inside it, is what
stops `put()` destroying them whenever a key is re-derived — but it also let them survive a key
*change*: a correction typed into the Sessions tab, a JSON import, or a fresh handshake with
different randoms. RC4 state is a function of the key **and** the byte count, so a count accumulated
under the old key describes nothing under the new one. The next send would seed a cipher with the new
key, skip it to the old count, and encrypt at an arbitrary offset — which succeeds, and which the
server reads as noise. Precisely the outcome §6.4 says must never be guessed at, arrived at without
anyone guessing.

Fixed by binding the counters to their key: `StreamPositions` now carries a digest of the key it was
measured under, `StreamRegistry` refuses to resume a set that does not match and measures the session
again instead, and `PersistedKeyStore.put` drops them when the key changes. The registry check is the
load-bearing one, because it does not depend on every writer remembering; the `put` cleanup is
hygiene. Counters written before the binding existed are treated as unidentifiable and rebuilt.

**3. "The PR does not compile" — false positive.** The reviewer's checkout saw the eight modified
files without the thirty-seven new ones, because at the time they were untracked and so absent from
the diff it was given. Verified directly: the tree compiles, 185 tests pass, and the jar builds. Worth
recording because the same scoping trap will catch the next review of a branch with new files in it.

`KeyChangeInvalidatesStreamsTest` covers finding 2 end to end, including that a send after a key
change still lands where a server holding the new key actually is. Finding 1 has no automated test:
reproducing it means making a Montoya `HttpRequestToBeSent` throw, and constructing one needs Burp's
object factory. That is the `burp/` coverage gap again — the fourth defect to land in it.

## 2026-08-14 — Verified the send path against a live Burp; fixed a Content-Length bug

The Repeater send path was exercised end to end against a **loaded extension in a running Burp**,
rather than only in simulation, by issuing requests through Burp's own HTTP stack at a local listener
standing in for the Forms servlet. That listener answers a `GDay` handshake with `Mate`, which is
enough for the live extension to derive and store a key, after which drafts can be sent at it and the
resulting ciphertext checked against an independent RC4 implementation in Python.

**What passed, on the deployed extension:**

- Live key capture from a Pragma 1 handshake, and the derived key matched an independent computation
  of the §1 formula exactly (`4395ae4285`).
- Offset mode: ciphertext byte-identical to independently computed `RC4(key)` from offset 0.
- Tail mode: two consecutive sends encrypted at offsets 0 and 30 against **one continuous
  keystream** — the ledger advances correctly across sends.
- `Pragma` rewriting: a draft sent with `Pragma: 99` went out as 3, then 4, then 5, then 6.
- Offset mode left the ledger untouched, proven by the first tail send afterwards still starting at
  offset 0.
- `NULLPOST` outbound: passed through as cleartext, and the following send still encrypted at offset
  60 rather than 68 — the sentinel consumed no keystream.
- Fail-closed: a draft for a session with no stored key produced the 599 refusal and **nothing
  reached the listener**.
- The trust rule: the same markers sent *through the Burp proxy* were stripped and ignored, and the
  body went out unencrypted. Honoured only from Burp's own tools, exactly as specified.

**The bug.** The refusal response computed `Content-Length` from the body's **UTF-8** byte count and
then handed the whole message to `HttpResponse.httpResponse(String)`, which Burp encodes as Latin-1.
Every multi-byte character shrank on the way out while the header kept the larger count. Two em
dashes in the "no key is stored" message were enough: a live refusal declared 391 bytes and sent
fewer, and a client honouring `Content-Length` waits for a remainder that never comes.

Fixed by assembling the response as bytes — ASCII header block, UTF-8 body, length taken from the
body array — so the declared length is the real one whatever the reason contains. That matters beyond
the em dashes, because one refusal interpolates a session id read straight off a request header and
so is not the extension's to trust (criterion 3). The em dashes were also replaced with ASCII, which
is the same decision `FormsEditorPane` already documents for rendered output.

`RefusalResponseTest` pins the invariant for ASCII, multi-byte characters, hostile session ids, an
empty reason, and CRLF in the reason. 180 tests.

**Why simulation missed it:** every existing test drives `InjectionPlan` and `SessionStreams`
directly, and none of them construct a Montoya `HttpResponse` — that needs a running Burp. This is
the `burp/` coverage gap `features/improvements.md` item 1 has been warning about, landing a third
bug.

**Affects:** `burp/repeater/RepeaterSendInterceptor.java`,
`burp/repeater/RefusalResponseTest.java` (new).

## 2026-08-14 — Built step 6a–6e: Repeater injection works

The design from earlier today is now implemented. A captured message can be drafted into Repeater as
plaintext, edited property by property, and re-encrypted at the live session's keystream position on
Send — with the real client's session surviving intact. 174 tests, up from 104.

Five things came out differently from the design, and four of them are corrections to it.

**1. `FhtWriter` splices; it does not re-serialize.** §6.3 preferred rebuilding the packet from the
model. That option does not exist: `FhtParser` is deliberately lossy — it drops the `ACTION_5`/`6`
delta byte, keeps only an `ExtValue`'s subtype and length, resolves back-references into plain
strings without recording the slots involved, and never records the slot a literal string was stored
into. Re-serializing would silently rewrite bytes nobody asked to change, on a shared continuous
keystream where a wrong byte damages every message after it. So the writer copies the original and
replaces only the byte ranges of the properties actually edited; where the model lacks something the
encoding needs, it reads it back out of the original bytes.

**Why that is better rather than merely necessary:** untouched bytes are untouched *by construction*,
which no test can promise. And it made room for the **identity gate** — before any edit is applied,
the property is re-encoded with its own *unchanged* value and compared against what is already there.
An encoder that cannot reproduce bytes it can read does not get to replace them. That runs at
runtime on every edit, not just in tests, so a type this codec gets subtly wrong surfaces as a
refused edit with a reason instead of a corrupted session. It also catches lossy *decoding*: a string
whose bytes are not valid UTF-8 comes back as a replacement character, would re-encode differently,
and is locked.

**2. The persisted stream counters are a sibling of the session entry, not a child.**
`PersistedKeyStore.put` replaces a session's entry wholesale, so counters nested inside would have
been destroyed every time a key was re-derived. Separating them makes that impossible rather than
merely avoided. A fifth field, `nextPragma`, rides along — after an injection the session has a
sequence number the capture has never seen, so it is not derivable either.

**3. `OutboundEncoder` was not built.** It would have been one method wrapping one call plus the
`NULLPOST` rule, and that rule belongs next to the state it protects. It lives in
`SessionStreams.apply`, beside the counters it must not advance.

**4. The handler does slightly more on the hot path than §5 allowed.** It now keeps an *already open*
session ledger level with traffic the real client is still generating. Without it a session goes
stale the moment the client sends anything after a Repeater send, and the next send would encrypt at
an offset the server has left behind — the exact failure the design exists to prevent. The cost is
one hash lookup per Forms message, and the cipher only advances for a session the user has already
sent into.

**5. `§6.2`'s claim was tested by simulation, and it holds.** `SessionStreamsTest` stands up an
independent client and server, each with their own continuous per-direction ciphers, and puts the
ledger between them. `RepeaterInjectionEndToEndTest` then runs the whole chain on real FHT packets:
replay a captured message, edit a string to something longer, plan a tail injection, have the
*server* decrypt and parse it and see the change, then keep the real client talking for ten more
messages in both directions. The offset-mode test is the sharpest of the set — an unedited draft must
re-encrypt to the captured ciphertext byte for byte, so an offset that is wrong by one fails it.

**Fail-closed, as specified.** A draft that cannot be encrypted is answered with
`RequestToBeSentAction.spoof` carrying a plain-text explanation, so the request never leaves Burp and
the reason appears in Repeater's response pane. Markers are honoured only from Repeater, Intruder and
extensions — one on proxied traffic was set by the application under test — and are stripped on every
path out.

**What is not built:** Mode B (bootstrap a fresh session), which is gated on §6.7 question 1, and
response editing, which is where fragment groups bite. **And nothing here has been run against a live
target.** What is verified is the cryptographic layer of §6.1; whether the Forms runtime accepts an
appended message is precisely what cannot be answered without it.

**Affects:** new — `codec/FhtWriter`, `FhtEdit`, `FhtUnwritableException`, `PropertyValues`;
`session/StreamLeg`, `SessionStreams`, `StreamPositions`, `StreamPositionStore`, `StreamRegistry`,
`SessionTail`, `StreamGapException`, `InjectionPlan`, `CookieHeader`; `burp/DecodedBodyCache`,
`burp/repeater/*`, `burp/ui/FhtDraftPanel`. Changed — `PragmaSource`, `PragmaHistorySource`,
`PersistedKeyStore`, `DecodeService`, `FormsHttpHandler`, `FormsRequestEditor`,
`FormsEditorProviders`, `OracleFormsDecoder`. Docs — `architecture/architecture.md` (§3, §4, §5, §6.3,
§6.6, §6.8, status), `features/features.md`, `CLAUDE.md`, `README.md`, `summary.md`.

## 2026-08-14 — Designed step 6: sending a modified message from Repeater

Documentation only; no code changed and all 104 tests still pass. Architecture §6 grew from a
30-line note about length-changing edits into the full design for the workflow the extension is
missing: send a captured message to Repeater, change a value, press Send, have the server accept it.

Four decisions carry the design.

**A Repeater injection is a length-changing edit with the length going 0 → n.** The four-stream model
already in §6 was written for edits, but it turns out to cover injection exactly: from the real
client's point of view the injected message had length zero, from the server's it had length `n`, and
four independent ciphers absorb the difference. That collapses what looked like two features into
one mechanism, and it *reverses* a claim the document previously made — §6 said replaying from
Repeater "still desyncs the real session (inherent, not fixable)". That is true of replaying into the
*middle* of a session, and false of appending to its *tail*; the two were conflated. Appending is
fully supported.

**The four streams are four `long`s, not four S-boxes.** RC4 state is a pure function of the key and
the bytes consumed, so the ledger persists as four counters and rebuilds with one `skip` each. That
removes the old caveat that "if the extension is unloaded mid-session the streams are lost" — the
divergence now survives a reload for the cost of four longs in the project file, written only once
the counters stop being equal. §3's persistence schema gained a `streams` child.

**The Repeater tab carries plaintext; the handler encrypts at send.** The obvious alternative — hold
ciphertext and re-encrypt in `getRequest()` — fails because Burp calls `getRequest()` whenever it
needs the message, so the keystream offset would be frozen at edit time, and by the time the user
presses Send the session tail may have moved. Putting the crypto in the handler means it happens once,
at the moment the correct offset is finally knowable. The cost is a marker-header contract
(`X-OracleForms-*`) and a hard rule: markers are honoured only from Burp's own tools, are stripped on
every path, and a marked request that cannot be encrypted is answered with a spoofed explanatory
response rather than sent. Sending unencrypted FHT would put readable credentials on the wire.

**Three send modes, chosen explicitly.** Append to a live session's tail; bootstrap a fresh session
and optionally replay a captured prefix; or encrypt at the captured offset for inspection only. They
differ in what they do to a live application session, and the difference is too large to pick a
default silently. Mode A also forces per-session serialisation, which makes explicit something that
would otherwise be discovered painfully: *Intruder with more than one thread is broken by construction
against this protocol*, because parallel payloads interleave into one keystream.

The section also separates three layers of validity — cryptographic, transport, application — because
all three fail identically from the outside and only the first two are the extension's to guarantee.
Five open questions with their experiments are in §6.7, and §6.8 replaces the one-line step 6 in the
build order with seven gated sub-steps.

**Why now:** the request was for the Repeater workflow, and the previous §6 was not a design so much
as a note that editing would be hard, with one sentence that was actively wrong about whether
Repeater could work at all. Writing it down first also surfaced the persistence and concurrency
consequences, neither of which would have been obvious mid-implementation.

**Also corrected while here:** `CLAUDE.md` still described the 4-byte FHT opening constant as the
blocker for validating key derivation, which §8 had already retracted — `KeyValidation` needs nothing
known in advance, and the real gap is a byte-exact fixture file. Test counts in `CLAUDE.md` and
architecture's status banner were stale at 73; the suite is 104.

**Affects:** `architecture/architecture.md` (§3 schema, §4 tree, §5 outbound flow, §6 rewritten, §9
step 6), `CLAUDE.md`, `features/features.md`, `features/improvements.md`, `README.md`.

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
  rotates mid-session (observed moving `rot01` → `rot02` within one session). The docs previously
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
