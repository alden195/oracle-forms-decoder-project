# Review and improvement backlog

A survey of the extension as built, and a prioritised list of what should change next.

Written 2026-08-13, after the first live run against the target. `features/features.md` tracks what
is done; this file tracks what is *worth doing* and why. Design detail belongs in
`architecture/architecture.md`; the reasoning behind past changes belongs in `changes/changes.md`.

---

## Part 1 — What the extension does today

Build order steps 1–5 are complete (architecture §9), and 6a–6e as of 2026-08-14. 185 tests pass.

### Core decode pipeline

Detection runs on every proxied request and is ordered cheapest-first: `lservlet` in the path, then a
numeric `Pragma` header, then cookie parsing for a `JSESSIONID`. The common case — traffic that is
not Forms at all — is rejected by a substring test.

Key capture is **the only work done on the proxy hot path**: `FormsHttpHandler` reads the client
random from the Pragma 1 `GDay` request and the server random from the `Mate` response, derives the
5-byte RC4 key, and stores it. No decryption, no parsing, no formatting there.

Everything expensive happens in `DecodeService`, on a two-thread executor: resolve the session, replay
the RC4 stream from the nearest checkpoint, decrypt, parse, render.

### Key session storage — the headline feature

Keys persist in the Burp project file under `api.persistence().extensionData()`, which is the right
lifetime: they belong to the traffic captured in that project, and they survive extension reload and
Burp restart. Four ways a key enters the store: derived live, recovered retroactively by scanning
proxy history, entered by hand, or imported from JSON.

Storing the key is necessary but not sufficient — see below.

### Replay and checkpointing

Because the keystream is continuous across a session, reading pragma 42 means running the cipher over
every byte of pragmas 3–41 in that direction. `StreamReplayer` does that from the nearest cached
checkpoint; `CheckpointCache` snapshots RC4 state plus the string dictionary every 25 pragmas.

The cache is bounded in **two** dimensions — streams tracked and checkpoints per stream — and when a
stream is full it is *thinned* (every second checkpoint dropped) rather than truncated. Discarding the
oldest would be worse than useless: the early checkpoints are what make the start of a session cheap
to reach, and they are the most expensive to rebuild.

### Transport framing

Two rules learned from live traffic, neither present in the reference implementation:

- A `NULLPOST` request is cleartext and contributes **zero** bytes to the request keystream.
- An oversized response is split across several pragmas and must be rejoined before parsing.
  Fragments are grouped by the `NULLPOST` sentinel rather than by the 66000-byte fragment size, so
  the rule does not depend on the server's buffer configuration.

### Failure is a first-class result

`ParseOutcome` distinguishes a clean parse from one truncated at a byte offset from one that failed
structurally. `ReplayResult` names *which* pragma is missing rather than failing blankly. A message
is never a blank tab: every failure states its reason and still shows the bytes.

### Validation

`KeyValidation` derives a key and checks that pragma 3 parses into real property ids, against a
control group of 32 random keys so the check is comparative and cannot rubber-stamp.
`RealCaptureValidationTest` runs it over exported fixtures and skips, with instructions, until a
fixture file exists.

### User interface

Read-only "Oracle Forms" tabs on requests and responses, sharing one `FormsEditorPane` that shows a
pending state immediately and repaints when the background decode lands. A generation counter
discards results that arrive after the user has moved on. The Sessions tab lists known sessions and
offers manual entry, retroactive scan, export/import, forget/clear-all, and fixture export. Forms
traffic is coloured and commented in the proxy history so it is findable.

### Quality gates

Clean unload: every registration deregistered, executors shut down, caches cleared — and `tearDown`
is safe to call twice, because Burp can unload an extension that failed partway through loading.
Swing components are built on the EDT. `codec/` and `session/` contain no Montoya imports, which is
what makes them directly unit-testable.

---

## Part 2 — Improvements

### Tier 1 — highest value

**1. Test the `burp/` package.**
Of 185 tests, nearly all live in `codec/` and `session/`. `FhtRenderer`, `PragmaHistorySource`,
`RetroactiveKeyScanner` and `DecodeService` have essentially none — and **four** bugs have now landed
in exactly that gap, most recently the refusal-response `Content-Length` bug, which no simulation
could have caught because constructing a Montoya `HttpResponse` needs a running Burp. The reflective-proxy harness in `ExtensionLifecycleTest` already proves no
mocking library is needed; extending it into a fake proxy history makes all four testable. This
protects every other item on this list, so it comes first.

**2. Search across decoded traffic.**
The biggest capability gap. Burp's search operates on raw bytes, so Forms traffic is effectively
*unsearchable* — the thing a tester most wants to do with it cannot be done at all today. The decoder
holds the plaintext. "Find every session and pragma whose decoded content matches this string or
regex" is something nothing else can offer for this protocol.

Search the parsed model, not the rendered text — regex over formatted output is the reference's
mistake (architecture §7.5), and it breaks on any value containing a quote or newline. Must be
cancellable, bounded, and off the EDT.

**3. Session transcript view.**
Only one message can be viewed at a time, through editor tabs. Understanding an application flow —
*where does the login actually happen* — needs every message in pragma order with both directions
interleaved. It is also the natural place to present reassembled fragment groups, which currently
render identically across all four pragmas of a group.

**4. Context menu integration.** *(Partly done 2026-08-14.)*
`registerContextMenuItemsProvider` now carries the two "Send decoded to Repeater" items. "Copy
decoded text", "Scan history for this session's key" and "Export this session's fixtures" are still
cheap to add, and context menus are the main discoverability path in Burp.

**5. ~~Editing and Repeater — build order step 6.~~ Built, 6a–6e** (2026-08-14).
`FhtWriter`, the identity gate, the four-stream ledger, the marker contract, the editable property
table, and mode A tail append all ship. Item 4 above went with it: the context menu now exists,
though only with the two "Send decoded to Repeater" items.

**What remains of step 6:** mode B session bootstrap (6f), gated on architecture §6.7 question 1, and
response editing (6g). See `changes/changes.md` for the five ways the build differed from the design.

**The most valuable next step is not more code.** Everything in §6 is verified by simulation only —
the five experiments in architecture §6.7 need a live target, and question 1 decides whether mode B
is cheap or expensive to build.

### Tier 2 — correctness

**6. Auto-detect the derivation scheme.**
`KeyDerivation` is an interface with a single implementation, and the version risk in architecture §1
is real: Forms 12c or a deployment using `INITIAL_ENCRYPTKEY` (property 271) may derive keys
differently. `KeyValidation` can now tell whether a candidate key is right, so the extension can try
each registered scheme and keep whichever validates. That turns broader version support from a guess
into a self-checking feature, and it is a much better use of the validator than running it once by
hand.

**7. Settle the `DictionaryScope` question (architecture §7.2).**
Currently a compile-time constant set to `PACKET`. Now that traffic decodes, the answer is
measurable rather than theoretical: count back-references that resolve to empty strings under each
scope. A session that resolves many to empty under `PACKET` is telling you it is session-scoped. Both
scopes are already implemented, so this is analysis, not new machinery.

**8. Settle class-id masking (architecture §7.1).**
`FhtMessage` retains `rawHeader` specifically so this can be answered from a decoded capture without
re-decoding. Low effort now that decoding works.

**9. Report unknown property ids.**
`PropertyIds.isKnown` exists but nothing surfaces misses. "This session used 3 property ids not in
the table" both catches protocol drift and tells you exactly how to grow the 470-entry table.

### Tier 3 — resources and performance

**10. Stop holding bodies that will never be decrypted.**
`PragmaHistorySource` indexes *every* body for a session into memory. With 66000-byte response
fragments that is tens of megabytes per session, and three sessions are cached. `indexedBytes()` is
computed but bounds nothing.

The fix falls straight out of the replay algorithm: under `PACKET` scope, intervening pragmas
contribute only their **length** to the stream (`rc4.skip`), never their content. Store lengths for
everything and bodies only for the target's fragment group. Large win, no behaviour change.

**11. Stop rescanning the whole history per session.**
`PragmaHistorySource.forSession` walks the entire project history for one session, and runs
`FormsDetector.detect` twice on every candidate — once in the filter, once in the loop. With
`MAX_CACHED_SESSIONS = 3`, moving between four sessions rescans constantly. One pass indexing all
sessions at once fixes both.

**12. Invalidate caches when new traffic arrives.**
`DecodeService` only rebuilds an index on a `MissingPragma` retry. A fragment group cached as
incomplete stays incomplete even after its tail is captured. The HTTP handler already knows when a
session receives new traffic; wiring that to `invalidateHistory` closes the gap.

**13. Cap rendered output.**
A reassembled 218 KB message with thousands of properties becomes one very large `String`, built in a
`StringBuilder` and pushed into a Swing editor. Page it, or cap the number of messages rendered with
a "showing N of M" line.

### Tier 4 — housekeeping and submission readiness

**14. Write the README.**
It is still the unmodified PortSwigger template, which fails BApp criterion 2 outright. Architecture
§3 also specifies that the "keys are session secrets in an unencrypted project file" note belongs
there — and exported validation fixtures now carry the handshake randoms, so they need the same
warning.

**15. Settings panel.**
`ANNOTATE_HISTORY`, `DICTIONARY_SCOPE` and the `lservlet` path marker are all compile-time constants.
An endpoint override matters for deployments that do not use the default servlet path.

**16. Consolidate the two validation APIs.**
`Pragma3SelfTest.checkKey` is largely superseded by `KeyValidation`. Leaving both in place invites
reaching for the weaker one; either fold it in or mark it clearly as the keyless-symmetry check only.

---

## A note on build order step 6

> **Resolved 2026-08-14.** Architecture §6 has been rewritten and now answers both points. Kept here
> because it is the record of what forced the rewrite, and because the second point turned out to
> constrain the build order rather than the design.

The `NULLPOST` and fragmentation findings add requirements the four-stream design in architecture §6
did not anticipate, and they should be worked through before any of it is built:

- **Re-encryption must skip `NULLPOST`s entirely.** They never entered the cipher, so a forwarding
  stream that encrypts them desynchronises the server exactly the way decoding did before the fix.

  *Answered:* §6.5, handler rule 4 — a plaintext body of exactly those eight bytes is sent cleartext
  and advances nothing, mirroring the decode rule.

- **A length-changing edit inside a fragment group moves the group's boundaries.** The server splits
  its output at buffer-sized offsets that have nothing to do with message boundaries, so editing a
  reassembled message means deciding how the result is re-split — and the client pulls continuations
  with `NULLPOST`s whose count may then change.

  *Answered:* this is a **response**-side problem only. Requests are small and are never fragmented,
  so it does not touch the Repeater feature at all — it is confined to step 6g, editing responses in
  flight to the client, which is deliberately last. The concern is real but it holds up much less
  than it appeared to.

In short, the four-stream model needs to reason about fragment groups, not individual messages.
