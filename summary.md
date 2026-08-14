# Oracle Forms Traffic Decoder — Technical Summary

A Burp Suite extension that makes encrypted Oracle Forms application traffic readable and, in
particular, makes *previously captured* traffic readable.

Written for a reader who knows software engineering and security testing in general, but not Oracle
Forms or Burp's extension API specifically.

| | |
| --- | --- |
| **Language / platform** | Java 21, Burp Suite Montoya API 2026.7, Gradle (Kotlin DSL) |
| **Size** | 8,439 lines of main source across 64 files; 4,552 lines of tests across 24 files |
| **Tests** | 185, all passing |
| **Status** | Decoding and Repeater sending complete (architecture §6, steps 6a–6e); session bootstrap, response editing and rule-based modification not yet built |

---

## 1. The problem

**Oracle Forms** is a legacy enterprise application platform, still widely deployed in universities,
government and banking. The client is a Java application launched from a `.jnlp` file; the server is
a servlet. Between them they speak a proprietary binary protocol called **Oracle Forms HTTP
Transport (FHT)**, and that protocol is **encrypted with RC4** underneath whatever TLS the site uses.

This matters for security testing. A tester using an intercepting proxy such as Burp Suite can see
the TLS-decrypted HTTP requests, but the bodies are opaque binary:

```
POST /forms/lservlet HTTP/1.1
Pragma: 8
Content-Length: 22

¹Eà G#Ð?ÿIvdHÏ@lyÊªJ^m
```

Every meaningful thing a tester wants to examine — field values, submitted credentials, server
responses, authorisation decisions — is inside that blob. Without decoding it, the application is
effectively untestable through a proxy: you cannot read the traffic, cannot search it, and cannot
modify it.

The encryption here is **not** a transport security control. It is a 40-bit RC4 key derived from two
random values that the client and server exchange **in cleartext** during a handshake. Anyone who
can observe the connection can derive the key. It is obfuscation, not protection — which is exactly
why decoding it is a legitimate and useful capability for an authorised tester.

---

## 2. The central technical difficulty

The single fact that shapes the entire design:

> **The RC4 keystream is continuous across the whole session, not reset per message.**

RC4 is a stream cipher. It produces a pseudorandom byte sequence which is XORed with the plaintext.
Because Oracle Forms never re-initialises the cipher between messages, the keystream runs
continuously from the first encrypted message to the last, with one independent stream per direction.

The consequence is that **RC4 has no random access**. Knowing the key is not enough to decrypt
message 42:

```
Session keystream, request direction (one continuous RC4 stream)

  pragma:      3         4        5        6         7
  body:   [--145B--][--88B--][--12B--][--18B--][--20B--] ...
  offset: 0        145      233      245      263      283
                                                  ^
                        to decrypt pragma 7 the cipher must
                        first be advanced over pragmas 3-6
```

To read pragma 7 you must re-run the cipher over every byte of pragmas 3–6 first. To read pragma 42
you must replay 3–41.

This is why simply storing the key does not solve the problem, and it is the reason the project has
the architecture it does.

---

## 3. The key design decision

There is an existing open-source decoder for this protocol (`3erk1n/oracle-forms-decoder`), a
single-file Python extension for Burp's legacy API. Its protocol research is valuable and was ported.
Its *structure* was deliberately not.

That implementation **decodes live and only live**. It decrypts inside the proxy listener as traffic
flows and stores the formatted text in dictionaries in memory. Two consequences follow:

- Traffic that did not flow through the proxy while the extension was loaded can never be decoded.
- Reloading the extension, or reopening the project, loses every key and every decode. Existing
  proxy history becomes permanently opaque.

This project inverts that model:

> **Capture keys eagerly and persist them. Decode lazily, on demand, by replaying the keystream.**

The key is captured on the proxy hot path and written to Burp's project file, so it survives
extension reloads and Burp restarts. Decoding happens later, when the user actually asks to view a
message, by replaying the stream from the start of the session.

This is what makes the headline capability possible: **traffic captured before the extension was even
installed can be decoded**, because the key can be recovered retroactively by scanning proxy history
for handshakes, and the plaintext reconstructed by replay.

It also yields a diagnostic the live-only model cannot produce. If a message is missing from history,
the tool reports *which* pragma is missing — "Pragma 17 was not captured, so 18 onward cannot be
decoded" — rather than showing a blank tab.

---

## 4. How it works

### 4.1 Message flow

```
   Proxied request
         │
         ▼
   ┌───────────────────────────────────────────────┐
   │ Detection (runs on EVERY request)             │
   │   1. path contains "lservlet"?      cheapest  │
   │   2. numeric "Pragma" header?                 │
   │   3. JSESSIONID cookie resolvable?  costliest │
   └───────────────────────────────────────────────┘
         │ yes
         ▼
   ┌───────────────────────────────────────────────┐
   │ Hot path: capture the key ONLY                │
   │   Pragma 1 request  -> client random (GDay)   │
   │   Pragma 1 response -> server random (Mate)   │
   │   derive 5-byte key -> persist to project     │
   └───────────────────────────────────────────────┘

   ... later, when the user opens a message ...

   ┌───────────────────────────────────────────────┐
   │ Background executor (never the UI thread)     │
   │                                               │
   │   key from store ──┬─ absent  -> explain,     │
   │                    │            offer manual  │
   │                    │            entry / scan  │
   │                    └─ present -> nearest      │
   │                                  checkpoint   │
   │                         │                     │
   │                         ▼                     │
   │              replay intervening pragmas       │
   │                         │                     │
   │            ┌────────────┴───────────┐         │
   │            ▼                        ▼         │
   │      gap detected            complete         │
   │      "Pragma N missing"      decrypt target   │
   │                                   │           │
   │                                   ▼           │
   │                          parse FHT -> render  │
   └───────────────────────────────────────────────┘
```

### 4.2 Key derivation

During the handshake the client sends the 8 bytes `GDay` + a 4-byte random; the server replies
`Mate` + a 4-byte random. Both are cleartext. The 5-byte RC4 key is assembled from selected bytes of
those two randoms plus one hard-coded constant:

```
key[0] = (client_random >> 8)  & 0xFF
key[1] = (server_random >> 4)  & 0xFF
key[2] = 0xAE                          // constant
key[3] = (client_random >> 16) & 0xFF
key[4] = (server_random >> 12) & 0xFF
```

40 bits, from values sent in the clear. The derivation is isolated behind an interface so that a
different scheme (Oracle Forms 12c may differ) can be added without touching anything else.

### 4.3 Checkpointing — making replay affordable

Naive replay is O(n) per message and therefore **O(n²) to browse a whole session**. A 1,000-message
session would become unusable.

The solution is to snapshot the cipher state periodically. An RC4 state is small — a 256-byte
permutation plus two indices — so a checkpoint every 25 messages costs little and turns browsing back
into roughly linear time.

The checkpoint cache is bounded in two dimensions (how many streams, how many checkpoints per
stream). When a stream is full it is **thinned** — every second checkpoint dropped — rather than
truncated. Discarding the oldest would be counterproductive: early checkpoints are what make the
*start* of a session cheap to reach, and they are the most expensive to rebuild.

### 4.4 Parsing

The decrypted plaintext is a proprietary binary format: a sequence of messages, each with an action,
a class id, a handler id, and a list of properties. Property names come from a table of **466
identifiers** ported from the reference implementation; **9** are flagged as sensitive (credential
fields) and highlighted.

The parser is written defensively, because message bodies come from the application under test and
are therefore untrusted input. All reads are bounded, and the result is an explicit outcome —
*complete*, *truncated at byte offset N*, or *failed* — never a silent partial result presented as a
whole one.

---

## 5. Three problems discovered from real traffic

These were not in the reference implementation or in any documentation. Each was found by reading
actual captured traffic, and each silently corrupts decoding.

### 5.1 Session identity

Sessions must be keyed correctly or the continuous stream shatters. The target sets **two** session
cookies:

| Cookie | Behaviour | Usable as session id? |
| --- | --- | --- |
| `JSESSIONID` | constant for the session | **Yes** |
| `JSESSIONID_FORMS` | rotates every few messages | **No** |

Keying on the rotating cookie would split one continuous RC4 stream into dozens of fragments, each
missing the handshake that carries its key — presenting as "no key for this session" on almost every
message.

A further subtlety: the request that *establishes* a session still carries the **previous** session's
cookie, because the new one is assigned in its response. That message must therefore be identified
from its response, not its request. And which message that is varies by client: the Java Web Start
launcher numbers it Pragma 0, while the applet client numbers it Pragma 1 — the same number as the
handshake.

### 5.2 `NULLPOST` — a cleartext control message

When the server has more data to send than fits in one HTTP response, the client keeps the exchange
going by POSTing the literal ASCII bytes `NULLPOST`. This body is written straight to the socket and
**never passes through the cipher**.

It must therefore contribute **zero** bytes to the keystream. Treating it as ordinary ciphertext
advances the stream by 8 bytes that the real client never consumed. In one captured session three
consecutive `NULLPOST`s meant every subsequent request decrypted 24 bytes out of position — producing
noise, silently.

### 5.3 Response fragmentation

Those `NULLPOST`s exist because a large response is **split across several HTTP exchanges**:

```
pragma  request         response        meaning
  7     (real, 20 B)    66,000 bytes  ─┐
  8     NULLPOST        66,000 bytes   │  ONE logical message
  9     NULLPOST        66,000 bytes   │  of 218,892 bytes
 10     NULLPOST        20,892 bytes  ─┘
 11     (real, 20 B)         2 bytes     next message
```

The cipher runs continuously across these, so each fragment *decrypts* correctly in isolation. But
every fragment after the first **begins in the middle of a binary structure**, so parsing one alone
produces convincing-looking nonsense.

This is a subtle failure mode worth dwelling on: the symptom looked like a decryption failure, but
decryption was entirely correct. The bug was in *framing* — deciding where a message begins and ends.

The fix rejoins fragments before parsing. The grouping rule keys on the `NULLPOST` sentinel —
*response N+1 continues response N if and only if request N+1 is a `NULLPOST`* — rather than on the
66,000-byte size, so it does not depend on how the server's buffer happens to be configured.

---

## 6. Verification methodology

This is the part of the project with the most transferable content, because it is a case study in a
test that looked rigorous and was worthless.

### 6.1 A test that could not fail

The original design proposed this check on key correctness:

> Decrypt the first four bytes of the Pragma 3 request and of the Pragma 3 response. If they do not
> match, the key is wrong.

The premise was an observation that those two ciphertexts are identical. But both directions are
seeded from the same key and both sit at keystream offset 0, so both prefixes are XORed with the
**same** keystream bytes. Decrypting two identical ciphertexts with the same keystream always yields
two identical plaintexts — *whatever the keystream is*.

A completely wrong key produces two identical wrong prefixes and passes. **The test had no
discriminating power at all.** It was caught by writing a unit test that deliberately fed it a wrong
key and observed it pass.

The useful content survived, but split in two: comparing the *raw ciphertexts* validates the
architectural assumption that both directions share a key and a starting position (and needs no key
at all); checking a *decrypted* prefix against a known constant is the only form that can falsify a
key.

### 6.2 Replacing it with something falsifiable

The project then treated an unknown 4-byte constant as a blocker for validating key derivation at
all. That premise was also wrong.

A 4-byte constant is a 32-bit oracle. **The parser is a far stronger one.** A correct key turns a
message into well-formed FHT — valid headers, property identifiers drawn from a 466-entry table, type
markers from a small set, string lengths that land inside the buffer. A wrong key yields uniform
random bytes. Asking *"does it parse, and are the identifiers real?"* tests hundreds of bits of
structure instead of 32, and requires nothing known in advance.

To prevent this from becoming a rubber stamp, every check runs against a **control group of 32 random
keys** on the same ciphertext, and the verdict is comparative: the derived key must out-parse every
control. There is no hand-tuned threshold standing between a wrong answer and a pass.

Measured separation:

| | Known property identifiers |
| --- | --- |
| Correct key | 100% |
| Wrong key | 16–24% |
| Random keys | 16–24% |

Two intuitive metrics were tried and rejected, both recorded in the code because they look plausible:

- **Bytes parsed before failure** — a poor discriminator. The parser is deliberately lenient, so
  random bytes routinely walk *further* through a body than a short well-formed message does.
- **Hit rate alone** — noisy at small sample sizes. A control that stumbles onto a single real
  identifier scores a perfect 1.0 and ties a genuine decryption that found seven of seven.

### 6.3 Mutation testing

Passing tests prove nothing unless they can fail. Each significant fix was verified by deliberately
reverting it and confirming the relevant tests broke:

| Reverted change | Tests that failed |
| --- | --- |
| `NULLPOST` zero-length keystream advance | 2 |
| Response fragment reassembly | 3 |
| Correct key derivation (via a synthetic wrong-key fixture) | end-to-end validation suite |

One such run initially appeared to pass, which turned out to be a compilation error hidden by the
command used to filter output — a reminder that a green result must be confirmed to be a real one.

---

## 7. Software engineering properties

The extension is written against Burp's published acceptance criteria for third-party extensions.

**Layered for testability.** The `codec` and `session` packages contain no Burp imports at all — they
receive plain byte arrays and values. This is what allows the protocol logic, where the subtle bugs
live, to be unit-tested without a running Burp instance. Only the `burp` package touches the vendor
API.

```
   burp/        <- Montoya API, UI, persistence, proxy history
     │  depends on
     ▼
   session/     <- keys, replay, checkpoints      no Burp imports
     │  depends on
     ▼
   codec/       <- RC4, binary parser, id table   no Burp imports
```

**Threading discipline.** Slow work must never run on the proxy path (it would delay the user's
browsing) or on the Swing event thread (it would freeze the UI). Key capture — a handful of byte
reads — is the only thing on the proxy path. All decoding happens on a background executor, and the
editor shows a pending state and repaints when the result arrives. A generation counter discards
results that arrive after the user has moved to another message.

**Bounded memory.** Burp projects can be very large. Every cache is a bounded LRU, and none holds
long-term references to Burp objects. The reference implementation's equivalent caches grew without
limit.

**Clean shutdown.** All registrations are deregistered, executors stopped and caches cleared on
unload — and the teardown is safe to call twice, because Burp can unload an extension that failed
partway through loading.

---

## 8. Current status and honest limitations

**Working:** detection, live key capture, persistence across restarts, retroactive key recovery from
history, on-demand decoding in both directions with gap reporting, fragment reassembly, sensitive
value highlighting, and a session management interface with manual key entry and import/export.

**Not yet built:** message *editing*, and sending a modified message from **Repeater**. Re-encoding
requires a writer that can reproduce captured messages byte for byte, because any length change shifts
the keystream position for every later message in the session. Shipping editing before that is
verified would corrupt sessions.

A full design for both now exists in `architecture/architecture.md` §6 but is not implemented. Its
core claim: maintaining separate cipher states toward the client and toward the server covers a
Repeater injection as well as an edit — an injected message has length zero as far as the real client
is concerned and length *n* as far as the server is concerned, which is the same asymmetry an edit
creates. §6.8 breaks the work into seven gated sub-steps, and §6.7 lists the five questions about the
server that only a live target can answer.

**The most important limitation:** the key derivation formula is **not yet validated against real
captured bytes**. Every test to date builds its own session using the same formula it is checking, so
those tests prove the implementation is self-consistent — not that the formula is correct. If the
formula were wrong, they would all still pass.

The machinery to settle this now exists and is proven capable of failing: an export function dumps
byte-exact handshake material from inside the extension, and a test runs the control-group validation
against it. It was verified end-to-end by generating one fixture encrypted with the derived key and
another encrypted with an unrelated key, and confirming the suite passes on the first and fails on
the second. **Running it against the real capture is the immediate next step.**

Being able to state precisely what has and has not been demonstrated is, arguably, the more important
outcome than the decoder itself.

---

## 9. Suggested demonstration

1. Show a captured Oracle Forms request in Burp — an opaque binary body.
2. Open the extension's tab on the same message — the decoded property list.
3. Show the Sessions tab: stored keys, persisted in the project file.
4. Reload the extension, or restart Burp, and decode the same message again — demonstrating that
   persistence plus replay makes historical traffic readable, which the existing tool cannot do.
5. Show a fragmented response (pragmas 7–10 in the capture) reassembled into one message, with the
   tool stating which pragmas it joined.
6. Run `./gradlew test` — 185 tests.
