# Oracle Forms Decoder

A Burp Suite extension that decodes the encrypted, proprietary binary traffic exchanged between an
Oracle Forms client and server, so it can be read inside Burp — including traffic that was captured
**before the extension was installed**.

Built on the Montoya API, Java 21.

---

## Why

Oracle Forms is a legacy enterprise application platform still widely deployed in universities,
government and banking. Its client and server speak a proprietary binary protocol (Oracle Forms HTTP
Transport, "FHT") which is RC4-encrypted underneath whatever TLS the site uses. A tester with an
intercepting proxy sees only opaque binary:

```
POST /forms/lservlet HTTP/1.1
Pragma: 8
Content-Length: 22

<22 bytes of ciphertext>
```

Everything worth examining — submitted values, credentials, server responses, authorisation
decisions — is inside that blob. This extension makes it readable.

The RC4 layer is not a transport security control: the 40-bit key is derived from two random values
the client and server exchange **in cleartext** during a handshake. It is obfuscation, and decoding it
is a normal part of assessing one of these applications.

---

## What makes it different

The one existing open-source decoder for this protocol decodes **live and only live** — it decrypts
inside the proxy listener and keeps the result in memory. Anything that did not flow through the
proxy while it was loaded can never be decoded, and reloading the extension loses everything.

This extension inverts that:

> **Capture keys eagerly and persist them. Decode lazily, on demand, by replaying the keystream.**

Keys are written to the Burp project file, so they survive extension reloads and Burp restarts, and
keys for old sessions can be recovered by scanning existing proxy history. That is what makes
historical traffic readable.

This is harder than it sounds, because **the RC4 keystream is continuous across a whole session**
rather than reset per message. Knowing the key does not let you decrypt message 42 — the cipher must
first be advanced over messages 3 to 41. The extension does that by replay, with periodic cipher-state
checkpoints so that browsing a session stays roughly linear instead of quadratic.

Full explanation in [`summary.md`](summary.md).

---

## Authorised use only

This is a security testing tool. Use it only against systems you own or have explicit written
permission to test.

**It handles secrets in the clear.** Session keys are stored unencrypted in the Burp project file,
which is a deliberate and reasonable trade-off for a pentest tool — the traffic those keys protect
already contains plaintext credentials — but it should be a known choice rather than a surprise. The
Sessions tab provides "Forget session" and "Clear all keys" for this reason.

The two export features write secrets to disk:

| Export | Contains |
| --- | --- |
| `oracle-forms-keys.json` | the 5-byte RC4 key for each session |
| `oracle-forms-fixtures.json` | the handshake randoms the keys are derived from |

Both are enough to decrypt the traffic they came from. Both are listed in `.gitignore`; treat them as
credential material.

---

## Requirements

- JDK 21
- Burp Suite (Community or Professional) with Montoya API support

No runtime dependencies — the Montoya API is `compileOnly` and provided by Burp.

## Build

```bash
./gradlew jar
```

The extension JAR is written to `build/libs/`.

```bash
./gradlew test     # 104 unit and integration tests
./gradlew build    # compile + test
```

## Install

1. Build the JAR.
2. In Burp: **Extensions → Installed → Add**, select **Java**, choose `build/libs/*.jar`.
3. An **Oracle Forms** suite tab appears, plus an **Oracle Forms** tab on Forms requests and
   responses.

For quick reloading during development, Ctrl/⌘-click the extension's *Loaded* checkbox.

---

## Usage

**Live traffic.** Load the extension, then use the target application through Burp. Keys are captured
automatically from each session's handshake. Open any Forms message and select the *Oracle Forms* tab
to see it decoded.

**Traffic captured earlier.** Open the **Oracle Forms** suite tab and run **Scan history for keys**.
This walks the existing proxy history, recovers a key for every session whose handshake was captured,
and stores it. Those sessions are then decodable.

**Traffic captured elsewhere.** If you obtained a key by other means, paste it with **Add key
manually**.

If a message cannot be decoded the tab explains why rather than showing nothing — most usefully, it
reports *which* pragma is missing from history when a gap makes replay impossible.

---

## Project layout

The dependency arrow points one way. `codec` and `session` contain **no Burp imports at all**, which
is what allows the protocol logic — where the subtle bugs live — to be unit-tested without a running
Burp instance.

```
src/main/java/oracleforms/
  codec/      RC4 stream, FHT binary parser, 466-entry property id table
  session/    key derivation, stream replay, checkpoints, key store, validation
  burp/       everything Montoya-facing: handler, persistence, history, editors, UI
```

## Documentation

| File | Contents |
| --- | --- |
| [`summary.md`](summary.md) | How the extension works, end to end. Start here. |
| [`architecture/architecture.md`](architecture/architecture.md) | Protocol facts, design rationale, open questions |
| [`features/features.md`](features/features.md) | Feature status |
| [`features/improvements.md`](features/improvements.md) | Review of the built extension and prioritised backlog |
| [`changes/changes.md`](changes/changes.md) | Change log, newest first, with reasoning |

---

## Status

**Working:** detection, live key capture, persistence across restarts, retroactive key recovery,
on-demand decoding in both directions, gap reporting, reassembly of responses split across messages,
sensitive-value highlighting, and session management with import/export.

**Not yet built:** message editing. Re-encoding requires a writer that reproduces captured messages
byte for byte, because any length change shifts the keystream position for every later message in the
session; shipping it before that is verified would corrupt sessions.

**Known limitation:** the key derivation formula is not yet validated against real captured bytes.
The existing tests build their sessions with the same formula they check, so they demonstrate
self-consistency rather than correctness. The machinery to settle this exists — see the validation
section of [`summary.md`](summary.md) — and running it against a real capture is the next step.

---

## Credits

Protocol research (the property id table, key derivation formula and wire format) is ported from
[`3erk1n/oracle-forms-decoder`](https://github.com/3erk1n/oracle-forms-decoder), a Jython extension
for Burp's legacy API. The structure here is a deliberate rewrite; `architecture/architecture.md` §7
documents the specific issues that motivated it.
