# Features

Feature list for the Oracle Forms traffic decoder. Design detail lives in
`architecture/architecture.md`; this file tracks *what* we build and where each item stands.

See `features/improvements.md` for a survey of the extension as built and a prioritised backlog of
what should change next — including the test-coverage gap that has now let two bugs through.

> **Status: build order steps 1–5 done** (2026-08-13). The extension builds, loads, decodes
> read-only in both directions, and persists keys. Editing (step 6) and the rules tab (step 7)
> remain. Numbers in brackets map to the build order in architecture §9.

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
| Structural key validation | done | `KeyValidation` decrypts pragma 3 with the derived key and checks it parses into real property ids, against a control group of 32 random keys so it cannot rubber-stamp. Replaces the "needs the opening constant" approach, which was never actually necessary (architecture §8) |
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

## Editing

Deferred until `FhtWriter` round-trips captured samples byte for byte — re-encoding is not
trustworthy before that.

| Feature | Status | Notes |
| --- | --- | --- |
| FHT re-encoder | planned | [6] |
| Round-trip verification tests | planned | decode→encode must reproduce the original bytes [6] |
| Editable request tab | planned | [6] |
| Four-stream model for length-changing edits | planned | Separate client-facing and server-facing streams; fixes the reference's documented limitation [6] |
| Auto-modification rules tab | planned | `PROPERTY = value`, applied in transit without interception [7] |

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
| Unit tests over `codec/` and `session/` | done | 73 tests, including a synthetic-session replay suite and an end-to-end handshake→properties test. Possible because neither package imports Montoya (criterion 12). Still to do: re-run against byte-exact fixtures exported from the 22 captured sessions |
| Decoder hardened against malformed input | done | Bounded reads; bodies are untrusted (criterion 3) |
| GUI elements parented to the Burp frame | done | Criterion 10 |

## Explicitly out of scope

- **TLS decryption.** Burp's proxy already handles it. We decode Oracle's RC4 layer underneath.
- **WebSocket transport.** Only HTTP Transport (`lservlet`) is covered, matching the reference.
- **Supporting the Java 8 client runtime.** The *target application* runs on Java 8; the extension
  builds and runs on Java 21.
- **Jython compatibility.** The reference is Jython 2.7 on the legacy API; we are Java on Montoya.
