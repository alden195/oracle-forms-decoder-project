# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This is a Burp Suite Extension built on the Montoya API. The goal is an **Oracle Forms traffic decoder**: an extension that decodes the proprietary, encoded/encrypted messages exchanged between an Oracle Forms client and server, so the traffic is readable and editable inside Burp.

## Extension Goal & Domain Context

We are building a decoder for **Oracle Forms** application traffic.

- **The client** is a Java application launched via **Java Web Start** (a `.jnlp` file) and runs on **Java 8**. It is the Oracle Forms client (`frmall.jar`).
- **The transport** is Oracle Forms HTTP Transport (FHT): the client POSTs to the Forms listener servlet (path contains `lservlet`), each message carrying a `Pragma: N` sequence header. Pragma 0 is cleartext servlet info, Pragma 1 is the cleartext `GDay`/`Mate` handshake, and Pragma 3 onward are RC4-encrypted (Pragma 2 does not exist). The keystream starts at Pragma 3, offset 0, in both directions.
- **Sessions are identified by the `JSESSIONID` cookie**, never the URL on this target. Do *not* key on `JSESSIONID_FORMS` — it rotates mid-session and would shatter the RC4 stream. See `architecture/architecture.md` §3.
- **What "encrypted" means here**: a 5-byte RC4 key derived from two randoms sent *in cleartext* during the Pragma 1 handshake. The keystream is **continuous across the whole session**, with a separate stream per direction. This is not TLS — Burp's proxy already handles that layer.

The full protocol detail, including the key derivation formula, its version caveats, and what has been confirmed against a live capture, is in `architecture/architecture.md` §1.

### Test data

The Burp project reachable through the `burp` MCP server holds real traffic against this target: ~1,100 encrypted pragma POSTs across 22 sessions, each with its cleartext Pragma 1 handshake. That is the fixture source for the codec and replay tests. Note the MCP tools render bodies as escaped text, which is lossy for binary — export byte-exact fixtures from Burp itself.

### Reference implementation

We build against [3erk1n/oracle-forms-decoder](https://github.com/3erk1n/oracle-forms-decoder), a single-file Jython extension on Burp's legacy API. Its protocol research (property id table, key derivation, wire format) is the valuable part and is worth porting. Its *structure* is not: it decodes live-only into unbounded module-level dicts, does all its work on the proxy hot path, and never unloads cleanly. `architecture/architecture.md` §7 lists the specific bugs and the BApp criteria it would fail — **read that before copying anything from it**.

### Key implementation considerations

The full design rationale lives in `architecture/architecture.md`; the constraints that shape it are:

- **Stored keys are necessary but not sufficient.** Because the RC4 stream is continuous, decoding message N requires replaying the cipher over all preceding messages in that direction. Persisting the key plus replaying from proxy history is what makes previously captured traffic readable — this is the project's headline feature.
- **Untrusted input**: message bodies come from the tested application. Parse defensively with bounded reads, and never deserialize attacker-controlled data into live Java objects (criterion 3).
- **Threading**: capture keys on the proxy hot path and nothing else; decode on a background executor, never on the EDT (criterion 5).
- **Bounded state**: every cache is an LRU and holds no long-term references to Burp objects (criterion 9).
- **No Java 8 constraint on the extension**: the *target application* runs on Java 8, but the extension itself builds and runs on Java 21 (see the toolchain below).

## Architecture

- **Main Entry Point**: `src/main/java/Extension.java` - implements `BurpExtension` interface
- **Build System**: Gradle with Kotlin DSL, Java 21 compatibility
- **Dependencies**: Montoya API 2026.7 (compile-only), no runtime dependencies
- **Extension Pattern**: Single-class extension that initializes through `initialize(MontoyaApi montoyaApi)` method

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` and can be loaded directly into Burp Suite.

## Extension Loading in Burp

1. Build the JAR using `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Documentation Structure

Project design docs (maintain these as the code evolves):

- See @architecture/architecture.md for the extension's architecture and layering
- See @features/features.md for the feature list and its current status
- Record every notable change in `changes/changes.md`, newest first, including *why*

Reference docs (background, not maintained by us):

- See @docs/bapp-store-requirements.md for BApp Store submission requirements
- See @docs/montoya-api-examples.md for code patterns and extension structure  
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links

## Current State

**Build order steps 1–5 are implemented** (`architecture/architecture.md` §9). The extension is called "Oracle Forms Decoder", builds to a loadable jar, and works read-only: it captures keys from live Pragma 1 handshakes, persists them to the Burp project file, and decodes any captured message on demand by replaying the RC4 stream from proxy history. 73 unit and integration tests pass (`./gradlew test`).

- `Extension.java` is a thin shell over `oracleforms.burp.OracleFormsDecoder`, which does the wiring and unloading.
- `codec/` and `session/` have no Burp imports and are directly unit-tested.
- `burp/` holds everything Montoya-facing: handler, persistence, history, editors, Sessions tab.

**What remains:** step 6 (`FhtWriter`, round-trip tests, then editing and the four-stream model) and step 7 (rules tab).

**Two things to know before continuing:**

1. **Key derivation is not yet validated against real traffic.** The Pragma 3 self-test described in the original §1 turned out to be vacuous — it passes for any key, right or wrong (see `changes/changes.md`, 2026-08-13). What replaced it validates the *stream-start assumption* without a key, but validating the *key* needs the 4-byte FHT opening constant, whose value is still unknown. Recovering it is the blocker; `Pragma3SelfTest.recoverOpeningConstant` run across the 22 captured sessions is the cheapest path.
2. **All tests run against synthetic sessions, not the real capture.** They prove the code is self-consistent, not that the protocol assumptions are right. Byte-exact fixtures still need exporting from Burp — the MCP server renders bodies as escaped text and is lossy for binary.