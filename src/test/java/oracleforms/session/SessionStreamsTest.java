package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The four-stream claim, tested the only way it can be: by simulating all three parties.
 *
 * <p>Architecture &sect;6.2 asserts that injecting a message the real client never sent leaves that
 * client's session working, because the client-facing and server-facing ciphers are separate and each
 * stays where its own counterpart thinks it is. That is not something a unit test of the cipher can
 * show. So these tests stand up an independent {@code client} and {@code server}, each with their own
 * continuous per-direction RC4 stream exactly as the real ones have, and put the ledger between them.
 *
 * <p>If the model is wrong, {@link #injectionLeavesTheLiveClientWorking} fails.
 */
class SessionStreamsTest {

    private static final String SESSION = "ledger-test-session";
    private static final byte[] KEY = {0x33, (byte) 0xCD, (byte) 0xAE, 0x22, (byte) 0xBC};

    /** One end of the conversation, holding the two continuous streams the protocol gives it. */
    private static final class Party {
        final Rc4Stream requests = new Rc4Stream(KEY);
        final Rc4Stream responses = new Rc4Stream(KEY);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private final Party client = new Party();
    private final Party server = new Party();
    private final SessionStreams streams = SessionStreams.atOrigin(SESSION, KEY);

    /** The client sends a message; returns what the server ends up reading. */
    private byte[] clientToServer(byte[] plaintext) {
        byte[] onTheWire = client.requests.applied(plaintext);
        byte[] proxySees = streams.apply(StreamLeg.CLIENT_REQUEST, onTheWire);
        byte[] forwarded = streams.apply(StreamLeg.SERVER_REQUEST, proxySees);
        return server.requests.applied(forwarded);
    }

    /** As above, but the proxy replaces the body with something of a different length. */
    private byte[] clientToServerEdited(byte[] plaintext, byte[] replacement) {
        byte[] onTheWire = client.requests.applied(plaintext);
        streams.apply(StreamLeg.CLIENT_REQUEST, onTheWire);
        byte[] forwarded = streams.apply(StreamLeg.SERVER_REQUEST, replacement);
        return server.requests.applied(forwarded);
    }

    /** The server replies; returns what the client ends up reading. */
    private byte[] serverToClient(byte[] plaintext) {
        byte[] onTheWire = server.responses.applied(plaintext);
        byte[] proxySees = streams.apply(StreamLeg.SERVER_RESPONSE, onTheWire);
        byte[] forwarded = streams.apply(StreamLeg.CLIENT_RESPONSE, proxySees);
        return client.responses.applied(forwarded);
    }

    /** A message the extension originates: it reaches the server, and the client never learns of it. */
    private byte[] inject(byte[] plaintext) {
        byte[] onTheWire = streams.apply(StreamLeg.SERVER_REQUEST, plaintext);
        return server.requests.applied(onTheWire);
    }

    /** The reply to an injected message: consumed by the extension, never forwarded on. */
    private byte[] consumeInjectedReply(byte[] plaintext) {
        byte[] onTheWire = server.responses.applied(plaintext);
        return streams.apply(StreamLeg.SERVER_RESPONSE, onTheWire);
    }

    private void exchange(int count) {
        for (int i = 0; i < count; i++) {
            assertArrayEquals(ascii("request " + i), clientToServer(ascii("request " + i)));
            assertArrayEquals(ascii("response " + i + " with some padding"),
                    serverToClient(ascii("response " + i + " with some padding")));
        }
    }

    // ---- the claim ------------------------------------------------------------------------

    @Test
    @DisplayName("an injected message reaches the server and leaves the live client working")
    void injectionLeavesTheLiveClientWorking() {
        exchange(8);
        assertFalse(streams.diverged(), "watching traffic must not move the legs apart");

        byte[] injected = ascii("INJECTED FROM REPEATER, a length nobody expected");
        assertArrayEquals(injected, inject(injected),
                "the server must read the injected message correctly");
        assertArrayEquals(ascii("reply to the injection"),
                consumeInjectedReply(ascii("reply to the injection")));

        assertTrue(streams.diverged(), "the server legs are now ahead of the client legs");
        assertEquals(injected.length,
                streams.consumed(StreamLeg.SERVER_REQUEST)
                        - streams.consumed(StreamLeg.CLIENT_REQUEST));

        // The whole point: the real client knows nothing of the injection and carries on from its
        // own position. Both directions must still work, for the rest of the session.
        for (int i = 0; i < 12; i++) {
            assertArrayEquals(ascii("after injection " + i),
                    clientToServer(ascii("after injection " + i)),
                    "the client's request desynchronised at message " + i);
            assertArrayEquals(ascii("server still talking " + i),
                    serverToClient(ascii("server still talking " + i)),
                    "the server's response desynchronised at message " + i);
        }
    }

    @Test
    @DisplayName("several injections in a row each land, and the client still survives")
    void repeatedInjectionsAccumulate() {
        exchange(4);
        for (int i = 0; i < 5; i++) {
            byte[] injected = ascii("injection number " + i + " of differing length" + "x".repeat(i));
            assertArrayEquals(injected, inject(injected));
            consumeInjectedReply(ascii("ack " + i));
        }
        exchange(6);
    }

    @Test
    @DisplayName("a length-changing edit keeps both sides consistent")
    void lengthChangingEditIsAbsorbed() {
        exchange(3);

        byte[] sent = ascii("username=alice");
        byte[] rewritten = ascii("username=administrator-with-a-much-longer-name");
        assertArrayEquals(rewritten, clientToServerEdited(sent, rewritten),
                "the server must read the replacement, not the original");

        assertTrue(streams.diverged());
        exchange(10);
    }

    @Test
    @DisplayName("an edit that shortens the body works the same way")
    void shorteningEditIsAbsorbed() {
        exchange(3);
        assertArrayEquals(ascii("x"),
                clientToServerEdited(ascii("a considerably longer original body"), ascii("x")));
        exchange(5);
    }

    // ---- NULLPOST -------------------------------------------------------------------------

    @Test
    @DisplayName("a NULLPOST passes through cleartext and consumes no keystream")
    void nullPostContributesNothing() {
        exchange(2);
        long before = streams.consumed(StreamLeg.SERVER_REQUEST);

        byte[] passedThrough = streams.apply(StreamLeg.SERVER_REQUEST, PragmaBody.NULL_POST.clone());

        assertArrayEquals(PragmaBody.NULL_POST, passedThrough, "it must not be encrypted");
        assertEquals(before, streams.consumed(StreamLeg.SERVER_REQUEST),
                "advancing over its eight bytes would desynchronise every later request");
        exchange(4);
    }

    @Test
    @DisplayName("those same eight bytes in the response direction are treated as ciphertext")
    void nullPostIsRequestDirectionOnly() {
        byte[] out = streams.apply(StreamLeg.SERVER_RESPONSE, PragmaBody.NULL_POST.clone());
        assertFalse(java.util.Arrays.equals(PragmaBody.NULL_POST, out),
                "the server never sends the sentinel; a collision must not be mistaken for it");
        assertEquals(PragmaBody.NULL_POST.length, streams.consumed(StreamLeg.SERVER_RESPONSE));
    }

    // ---- persistence ----------------------------------------------------------------------

    @Test
    @DisplayName("four counters are enough to rebuild a diverged ledger exactly")
    void divergenceSurvivesRebuildingFromCounters() {
        exchange(6);
        inject(ascii("an injection before the reload"));
        consumeInjectedReply(ascii("its reply"));
        exchange(2);

        StreamPositions saved = streams.positions();

        // Everything the extension held in memory is gone; only the four numbers survived.
        SessionStreams reloaded = SessionStreams.resumedAt(SESSION, KEY, saved);
        for (StreamLeg leg : StreamLeg.values()) {
            assertEquals(streams.consumed(leg), reloaded.consumed(leg));
        }
        assertTrue(reloaded.diverged());

        // And the conversation continues through the rebuilt ledger without a hiccup.
        byte[] plaintext = ascii("sent after the extension reloaded");
        byte[] onTheWire = client.requests.applied(plaintext);
        byte[] proxySees = reloaded.apply(StreamLeg.CLIENT_REQUEST, onTheWire);
        assertArrayEquals(plaintext, proxySees);
        assertArrayEquals(plaintext,
                server.requests.applied(reloaded.apply(StreamLeg.SERVER_REQUEST, proxySees)));
    }

    @Test
    @DisplayName("a ledger opened at a session's tail decrypts what comes next")
    void atTailResumesMidSession() {
        // Fast-forward both parties as if 40 messages had already been exchanged unobserved.
        byte[] filler = new byte[1000];
        client.requests.skip(filler.length);
        server.requests.skip(filler.length);

        SessionStreams opened = SessionStreams.atTail(SESSION, KEY,
                new SessionTail(42, filler.length, 42, 0));
        assertFalse(opened.diverged(), "a session opened from history has never diverged");

        byte[] plaintext = ascii("the first message the extension actually sees");
        byte[] proxySees = opened.apply(StreamLeg.CLIENT_REQUEST, client.requests.applied(plaintext));
        assertArrayEquals(plaintext, proxySees);

        // Forwarding is two steps, and between them the legs legitimately disagree. Only a completed
        // forward is a state worth persisting -- see StreamRegistry.checkpoint.
        assertTrue(opened.diverged(), "mid-forward, the client leg has moved and the server leg has not");
        assertArrayEquals(plaintext,
                server.requests.applied(opened.apply(StreamLeg.SERVER_REQUEST, proxySees)));
        assertFalse(opened.diverged(), "a completed forward leaves the legs level again");
    }

    @Test
    @DisplayName("an empty body neither moves the stream nor throws")
    void emptyBodiesAreInert() {
        assertEquals(0, streams.apply(StreamLeg.SERVER_REQUEST, new byte[0]).length);
        assertEquals(0, streams.consumed(StreamLeg.SERVER_REQUEST));
        streams.advance(StreamLeg.SERVER_REQUEST, 0);
        assertEquals(0, streams.consumed(StreamLeg.SERVER_REQUEST));
    }

    @Test
    @DisplayName("a detached cipher encrypts without committing the ledger")
    void speculativeEncryptionDoesNotAdvance() {
        exchange(2);
        long before = streams.consumed(StreamLeg.SERVER_REQUEST);

        byte[] speculative = streams.cipherAt(StreamLeg.SERVER_REQUEST).applied(ascii("maybe"));
        assertEquals(before, streams.consumed(StreamLeg.SERVER_REQUEST),
                "a send that might still be refused must not move the shared position");

        // Committing afterwards produces the identical bytes.
        assertArrayEquals(speculative, streams.apply(StreamLeg.SERVER_REQUEST, ascii("maybe")));
        assertEquals(before + 5, streams.consumed(StreamLeg.SERVER_REQUEST));
    }
}
