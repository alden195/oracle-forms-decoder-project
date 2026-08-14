package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import oracleforms.codec.FhtEdit;
import oracleforms.codec.FhtParser;
import oracleforms.codec.FhtWriter;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.StringDictionary;
import oracleforms.codec.TestPackets;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The whole feature, end to end, with nothing stubbed but Burp itself.
 *
 * <p>"Send a captured message to Repeater, change a value, press Send, and have the server accept
 * it" is the sentence architecture &sect;6 was written to make true. Every other test in the suite
 * checks one link in that chain; this one runs the chain:
 *
 * <ol>
 *   <li>a captured session of real FHT packets, encrypted with a continuous per-direction stream
 *   <li>replay one message out of it and parse it — what the editor does
 *   <li>change a property with {@link FhtWriter} — what the user does
 *   <li>plan a tail injection — what {@link InjectionPlan} does at send time
 *   <li>decrypt and parse it as the <em>server</em> would, and check the change arrived
 *   <li>keep the real client talking afterwards, and check it still works
 * </ol>
 *
 * <p>Step 6 is the one that would be missing from a naive implementation, and it is the reason the
 * four-stream ledger exists.
 */
class RepeaterInjectionEndToEndTest {

    private static final String SESSION = "end-to-end-session";
    private static final byte[] KEY = {0x2B, (byte) 0x9F, (byte) 0xAE, 0x14, 0x60};
    private static final int LAST_PRAGMA = 30;

    /** The property the test edits: a literal string in every captured request. */
    private static final int USERNAME_ID = 0x009;

    private final FhtParser parser = new FhtParser();

    /** One real FHT request packet, with a string a tester would plausibly want to change. */
    private static byte[] requestPacket(int pragma) {
        return new TestPackets()
                .message(0x1000, 0, pragma)
                .int32Property(0x005, pragma)
                .stringProperty(USERNAME_ID, 12, "alice")
                .boolProperty(0x00A, false)
                .endProperties()
                .endPacket()
                .build();
    }

    private static byte[] responsePacket(int pragma) {
        return new TestPackets()
                .message(0x1000, 0, pragma)
                .stringProperty(0x00F, 20, "server reply for pragma " + pragma)
                .endProperties()
                .endPacket()
                .build();
    }

    /** Both parties, each with the two continuous streams the protocol gives them. */
    private static final class Party {
        final Rc4Stream requests = new Rc4Stream(KEY);
        final Rc4Stream responses = new Rc4Stream(KEY);
    }

    private record Capture(
            Map<Direction, Map<Integer, byte[]>> cipher, Map<Integer, byte[]> requestPlain) {

        PragmaSource source() {
            return PragmaSource.of(cipher);
        }
    }

    /**
     * Plays out a session between a client and a server, recording what a proxy would have captured
     * and leaving both parties' ciphers where the exchange left them.
     */
    private static Capture playSession(Party client, Party server) {
        Map<Direction, Map<Integer, byte[]>> cipher = new HashMap<>();
        cipher.put(Direction.REQUEST, new LinkedHashMap<>());
        cipher.put(Direction.RESPONSE, new LinkedHashMap<>());
        Map<Integer, byte[]> requestPlain = new LinkedHashMap<>();

        for (int pragma = 3; pragma <= LAST_PRAGMA; pragma++) {
            byte[] request = requestPacket(pragma);
            requestPlain.put(pragma, request);
            byte[] onTheWire = client.requests.applied(request);
            cipher.get(Direction.REQUEST).put(pragma, onTheWire);
            server.requests.skip(onTheWire.length);

            byte[] response = responsePacket(pragma);
            byte[] responseWire = server.responses.applied(response);
            cipher.get(Direction.RESPONSE).put(pragma, responseWire);
            client.responses.skip(responseWire.length);
        }
        return new Capture(cipher, requestPlain);
    }

    private FhtProperty property(byte[] plaintext, int id) {
        FhtPacket packet = parser.parse(plaintext, new StringDictionary());
        for (FhtMessage message : packet.messages()) {
            for (FhtProperty candidate : message.properties()) {
                if (candidate.id() == id) {
                    return candidate;
                }
            }
        }
        throw new AssertionError("no property " + id + " in the packet");
    }

    private String stringValue(byte[] plaintext, int id) {
        return ((PropertyValue.StrValue) property(plaintext, id).value()).value();
    }

    @Test
    @DisplayName("decode, edit, inject: the server reads the change and the client keeps working")
    void theWholeChain() throws Exception {
        Party client = new Party();
        Party server = new Party();
        Capture capture = playSession(client, server);

        // 1. The editor decodes a captured message by replaying the session's stream.
        StreamReplayer replayer =
                new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET);
        SessionKey key = new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
        ReplayResult replayed = replayer.replay(
                SESSION, key, Direction.REQUEST, 20, capture.source());

        ReplayResult.Decrypted decrypted =
                assertInstanceOf(ReplayResult.Decrypted.class, replayed, replayed.describe());
        assertArrayEquals(capture.requestPlain().get(20), decrypted.plaintext(),
                "the decode must reproduce what the client actually sent");
        assertEquals("alice", stringValue(decrypted.plaintext(), USERNAME_ID));

        // 2. The user changes a value. The replacement is deliberately longer than the original, so
        //    this also exercises the length change the whole four-stream model exists for.
        byte[] draft = decrypted.plaintext();
        byte[] edited = FhtWriter.applyEdits(draft, List.of(new FhtEdit(
                property(draft, USERNAME_ID), new PropertyValue.StrValue("administrator"))));
        assertNotEquals(draft.length, edited.length);
        assertEquals("administrator", stringValue(edited, USERNAME_ID));

        // 3. Send: the ledger opens at the session tail and encrypts there.
        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());
        SessionStreams streams = registry.open(SESSION, key, capture.source());
        InjectionPlan.Result.Ready ready = assertInstanceOf(InjectionPlan.Result.Ready.class,
                InjectionPlan.atTail(streams, edited));
        assertEquals(LAST_PRAGMA + 1, ready.pragma());

        // 4. The server decrypts at its own position and parses a well-formed, edited message.
        byte[] serverSaw = server.requests.applied(ready.ciphertext());
        assertArrayEquals(edited, serverSaw, "the server did not receive what we sent");

        FhtPacket serverParsed = parser.parse(serverSaw, new StringDictionary());
        assertTrue(serverParsed.outcome().isComplete(),
                "the server must see a well-formed message: " + serverParsed.outcome().describe());
        assertEquals("administrator", stringValue(serverSaw, USERNAME_ID));

        // 5. The reply comes back on the server's response stream.
        byte[] reply = responsePacket(99);
        assertArrayEquals(reply,
                streams.apply(StreamLeg.SERVER_RESPONSE, server.responses.applied(reply)));

        // 6. And the real client, which knows nothing of any of this, carries on.
        assertTrue(streams.diverged());
        for (int pragma = LAST_PRAGMA + 1; pragma <= LAST_PRAGMA + 10; pragma++) {
            byte[] clientRequest = requestPacket(pragma);
            byte[] proxySaw = streams.apply(
                    StreamLeg.CLIENT_REQUEST, client.requests.applied(clientRequest));
            assertArrayEquals(clientRequest, proxySaw,
                    "the client's pragma " + pragma + " did not decode after the injection");

            byte[] forwarded = streams.apply(StreamLeg.SERVER_REQUEST, proxySaw);
            assertArrayEquals(clientRequest, server.requests.applied(forwarded),
                    "the server could not read the client's pragma " + pragma);

            byte[] serverResponse = responsePacket(pragma);
            byte[] seen = streams.apply(
                    StreamLeg.SERVER_RESPONSE, server.responses.applied(serverResponse));
            assertArrayEquals(serverResponse, seen);
            assertArrayEquals(serverResponse, client.responses.applied(
                    streams.apply(StreamLeg.CLIENT_RESPONSE, seen)));
        }
    }

    /**
     * The same chain in offset mode, where the answer is knowable exactly: an unedited draft must
     * re-encrypt to the bytes that were captured, and an edited one must differ only from the edit
     * onwards.
     */
    @Test
    @DisplayName("offset mode reproduces the capture, and carries an edit at the same position")
    void offsetModeRoundTrip() throws Exception {
        Capture capture = playSession(new Party(), new Party());

        StreamReplayer replayer =
                new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET);
        SessionKey key = new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
        ReplayResult.Decrypted decrypted = assertInstanceOf(ReplayResult.Decrypted.class,
                replayer.replay(SESSION, key, Direction.REQUEST, 15, capture.source()));

        InjectionPlan.Result.Ready unedited = assertInstanceOf(InjectionPlan.Result.Ready.class,
                InjectionPlan.atCapturedOffset(
                        capture.source(), KEY, 15, decrypted.plaintext()));
        assertArrayEquals(capture.cipher().get(Direction.REQUEST).get(15), unedited.ciphertext(),
                "an unedited draft must re-encrypt to exactly what was captured");

        byte[] edited = FhtWriter.applyEdits(decrypted.plaintext(), List.of(new FhtEdit(
                property(decrypted.plaintext(), 0x00A), new PropertyValue.BoolValue(true))));
        InjectionPlan.Result.Ready changed = assertInstanceOf(InjectionPlan.Result.Ready.class,
                InjectionPlan.atCapturedOffset(capture.source(), KEY, 15, edited));

        assertEquals(unedited.ciphertext().length, changed.ciphertext().length,
                "flipping a boolean cannot change the length");
        List<Integer> differing = new ArrayList<>();
        for (int i = 0; i < changed.ciphertext().length; i++) {
            if (changed.ciphertext()[i] != unedited.ciphertext()[i]) {
                differing.add(i);
            }
        }
        assertEquals(1, differing.size(),
                "a boolean flip changes one header byte, so exactly one ciphertext byte moves");
    }
}
