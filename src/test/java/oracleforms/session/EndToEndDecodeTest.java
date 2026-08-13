package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.OptionalInt;
import oracleforms.codec.FhtParser;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.StringDictionary;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The whole non-Burp pipeline in one test: a cleartext handshake yields a key, the key plus history
 * yields a keystream position, and that yields readable properties.
 *
 * <p>Everything the extension does to a captured session happens here except talking to Burp, so a
 * regression anywhere in {@code codec} or {@code session} shows up as a failure in this one place.
 */
class EndToEndDecodeTest {

    private static final String SESSION_ID = "HpCezl7mViVlVAFCN4h69BEX2t1E!-1111111111";
    private static final int CLIENT_RANDOM = 0x07E5A020;
    private static final int SERVER_RANDOM = 0x2FBCD219;

    /** Builds one FHT message carrying a string and an int property. */
    private static byte[] packet(int handlerId, String text, int number) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x10);                                   // UPDATE, class 0, 1-byte header
        out.write(handlerId >> 8);
        out.write(handlerId & 0xFF);

        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        out.write(0x40);                                   // string property, id 1
        out.write(0x01);
        out.write(0x00);                                   // dictionary slot
        out.write(bytes.length >> 8);
        out.write(bytes.length & 0xFF);
        out.writeBytes(bytes);

        out.write(0x00);                                   // int property, id 5
        out.write(0x05);
        out.write(number >> 24);
        out.write(number >> 16);
        out.write(number >> 8);
        out.write(number);

        out.write(0xF0);                                   // end of properties
        out.write(0xF0);                                   // end of packet
        return out.toByteArray();
    }

    private static byte[] handshake(String magic, int random) {
        byte[] out = new byte[8];
        System.arraycopy(magic.getBytes(StandardCharsets.US_ASCII), 0, out, 0, 4);
        out[4] = (byte) (random >> 24);
        out[5] = (byte) (random >> 16);
        out[6] = (byte) (random >> 8);
        out[7] = (byte) random;
        return out;
    }

    @Test
    @DisplayName("handshake to readable properties, for a message deep in the session")
    void decodesAMessageInTheMiddleOfASession() {
        // 1. The cleartext handshake, exactly as it appears on the wire.
        byte[] pragma1Request = handshake("GDay", CLIENT_RANDOM);
        byte[] pragma1Response = handshake("Mate", SERVER_RANDOM);

        OptionalInt clientRandom = Handshake.clientRandom(pragma1Request);
        OptionalInt serverRandom = Handshake.serverRandom(pragma1Response);
        assertTrue(clientRandom.isPresent() && serverRandom.isPresent());

        // 2. Derive and store the key, as the proxy handler would.
        byte[] derived = new GdayMateKeyDerivation()
                .deriveKey(clientRandom.getAsInt(), serverRandom.getAsInt());
        SessionKeyStore store = new InMemorySessionKeyStore();
        store.put(new SessionKey(SESSION_ID, derived, "forms.example.edu",
                1L, 2L, "", KeySource.DERIVED));

        // 3. The session's encrypted traffic: 60 messages under one continuous stream.
        Map<Integer, byte[]> ciphertexts = new LinkedHashMap<>();
        Map<Integer, byte[]> plaintexts = new LinkedHashMap<>();
        Rc4Stream encryptor = new Rc4Stream(derived);
        for (int pragma = 3; pragma <= 62; pragma++) {
            byte[] plain = packet(pragma, "value-for-pragma-" + pragma, pragma * 1000);
            plaintexts.put(pragma, plain);
            ciphertexts.put(pragma, encryptor.applied(plain));
        }

        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        bodies.put(Direction.REQUEST, ciphertexts);
        PragmaSource source = PragmaSource.of(bodies);

        // 4. Open pragma 47 cold, without having read anything before it.
        StreamReplayer replayer =
                new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET);
        ReplayResult result = replayer.replay(
                SESSION_ID, store.get(SESSION_ID).orElseThrow(), Direction.REQUEST, 47, source);

        ReplayResult.Decrypted decrypted =
                assertInstanceOf(ReplayResult.Decrypted.class, result, result.describe());

        // 5. Parse it into properties.
        FhtPacket packet = new FhtParser().parse(decrypted.plaintext(), new StringDictionary());

        assertTrue(packet.outcome().isComplete(), packet.outcome().describe());
        assertEquals(1, packet.messages().size());
        assertEquals(47, packet.messages().get(0).handlerId());
        assertEquals(new PropertyValue.StrValue("value-for-pragma-47"),
                packet.messages().get(0).properties().get(0).value());
        assertEquals(new PropertyValue.IntValue(47_000),
                packet.messages().get(0).properties().get(1).value());
    }

    @Test
    @DisplayName("without the key, the same traffic reports why it cannot be read")
    void withoutAKeyTheFailureIsExplicit() {
        SessionKeyStore emptyStore = new InMemorySessionKeyStore();

        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        bodies.put(Direction.REQUEST, Map.of(3, new byte[] {1, 2, 3, 4}));

        ReplayResult result = new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET)
                .replay(SESSION_ID, emptyStore.get(SESSION_ID).orElse(null),
                        Direction.REQUEST, 3, PragmaSource.of(bodies));

        assertInstanceOf(ReplayResult.NoKey.class, result);
        assertTrue(result.describe().contains("retroactive history scan"));
    }
}
