package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import oracleforms.codec.FhtParser;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for {@link DictionaryScope#SESSION}, where the checkpoint cache can silently
 * corrupt results in a way the {@link DictionaryScope#PACKET} default never exposes.
 *
 * <p>The bug these pin down: the checkpoint stored at the target pragma was snapshotted from the
 * session dictionary <em>before</em> the target's own strings were absorbed into it. Resuming from
 * that checkpoint to decode the next pragma then resolved every back-reference into the target's
 * slots to an empty string — reintroducing the exact §7.2 failure mode through the cache rather than
 * through the scope setting.
 */
class SessionScopeReplayTest {

    private static final String SESSION = "session-scope-test";
    private static final byte[] KEY = {0x33, (byte) 0xCD, (byte) 0xAE, 0x22, (byte) 0xBC};

    private static SessionKey sessionKey() {
        return new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    /** A packet that stores {@code text} into a dictionary slot. */
    private static byte[] definingPacket(int handlerId, int slot, String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x10);
        out.write(handlerId >> 8);
        out.write(handlerId & 0xFF);

        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        out.write(0x40);              // string property, id 1
        out.write(0x01);
        out.write(slot);
        out.write(bytes.length >> 8);
        out.write(bytes.length & 0xFF);
        out.writeBytes(bytes);

        out.write(0xF0);
        out.write(0xF0);
        return out.toByteArray();
    }

    /** A packet that only back-references a slot defined by an earlier packet. */
    private static byte[] referencingPacket(int handlerId, int dstSlot, int srcSlot) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x10);
        out.write(handlerId >> 8);
        out.write(handlerId & 0xFF);

        out.write(0x90);              // back-reference, id 2
        out.write(0x02);
        out.write(dstSlot);
        out.write(srcSlot);

        out.write(0xF0);
        out.write(0xF0);
        return out.toByteArray();
    }

    /**
     * Builds a session where pragma 4 defines a string and pragma 5 refers back to it, so decoding 5
     * is only correct if 4's strings reached the dictionary.
     */
    private static PragmaSource session() {
        Map<Integer, byte[]> cipher = new LinkedHashMap<>();
        Rc4Stream stream = new Rc4Stream(KEY);

        cipher.put(3, stream.applied(definingPacket(3, 10, "from-pragma-3")));
        cipher.put(4, stream.applied(definingPacket(4, 20, "from-pragma-4")));
        cipher.put(5, stream.applied(referencingPacket(5, 21, 20)));
        cipher.put(6, stream.applied(referencingPacket(6, 11, 10)));

        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        bodies.put(Direction.REQUEST, cipher);
        return PragmaSource.of(bodies);
    }

    private static String decodeStringAt(StreamReplayer replayer, PragmaSource source, int pragma) {
        ReplayResult result =
                replayer.replay(SESSION, sessionKey(), Direction.REQUEST, pragma, source);
        ReplayResult.Decrypted decrypted =
                assertInstanceOf(ReplayResult.Decrypted.class, result, result.describe());

        FhtPacket packet = new FhtParser().parse(decrypted.plaintext(), decrypted.dictionary());
        PropertyValue value = packet.messages().get(0).properties().get(0).value();
        return assertInstanceOf(PropertyValue.StrValue.class, value).value();
    }

    /**
     * The regression. Decoding 4 warms a checkpoint at 4; decoding 5 then resumes from it. If that
     * checkpoint's dictionary is missing pragma 4's string, the back-reference resolves to "".
     */
    @Test
    @DisplayName("a back-reference into the immediately preceding pragma survives its checkpoint")
    void checkpointCarriesTheTargetsOwnStrings() {
        PragmaSource source = session();
        StreamReplayer replayer =
                new StreamReplayer(new CheckpointCache(), DictionaryScope.SESSION);

        // Warm a checkpoint at pragma 4 by decoding it first.
        assertEquals("from-pragma-4", decodeStringAt(replayer, source, 4));

        // Now decode 5, which resumes from that checkpoint and refers back into slot 20.
        assertEquals("from-pragma-4", decodeStringAt(replayer, source, 5));
    }

    @Test
    @DisplayName("a warm replayer agrees with a cold one under session scope")
    void warmAndColdAgree() {
        PragmaSource source = session();

        StreamReplayer cold = new StreamReplayer(new CheckpointCache(), DictionaryScope.SESSION);
        String coldResult = decodeStringAt(cold, source, 6);

        StreamReplayer warm = new StreamReplayer(new CheckpointCache(), DictionaryScope.SESSION);
        for (int pragma = 3; pragma <= 6; pragma++) {
            decodeStringAt(warm, source, pragma);
        }
        String warmResult = decodeStringAt(warm, source, 6);

        assertEquals("from-pragma-3", coldResult);
        assertEquals(coldResult, warmResult);
    }

    /**
     * The counterpart: under packet scope the same back-reference must <em>not</em> resolve, because
     * the dictionary is per packet. Confirms the scopes really differ, so the open question in §7.2
     * can be settled by flipping the setting and comparing.
     */
    @Test
    @DisplayName("packet scope leaves the same back-reference empty, as designed")
    void packetScopeDoesNotCarryStrings() {
        PragmaSource source = session();
        StreamReplayer replayer =
                new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET);

        assertEquals("", decodeStringAt(replayer, source, 5));
    }
}
