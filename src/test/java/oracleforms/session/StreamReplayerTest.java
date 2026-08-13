package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Replay is where the subtle bugs live, so this is the test the architecture calls the most valuable
 * in the project. Everything here works against a synthetic session built the way the real protocol
 * builds one: one continuous RC4 stream per direction, starting at pragma 3, offset 0.
 */
class StreamReplayerTest {

    private static final String SESSION = "test-session-id";
    private static final byte[] KEY = {0x33, (byte) 0xCD, (byte) 0xAE, 0x22, (byte) 0xBC};
    private static final int LAST_PRAGMA = 120;

    private static SessionKey sessionKey() {
        return new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    /** A session's plaintexts and the ciphertexts a continuous per-direction stream produces. */
    private record Fixture(
            Map<Direction, Map<Integer, byte[]>> plaintexts,
            Map<Direction, Map<Integer, byte[]>> ciphertexts) {

        PragmaSource source() {
            return PragmaSource.of(ciphertexts);
        }

        /** A source with one pragma missing from history, as an uncaptured message would be. */
        PragmaSource sourceMissing(Direction direction, int pragma) {
            return (d, p) -> (d == direction && p == pragma)
                    ? Optional.empty()
                    : source().body(d, p);
        }

        byte[] plain(Direction d, int pragma) {
            return plaintexts.get(d).get(pragma);
        }
    }

    /**
     * Builds a session whose message sizes vary the way real traffic does: small requests against
     * large responses, and a 28 KB initial UI payload at pragma 3.
     */
    private static Fixture buildSession() {
        Random random = new Random(20260813L);
        Map<Direction, Map<Integer, byte[]>> plain = new HashMap<>();
        Map<Direction, Map<Integer, byte[]>> cipher = new HashMap<>();

        for (Direction direction : Direction.values()) {
            Map<Integer, byte[]> p = new LinkedHashMap<>();
            Map<Integer, byte[]> c = new LinkedHashMap<>();
            Rc4Stream stream = new Rc4Stream(KEY);

            for (int pragma = StreamReplayer.FIRST_ENCRYPTED_PRAGMA; pragma <= LAST_PRAGMA; pragma++) {
                int size;
                if (pragma == StreamReplayer.FIRST_ENCRYPTED_PRAGMA) {
                    size = direction == Direction.RESPONSE ? 28_296 : 8;
                } else {
                    size = direction == Direction.RESPONSE ? 100 + random.nextInt(300)
                            : 2 + random.nextInt(10);
                }
                byte[] body = new byte[size];
                random.nextBytes(body);

                p.put(pragma, body);
                c.put(pragma, stream.applied(body));
            }
            plain.put(direction, p);
            cipher.put(direction, c);
        }
        return new Fixture(plain, cipher);
    }

    private static StreamReplayer replayer() {
        return new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET);
    }

    @Test
    @DisplayName("decrypts every pragma in both directions")
    void decryptsWholeSession() {
        Fixture fixture = buildSession();
        StreamReplayer replayer = replayer();

        for (Direction direction : Direction.values()) {
            for (int pragma = StreamReplayer.FIRST_ENCRYPTED_PRAGMA; pragma <= LAST_PRAGMA; pragma++) {
                ReplayResult result =
                        replayer.replay(SESSION, sessionKey(), direction, pragma, fixture.source());

                ReplayResult.Decrypted decrypted =
                        assertInstanceOf(ReplayResult.Decrypted.class, result,
                                "pragma " + pragma + " " + direction + ": " + result.describe());
                assertArrayEquals(fixture.plain(direction, pragma), decrypted.plaintext(),
                        "pragma " + pragma + " " + direction);
            }
        }
    }

    /**
     * The headline capability: opening an arbitrary message in the middle of a captured session
     * without having walked there. Random access must give the same answer as sequential.
     */
    @Test
    @DisplayName("random access matches sequential access")
    void randomAccessMatchesSequential() {
        Fixture fixture = buildSession();

        List<Integer> order = new ArrayList<>();
        for (int p = StreamReplayer.FIRST_ENCRYPTED_PRAGMA; p <= LAST_PRAGMA; p++) {
            order.add(p);
        }
        Collections.shuffle(order, new Random(99L));

        StreamReplayer shuffled = replayer();
        for (int pragma : order) {
            ReplayResult result =
                    shuffled.replay(SESSION, sessionKey(), Direction.RESPONSE, pragma, fixture.source());
            assertArrayEquals(
                    fixture.plain(Direction.RESPONSE, pragma),
                    assertInstanceOf(ReplayResult.Decrypted.class, result).plaintext(),
                    "pragma " + pragma + " decoded out of order");
        }
    }

    @Test
    @DisplayName("a cold replayer with no checkpoints agrees with a warm one")
    void checkpointsDoNotChangeTheAnswer() {
        Fixture fixture = buildSession();

        StreamReplayer warm = replayer();
        for (int p = StreamReplayer.FIRST_ENCRYPTED_PRAGMA; p <= LAST_PRAGMA; p++) {
            warm.replay(SESSION, sessionKey(), Direction.REQUEST, p, fixture.source());
        }

        ReplayResult fromWarm =
                warm.replay(SESSION, sessionKey(), Direction.REQUEST, LAST_PRAGMA, fixture.source());
        ReplayResult fromCold =
                replayer().replay(SESSION, sessionKey(), Direction.REQUEST, LAST_PRAGMA, fixture.source());

        assertArrayEquals(
                assertInstanceOf(ReplayResult.Decrypted.class, fromCold).plaintext(),
                assertInstanceOf(ReplayResult.Decrypted.class, fromWarm).plaintext());
    }

    @Test
    @DisplayName("the two directions do not contaminate each other")
    void directionsAreIndependent() {
        Fixture fixture = buildSession();
        StreamReplayer replayer = replayer();

        // Walk the response stream first; the request stream must be unaffected.
        for (int p = StreamReplayer.FIRST_ENCRYPTED_PRAGMA; p <= 60; p++) {
            replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, p, fixture.source());
        }
        ReplayResult request =
                replayer.replay(SESSION, sessionKey(), Direction.REQUEST, 60, fixture.source());

        assertArrayEquals(fixture.plain(Direction.REQUEST, 60),
                assertInstanceOf(ReplayResult.Decrypted.class, request).plaintext());
    }

    /**
     * The diagnostic the reference implementation's live-only model cannot produce. A gap must name
     * the specific missing pragma, not fail blankly.
     */
    @Test
    @DisplayName("names the missing pragma instead of failing blankly")
    void reportsWhichPragmaIsMissing() {
        Fixture fixture = buildSession();
        PragmaSource gappy = fixture.sourceMissing(Direction.REQUEST, 17);

        ReplayResult result =
                replayer().replay(SESSION, sessionKey(), Direction.REQUEST, 18, gappy);

        ReplayResult.MissingPragma missing =
                assertInstanceOf(ReplayResult.MissingPragma.class, result);
        assertEquals(17, missing.missing());
        assertEquals(18, missing.target());
        assertTrue(missing.describe().contains("17"));
    }

    @Test
    @DisplayName("a gap does not block pragmas before it")
    void gapDoesNotBlockEarlierPragmas() {
        Fixture fixture = buildSession();
        PragmaSource gappy = fixture.sourceMissing(Direction.REQUEST, 17);

        ReplayResult before = replayer().replay(SESSION, sessionKey(), Direction.REQUEST, 16, gappy);

        assertArrayEquals(fixture.plain(Direction.REQUEST, 16),
                assertInstanceOf(ReplayResult.Decrypted.class, before).plaintext());
    }

    @Test
    @DisplayName("reports a missing key rather than decrypting to noise")
    void reportsMissingKey() {
        ReplayResult result =
                replayer().replay(SESSION, null, Direction.REQUEST, 5, buildSession().source());

        assertInstanceOf(ReplayResult.NoKey.class, result);
        assertTrue(result.describe().contains(SESSION));
    }

    @Test
    @DisplayName("pragmas below 3 are reported as cleartext, not decrypted")
    void cleartextPragmasAreNotDecrypted() {
        Fixture fixture = buildSession();
        for (int pragma : new int[] {0, 1, 2}) {
            ReplayResult result =
                    replayer().replay(SESSION, sessionKey(), Direction.REQUEST, pragma, fixture.source());
            assertInstanceOf(ReplayResult.NotEncrypted.class, result);
        }
    }

    @Test
    @DisplayName("a wrong key decrypts to something other than the plaintext")
    void wrongKeyDoesNotDecrypt() {
        Fixture fixture = buildSession();
        SessionKey wrong = new SessionKey(
                SESSION, new byte[] {1, 2, 3, 4, 5}, "host", 0L, 0L, "", KeySource.MANUAL);

        ReplayResult result =
                replayer().replay(SESSION, wrong, Direction.REQUEST, 10, fixture.source());

        assertTrue(!java.util.Arrays.equals(
                fixture.plain(Direction.REQUEST, 10),
                assertInstanceOf(ReplayResult.Decrypted.class, result).plaintext()));
    }
}
