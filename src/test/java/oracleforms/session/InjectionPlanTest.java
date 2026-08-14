package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Planning a send.
 *
 * <p>{@link #offsetModeReproducesTheOriginalCiphertext} is the one that ties the whole feature
 * together: take a captured message, decrypt it, hand the plaintext straight back to the planner, and
 * the bytes that come out must be the bytes that went in. If the offset arithmetic is wrong by so
 * much as one byte, that test fails — and every send would have been noise.
 */
class InjectionPlanTest {

    private static final String SESSION = "injection-test-session";
    private static final byte[] KEY = {0x51, 0x22, (byte) 0xAE, 0x71, (byte) 0x9C};
    private static final int LAST_PRAGMA = 40;

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** A synthetic session: one continuous stream per direction from pragma 3, offset 0. */
    private record Fixture(
            Map<Direction, Map<Integer, byte[]>> plain,
            Map<Direction, Map<Integer, byte[]>> cipher) {

        PragmaSource source() {
            return PragmaSource.of(cipher);
        }
    }

    /**
     * Builds a session including a {@code NULLPOST} at pragma 12, because the sentinel is exactly the
     * kind of thing an offset calculation gets wrong: it occupies a pragma but contributes no
     * keystream.
     */
    private static Fixture buildSession() {
        Random random = new Random(20260814L);
        Map<Direction, Map<Integer, byte[]>> plain = new HashMap<>();
        Map<Direction, Map<Integer, byte[]>> cipher = new HashMap<>();

        for (Direction direction : Direction.values()) {
            Map<Integer, byte[]> p = new LinkedHashMap<>();
            Map<Integer, byte[]> c = new LinkedHashMap<>();
            Rc4Stream stream = new Rc4Stream(KEY);

            for (int pragma = 3; pragma <= LAST_PRAGMA; pragma++) {
                if (direction == Direction.REQUEST && pragma == 12) {
                    // Cleartext, and it never enters the cipher.
                    p.put(pragma, PragmaBody.NULL_POST.clone());
                    c.put(pragma, PragmaBody.NULL_POST.clone());
                    continue;
                }
                int size = direction == Direction.REQUEST
                        ? 8 + random.nextInt(24)
                        : 100 + random.nextInt(400);
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

    private static SessionKey key() {
        return new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    // ---- offset mode ----------------------------------------------------------------------

    /**
     * The round trip that proves the offset arithmetic. Re-encrypting a message's own plaintext at
     * the position it originally occupied must give back exactly the ciphertext that was captured.
     */
    @Test
    @DisplayName("offset mode reproduces a captured message's ciphertext byte for byte")
    void offsetModeReproducesTheOriginalCiphertext() {
        Fixture fixture = buildSession();

        for (int pragma : new int[]{3, 4, 11, 13, 25, LAST_PRAGMA}) {
            byte[] plaintext = fixture.plain().get(Direction.REQUEST).get(pragma);
            byte[] expected = fixture.cipher().get(Direction.REQUEST).get(pragma);

            InjectionPlan.Result result =
                    InjectionPlan.atCapturedOffset(fixture.source(), KEY, pragma, plaintext);

            InjectionPlan.Result.Ready ready =
                    assertInstanceOf(InjectionPlan.Result.Ready.class, result,
                            "pragma " + pragma + " was refused");
            assertArrayEquals(expected, ready.ciphertext(),
                    "pragma " + pragma + " did not re-encrypt to its captured bytes");
            assertEquals(pragma, ready.pragma());
        }
    }

    @Test
    @DisplayName("the NULLPOST at pragma 12 contributes nothing to later offsets")
    void offsetsSkipTheSentinel() {
        Fixture fixture = buildSession();

        // Pragma 13 sits immediately after the sentinel. If its eight bytes had been counted, this
        // would decrypt to noise rather than reproduce the capture.
        byte[] plaintext = fixture.plain().get(Direction.REQUEST).get(13);
        InjectionPlan.Result.Ready ready = assertInstanceOf(InjectionPlan.Result.Ready.class,
                InjectionPlan.atCapturedOffset(fixture.source(), KEY, 13, plaintext));

        assertArrayEquals(fixture.cipher().get(Direction.REQUEST).get(13), ready.ciphertext());
    }

    @Test
    @DisplayName("an edited message encrypts to something different, at the same offset")
    void offsetModeCarriesTheEdit() {
        Fixture fixture = buildSession();
        byte[] original = fixture.plain().get(Direction.REQUEST).get(20);
        byte[] edited = original.clone();
        edited[0] ^= 0xFF;

        InjectionPlan.Result.Ready ready = assertInstanceOf(InjectionPlan.Result.Ready.class,
                InjectionPlan.atCapturedOffset(fixture.source(), KEY, 20, edited));

        assertNotEquals(fixture.cipher().get(Direction.REQUEST).get(20)[0], ready.ciphertext()[0]);
        // And the untouched tail of the message is unchanged, because the keystream is the same.
        for (int i = 1; i < original.length; i++) {
            assertEquals(fixture.cipher().get(Direction.REQUEST).get(20)[i], ready.ciphertext()[i]);
        }
    }

    @Test
    @DisplayName("a gap before the target refuses the send rather than guessing an offset")
    void offsetModeRefusesOnAGap() {
        Fixture fixture = buildSession();
        PragmaSource holed = (direction, pragma) ->
                (direction == Direction.REQUEST && pragma == 9)
                        ? Optional.empty()
                        : fixture.source().body(direction, pragma);

        InjectionPlan.Result result = InjectionPlan.atCapturedOffset(
                new BoundedSource(holed, LAST_PRAGMA), KEY, 20,
                fixture.plain().get(Direction.REQUEST).get(20));

        InjectionPlan.Result.Refused refused =
                assertInstanceOf(InjectionPlan.Result.Refused.class, result);
        assertTrue(refused.reason().contains("Pragma 9"), refused.reason());
    }

    @Test
    @DisplayName("a cleartext pragma is refused")
    void cleartextPragmasAreRefused() {
        Fixture fixture = buildSession();
        assertInstanceOf(InjectionPlan.Result.Refused.class,
                InjectionPlan.atCapturedOffset(fixture.source(), KEY, 1, ascii("anything")));
    }

    @Test
    @DisplayName("an empty body is refused in either mode")
    void emptyBodiesAreRefused() {
        Fixture fixture = buildSession();
        assertInstanceOf(InjectionPlan.Result.Refused.class,
                InjectionPlan.atCapturedOffset(fixture.source(), KEY, 10, new byte[0]));
        assertInstanceOf(InjectionPlan.Result.Refused.class,
                InjectionPlan.atTail(SessionStreams.atOrigin(SESSION, KEY), new byte[0]));
    }

    // ---- tail mode ------------------------------------------------------------------------

    @Test
    @DisplayName("tail mode encrypts where the server's cipher actually is")
    void tailModeLandsAtTheServersPosition() throws Exception {
        Fixture fixture = buildSession();

        // A server that has consumed the whole captured session, exactly as the real one would have.
        Rc4Stream serverRequests = new Rc4Stream(KEY);
        for (int pragma = 3; pragma <= LAST_PRAGMA; pragma++) {
            byte[] body = fixture.cipher().get(Direction.REQUEST).get(pragma);
            if (!PragmaBody.isNullPost(body)) {
                serverRequests.skip(body.length);
            }
        }

        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());
        SessionStreams streams = registry.open(SESSION, key(), fixture.source());

        byte[] plaintext = ascii("an injected message the client never sent");
        InjectionPlan.Result.Ready ready = assertInstanceOf(InjectionPlan.Result.Ready.class,
                InjectionPlan.atTail(streams, plaintext));

        assertArrayEquals(plaintext, serverRequests.applied(ready.ciphertext()),
                "the server must read the injection correctly at its own position");
        assertEquals(LAST_PRAGMA + 1, ready.pragma());
    }

    @Test
    @DisplayName("consecutive injections advance both the offset and the pragma number")
    void tailModeAdvancesPerSend() throws Exception {
        Fixture fixture = buildSession();
        Rc4Stream serverRequests = new Rc4Stream(KEY);
        for (int pragma = 3; pragma <= LAST_PRAGMA; pragma++) {
            byte[] body = fixture.cipher().get(Direction.REQUEST).get(pragma);
            if (!PragmaBody.isNullPost(body)) {
                serverRequests.skip(body.length);
            }
        }

        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());
        SessionStreams streams = registry.open(SESSION, key(), fixture.source());

        for (int i = 0; i < 5; i++) {
            byte[] plaintext = ascii("injection " + i);
            InjectionPlan.Result.Ready ready = assertInstanceOf(InjectionPlan.Result.Ready.class,
                    InjectionPlan.atTail(streams, plaintext));

            assertEquals(LAST_PRAGMA + 1 + i, ready.pragma());
            assertArrayEquals(plaintext, serverRequests.applied(ready.ciphertext()),
                    "injection " + i + " landed at the wrong offset");
        }
    }

    /** A source that reports a fixed bound, so a hole can be told from the end of the session. */
    private record BoundedSource(PragmaSource delegate, int highest) implements PragmaSource {

        @Override
        public Optional<PragmaBody> body(Direction direction, int pragma) {
            return delegate.body(direction, pragma);
        }

        @Override
        public int highestPragma() {
            return highest;
        }
    }
}
