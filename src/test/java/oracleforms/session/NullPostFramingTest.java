package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The two framing rules the {@code NULLPOST} sentinel implies, tested against a synthetic session
 * built to the exact shape of a real one.
 *
 * <p>The layout below is copied from a live capture (session {@code xJ5grzn3…}, 2026-08-13):
 * pragmas 3–7 are ordinary exchanges, then the server owes a 218 892-byte message that it flushes in
 * fragments of 66 000, 66 000, 66 000 and 20 892 bytes, which the client collects by POSTing the
 * cleartext bytes {@code NULLPOST} at pragmas 8, 9 and 10. Both consequences are load-bearing:
 *
 * <ol>
 *   <li>A NULLPOST never entered the client's cipher, so it must advance the request keystream by
 *       <em>zero</em> bytes. Advancing by its 8 bytes desynchronises every later request — with
 *       three of them here, pragma 11 onwards would decrypt to noise.
 *   <li>Its response is a <em>continuation</em>. Decrypting fragment 2 alone succeeds, but the bytes
 *       start mid-structure, so parsing them alone yields convincing nonsense. The fragments must be
 *       rejoined before the parser sees them.
 * </ol>
 *
 * <p>The fixture is built here by hand, modelling what the client and server actually do, so it is an
 * independent check on the replayer rather than a restatement of it.
 */
class NullPostFramingTest {

    private static final String SESSION = "nullpost-session";
    private static final byte[] KEY = {0x11, (byte) 0x9C, (byte) 0xAE, 0x44, (byte) 0xD3};

    private static SessionKey sessionKey() {
        return new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    /** One exchange: what the client posted, and how big the server's response fragment was. */
    private record Exchange(int pragma, int requestSize, int responseSize) {

        /** A request that carries no payload, so nothing of it reaches the cipher. */
        static Exchange nullPost(int pragma, int responseSize) {
            return new Exchange(pragma, -1, responseSize);
        }

        boolean isNullPost() {
            return requestSize < 0;
        }
    }

    /** The observed session, fragment sizes and all. */
    private static final List<Exchange> SESSION_SHAPE = List.of(
            new Exchange(3, 145, 28_296),
            new Exchange(4, 88, 20),
            new Exchange(5, 12, 15),
            new Exchange(6, 18, 7),
            new Exchange(7, 20, 66_000),
            Exchange.nullPost(8, 66_000),
            Exchange.nullPost(9, 66_000),
            Exchange.nullPost(10, 20_892),
            new Exchange(11, 20, 2),
            new Exchange(12, 12, 2));

    /** The pragmas whose responses form the one oversized message. */
    private static final int GROUP_FIRST = 7;
    private static final int GROUP_LAST = 10;

    private final Map<Direction, Map<Integer, byte[]>> plaintexts = new LinkedHashMap<>();
    private final Map<Direction, Map<Integer, byte[]>> ciphertexts = new LinkedHashMap<>();

    NullPostFramingTest() {
        Random random = new Random(20260813L);
        for (Direction direction : Direction.values()) {
            plaintexts.put(direction, new LinkedHashMap<>());
            ciphertexts.put(direction, new LinkedHashMap<>());
        }

        // The client: encrypts real payloads through one continuous stream, and writes a NULLPOST
        // straight to the socket without touching the cipher.
        Rc4Stream requestStream = new Rc4Stream(KEY);
        for (Exchange exchange : SESSION_SHAPE) {
            if (exchange.isNullPost()) {
                plaintexts.get(Direction.REQUEST).put(exchange.pragma(), PragmaBody.NULL_POST);
                ciphertexts.get(Direction.REQUEST).put(exchange.pragma(), PragmaBody.NULL_POST);
                continue;
            }
            byte[] body = new byte[exchange.requestSize()];
            random.nextBytes(body);
            plaintexts.get(Direction.REQUEST).put(exchange.pragma(), body);
            ciphertexts.get(Direction.REQUEST).put(exchange.pragma(), requestStream.applied(body));
        }

        // The server: one continuous stream over its whole output, chopped into HTTP responses at
        // byte boundaries that have nothing to do with message boundaries.
        Rc4Stream responseStream = new Rc4Stream(KEY);
        for (Exchange exchange : SESSION_SHAPE) {
            byte[] body = new byte[exchange.responseSize()];
            random.nextBytes(body);
            plaintexts.get(Direction.RESPONSE).put(exchange.pragma(), body);
            ciphertexts.get(Direction.RESPONSE).put(exchange.pragma(), responseStream.applied(body));
        }
    }

    private PragmaSource source() {
        return PragmaSource.of(ciphertexts);
    }

    private byte[] plain(Direction direction, int pragma) {
        return plaintexts.get(direction).get(pragma);
    }

    /** The whole oversized message, as the server meant it to be read. */
    private byte[] reassembledGroup() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int pragma = GROUP_FIRST; pragma <= GROUP_LAST; pragma++) {
            byte[] fragment = plain(Direction.RESPONSE, pragma);
            out.write(fragment, 0, fragment.length);
        }
        return out.toByteArray();
    }

    private static StreamReplayer replayer() {
        return new StreamReplayer(new CheckpointCache(), DictionaryScope.PACKET);
    }

    @Test
    @DisplayName("a NULLPOST does not advance the request keystream")
    void nullPostDoesNotAdvanceTheRequestStream() {
        StreamReplayer replayer = replayer();

        // Pragmas 11 and 12 sit behind three NULLPOSTs. If those had advanced the stream by their
        // eight bytes each, these would decrypt 24 bytes out of position and come back as noise.
        for (int pragma : new int[] {11, 12}) {
            ReplayResult result =
                    replayer.replay(SESSION, sessionKey(), Direction.REQUEST, pragma, source());

            ReplayResult.Decrypted decrypted = assertInstanceOf(
                    ReplayResult.Decrypted.class, result, result.describe());
            assertArrayEquals(plain(Direction.REQUEST, pragma), decrypted.plaintext(),
                    "request " + pragma + " decrypted out of stream position");
        }
    }

    @Test
    @DisplayName("a NULLPOST request is reported as having no payload, not as a failure")
    void nullPostRequestIsItsOwnOutcome() {
        StreamReplayer replayer = replayer();

        for (int pragma : new int[] {8, 9, 10}) {
            ReplayResult result =
                    replayer.replay(SESSION, sessionKey(), Direction.REQUEST, pragma, source());

            ReplayResult.NullPost nullPost =
                    assertInstanceOf(ReplayResult.NullPost.class, result, result.describe());
            assertEquals(pragma, nullPost.pragma());
        }
    }

    @Test
    @DisplayName("PragmaBody reports a NULLPOST as contributing nothing to the request stream")
    void nullPostContributesNoStreamBytes() {
        PragmaBody body = new PragmaBody(8, PragmaBody.NULL_POST);

        assertTrue(body.isNullPost());
        assertEquals(8, body.length(), "the body really is eight bytes on the wire");
        assertEquals(0, body.streamLength(Direction.REQUEST), "but none of them reach the cipher");

        // The server never sends the sentinel; identical bytes there would be ciphertext and must
        // still be consumed.
        assertEquals(8, body.streamLength(Direction.RESPONSE));
    }

    @Test
    @DisplayName("an oversized response is rejoined from every fragment the NULLPOSTs pulled")
    void responseFragmentsAreReassembled() {
        StreamReplayer replayer = replayer();
        byte[] whole = reassembledGroup();

        // Whichever fragment the user clicks, they get the whole message.
        for (int pragma = GROUP_FIRST; pragma <= GROUP_LAST; pragma++) {
            ReplayResult result =
                    replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, pragma, source());

            ReplayResult.Decrypted decrypted = assertInstanceOf(
                    ReplayResult.Decrypted.class, result, result.describe());

            assertArrayEquals(whole, decrypted.plaintext(),
                    "response " + pragma + " was not reassembled into the whole message");

            ReplayResult.FragmentGroup fragments = decrypted.fragments();
            assertEquals(GROUP_FIRST, fragments.first());
            assertEquals(GROUP_LAST, fragments.last());
            assertEquals(4, fragments.count());
            assertEquals(pragma - GROUP_FIRST + 1, fragments.targetIndex());
            assertTrue(fragments.isSplit());
            assertTrue(fragments.complete());
        }
    }

    @Test
    @DisplayName("an unfragmented response is left alone")
    void ordinaryResponsesAreNotGrouped() {
        StreamReplayer replayer = replayer();

        for (int pragma : new int[] {3, 4, 5, 6, 11, 12}) {
            ReplayResult result =
                    replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, pragma, source());

            ReplayResult.Decrypted decrypted = assertInstanceOf(
                    ReplayResult.Decrypted.class, result, result.describe());
            assertArrayEquals(plain(Direction.RESPONSE, pragma), decrypted.plaintext(),
                    "response " + pragma);
            assertFalse(decrypted.fragments().isSplit(), "pragma " + pragma + " is not fragmented");
        }
    }

    @Test
    @DisplayName("the response stream stays in position across a fragment group")
    void streamSurvivesTheGroup() {
        StreamReplayer replayer = replayer();

        // Pragma 11's response sits after 218 892 bytes of fragments. Getting it right proves the
        // group consumed exactly the keystream it should have.
        ReplayResult result =
                replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, 11, source());

        assertArrayEquals(plain(Direction.RESPONSE, 11),
                assertInstanceOf(ReplayResult.Decrypted.class, result, result.describe()).plaintext());
    }

    @Test
    @DisplayName("a group whose tail was never captured is reported as cut short")
    void incompleteGroupIsFlagged() {
        // The client asked for fragment 4, so we know it exists — it just is not in history.
        PragmaSource missingTail = (direction, pragma) ->
                (direction == Direction.RESPONSE && pragma == GROUP_LAST)
                        ? Optional.empty()
                        : source().body(direction, pragma);

        ReplayResult result =
                replayer().replay(SESSION, sessionKey(), Direction.RESPONSE, GROUP_FIRST, missingTail);

        ReplayResult.Decrypted decrypted =
                assertInstanceOf(ReplayResult.Decrypted.class, result, result.describe());

        assertFalse(decrypted.fragments().complete(),
                "a group missing its tail must not be presented as a whole message");
        assertEquals(GROUP_LAST - 1, decrypted.fragments().last());
        assertTrue(decrypted.describe().contains("incomplete"), decrypted.describe());
    }

    @Test
    @DisplayName("decoding is unaffected by which pragma is asked for first")
    void checkpointsDoNotCorruptTheGroup() {
        // Warming the cache mid-group is the case a checkpoint stored at a fragment boundary would
        // break: a later resume would restart the stream inside the message.
        StreamReplayer replayer = replayer();
        replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, 9, source());
        replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, 12, source());

        ReplayResult result =
                replayer.replay(SESSION, sessionKey(), Direction.RESPONSE, GROUP_FIRST, source());

        assertArrayEquals(reassembledGroup(),
                assertInstanceOf(ReplayResult.Decrypted.class, result, result.describe()).plaintext());
    }
}
