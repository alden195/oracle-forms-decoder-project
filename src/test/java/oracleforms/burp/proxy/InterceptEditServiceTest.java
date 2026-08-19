package oracleforms.burp.proxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.logging.Logging;
import java.lang.reflect.Proxy;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import oracleforms.burp.FormsDetector;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.TestPackets;
import oracleforms.session.Direction;
import oracleforms.session.InMemorySessionKeyStore;
import oracleforms.session.KeySource;
import oracleforms.session.PragmaSource;
import oracleforms.session.SessionKey;
import oracleforms.session.StreamLeg;
import oracleforms.session.StreamRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Preparing a held request for editing (architecture &sect;6.12), and the offset it decodes at.
 *
 * <p><strong>The bug these were written for.</strong> Burp records a request in the proxy history as
 * soon as it intercepts it — not when it is forwarded — so a request sitting in the Intercept tab is
 * already in history, indistinguishable from one the server has read. The ledger was opened at the
 * session's <em>tail</em>, which therefore counted the very message being held, and the in-flight
 * decode was one whole message too far along the keystream. Seen live on 2026-08-19: pragma 25 of a
 * real session refused with "does not decode as Oracle Forms data at the keystream offset this
 * session is believed to be at", the ledger sitting 283 bytes — the length of an earlier held
 * message — past where the client's cipher actually was.
 *
 * <p>The second half of the bug is why it survived a session rather than being noticed at once: the
 * error is inherited. Forwarding the held message advances the ledger over bytes the tail had
 * already counted, so every later position in that session carries the same offset, and a message
 * too small to judge ({@link InterceptEditService.Verdict#UNVERIFIABLE}) was edited and sent at it
 * without complaint.
 */
class InterceptEditServiceTest {

    private static final String SESSION = "intercept-service-session";
    private static final byte[] KEY = {0x21, 0x5C, (byte) 0xAE, 0x0D, (byte) 0x9F};

    /** The pragma the proxy is holding: the newest, as an intercepted request always is. */
    private static final int HELD = 12;

    private final InMemorySessionKeyStore keyStore = new InMemorySessionKeyStore();
    private final StreamRegistry registry = new StreamRegistry(null);
    private final AtomicInteger refreshes = new AtomicInteger();

    /** The captured traffic, swappable so a stale index can be modelled. */
    private PragmaSource history;

    private final Map<Integer, byte[]> requestPlain = new LinkedHashMap<>();
    private final Map<Integer, byte[]> requestCipher = new LinkedHashMap<>();
    private final Map<Integer, byte[]> responseCipher = new LinkedHashMap<>();

    /** Where the client's request cipher stood before each pragma. */
    private final Map<Integer, Long> offsetBefore = new LinkedHashMap<>();

    InterceptEditServiceTest() {
        buildSession(packet(HELD));
    }

    /**
     * A session of real FHT requests, encrypted the way the client encrypts them: one continuous
     * cipher from pragma 3, with the held message last and its response not yet in existence.
     */
    private void buildSession(byte[] heldPlaintext) {
        requestPlain.clear();
        requestCipher.clear();
        responseCipher.clear();
        offsetBefore.clear();

        keyStore.put(new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED));

        Rc4Stream requests = new Rc4Stream(KEY);
        Rc4Stream responses = new Rc4Stream(KEY);
        long consumed = 0;

        for (int pragma = 3; pragma <= HELD; pragma++) {
            byte[] plaintext = pragma == HELD ? heldPlaintext : packet(pragma);
            offsetBefore.put(pragma, consumed);
            requestPlain.put(pragma, plaintext);
            requestCipher.put(pragma, requests.applied(plaintext));
            consumed += plaintext.length;

            // The held request has not been answered -- it has not even been sent.
            if (pragma < HELD) {
                responseCipher.put(pragma, responses.applied(packet(pragma)));
            }
        }
        history = sourceOf(requestCipher, responseCipher);
    }

    /**
     * One request the way the wire carries them: real property ids, so the FHT check has something
     * to recognise, and long enough to be judged at all.
     */
    private static byte[] packet(int pragma) {
        return new TestPackets()
                .message(0x1000, 0, pragma)
                .int32Property(131, pragma)                    // VALUE
                .stringProperty(116, 12, "customer-id-field")  // LABEL
                .boolProperty(144, true)                       // ENABLED
                .endProperties()
                .endPacket()
                .build();
    }

    private static PragmaSource sourceOf(
            Map<Integer, byte[]> requests, Map<Integer, byte[]> responses) {
        Map<Direction, Map<Integer, byte[]>> bodies = new EnumMap<>(Direction.class);
        bodies.put(Direction.REQUEST, new LinkedHashMap<>(requests));
        bodies.put(Direction.RESPONSE, new LinkedHashMap<>(responses));
        return PragmaSource.of(bodies);
    }

    /** Logging without a running Burp; nothing here reads back what it was told. */
    private static Logging logging() {
        return (Logging) Proxy.newProxyInstance(
                Logging.class.getClassLoader(), new Class<?>[] {Logging.class},
                (proxy, method, args) -> null);
    }

    private InterceptEditService service() {
        return new InterceptEditService(
                keyStore,
                registry,
                sessionId -> history,
                sessionId -> refreshes.incrementAndGet(),
                new InterceptTokens(),
                Runnable::run,
                logging());
    }

    private InterceptEditService.Prepared prepareHeld() {
        return service()
                .prepare(new FormsDetector.FormsTarget(SESSION, HELD), requestCipher.get(HELD))
                .join();
    }

    private SessionKey key() {
        return keyStore.get(SESSION).orElseThrow();
    }

    private long ledgerPosition() {
        return registry.peek(SESSION).orElseThrow().consumed(StreamLeg.CLIENT_REQUEST);
    }

    // ---- the bug ------------------------------------------------------------------------------

    @Test
    @DisplayName("a held request is decoded at its own offset, not at the session's tail")
    void decodesTheHeldRequestAtItsOwnOffset() {
        InterceptEditService.Prepared prepared = prepareHeld();

        assertTrue(prepared.ok(), prepared.detail());
        assertEquals(InterceptEditService.Verdict.VERIFIED, prepared.verdict(), prepared.detail());
        assertArrayEquals(requestPlain.get(HELD), prepared.plaintext());
        assertEquals(offsetBefore.get(HELD).longValue(), prepared.position());
        assertEquals(requestCipher.get(HELD).length, prepared.originalStreamLength());
    }

    @Test
    @DisplayName("the ledger it opens is positioned before the held message, so Forward encrypts there")
    void opensTheLedgerBeforeTheHeldMessage() {
        prepareHeld();

        assertEquals(offsetBefore.get(HELD).longValue(), ledgerPosition());
        assertEquals(HELD, registry.peek(SESSION).orElseThrow().nextPragma(),
                "the message about to go out is the one the ledger should be expecting");
    }

    // ---- repairing a ledger that was left at the tail ------------------------------------------

    @Test
    @DisplayName("a ledger left at the tail is caught by the decode and corrected from the traffic")
    void correctsALedgerThatCountedTheHeldMessage() throws Exception {
        // Exactly what the old code did, and what a Mode A send still does while a request is held:
        // measure the tail, which counts the message that has not been sent.
        registry.open(SESSION, key(), history);
        long tail = ledgerPosition();
        assertNotEquals(offsetBefore.get(HELD).longValue(), tail);

        InterceptEditService.Prepared prepared = prepareHeld();

        assertTrue(prepared.ok(), prepared.detail());
        assertArrayEquals(requestPlain.get(HELD), prepared.plaintext());
        assertEquals(offsetBefore.get(HELD).longValue(), prepared.position());
        assertEquals(offsetBefore.get(HELD).longValue(), ledgerPosition(),
                "the ledger itself must be corrected, or Forward would encrypt at the wrong offset");
        assertTrue(prepared.detail().contains(String.valueOf(tail)),
                "the banner should say what was corrected: " + prepared.detail());
    }

    @Test
    @DisplayName("a disagreement the message is too small to settle is refused, never guessed at")
    void refusesWhenTooSmallToTellWhichOffsetIsRight() throws Exception {
        // Eight bytes is the steady-state Forms request, and there is no structure in it to be right
        // or wrong about. This is the case that sent an edit to the live server at a stale offset.
        buildSession(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
        registry.open(SESSION, key(), history);

        InterceptEditService.Prepared prepared = prepareHeld();

        assertFalse(prepared.ok(), "an unverifiable offset that is also disputed must not be edited");
        assertEquals(InterceptEditService.Verdict.FAILED, prepared.verdict());
        assertTrue(prepared.detail().contains("too small"), prepared.detail());
    }

    @Test
    @DisplayName("a small message is still editable when nothing disputes the offset")
    void offersASmallMessageWhenTheOffsetIsUndisputed() {
        buildSession(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});

        InterceptEditService.Prepared prepared = prepareHeld();

        assertTrue(prepared.ok(), prepared.detail());
        assertEquals(InterceptEditService.Verdict.UNVERIFIABLE, prepared.verdict());
        assertEquals(offsetBefore.get(HELD).longValue(), prepared.position());
    }

    // ---- the history index --------------------------------------------------------------------

    @Test
    @DisplayName("an index that predates the message before the held one is rebuilt first")
    void rebuildsAStaleHistoryIndex() {
        PragmaSource complete = history;

        // An index built twenty messages ago is the normal state of a cache on a live session. Here
        // it is missing the message before the held one, so a tail measured from it would stop early
        // and report a position short by that message -- which decodes to noise.
        Map<Integer, byte[]> stale = new LinkedHashMap<>(requestCipher);
        stale.remove(HELD);
        stale.remove(HELD - 1);
        Map<Integer, byte[]> staleResponses = new LinkedHashMap<>(responseCipher);
        staleResponses.remove(HELD - 1);
        history = sourceOf(stale, staleResponses);

        InterceptEditService service = new InterceptEditService(
                keyStore,
                registry,
                sessionId -> history,
                sessionId -> {
                    refreshes.incrementAndGet();
                    history = complete;
                },
                new InterceptTokens(),
                Runnable::run,
                logging());

        InterceptEditService.Prepared prepared = service
                .prepare(new FormsDetector.FormsTarget(SESSION, HELD), requestCipher.get(HELD))
                .join();

        assertEquals(1, refreshes.get());
        assertTrue(prepared.ok(), prepared.detail());
        assertEquals(offsetBefore.get(HELD).longValue(), prepared.position());
    }

    @Test
    @DisplayName("an index that already reaches the held message is not rebuilt")
    void leavesACurrentHistoryIndexAlone() {
        prepareHeld();
        assertEquals(0, refreshes.get());
    }
}
