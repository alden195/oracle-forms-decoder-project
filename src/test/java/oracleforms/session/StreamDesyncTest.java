package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The desync guard: a session that had traffic reach the server outside the proxy must refuse to be
 * appended to, rather than encrypt at an offset it has no right to.
 *
 * <p>This is the fix for what the first live-target send found (architecture &sect;6.11). The failure
 * being prevented is not an exception or a wrong value — it is a <em>plausible number</em>. A tail
 * measured from a capture that is missing sends will be short by exactly their length, will encrypt
 * without complaint, and will be read by the server as noise. The whole point of these tests is that
 * the refusal happens at all.
 */
class StreamDesyncTest {

    private static final String SESSION = "desync-test-session";
    private static final byte[] KEY = {0x11, 0x22, (byte) 0xAE, 0x33, 0x44};

    private static final String REASON =
            "Pragma 41 (12 bytes of ciphertext) was sent to the server from one of Burp's own tools "
                    + "without the Oracle Forms draft markers.";

    private static SessionKey key() {
        return new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    /** A contiguous session from pragma 3 to {@code last}, with fixed body sizes. */
    private static PragmaSource contiguous(int last, int requestSize, int responseSize) {
        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        Map<Integer, byte[]> requests = new LinkedHashMap<>();
        Map<Integer, byte[]> responses = new LinkedHashMap<>();
        for (int pragma = 3; pragma <= last; pragma++) {
            requests.put(pragma, new byte[requestSize]);
            responses.put(pragma, new byte[responseSize]);
        }
        bodies.put(Direction.REQUEST, requests);
        bodies.put(Direction.RESPONSE, responses);
        return PragmaSource.of(bodies);
    }

    /** A store that survives being handed to a second registry, standing in for the project file. */
    private static final class Store implements StreamPositionStore {
        final Map<String, StreamPositions> saved = new HashMap<>();
        final Map<String, String> desyncs = new HashMap<>();
        int desyncWrites;

        @Override
        public Optional<StreamPositions> load(String sessionId) {
            return Optional.ofNullable(saved.get(sessionId));
        }

        @Override
        public void save(String sessionId, StreamPositions positions) {
            saved.put(sessionId, positions);
        }

        @Override
        public void forgetPositions(String sessionId) {
            saved.remove(sessionId);
            desyncs.remove(sessionId);
        }

        @Override
        public Optional<String> desyncReason(String sessionId) {
            return Optional.ofNullable(desyncs.get(sessionId));
        }

        @Override
        public void markDesynced(String sessionId, String reason) {
            desyncs.put(sessionId, reason);
            desyncWrites++;
        }
    }

    @Test
    @DisplayName("a desynchronised session refuses to open, naming what happened")
    void desyncedSessionRefusesToOpen() {
        StreamRegistry registry = new StreamRegistry(new Store());
        assertTrue(registry.markDesynced(SESSION, REASON));

        StreamDesyncException refused = assertThrows(StreamDesyncException.class,
                () -> registry.open(SESSION, key(), contiguous(10, 8, 200)));

        assertEquals(SESSION, refused.sessionId());
        assertTrue(refused.getMessage().contains("Pragma 41"),
                "the refusal must say what desynchronised it: " + refused.getMessage());
        assertTrue(refused.getMessage().contains("Send decoded to Repeater"),
                "the refusal must say how to avoid it next time: " + refused.getMessage());
        assertFalse(refused.isRecoverable());
    }

    /**
     * The dangerous case. An already-open ledger looks authoritative and would hand back a
     * confident, wrong offset, so the check has to come before the cache is consulted.
     */
    @Test
    @DisplayName("an already-open ledger is dropped, so it cannot serve a stale offset")
    void openLedgerIsInvalidated() throws Exception {
        StreamRegistry registry = new StreamRegistry(new Store());

        SessionStreams before = registry.open(SESSION, key(), contiguous(10, 8, 200));
        assertNotNull(before);
        assertTrue(registry.peek(SESSION).isPresent());

        registry.markDesynced(SESSION, REASON);

        assertTrue(registry.peek(SESSION).isEmpty(), "the stale ledger must not survive");
        assertThrows(StreamDesyncException.class,
                () -> registry.open(SESSION, key(), contiguous(10, 8, 200)));
    }

    /**
     * The server stays ahead across an extension reload, so the marker has to as well. A refusal that
     * evaporated on reload would be worse than none: the extension would have detected the problem
     * and then forgotten it.
     */
    @Test
    @DisplayName("the marker survives a reload, because the server's position does")
    void desyncSurvivesAReload() {
        Store store = new Store();

        new StreamRegistry(store).markDesynced(SESSION, REASON);

        StreamRegistry afterReload = new StreamRegistry(store);
        assertTrue(afterReload.isDesynced(SESSION));
        assertThrows(StreamDesyncException.class,
                () -> afterReload.open(SESSION, key(), contiguous(10, 8, 200)));
    }

    /**
     * Intruder sends one request per payload, and every one of them desynchronises a session that is
     * already desynchronised. Writing to the project file each time would be pure waste.
     */
    @Test
    @DisplayName("marking twice writes once, so a payload run does not hammer the project file")
    void markingIsIdempotent() {
        Store store = new Store();
        StreamRegistry registry = new StreamRegistry(store);

        assertTrue(registry.markDesynced(SESSION, REASON), "the first mark is news");
        for (int i = 0; i < 100; i++) {
            assertFalse(registry.markDesynced(SESSION, REASON), "every later mark is not");
        }
        assertEquals(1, store.desyncWrites);
    }

    @Test
    @DisplayName("an untouched session is unaffected and still opens normally")
    void cleanSessionsAreUnaffected() throws Exception {
        StreamRegistry registry = new StreamRegistry(new Store());
        registry.markDesynced("some-other-session", REASON);

        SessionStreams streams = registry.open(SESSION, key(), contiguous(10, 8, 200));

        assertEquals(64, streams.consumed(StreamLeg.SERVER_REQUEST));
        assertFalse(registry.isDesynced(SESSION));
    }

    @Test
    @DisplayName("forgetting a session clears its marker along with everything else")
    void forgetClearsTheMarker() throws Exception {
        Store store = new Store();
        StreamRegistry registry = new StreamRegistry(store);

        registry.markDesynced(SESSION, REASON);
        assertTrue(registry.isDesynced(SESSION));

        registry.forget(SESSION);

        assertFalse(registry.isDesynced(SESSION));
        assertTrue(store.desyncs.isEmpty());
        assertNotNull(registry.open(SESSION, key(), contiguous(10, 8, 200)));
    }

    /**
     * A marker written by another part of the extension, or by a previous run, must be honoured by a
     * registry that has never seen it in memory.
     */
    @Test
    @DisplayName("a marker present only in the store is still honoured")
    void storeOnlyMarkerIsHonoured() {
        Store store = new Store();
        store.markDesynced(SESSION, REASON);

        StreamRegistry registry = new StreamRegistry(store);

        assertTrue(registry.isDesynced(SESSION));
        assertThrows(StreamDesyncException.class,
                () -> registry.open(SESSION, key(), contiguous(10, 8, 200)));
    }

    /**
     * Both refusals are the same answer to the caller — "there is no offset to encrypt at" — which is
     * what lets the send path catch one type and still report either accurately.
     */
    @Test
    @DisplayName("a gap and a desync share a supertype, so the send path catches one thing")
    void bothRefusalsShareASupertype() {
        StreamRegistry registry = new StreamRegistry(new Store());
        registry.markDesynced(SESSION, REASON);

        StreamPositionUnknownException desync = assertThrows(StreamPositionUnknownException.class,
                () -> registry.open(SESSION, key(), contiguous(10, 8, 200)));
        assertFalse(desync.isRecoverable());

        Map<Direction, Map<Integer, byte[]>> holed = new HashMap<>();
        Map<Integer, byte[]> requests = new LinkedHashMap<>();
        requests.put(3, new byte[10]);
        requests.put(9, new byte[10]);
        holed.put(Direction.REQUEST, requests);
        holed.put(Direction.RESPONSE, new LinkedHashMap<>());

        StreamPositionUnknownException gap = assertThrows(StreamPositionUnknownException.class,
                () -> new StreamRegistry(new Store())
                        .open("gapped", key(), PragmaSource.of(holed)));
        assertTrue(gap.isRecoverable(), "a gap might still be captured; a desync never can be");
    }
}
