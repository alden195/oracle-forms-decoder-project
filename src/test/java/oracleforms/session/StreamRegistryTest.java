package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tail measurement and the ledger registry.
 *
 * <p>The tests that matter most here are the refusals. Encrypting at a position the server is not at
 * does not fail politely — the server reads the message as noise — so a session with a hole in its
 * capture must produce an exception, never a plausible number.
 */
class StreamRegistryTest {

    private static final String SESSION = "registry-test-session";
    private static final byte[] KEY = {0x11, 0x22, (byte) 0xAE, 0x33, 0x44};

    private static SessionKey key() {
        return new SessionKey(SESSION, KEY, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    /** Builds a source with the given per-direction body sizes, keyed by pragma. */
    private static PragmaSource source(
            Map<Integer, Integer> requestSizes, Map<Integer, Integer> responseSizes) {

        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        bodies.put(Direction.REQUEST, sized(requestSizes));
        bodies.put(Direction.RESPONSE, sized(responseSizes));
        return PragmaSource.of(bodies);
    }

    private static Map<Integer, byte[]> sized(Map<Integer, Integer> sizes) {
        Map<Integer, byte[]> out = new LinkedHashMap<>();
        sizes.forEach((pragma, size) -> out.put(pragma, new byte[size]));
        return out;
    }

    /** A contiguous session from pragma 3 to {@code last}, with fixed body sizes. */
    private static PragmaSource contiguous(int last, int requestSize, int responseSize) {
        Map<Integer, Integer> requests = new LinkedHashMap<>();
        Map<Integer, Integer> responses = new LinkedHashMap<>();
        for (int pragma = 3; pragma <= last; pragma++) {
            requests.put(pragma, requestSize);
            responses.put(pragma, responseSize);
        }
        return source(requests, responses);
    }

    // ---- tail measurement -----------------------------------------------------------------

    @Test
    @DisplayName("the tail is the sum of every captured body in each direction")
    void tailSumsBothDirections() throws Exception {
        SessionTail tail = SessionTail.measure(contiguous(12, 10, 100));

        assertEquals(12, tail.requestPragma());
        assertEquals(12, tail.responsePragma());
        assertEquals(10 * 10, tail.requestBytes(), "pragmas 3..12 inclusive is ten messages");
        assertEquals(100 * 10, tail.responseBytes());
        assertEquals(13, tail.nextPragma());
        assertTrue(tail.hasTraffic());
    }

    @Test
    @DisplayName("a NULLPOST contributes nothing to the request tail")
    void nullPostIsExcludedFromTheTail() throws Exception {
        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        Map<Integer, byte[]> requests = new LinkedHashMap<>();
        requests.put(3, new byte[10]);
        requests.put(4, PragmaBody.NULL_POST.clone());
        requests.put(5, new byte[10]);
        bodies.put(Direction.REQUEST, requests);
        bodies.put(Direction.RESPONSE, sized(Map.of(3, 50, 4, 50, 5, 50)));

        SessionTail tail = SessionTail.measure(PragmaSource.of(bodies));

        assertEquals(20, tail.requestBytes(),
                "the sentinel was never encrypted, so the server's cipher never saw it");
        assertEquals(150, tail.responseBytes());
    }

    @Test
    @DisplayName("an empty session has no usable tail")
    void emptySessionHasNoTraffic() throws Exception {
        SessionTail tail = SessionTail.measure(source(Map.of(), Map.of()));
        assertFalse(tail.hasTraffic());
        assertEquals(0, tail.requestBytes());
    }

    /**
     * The failure this class exists to prevent. Walking forward and stopping at the first absence
     * would report a tail of pragma 5 while the server had actually consumed everything up to 20 —
     * roughly fifteen messages' worth of keystream too early.
     */
    @Test
    @DisplayName("a hole in the middle of a session is refused, not silently truncated")
    void interiorGapIsRefused() {
        Map<Integer, Integer> requests = new LinkedHashMap<>();
        Map<Integer, Integer> responses = new LinkedHashMap<>();
        for (int pragma = 3; pragma <= 20; pragma++) {
            if (pragma != 6) {
                requests.put(pragma, 10);
            }
            responses.put(pragma, 50);
        }

        StreamGapException gap = assertThrows(StreamGapException.class,
                () -> SessionTail.measure(source(requests, responses)));

        assertEquals(Direction.REQUEST, gap.direction());
        assertEquals(6, gap.missing());
        assertTrue(gap.seenLater() > 6);
        assertTrue(gap.getMessage().contains("Pragma 6"), gap.getMessage());
    }

    @Test
    @DisplayName("a session that simply ends is not a gap")
    void trailingAbsenceIsTheEndOfTheSession() throws Exception {
        SessionTail tail = SessionTail.measure(contiguous(9, 10, 50), 9);
        assertEquals(9, tail.requestPragma());
        assertEquals(70, tail.requestBytes());
    }

    @Test
    @DisplayName("a request captured without its response yet is not a gap")
    void inFlightRequestIsTolerated() throws Exception {
        Map<Integer, Integer> requests = new LinkedHashMap<>();
        Map<Integer, Integer> responses = new LinkedHashMap<>();
        for (int pragma = 3; pragma <= 8; pragma++) {
            requests.put(pragma, 10);
            if (pragma < 8) {
                responses.put(pragma, 50);
            }
        }

        SessionTail tail = SessionTail.measure(source(requests, responses));

        assertEquals(8, tail.requestPragma());
        assertEquals(7, tail.responsePragma(), "the last response is still in flight");
        assertEquals(60, tail.requestBytes());
        assertEquals(250, tail.responseBytes());
    }

    // ---- the registry ---------------------------------------------------------------------

    @Test
    @DisplayName("opening a session measures its tail and starts both sides level")
    void openMeasuresTheTail() throws Exception {
        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());

        SessionStreams streams = registry.open(SESSION, key(), contiguous(10, 8, 200));

        assertEquals(64, streams.consumed(StreamLeg.SERVER_REQUEST));
        assertEquals(64, streams.consumed(StreamLeg.CLIENT_REQUEST));
        assertEquals(1600, streams.consumed(StreamLeg.SERVER_RESPONSE));
        assertFalse(streams.diverged());
    }

    @Test
    @DisplayName("a second open returns the same ledger, not a second one")
    void openIsIdempotent() throws Exception {
        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());
        PragmaSource source = contiguous(6, 8, 200);

        assertSame(registry.open(SESSION, key(), source), registry.open(SESSION, key(), source));
    }

    @Test
    @DisplayName("persisted counters win over history, because history can no longer supply them")
    void persistedPositionsTakePrecedence() throws Exception {
        Map<String, StreamPositions> saved = new HashMap<>();
        saved.put(SESSION, new StreamPositions(Map.of(
                StreamLeg.CLIENT_REQUEST, 100L,
                StreamLeg.SERVER_REQUEST, 175L,
                StreamLeg.SERVER_RESPONSE, 900L,
                StreamLeg.CLIENT_RESPONSE, 900L), 30, StreamPositions.fingerprint(KEY)));

        StreamRegistry registry = new StreamRegistry(recordingStore(saved));
        SessionStreams streams = registry.open(SESSION, key(), contiguous(10, 8, 200));

        assertEquals(175, streams.consumed(StreamLeg.SERVER_REQUEST),
                "the divergence is only recorded here; the capture cannot show it");
        assertTrue(streams.diverged());
    }

    @Test
    @DisplayName("only a diverged session is written to the project file")
    void checkpointSkipsUndivergedSessions() throws Exception {
        Map<String, StreamPositions> saved = new HashMap<>();
        StreamRegistry registry = new StreamRegistry(recordingStore(saved));

        SessionStreams streams = registry.open(SESSION, key(), contiguous(10, 8, 200));
        registry.checkpoint(streams);
        assertTrue(saved.isEmpty(), "watching traffic must not write to the project file");

        streams.advance(StreamLeg.SERVER_REQUEST, 40);
        registry.checkpoint(streams);
        assertEquals(1, saved.size());
        assertEquals(104L, saved.get(SESSION).at(StreamLeg.SERVER_REQUEST));
    }

    @Test
    @DisplayName("a gap in history means no ledger at all")
    void openRefusesOnAGap() {
        Map<Integer, Integer> requests = new LinkedHashMap<>(Map.of(3, 10, 4, 10, 9, 10));
        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());

        assertThrows(StreamGapException.class,
                () -> registry.open(SESSION, key(), source(requests, Map.of())));
    }

    @Test
    @DisplayName("forgetting a session clears both the ledger and its stored counters")
    void forgetClearsBoth() throws Exception {
        Map<String, StreamPositions> saved = new HashMap<>();
        StreamRegistry registry = new StreamRegistry(recordingStore(saved));

        SessionStreams streams = registry.open(SESSION, key(), contiguous(5, 8, 100));
        streams.advance(StreamLeg.SERVER_REQUEST, 12);
        registry.checkpoint(streams);
        assertFalse(saved.isEmpty());

        registry.forget(SESSION);

        assertTrue(registry.peek(SESSION).isEmpty());
        assertTrue(saved.isEmpty());
    }

    @Test
    @DisplayName("the registry is bounded, so a large project cannot grow it without limit")
    void registryIsBounded() throws Exception {
        StreamRegistry registry = new StreamRegistry(StreamPositionStore.none());
        for (int i = 0; i < 50; i++) {
            String id = "session-" + i;
            registry.open(id, new SessionKey(id, KEY, "h", 0L, 0L, "", KeySource.DERIVED),
                    contiguous(5, 8, 100));
        }
        assertTrue(registry.size() <= 8, "expected an LRU bound, got " + registry.size());

        registry.clear();
        assertEquals(0, registry.size());
    }

    private static StreamPositionStore recordingStore(Map<String, StreamPositions> backing) {
        return new StreamPositionStore() {
            @Override
            public Optional<StreamPositions> load(String sessionId) {
                return Optional.ofNullable(backing.get(sessionId));
            }

            @Override
            public void save(String sessionId, StreamPositions positions) {
                assertNotNull(positions);
                backing.put(sessionId, positions);
            }

            @Override
            public void forgetPositions(String sessionId) {
                backing.remove(sessionId);
            }
        };
    }
}
