package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Stream counters must never be resumed under a key other than the one that produced them.
 *
 * <p>Found by review. The counters are persisted in a collection that sits <em>beside</em> the
 * session entry rather than inside it, which is what stops {@code PersistedKeyStore.put} destroying
 * them every time a key is re-derived. The cost of that layout is that they also survive a key
 * <em>change</em> — a hand-entered correction, a JSON import, or a fresh handshake with different
 * randoms — and a byte count accumulated under the old key means nothing under the new one.
 *
 * <p>The failure is silent and expensive: skipping a cipher seeded with key B to a count measured
 * under key A lands on an arbitrary offset, encrypts perfectly, and is read by the server as noise.
 * Exactly what architecture §6.4 says must never be guessed at.
 */
class KeyChangeInvalidatesStreamsTest {

    private static final String SESSION = "key-change-session";
    private static final byte[] KEY_A = {0x11, (byte) 0x9C, (byte) 0xAE, 0x44, (byte) 0xD3};
    private static final byte[] KEY_B = {0x22, (byte) 0x8B, (byte) 0xAE, 0x55, (byte) 0xC2};

    private static SessionKey key(byte[] bytes) {
        return new SessionKey(SESSION, bytes, "host", 0L, 0L, "", KeySource.DERIVED);
    }

    /** A contiguous session of fixed-size bodies, so the measured tail is predictable. */
    private static PragmaSource history(int lastPragma, int requestSize, int responseSize) {
        Map<Direction, Map<Integer, byte[]>> bodies = new HashMap<>();
        Map<Integer, byte[]> requests = new LinkedHashMap<>();
        Map<Integer, byte[]> responses = new LinkedHashMap<>();
        for (int pragma = 3; pragma <= lastPragma; pragma++) {
            requests.put(pragma, new byte[requestSize]);
            responses.put(pragma, new byte[responseSize]);
        }
        bodies.put(Direction.REQUEST, requests);
        bodies.put(Direction.RESPONSE, responses);
        return PragmaSource.of(bodies);
    }

    private static final class RecordingStore implements StreamPositionStore {
        private final Map<String, StreamPositions> saved = new HashMap<>();
        private final Map<String, String> desyncs = new HashMap<>();
        private int forgets;

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
            forgets++;
        }

        @Override
        public Optional<String> desyncReason(String sessionId) {
            return Optional.ofNullable(desyncs.get(sessionId));
        }

        @Override
        public void markDesynced(String sessionId, String reason) {
            desyncs.put(sessionId, reason);
        }
    }

    @Test
    @DisplayName("a fingerprint identifies the key a set of counters belongs to")
    void fingerprintDistinguishesKeys() {
        assertNotEquals(StreamPositions.fingerprint(KEY_A), StreamPositions.fingerprint(KEY_B));
        assertEquals(StreamPositions.fingerprint(KEY_A), StreamPositions.fingerprint(KEY_A.clone()));

        StreamPositions positions = new StreamPositions(
                Map.of(StreamLeg.SERVER_REQUEST, 148L), 42, StreamPositions.fingerprint(KEY_A));
        assertTrue(positions.belongsTo(KEY_A));
        assertFalse(positions.belongsTo(KEY_B));
        assertFalse(positions.belongsTo(null));
    }

    /**
     * The bug itself. Counters saved under key A must not be applied to key B — the resulting
     * cipher would sit at an offset that corresponds to nothing.
     */
    @Test
    @DisplayName("counters saved under one key are discarded when the session's key changes")
    void staleCountersAreDiscardedOnAKeyChange() throws Exception {
        RecordingStore store = new RecordingStore();
        StreamRegistry registry = new StreamRegistry(store);
        PragmaSource source = history(10, 8, 200);

        // A divergence is created and persisted under key A.
        SessionStreams underA = registry.open(SESSION, key(KEY_A), source);
        underA.advance(StreamLeg.SERVER_REQUEST, 84);
        registry.checkpoint(underA);
        assertTrue(store.load(SESSION).isPresent(), "the divergence should have been recorded");
        long divergedPosition = underA.consumed(StreamLeg.SERVER_REQUEST);
        assertEquals(64 + 84, divergedPosition);

        // The key is corrected and the ledger rebuilt from scratch, as it would be after a reload.
        registry.clear();
        SessionStreams underB = registry.open(SESSION, key(KEY_B), source);

        assertEquals(64, underB.consumed(StreamLeg.SERVER_REQUEST),
                "the ledger must fall back to the tail measured from history, not the stale count");
        assertNotEquals(divergedPosition, underB.consumed(StreamLeg.SERVER_REQUEST));
        assertFalse(underB.diverged(), "a rebuilt ledger starts level");
        assertTrue(store.load(SESSION).isEmpty(), "the stale counters should have been dropped");
        assertEquals(1, store.forgets);
    }

    @Test
    @DisplayName("counters are still resumed when the key is unchanged")
    void matchingKeyStillResumes() throws Exception {
        RecordingStore store = new RecordingStore();
        StreamRegistry registry = new StreamRegistry(store);
        PragmaSource source = history(10, 8, 200);

        SessionStreams first = registry.open(SESSION, key(KEY_A), source);
        first.advance(StreamLeg.SERVER_REQUEST, 84);
        registry.checkpoint(first);

        registry.clear();
        SessionStreams resumed = registry.open(SESSION, key(KEY_A), source);

        assertEquals(148, resumed.consumed(StreamLeg.SERVER_REQUEST),
                "an unchanged key must still resume the divergence, which is the whole point");
        assertTrue(resumed.diverged());
        assertEquals(0, store.forgets);
    }

    /**
     * The consequence, made concrete: a server that has consumed the session must still be able to
     * read what the rebuilt ledger encrypts. Resuming the stale count would fail this.
     */
    @Test
    @DisplayName("after a key change the next send lands where the server actually is")
    void sendAfterAKeyChangeIsStillReadable() throws Exception {
        RecordingStore store = new RecordingStore();
        StreamRegistry registry = new StreamRegistry(store);
        PragmaSource source = history(10, 8, 200);

        SessionStreams underA = registry.open(SESSION, key(KEY_A), source);
        underA.advance(StreamLeg.SERVER_REQUEST, 84);
        registry.checkpoint(underA);
        registry.clear();

        // A server holding key B that has consumed the captured session: 8 pragmas of 8 bytes.
        Rc4Stream server = new Rc4Stream(KEY_B);
        server.skip(64);

        SessionStreams underB = registry.open(SESSION, key(KEY_B), source);
        byte[] plaintext = "a send after the key was corrected".getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
        InjectionPlan.Result.Ready ready = (InjectionPlan.Result.Ready)
                InjectionPlan.atTail(underB, plaintext);

        org.junit.jupiter.api.Assertions.assertArrayEquals(
                plaintext, server.applied(ready.ciphertext()),
                "the server must be able to read the send; a stale offset would give it noise");
    }

    @Test
    @DisplayName("counters written before key binding existed are not trusted")
    void unboundCountersAreRejected() throws Exception {
        RecordingStore store = new RecordingStore();
        // Fingerprint 0 stands in for an entry with no key binding at all.
        store.save(SESSION, new StreamPositions(Map.of(StreamLeg.SERVER_REQUEST, 900L), 40, 0L));

        StreamRegistry registry = new StreamRegistry(store);
        SessionStreams streams = registry.open(SESSION, key(KEY_A), history(10, 8, 200));

        assertEquals(64, streams.consumed(StreamLeg.SERVER_REQUEST),
                "an unidentifiable set of counters must be rebuilt, not adopted");
    }
}
