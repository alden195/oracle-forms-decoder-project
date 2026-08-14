package oracleforms.session;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The live {@link SessionStreams} for recently used sessions.
 *
 * <p>Two ways a session's ledger comes into existence, and the order matters:
 *
 * <ol>
 *   <li><b>Resumed</b> from persisted counters, if the session has diverged before. Those counters
 *       are the only record of the divergence, so history can no longer supply them.
 *   <li><b>Measured</b> from captured traffic otherwise, by {@link SessionTail}. An undiverged
 *       session is entirely reconstructible this way, which is why a Repeater send works against a
 *       session the extension was not even loaded for when it was captured.
 * </ol>
 *
 * <p>Bounded, in-memory, and holding no Burp objects (BApp criterion 9). Dropping a session costs
 * only the rebuild — unless it had diverged, in which case its counters were persisted precisely
 * because they could not be rebuilt.
 */
public final class StreamRegistry {

    /** Sessions whose ciphers are kept materialised. Each holds four 256-byte S-boxes. */
    private static final int MAX_LIVE_SESSIONS = 8;

    private final StreamPositionStore positions;
    private final Map<String, SessionStreams> live;

    public StreamRegistry(StreamPositionStore positions) {
        this.positions = positions == null ? StreamPositionStore.none() : positions;
        this.live = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, SessionStreams> eldest) {
                return size() > MAX_LIVE_SESSIONS;
            }
        };
    }

    /** The session's ledger if it is already materialised, without building one. */
    public Optional<SessionStreams> peek(String sessionId) {
        synchronized (live) {
            return Optional.ofNullable(live.get(sessionId));
        }
    }

    /**
     * The session's ledger, building it if necessary.
     *
     * <p>Call this off the EDT and off the proxy hot path: on a miss it walks the session's captured
     * traffic and may run the cipher over every byte of it.
     *
     * @throws StreamGapException if the session's traffic has a hole, so its position is unknown
     */
    public SessionStreams open(String sessionId, SessionKey key, PragmaSource source)
            throws StreamGapException {

        Optional<SessionStreams> existing = peek(sessionId);
        if (existing.isPresent()) {
            return existing.get();
        }

        // Built outside the lock: measuring a tail walks the session and skipping the cipher to it
        // is linear in the session's size.
        SessionStreams built = build(sessionId, key, source);

        synchronized (live) {
            // Another thread may have built it meanwhile. Theirs wins, so a session never has two
            // ledgers and two callers cannot both think they own the tail.
            SessionStreams raced = live.get(sessionId);
            if (raced != null) {
                return raced;
            }
            live.put(sessionId, built);
            return built;
        }
    }

    private SessionStreams build(String sessionId, SessionKey key, PragmaSource source)
            throws StreamGapException {

        Optional<StreamPositions> stored = positions.load(sessionId);
        if (stored.isPresent()) {
            if (stored.get().belongsTo(key.key())) {
                return SessionStreams.resumedAt(sessionId, key.key(), stored.get());
            }
            // The session's key has changed since these counters were written -- re-entered by
            // hand, imported, or re-derived from a fresh handshake. They describe a cipher timeline
            // that no longer exists, and resuming from them would skip a cipher seeded with the new
            // key to a byte count accumulated under the old one: an arbitrary offset that encrypts
            // perfectly and decrypts to nothing. Discard, and measure the session again.
            positions.forgetPositions(sessionId);
        }
        return SessionStreams.atTail(sessionId, key.key(), SessionTail.measure(source));
    }

    /**
     * Persists a session's counters if — and only if — its legs have diverged.
     *
     * <p>Called after anything that moves one leg without the other. An undiverged session is left
     * unwritten on purpose: it is cheaper to rebuild from history than to keep in the project file,
     * and writing it would make every proxied message a project-file write.
     *
     * <p>Call it only once a forward has <em>completed</em>. Forwarding is two steps — decrypt on one
     * leg, re-encrypt on the other — and between them the legs disagree for reasons that are not a
     * real divergence. Checkpointing there would persist a state that is one message wrong.
     */
    public void checkpoint(SessionStreams streams) {
        if (streams != null && streams.diverged()) {
            positions.save(streams.sessionId(), streams.positions());
        }
    }

    /** Drops a session's ledger and its persisted counters. */
    public void forget(String sessionId) {
        synchronized (live) {
            live.remove(sessionId);
        }
        positions.forgetPositions(sessionId);
    }

    /** Releases every materialised ledger. Called on unload (BApp criterion 6). */
    public void clear() {
        synchronized (live) {
            live.clear();
        }
    }

    public int size() {
        synchronized (live) {
            return live.size();
        }
    }
}
