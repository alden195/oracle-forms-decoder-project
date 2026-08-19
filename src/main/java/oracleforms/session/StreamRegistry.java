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

    /**
     * Desynchronised sessions remembered in memory, so repeat sends into one cost a hash lookup
     * rather than a project-file write. The durable record is in the store; this is only a cache.
     */
    private static final int MAX_REMEMBERED_DESYNCS = 64;

    /**
     * Sessions whose divergence has been looked up, so the proxy hot path does not re-read the
     * project file for every message. Holds one boolean each.
     */
    private static final int MAX_REMEMBERED_DIVERGENCE = 256;

    private final StreamPositionStore positions;
    private final Map<String, SessionStreams> live;
    private final Map<String, String> desynced;
    private final Map<String, Boolean> divergence;

    public StreamRegistry(StreamPositionStore positions) {
        this.positions = positions == null ? StreamPositionStore.none() : positions;
        this.divergence = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                return size() > MAX_REMEMBERED_DIVERGENCE;
            }
        };
        this.live = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, SessionStreams> eldest) {
                return size() > MAX_LIVE_SESSIONS;
            }
        };
        this.desynced = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                return size() > MAX_REMEMBERED_DESYNCS;
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
     * The ledger a proxied message must be carried across, if this session has one.
     *
     * <p>Safe to call from the proxy hot path, which is the whole design of it. A session that has
     * never diverged needs no ledger at all — its two legs share a keystream position, so forwarding
     * the bytes unchanged is right — and the answer for one is a single lookup in a bounded map.
     *
     * <p>The reason this exists rather than {@link #peek} is that a diverged session <em>must</em> be
     * translated and the live map is not a reliable record of which those are: it is an LRU, and it
     * is empty after an extension reload. Both of those would silently drop a session back to
     * forwarding client-side ciphertext to a server whose cipher has moved on, which is exactly the
     * failure this whole path exists to prevent. The persisted counters are the durable record, and
     * they are only consulted once per session because the answer is then cached either way.
     *
     * @param key the session's key, needed to rebuild the ciphers and to prove the counters are
     *            still about this key rather than one that has since been replaced
     */
    public Optional<SessionStreams> forProxiedMessage(String sessionId, SessionKey key) {
        Optional<SessionStreams> open = peek(sessionId);
        if (open.isPresent()) {
            return open;
        }
        if (sessionId == null || sessionId.isEmpty() || key == null
                || Boolean.FALSE.equals(divergenceOf(sessionId))) {
            return Optional.empty();
        }
        // A desynced session is one markDesynced has already dropped the ledger for, on purpose.
        // Rebuilding it here would resurrect exactly what that dropped, and it could not be right
        // anyway: the server consumed bytes nothing here ever saw.
        if (desyncReasonFor(sessionId) != null) {
            return Optional.empty();
        }

        Optional<StreamPositions> stored = positions.load(sessionId);
        if (stored.isEmpty() || !stored.get().diverged()) {
            noteDivergence(sessionId, false);
            return Optional.empty();
        }
        if (!stored.get().belongsTo(key.key())) {
            // Counters from a cipher timeline this key never took part in. Resuming from them would
            // skip a stream seeded with the new key to a byte count accumulated under the old one.
            positions.forgetPositions(sessionId);
            noteDivergence(sessionId, false);
            return Optional.empty();
        }

        SessionStreams resumed = SessionStreams.resumedAt(sessionId, key.key(), stored.get());
        noteDivergence(sessionId, true);
        synchronized (live) {
            SessionStreams raced = live.get(sessionId);
            if (raced != null) {
                return Optional.of(raced);
            }
            live.put(sessionId, resumed);
            return Optional.of(resumed);
        }
    }

    /**
     * The session's ledger, building it if necessary.
     *
     * <p>Call this off the EDT and off the proxy hot path: on a miss it walks the session's captured
     * traffic and may run the cipher over every byte of it.
     *
     * @throws StreamDesyncException if traffic reached the server that history never recorded
     * @throws StreamGapException    if the session's traffic has a hole, so its position is unknown
     */
    public SessionStreams open(String sessionId, SessionKey key, PragmaSource source)
            throws StreamPositionUnknownException {

        // Checked before the live ledger is consulted, not after. An already-open ledger is exactly
        // as wrong as a freshly measured one once untracked bytes have reached the server, and it is
        // the more dangerous of the two because it looks authoritative.
        String desync = desyncReasonFor(sessionId);
        if (desync != null) {
            throw new StreamDesyncException(sessionId, desync);
        }

        Optional<SessionStreams> existing = peek(sessionId);
        if (existing.isPresent()) {
            return existing.get();
        }

        // Built outside the lock: measuring a tail walks the session and skipping the cipher to it
        // is linear in the session's size.
        SessionStreams built = build(sessionId, key, SessionTail.measure(source));

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

    /**
     * The session's ledger, positioned where its ciphers stood <em>before</em> {@code pragma}.
     *
     * <p>What an in-flight edit needs, and not the same thing as {@link #open}. The tail is where
     * the server's cipher has got to, and a request held in the Intercept tab is <em>in proxy
     * history but has not been sent</em> — so a tail measured while one is held counts a message the
     * server has never read, and everything encrypted afterwards is that message's length too far
     * along the keystream. {@link SessionTail#before} is the measurement that excludes it.
     *
     * <p>Like {@link #open}, an already-materialised ledger wins: it is the live record, including
     * any divergence, and history cannot reconstruct it. The caller is expected to check that it is
     * where it should be — {@link #measureBefore} and {@link #resynchronise} are the two halves of
     * doing so.
     *
     * @throws StreamDesyncException if traffic reached the server that history never recorded
     * @throws StreamGapException    if the traffic before {@code pragma} has a hole in it
     */
    public SessionStreams openBefore(
            String sessionId, SessionKey key, PragmaSource source, int pragma)
            throws StreamPositionUnknownException {

        String desync = desyncReasonFor(sessionId);
        if (desync != null) {
            throw new StreamDesyncException(sessionId, desync);
        }

        Optional<SessionStreams> existing = peek(sessionId);
        if (existing.isPresent()) {
            return existing.get();
        }

        SessionStreams built = build(sessionId, key, SessionTail.before(source, pragma));

        synchronized (live) {
            SessionStreams raced = live.get(sessionId);
            if (raced != null) {
                return raced;
            }
            live.put(sessionId, built);
            return built;
        }
    }

    /**
     * A detached ledger at the position captured traffic says this session held before
     * {@code pragma}, built without disturbing the live one.
     *
     * <p>The second opinion. A ledger that has been advanced message by message can only be checked
     * against something measured independently, and this is that something — but it is a
     * <em>candidate</em>, not an authority, so it is deliberately not installed. The caller decrypts
     * with it, checks the result reads as FHT, and only then calls {@link #resynchronise}.
     *
     * <p>Says nothing about the server-facing legs of a session that has diverged: history has no
     * record of what this extension injected, which is exactly why the counters are persisted.
     * {@link #resynchronise} refuses such a session for that reason.
     *
     * @throws StreamGapException if the traffic before {@code pragma} has a hole in it
     */
    public SessionStreams measureBefore(
            String sessionId, SessionKey key, PragmaSource source, int pragma)
            throws StreamGapException {
        return SessionStreams.atTail(sessionId, key.key(), SessionTail.before(source, pragma));
    }

    /**
     * Adopts a freshly measured ledger in place of one the caller has shown to be at the wrong
     * offset.
     *
     * <p>Only ever called with a position that has been <em>verified</em> — decrypted and shown to
     * parse as FHT — because replacing a wrong offset with another wrong one is not an improvement,
     * and the ledger it overwrites is what every later message in the session is encrypted against.
     *
     * <p>Refuses a session that has diverged, in memory or in the project file. Its counters are the
     * only record of traffic this extension injected, history never saw those bytes, and a
     * measurement that cannot see them cannot correct them.
     *
     * <p>The <em>response</em> legs come from the same measurement, so a response offset that an
     * earlier reply recovery had corrected is measured from history again — short by the outstanding
     * response the client's long poll leaves in flight (&sect;6.11). That is deliberate rather than
     * overlooked: the next reply re-solves and re-synchronises it, and a ledger assembled half from a
     * measurement and half from memory is harder to reason about than one that is wholly either.
     *
     * @return whether the correction was adopted
     */
    public boolean resynchronise(SessionStreams corrected) {
        if (corrected == null) {
            return false;
        }
        String sessionId = corrected.sessionId();
        if (positions.load(sessionId).map(StreamPositions::diverged).orElse(false)) {
            return false;
        }
        synchronized (live) {
            SessionStreams existing = live.get(sessionId);
            if (existing != null && existing.diverged()) {
                return false;
            }
            live.put(sessionId, corrected);
            return true;
        }
    }

    /**
     * Resumes a session's persisted counters, or accepts the measurement offered for it.
     *
     * @param measured where captured traffic says the session is, used only when nothing durable
     *                 contradicts it
     */
    private SessionStreams build(String sessionId, SessionKey key, SessionTail measured) {

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
        return SessionStreams.atTail(sessionId, key.key(), measured);
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
            noteDivergence(streams.sessionId(), true);
            positions.save(streams.sessionId(), streams.positions());
        }
    }

    /**
     * Remembers whether a session has diverged, so {@link #forProxiedMessage} asks the project file
     * once rather than once per message.
     *
     * <p>Caching the negative is safe only because every transition to diverged runs through
     * {@link #checkpoint}, which overwrites it. A session can never become diverged behind this
     * cache's back: divergence is created by this extension sending something, and nothing else.
     */
    private void noteDivergence(String sessionId, boolean diverged) {
        synchronized (divergence) {
            divergence.put(sessionId, diverged);
        }
    }

    /** What we already know about a session's divergence, or null if we have never looked. */
    private Boolean divergenceOf(String sessionId) {
        synchronized (divergence) {
            return divergence.get(sessionId);
        }
    }

    /**
     * Records that bytes reached the server which proxy history did not capture, making this
     * session's keystream position unrecoverable (architecture &sect;6.11).
     *
     * <p>Safe to call from the proxy hot path. The first call for a session writes to the project
     * file and drops any open ledger; every call after that is a hash lookup and returns false, which
     * is what keeps an Intruder run from writing once per payload.
     *
     * @return true if this is the first time the session has been marked, so the caller can log once
     */
    public boolean markDesynced(String sessionId, String reason) {
        if (sessionId == null || sessionId.isEmpty()) {
            return false;
        }
        synchronized (desynced) {
            if (desynced.containsKey(sessionId)) {
                return false;
            }
            desynced.put(sessionId, reason == null ? "" : reason);
        }

        positions.markDesynced(sessionId, reason);

        // The open ledger, if there is one, now describes a server position that no longer exists.
        // Dropping it means the next open() takes the refusing path above rather than handing back
        // a ledger that would encrypt confidently at the wrong offset.
        synchronized (live) {
            live.remove(sessionId);
        }
        return true;
    }

    /** Whether this session's keystream position is known to be unrecoverable. */
    public boolean isDesynced(String sessionId) {
        return desyncReasonFor(sessionId) != null;
    }

    /**
     * The recorded reason, from memory if we have seen it this session and from the project file
     * otherwise. Only positives are cached: a clean session must keep consulting the store, because
     * another part of the extension may have marked it since.
     */
    private String desyncReasonFor(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return null;
        }
        synchronized (desynced) {
            String remembered = desynced.get(sessionId);
            if (remembered != null) {
                return remembered;
            }
        }
        Optional<String> stored = positions.desyncReason(sessionId);
        if (stored.isEmpty()) {
            return null;
        }
        synchronized (desynced) {
            desynced.put(sessionId, stored.get());
        }
        return stored.get();
    }

    /**
     * Drops a session's ledger, its persisted counters and any desync marker.
     *
     * <p>Clearing the desync is deliberate. This is the explicit "start over" action, and the marker
     * describes a cipher timeline the user has just declared they no longer care about. It does not
     * make the old session sendable again — the server is still ahead — but it stops a stale marker
     * outliving the session it was about.
     */
    public void forget(String sessionId) {
        synchronized (live) {
            live.remove(sessionId);
        }
        synchronized (desynced) {
            desynced.remove(sessionId);
        }
        synchronized (divergence) {
            divergence.remove(sessionId);
        }
        positions.forgetPositions(sessionId);
    }

    /** Releases every materialised ledger. Called on unload (BApp criterion 6). */
    public void clear() {
        synchronized (live) {
            live.clear();
        }
        // The in-memory desync cache goes too; the durable markers stay in the project file, which
        // is the whole point of their being there.
        synchronized (desynced) {
            desynced.clear();
        }
        // Rebuilt from the project file on demand, like the desync markers above.
        synchronized (divergence) {
            divergence.clear();
        }
    }

    public int size() {
        synchronized (live) {
            return live.size();
        }
    }
}
