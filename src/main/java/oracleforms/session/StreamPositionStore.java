package oracleforms.session;

import java.util.Optional;

/**
 * Durable storage for a session's four stream counters (architecture &sect;3, &sect;6.2).
 *
 * <p>Separate from {@link SessionKeyStore} because it has a different lifetime and a different
 * write pattern: a key is written once, whereas these change whenever a session diverges further,
 * and they are only worth writing <em>at all</em> once the client-facing and server-facing legs stop
 * agreeing. Before that they are reconstructible from proxy history, and writing them on every
 * message would touch the project file constantly for nothing.
 */
public interface StreamPositionStore {

    /** The stored counters for a session, or empty if it has never diverged. */
    Optional<StreamPositions> load(String sessionId);

    /** Records a diverged session's counters. */
    void save(String sessionId, StreamPositions positions);

    /**
     * Drops a session's counters and any desync marker, returning it to "reconstructible from
     * history".
     *
     * <p>Named apart from {@code SessionKeyStore.forget} because one implementation — the
     * project-file store — is both, and the two differ in return type.
     */
    void forgetPositions(String sessionId);

    /**
     * Why this session's position can no longer be recovered, or empty if it still can.
     *
     * <p>Separate from {@link #load} because the two are independent: a session can be desynchronised
     * without ever having diverged, which is the common case — someone pressed Send on a plain
     * ciphertext Repeater tab before ever drafting one.
     */
    Optional<String> desyncReason(String sessionId);

    /**
     * Records that traffic reached the server which proxy history did not capture.
     *
     * <p>Durable on purpose. The server's request cipher stays ahead across an extension reload and a
     * Burp restart, so a marker that did not survive them would let a later send encrypt at an offset
     * this extension already knew was wrong — the worst of both worlds, since it would have detected
     * the problem and then forgotten it (architecture &sect;6.11).
     */
    void markDesynced(String sessionId, String reason);

    /** A store that keeps nothing, for tests and for a project file that could not be opened. */
    static StreamPositionStore none() {
        return new StreamPositionStore() {
            @Override
            public Optional<StreamPositions> load(String sessionId) {
                return Optional.empty();
            }

            @Override
            public void save(String sessionId, StreamPositions positions) {
            }

            @Override
            public void forgetPositions(String sessionId) {
            }

            @Override
            public Optional<String> desyncReason(String sessionId) {
                return Optional.empty();
            }

            @Override
            public void markDesynced(String sessionId, String reason) {
            }
        };
    }
}
