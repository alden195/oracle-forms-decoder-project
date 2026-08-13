package oracleforms.session;

import java.util.List;
import java.util.Optional;

/**
 * Where session keys live.
 *
 * <p>An interface with no Burp types in its signature, so the replayer and the Sessions tab can be
 * driven by an in-memory store in tests while the real implementation writes to the project file.
 *
 * <p>Implementations must be safe to call from several threads: keys are written from the proxy hot
 * path and read from the decode executor and the EDT.
 */
public interface SessionKeyStore {

    Optional<SessionKey> get(String sessionId);

    /** Stores or replaces the key for a session. */
    void put(SessionKey key);

    /** All known sessions, most recently seen first. */
    List<SessionKey> list();

    /** Removes one session's key. Returns whether anything was removed. */
    boolean forget(String sessionId);

    /** Removes every key. The user-facing "clear all keys" action. */
    void clear();

    default boolean contains(String sessionId) {
        return get(sessionId).isPresent();
    }

    default int size() {
        return list().size();
    }
}
