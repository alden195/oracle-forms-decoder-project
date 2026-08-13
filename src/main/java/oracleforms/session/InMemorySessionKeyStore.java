package oracleforms.session;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link SessionKeyStore} held only in memory.
 *
 * <p>Used by the unit tests, and as a fallback if the persisted store cannot be opened — a session
 * that decodes until Burp restarts is better than an extension that fails to load.
 */
public final class InMemorySessionKeyStore implements SessionKeyStore {

    private final Map<String, SessionKey> keys = new ConcurrentHashMap<>();

    @Override
    public Optional<SessionKey> get(String sessionId) {
        return sessionId == null ? Optional.empty() : Optional.ofNullable(keys.get(sessionId));
    }

    @Override
    public void put(SessionKey key) {
        keys.put(key.sessionId(), key);
    }

    @Override
    public List<SessionKey> list() {
        return keys.values().stream()
                .sorted(Comparator.comparingLong(SessionKey::lastSeen).reversed())
                .toList();
    }

    @Override
    public boolean forget(String sessionId) {
        return sessionId != null && keys.remove(sessionId) != null;
    }

    @Override
    public void clear() {
        keys.clear();
    }
}
