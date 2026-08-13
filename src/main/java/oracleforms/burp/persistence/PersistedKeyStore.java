package oracleforms.burp.persistence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import oracleforms.session.KeySource;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;

/**
 * A {@link SessionKeyStore} backed by Burp's project-scoped extension data.
 *
 * <p>Project scope is exactly the right lifetime: keys belong to the traffic captured in that
 * project, and they survive both an extension reload and a Burp restart. That persistence is what
 * turns a stored key from a session-lifetime convenience into the feature that makes previously
 * captured traffic readable (architecture &sect;3).
 *
 * <p>Layout under {@code extensionData()}:
 *
 * <pre>
 * oracleForms
 *   └── sessions
 *         └── &lt;jsessionid&gt;
 *               ├── key        ByteArray(5)
 *               ├── host       String
 *               ├── firstSeen  Long
 *               ├── lastSeen   Long
 *               ├── label      String
 *               └── source     String
 * </pre>
 *
 * <p>Every read is defensive. The project file is user-editable state that may have been written by
 * an older version of this extension, so a malformed entry is logged and skipped rather than being
 * allowed to break the Sessions tab.
 */
public final class PersistedKeyStore implements SessionKeyStore {

    private static final String ROOT = "oracleForms";
    private static final String SESSIONS = "sessions";

    private static final String KEY = "key";
    private static final String HOST = "host";
    private static final String FIRST_SEEN = "firstSeen";
    private static final String LAST_SEEN = "lastSeen";
    private static final String LABEL = "label";
    private static final String SOURCE = "source";

    private final PersistedObject extensionData;
    private final Logging logging;

    public PersistedKeyStore(PersistedObject extensionData, Logging logging) {
        this.extensionData = extensionData;
        this.logging = logging;
    }

    @Override
    public synchronized Optional<SessionKey> get(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return Optional.empty();
        }
        PersistedObject sessions = sessions(false);
        if (sessions == null) {
            return Optional.empty();
        }
        PersistedObject entry = sessions.getChildObject(sessionId);
        return entry == null ? Optional.empty() : read(sessionId, entry);
    }

    @Override
    public synchronized void put(SessionKey key) {
        PersistedObject sessions = sessions(true);
        PersistedObject entry = PersistedObject.persistedObject();

        entry.setByteArray(KEY, ByteArray.byteArray(key.key()));
        entry.setString(HOST, key.host());
        entry.setLong(FIRST_SEEN, key.firstSeen());
        entry.setLong(LAST_SEEN, key.lastSeen());
        entry.setString(LABEL, key.label());
        entry.setString(SOURCE, key.source().wireName());

        sessions.setChildObject(key.sessionId(), entry);
    }

    @Override
    public synchronized List<SessionKey> list() {
        PersistedObject sessions = sessions(false);
        if (sessions == null) {
            return List.of();
        }
        List<SessionKey> out = new ArrayList<>();
        for (String sessionId : sessions.childObjectKeys()) {
            PersistedObject entry = sessions.getChildObject(sessionId);
            if (entry != null) {
                read(sessionId, entry).ifPresent(out::add);
            }
        }
        out.sort(Comparator.comparingLong(SessionKey::lastSeen).reversed());
        return out;
    }

    @Override
    public synchronized boolean forget(String sessionId) {
        PersistedObject sessions = sessions(false);
        if (sessions == null || sessionId == null || sessions.getChildObject(sessionId) == null) {
            return false;
        }
        sessions.deleteChildObject(sessionId);
        return true;
    }

    @Override
    public synchronized void clear() {
        PersistedObject root = extensionData.getChildObject(ROOT);
        if (root != null) {
            root.deleteChildObject(SESSIONS);
        }
    }

    /**
     * @param create whether to build the nested objects if they are absent; readers pass false so
     *               that merely opening the Sessions tab does not write to the project file
     */
    private PersistedObject sessions(boolean create) {
        PersistedObject root = getOrCreate(extensionData, ROOT, create);
        if (root == null) {
            return null;
        }
        return getOrCreate(root, SESSIONS, create);
    }

    /**
     * Fetches a nested object, optionally creating it.
     *
     * <p>The re-read after {@code setChildObject} matters: the API does not promise that the
     * instance handed in is the one subsequently stored, so writing through the local reference could
     * write to an object the project file never sees. The null check after that re-read matters too —
     * without it a store that refused the write would NPE inside {@link #put}, and since {@code put}
     * is called from the proxy response path, the only symptom would be captured keys quietly going
     * missing.
     */
    private PersistedObject getOrCreate(PersistedObject parent, String name, boolean create) {
        PersistedObject child = parent.getChildObject(name);
        if (child != null) {
            return child;
        }
        if (!create) {
            return null;
        }
        parent.setChildObject(name, PersistedObject.persistedObject());
        child = parent.getChildObject(name);
        if (child == null) {
            throw new IllegalStateException(
                    "Burp did not persist the '" + name + "' object; session keys cannot be saved");
        }
        return child;
    }

    private Optional<SessionKey> read(String sessionId, PersistedObject entry) {
        try {
            ByteArray stored = entry.getByteArray(KEY);
            if (stored == null) {
                return Optional.empty();
            }
            return Optional.of(new SessionKey(
                    sessionId,
                    stored.getBytes(),
                    orEmpty(entry.getString(HOST)),
                    orZero(entry.getLong(FIRST_SEEN)),
                    orZero(entry.getLong(LAST_SEEN)),
                    orEmpty(entry.getString(LABEL)),
                    KeySource.fromWireName(entry.getString(SOURCE))));
        } catch (RuntimeException e) {
            // A key of the wrong length, or a field of the wrong type from an older layout.
            logging.logToError("Skipping unreadable stored key for session " + sessionId + ": " + e);
            return Optional.empty();
        }
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static long orZero(Long value) {
        return value == null ? 0L : value;
    }
}
