package oracleforms.burp.persistence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import oracleforms.session.KeySource;
import oracleforms.session.SessionKey;
import oracleforms.session.SessionKeyStore;
import oracleforms.session.StreamLeg;
import oracleforms.session.StreamPositionStore;
import oracleforms.session.StreamPositions;

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
 *   ├── sessions
 *   │     └── &lt;jsessionid&gt;
 *   │           ├── key        ByteArray(5)
 *   │           ├── host       String
 *   │           ├── firstSeen  Long
 *   │           ├── lastSeen   Long
 *   │           ├── label      String
 *   │           └── source     String
 *   └── streams
 *         └── &lt;jsessionid&gt;          only once the session's four legs diverge
 *               ├── clientRequestBytes   Long
 *               ├── serverRequestBytes   Long
 *               ├── serverResponseBytes  Long
 *               ├── clientResponseBytes  Long
 *               ├── nextPragma           Long
 *               └── keyFingerprint       Long
 * </pre>
 *
 * <p>The stream counters are a <em>sibling</em> of the session entry rather than a child of it, which
 * deviates from the tree drawn in architecture &sect;3. The reason is {@link #put}: it replaces a
 * session's entry wholesale, so anything nested inside would be silently destroyed every time a key
 * was re-derived. Keeping them apart makes that impossible rather than merely avoided.
 *
 * <p>Every read is defensive. The project file is user-editable state that may have been written by
 * an older version of this extension, so a malformed entry is logged and skipped rather than being
 * allowed to break the Sessions tab.
 */
public final class PersistedKeyStore implements SessionKeyStore, StreamPositionStore {

    private static final String ROOT = "oracleForms";
    private static final String SESSIONS = "sessions";
    private static final String STREAMS = "streams";

    private static final String KEY = "key";
    private static final String HOST = "host";
    private static final String FIRST_SEEN = "firstSeen";
    private static final String LAST_SEEN = "lastSeen";
    private static final String LABEL = "label";
    private static final String SOURCE = "source";

    /** Field names for the four stream counters, in {@link StreamLeg} order. */
    private static final Map<StreamLeg, String> LEG_FIELDS = Map.of(
            StreamLeg.CLIENT_REQUEST, "clientRequestBytes",
            StreamLeg.SERVER_REQUEST, "serverRequestBytes",
            StreamLeg.SERVER_RESPONSE, "serverResponseBytes",
            StreamLeg.CLIENT_RESPONSE, "clientResponseBytes");

    private static final String NEXT_PRAGMA = "nextPragma";
    private static final String KEY_FINGERPRINT = "keyFingerprint";

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
        // Stream counters describe a cipher timeline under one specific key. If the key for this
        // session changes -- re-entered by hand, imported from JSON, or re-derived from a fresh
        // handshake with different randoms -- the stored counters no longer describe anything that
        // exists, and resuming from them would encrypt at an arbitrary offset. Drop them alongside
        // the key they belonged to. StreamRegistry checks the fingerprint as well, so this is
        // hygiene rather than the only defence.
        Optional<SessionKey> existing = get(key.sessionId());
        if (existing.isPresent() && !java.util.Arrays.equals(existing.get().key(), key.key())) {
            logging.logToOutput("Oracle Forms: the key for session " + key.sessionId()
                    + " changed; discarding its stored stream positions.");
            forget0(key.sessionId());
        }

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
        forget0(sessionId);
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
            root.deleteChildObject(STREAMS);
        }
    }

    // ---- StreamPositionStore --------------------------------------------------------------

    /**
     * The four stream counters for a session, or empty if it has never diverged.
     *
     * <p>A partially written entry is treated as absent rather than as three-quarters of a position.
     * Resuming a ledger from an incomplete record would put one leg at zero and desynchronise it
     * silently, which is far worse than rebuilding the whole thing from history.
     */
    @Override
    public synchronized Optional<StreamPositions> load(String sessionId) {
        PersistedObject streams = streams(false);
        if (streams == null || sessionId == null) {
            return Optional.empty();
        }
        PersistedObject entry = streams.getChildObject(sessionId);
        if (entry == null) {
            return Optional.empty();
        }
        try {
            Map<StreamLeg, Long> positions = new EnumMap<>(StreamLeg.class);
            for (StreamLeg leg : StreamLeg.values()) {
                Long value = entry.getLong(LEG_FIELDS.get(leg));
                if (value == null || value < 0) {
                    logging.logToError("Ignoring incomplete stream positions for session "
                            + sessionId + "; rebuilding from history instead.");
                    return Optional.empty();
                }
                positions.put(leg, value);
            }
            Long nextPragma = entry.getLong(NEXT_PRAGMA);
            Long fingerprint = entry.getLong(KEY_FINGERPRINT);
            if (fingerprint == null) {
                // Written before the counters were bound to a key. There is no way to tell which
                // key they belong to, so they cannot be trusted; rebuilding from history is safe.
                logging.logToError("Ignoring stream positions for session " + sessionId
                        + " that predate key binding; rebuilding from history instead.");
                return Optional.empty();
            }
            return Optional.of(new StreamPositions(
                    positions, nextPragma == null ? 0 : nextPragma.intValue(), fingerprint));
        } catch (RuntimeException e) {
            logging.logToError("Skipping unreadable stream positions for session " + sessionId
                    + ": " + e);
            return Optional.empty();
        }
    }

    @Override
    public synchronized void save(String sessionId, StreamPositions positions) {
        if (sessionId == null || sessionId.isEmpty() || positions == null) {
            return;
        }
        try {
            PersistedObject entry = PersistedObject.persistedObject();
            for (StreamLeg leg : StreamLeg.values()) {
                entry.setLong(LEG_FIELDS.get(leg), positions.at(leg));
            }
            entry.setLong(NEXT_PRAGMA, positions.nextPragma());
            entry.setLong(KEY_FINGERPRINT, positions.keyFingerprint());
            streams(true).setChildObject(sessionId, entry);
        } catch (RuntimeException e) {
            // Losing the counters costs a rebuild from history at worst, and for a diverged session
            // it costs the divergence. Neither is worth taking the extension down for.
            logging.logToError("Could not persist stream positions for session " + sessionId
                    + ": " + e);
        }
    }

    @Override
    public synchronized void forgetPositions(String sessionId) {
        forget0(sessionId);
    }

    private void forget0(String sessionId) {
        PersistedObject streams = streams(false);
        if (streams != null && sessionId != null && streams.getChildObject(sessionId) != null) {
            streams.deleteChildObject(sessionId);
        }
    }

    /**
     * @param create whether to build the nested objects if they are absent; readers pass false so
     *               that merely opening the Sessions tab does not write to the project file
     */
    private PersistedObject sessions(boolean create) {
        return collection(SESSIONS, create);
    }

    private PersistedObject streams(boolean create) {
        return collection(STREAMS, create);
    }

    private PersistedObject collection(String name, boolean create) {
        PersistedObject root = getOrCreate(extensionData, ROOT, create);
        if (root == null) {
            return null;
        }
        return getOrCreate(root, name, create);
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
