package oracleforms.burp.history;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import oracleforms.burp.FormsDetector;
import oracleforms.session.Direction;
import oracleforms.session.PragmaBody;
import oracleforms.session.PragmaSource;

/**
 * Supplies a session's captured bodies from Burp's proxy history.
 *
 * <p>The Burp-facing half of the seam described in architecture &sect;4: this class knows about
 * {@code proxy().history()} and nothing about RC4, while {@link oracleforms.session.StreamReplayer}
 * knows about RC4 and nothing about where bodies come from.
 *
 * <p>Two things keep it honest on large projects (BApp criterion 9):
 *
 * <ul>
 *   <li>It uses the {@code history(ProxyHistoryFilter)} overload, so Burp evaluates the predicate
 *       per item and the full history is never materialized into a list.
 *   <li>It copies the bodies out as plain {@code byte[]} and retains no {@link ProxyHttpRequestResponse}
 *       references. The index it keeps is one session's bodies, not the project's.
 * </ul>
 *
 * <p>The index is built once per instance and then served from memory, because a replay asks for
 * every pragma from the last checkpoint to the target and re-scanning history for each would be
 * quadratic in exactly the case that already hurts.
 */
public final class PragmaHistorySource implements PragmaSource {

    private final String sessionId;
    private final Map<Direction, Map<Integer, byte[]>> index;
    private final int highestPragma;

    private PragmaHistorySource(
            String sessionId, Map<Direction, Map<Integer, byte[]>> index, int highestPragma) {
        this.sessionId = sessionId;
        this.index = index;
        this.highestPragma = highestPragma;
    }

    /**
     * Scans proxy history once and indexes every captured pragma for one session.
     *
     * <p>Call this off the EDT and off the proxy hot path — it walks the project's history.
     */
    public static PragmaHistorySource forSession(MontoyaApi api, String sessionId) {
        Map<Direction, Map<Integer, byte[]>> index = new EnumMap<>(Direction.class);
        index.put(Direction.REQUEST, new LinkedHashMap<>());
        index.put(Direction.RESPONSE, new LinkedHashMap<>());
        int highest = 0;

        for (ProxyHttpRequestResponse item : api.proxy().history(
                candidate -> matchesSession(candidate, sessionId))) {

            // Pass the response so a Pragma 0 is attributed to the session it establishes rather
            // than the stale one its request cookie still names.
            Optional<FormsDetector.FormsTarget> target =
                    FormsDetector.detect(item.finalRequest(), item.response());
            if (target.isEmpty()) {
                continue;
            }
            // Only POSTs carry FHT bodies. The control GETs -- `ifcmd=getinfo`, `ifcmd=regFile` --
            // belong to the session but are not messages in its stream, and the applet client
            // numbers its getinfo GET Pragma 1, colliding with the GDay handshake POST. Indexing it
            // would put an empty body where the handshake should be and lose the key material.
            if (!"POST".equalsIgnoreCase(item.finalRequest().method())) {
                continue;
            }

            int pragma = target.get().pragma();
            highest = Math.max(highest, pragma);

            index.get(Direction.REQUEST)
                    .putIfAbsent(pragma, item.finalRequest().body().getBytes());

            if (item.response() != null) {
                index.get(Direction.RESPONSE)
                        .putIfAbsent(pragma, item.response().body().getBytes());
            }
        }
        return new PragmaHistorySource(sessionId, index, highest);
    }

    /**
     * The history filter. Kept cheap because Burp calls it for every item in the project: a path
     * substring test before any header or cookie parsing.
     */
    private static boolean matchesSession(ProxyHttpRequestResponse candidate, String sessionId) {
        try {
            if (!FormsDetector.isFormsPath(candidate.finalRequest())) {
                return false;
            }
            // The response is consulted here for the same reason it is consulted in the loop below:
            // the session-establishing GET's request cookie names the *previous* session, so a
            // request-only match files it under the wrong one and the loop's own response-aware
            // check never gets to see it.
            return FormsDetector.detect(candidate.finalRequest(), candidate.response())
                    .map(t -> t.sessionId().equals(sessionId))
                    .orElse(false);
        } catch (RuntimeException e) {
            // A malformed history item must not abort the scan.
            return false;
        }
    }

    @Override
    public Optional<PragmaBody> body(Direction direction, int pragma) {
        byte[] bytes = index.get(direction).get(pragma);
        return bytes == null ? Optional.empty() : Optional.of(new PragmaBody(pragma, bytes));
    }

    public String sessionId() {
        return sessionId;
    }

    /** How many pragmas were found in a direction, for the Sessions tab. */
    public int count(Direction direction) {
        return index.get(direction).size();
    }

    /** The highest pragma number seen for this session. */
    public int highestPragma() {
        return highestPragma;
    }

    /** Total bytes indexed, so the caller can reason about what it is holding. */
    public long indexedBytes() {
        return index.values().stream()
                .flatMap(m -> m.values().stream())
                .mapToLong(b -> b.length)
                .sum();
    }
}
