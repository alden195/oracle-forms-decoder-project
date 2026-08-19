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
    private final String latestCookieHeader;

    private PragmaHistorySource(
            String sessionId, Map<Direction, Map<Integer, byte[]>> index, int highestPragma,
            String latestCookieHeader) {
        this.sessionId = sessionId;
        this.index = index;
        this.highestPragma = highestPragma;
        this.latestCookieHeader = latestCookieHeader;
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

        // The Cookie header of the latest message, so an injected one can carry the rotating
        // JSESSIONID_FORMS the client is actually using rather than whatever a captured draft had.
        String latestCookie = null;
        int latestCookiePragma = -1;

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

            if (pragma > latestCookiePragma) {
                String cookie = cookieHeaderOf(item.finalRequest());
                if (cookie != null) {
                    latestCookie = cookie;
                    latestCookiePragma = pragma;
                }
            }

            // The *client's* bytes, not the ones forwarded to the server, and the difference only
            // appears once a session has diverged. From pragma 3 the client runs one continuous
            // request cipher, so replaying it means summing the lengths the client produced and
            // decrypting what the client wrote — which is precisely `request()`. After a Repeater
            // injection the handler re-encrypts each forwarded message at the server's position
            // (architecture §6.2), so `finalRequest()` would be ciphertext from a stream this replay
            // does not follow, and every message after the injection would decode to noise.
            //
            // Lengths are identical either way — RC4 preserves them and nothing here resizes a
            // proxied body — so the tail measurement is unaffected by the choice.
            index.get(Direction.REQUEST)
                    .putIfAbsent(pragma, clientRequestBody(item));

            if (item.response() != null) {
                index.get(Direction.RESPONSE)
                        .putIfAbsent(pragma, item.response().body().getBytes());
            }
        }
        return new PragmaHistorySource(sessionId, index, highest, latestCookie);
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

    /**
     * The {@code Cookie} header from the highest-numbered captured message of this session.
     *
     * <p>Used to refresh {@code JSESSIONID_FORMS} on an injected message. That cookie rotates every
     * few messages, and a stale value can be routed to a backend that has never heard of the session
     * — a failure that looks like bad decryption and is not.
     */
    public Optional<String> latestCookieHeader() {
        return Optional.ofNullable(latestCookieHeader);
    }

    /**
     * The request body as the client wrote it, falling back to the forwarded one.
     *
     * <p>The fallback matters for a history item Burp did not record an unmodified copy of. Falling
     * back is right rather than skipping: for every session that has never been injected into the two
     * are the same bytes, and that is almost all of them.
     */
    private static byte[] clientRequestBody(ProxyHttpRequestResponse item) {
        try {
            if (item.request() != null) {
                return item.request().body().getBytes();
            }
        } catch (RuntimeException e) {
            // Fall through to the forwarded request.
        }
        return item.finalRequest().body().getBytes();
    }

    private static String cookieHeaderOf(burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            return request.hasHeader("Cookie") ? request.headerValue("Cookie") : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Total bytes indexed, so the caller can reason about what it is holding. */
    public long indexedBytes() {
        return index.values().stream()
                .flatMap(m -> m.values().stream())
                .mapToLong(b -> b.length)
                .sum();
    }
}
