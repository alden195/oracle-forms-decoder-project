package oracleforms.burp.repeater;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;
import java.util.Optional;

/**
 * The headers that mark a request as an FHT <em>plaintext draft</em> (architecture &sect;6.5).
 *
 * <p>A Repeater tab holding one of these carries decoded FHT in its body, not ciphertext. That is the
 * central choice of the whole feature: the correct keystream offset is not knowable until the instant
 * the request actually leaves, so the encryption has to happen in the HTTP handler, and the editor has
 * to hold something the handler can encrypt.
 *
 * <p>Three rules make that safe, and all three are enforced in {@link RepeaterSendInterceptor}:
 *
 * <ol>
 *   <li>Markers are honoured only on requests originating from Burp's own tools. A marker on a
 *       proxied request was put there by the client, and the client is the application under test.
 *   <li>The markers are stripped on <em>every</em> path out, including refusals.
 *   <li>A marked request that cannot be encrypted never leaves Burp. Sending the body as it stands
 *       would put readable FHT — and any credentials in it — on the wire.
 * </ol>
 *
 * @param sessionId    the {@code JSESSIONID} whose key and streams to encrypt with
 * @param mode         how to choose the keystream offset
 * @param originPragma the pragma the draft was taken from, for provenance and for
 *                     {@link SendMode#OFFSET}
 */
public record DraftMarkers(String sessionId, SendMode mode, int originPragma) {

    public static final String SESSION_HEADER = "X-OracleForms-Session";
    public static final String SEND_HEADER = "X-OracleForms-Send";
    public static final String ORIGIN_HEADER = "X-OracleForms-Origin";

    private static final List<String> ALL_HEADERS =
            List.of(SESSION_HEADER, SEND_HEADER, ORIGIN_HEADER);

    public DraftMarkers {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }
        if (mode == null) {
            throw new IllegalArgumentException("mode must not be null");
        }
    }

    /**
     * Reads the markers from a request, or empty if it is not a draft.
     *
     * <p>A request carrying the session header but a malformed mode is <em>not</em> a draft. Falling
     * back to a default mode would pick, on the user's behalf, between "encrypt at a historical
     * offset" and "act on a live session", which is exactly the choice that must never be guessed.
     */
    public static Optional<DraftMarkers> from(HttpRequest request) {
        String sessionId = headerOrNull(request, SESSION_HEADER);
        if (sessionId == null || sessionId.isBlank()) {
            return Optional.empty();
        }
        Optional<SendMode> mode = SendMode.fromWireName(headerOrNull(request, SEND_HEADER));
        if (mode.isEmpty()) {
            return Optional.empty();
        }
        int origin = 0;
        try {
            String value = headerOrNull(request, ORIGIN_HEADER);
            if (value != null) {
                origin = Integer.parseInt(value.trim());
            }
        } catch (NumberFormatException e) {
            origin = 0;
        }
        return Optional.of(new DraftMarkers(sessionId.trim(), mode.get(), origin));
    }

    /** Whether a request carries the session marker at all, malformed or not. */
    public static boolean isMarked(HttpRequest request) {
        String sessionId = headerOrNull(request, SESSION_HEADER);
        return sessionId != null && !sessionId.isBlank();
    }

    /** Adds these markers to a request, replacing any already present. */
    public HttpRequest applyTo(HttpRequest request) {
        return strip(request)
                .withAddedHeader(SESSION_HEADER, sessionId)
                .withAddedHeader(SEND_HEADER, mode.wireName())
                .withAddedHeader(ORIGIN_HEADER, Integer.toString(originPragma));
    }

    /**
     * Removes every marker header.
     *
     * <p>Called unconditionally before a request leaves Burp. These are our own bookkeeping and have
     * no business on the wire — they would tell the target that its traffic is being decoded, and
     * they name a session identifier.
     */
    public static HttpRequest strip(HttpRequest request) {
        HttpRequest stripped = request;
        for (String header : ALL_HEADERS) {
            if (stripped.hasHeader(header)) {
                stripped = stripped.withRemovedHeader(header);
            }
        }
        return stripped;
    }

    private static String headerOrNull(HttpRequest request, String name) {
        if (request == null) {
            return null;
        }
        try {
            return request.hasHeader(name) ? request.headerValue(name) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }
}
