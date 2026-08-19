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
 * <p>{@link SendMode#INTERCEPT} adds two more (architecture &sect;6.12). {@code originalLength}
 * carries what the client's own message contributed to its request keystream, which only the editor
 * knows by the time the handler sees the edited body; {@code token} is the single-use capability
 * that makes a marker arriving <em>from the Proxy</em> trustworthy without weakening rule 1 above.
 *
 * @param sessionId      the {@code JSESSIONID} whose key and streams to encrypt with
 * @param mode           how to choose the keystream offset
 * @param originPragma   the pragma the draft was taken from, for provenance and for
 *                       {@link SendMode#OFFSET}
 * @param originalLength {@link SendMode#INTERCEPT} only: the client's own body length in bytes
 * @param token          {@link SendMode#INTERCEPT} only: the capability, or null for every other
 *                       mode, which is trusted by tool origin instead
 * @param expectedPosition {@link SendMode#INTERCEPT} only: where the client's keystream leg stood
 *                       when the message was decoded, or -1 if not stated. Checked again at Forward,
 *                       because a ledger that moved in between means the decode this edit was made
 *                       against no longer describes the session
 */
public record DraftMarkers(
        String sessionId, SendMode mode, int originPragma, int originalLength, String token,
        long expectedPosition) {

    public static final String SESSION_HEADER = "X-OracleForms-Session";
    public static final String SEND_HEADER = "X-OracleForms-Send";
    public static final String ORIGIN_HEADER = "X-OracleForms-Origin";

    /** Mode D: the client's own body length, so its keystream leg can be advanced past it. */
    public static final String ORIGINAL_HEADER = "X-OracleForms-Original";

    /** Mode D: the single-use capability that authorises a Proxy-originated marker. */
    public static final String TOKEN_HEADER = "X-OracleForms-Token";

    /** Mode D: the client-leg keystream offset the edit was decoded against. */
    public static final String POSITION_HEADER = "X-OracleForms-Position";

    private static final List<String> ALL_HEADERS = List.of(
            SESSION_HEADER, SEND_HEADER, ORIGIN_HEADER, ORIGINAL_HEADER, TOKEN_HEADER,
            POSITION_HEADER);

    public DraftMarkers {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }
        if (mode == null) {
            throw new IllegalArgumentException("mode must not be null");
        }
        if (originalLength < 0) {
            throw new IllegalArgumentException("originalLength must not be negative");
        }
        token = token == null || token.isBlank() ? null : token.trim();
    }

    /** The three-marker form every mode except {@link SendMode#INTERCEPT} uses. */
    public DraftMarkers(String sessionId, SendMode mode, int originPragma) {
        this(sessionId, mode, originPragma, 0, null, -1);
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
        int origin = intHeader(request, ORIGIN_HEADER, 0);

        // Only meaningful for INTERCEPT, and deliberately read for every mode anyway: a stray
        // length or token on some other mode's draft is then visible to the handler's checks
        // rather than being quietly dropped here.
        int originalLength = intHeader(request, ORIGINAL_HEADER, -1);
        String token = headerOrNull(request, TOKEN_HEADER);
        long position = longHeader(request, POSITION_HEADER, -1);

        if (mode.get() == SendMode.INTERCEPT && originalLength < 0) {
            // Without it the client's keystream leg cannot be advanced past what the client wrote,
            // and guessing would desynchronise the session permanently. Not a draft.
            return Optional.empty();
        }
        return Optional.of(new DraftMarkers(sessionId.trim(), mode.get(), origin,
                Math.max(originalLength, 0), token, position));
    }

    /** As {@link #intHeader}, for the keystream offset, which outgrows an int on a long session. */
    private static long longHeader(HttpRequest request, String name, long fallback) {
        try {
            String value = headerOrNull(request, name);
            return value == null ? fallback : Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /** Reads a numeric header, falling back rather than throwing on anything unparseable. */
    private static int intHeader(HttpRequest request, String name, int fallback) {
        try {
            String value = headerOrNull(request, name);
            return value == null ? fallback : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /** Whether a request carries the session marker at all, malformed or not. */
    public static boolean isMarked(HttpRequest request) {
        String sessionId = headerOrNull(request, SESSION_HEADER);
        return sessionId != null && !sessionId.isBlank();
    }

    /**
     * Adds these markers to a request, replacing any already present.
     *
     * <p>The Mode D pair is added only for Mode D. Putting a token on a Repeater draft would be
     * inert — that path is trusted by tool origin — but it would also mint a spendable capability
     * into a tab the user may keep for hours, so it is simply not done.
     */
    public HttpRequest applyTo(HttpRequest request) {
        HttpRequest marked = strip(request)
                .withAddedHeader(SESSION_HEADER, sessionId)
                .withAddedHeader(SEND_HEADER, mode.wireName())
                .withAddedHeader(ORIGIN_HEADER, Integer.toString(originPragma));

        if (mode == SendMode.INTERCEPT) {
            marked = marked.withAddedHeader(ORIGINAL_HEADER, Integer.toString(originalLength));
            if (token != null) {
                marked = marked.withAddedHeader(TOKEN_HEADER, token);
            }
            if (expectedPosition >= 0) {
                marked = marked.withAddedHeader(
                        POSITION_HEADER, Long.toString(expectedPosition));
            }
        }
        return marked;
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
