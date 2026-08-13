package oracleforms.burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import oracleforms.session.SessionId;

/**
 * Decides whether a message is Oracle Forms traffic, and extracts what identifies it.
 *
 * <p>This runs on every proxied request, so the checks are ordered cheapest-first: a substring test
 * on the path, then a header lookup, then cookie parsing. The common case — traffic that is not
 * Forms at all — is rejected by the first test (architecture &sect;5).
 *
 * <p>Detection deliberately ignores the User-Agent. The capture shows two clients speaking the
 * protocol, {@code Java/11.0.31} (the Web Start launcher) and a {@code Java/1.8.0_461} applet
 * client, so filtering on it would silently drop half the traffic.
 */
public final class FormsDetector {

    /** The Forms listener servlet. Present in the path of every message that matters. */
    private static final String SERVLET_MARKER = "lservlet";

    private static final String PRAGMA_HEADER = "Pragma";
    private static final String COOKIE_HEADER = "Cookie";
    private static final String SET_COOKIE_HEADER = "Set-Cookie";

    /** An identified Forms message: which session it belongs to and where in the sequence it sits. */
    public record FormsTarget(String sessionId, int pragma) {

        /** True when this message's body is RC4-encrypted rather than cleartext. */
        public boolean isEncrypted() {
            return pragma >= oracleforms.session.StreamReplayer.FIRST_ENCRYPTED_PRAGMA;
        }
    }

    private FormsDetector() {
    }

    /** Whether the path looks like the Forms listener servlet. The cheap first gate. */
    public static boolean isFormsPath(HttpRequest request) {
        if (request == null) {
            return false;
        }
        String path = request.path();
        return path != null && path.toLowerCase(java.util.Locale.ROOT).contains(SERVLET_MARKER);
    }

    /**
     * Identifies a Forms message, or returns empty if this is not one.
     *
     * <p>Empty means "not our traffic" for any reason: wrong path, no {@code Pragma} header, a
     * non-numeric one, or no resolvable session id.
     */
    public static Optional<FormsTarget> detect(HttpRequest request) {
        return detect(request, null);
    }

    /**
     * As {@link #detect(HttpRequest)}, but consults the response when identifying a Pragma 0.
     *
     * <p><strong>Pragma 0 is the one message whose request cookie is the wrong answer.</strong> It is
     * the GET that *establishes* the session, so its request still carries the <em>previous</em>
     * session's {@code JSESSIONID} while its response hands out the new one. Observed directly in the
     * capture: a Pragma 0 request sent {@code JSESSIONID=A5bnVY0l…} and its response replied
     * {@code Set-Cookie: JSESSIONID=HpCezl7m…}, which is the id every subsequent pragma of that
     * session then used.
     *
     * <p>Reading the request cookie for Pragma 0 therefore files it under a stale, unrelated session.
     * It does no harm to replay — pragma 0 is cleartext and the keystream starts at 3 — but it
     * mislabels the message in the editor and pollutes the wrong session's index, which is exactly
     * the kind of thing that wastes an hour when a decode misbehaves.
     *
     * @param response the paired response, or {@code null} if unavailable
     */
    public static Optional<FormsTarget> detect(HttpRequest request, HttpResponse response) {
        if (!isFormsPath(request)) {
            return Optional.empty();
        }
        Optional<Integer> pragma = pragmaNumber(request);
        if (pragma.isEmpty()) {
            return Optional.empty();
        }

        return SessionId.resolveForPragma(
                        pragma.get(),
                        headerOrNull(request, COOKIE_HEADER),
                        request.url(),
                        setCookieValues(response))
                .map(id -> new FormsTarget(id, pragma.get()));
    }

    /**
     * Every {@code Set-Cookie} value on the response.
     *
     * <p>Iterates the headers rather than using {@code headerValue("Set-Cookie")}, which returns only
     * the first match — and these responses carry two, {@code JSESSIONID} and
     * {@code JSESSIONID_FORMS}, in an order that is not guaranteed.
     */
    private static List<String> setCookieValues(HttpResponse response) {
        if (response == null) {
            return List.of();
        }
        try {
            List<String> values = new ArrayList<>(2);
            for (HttpHeader header : response.headers()) {
                if (SET_COOKIE_HEADER.equalsIgnoreCase(header.name())) {
                    values.add(header.value());
                }
            }
            return values;
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    /** The {@code Pragma} header as a number, or empty if absent or not numeric. */
    public static Optional<Integer> pragmaNumber(HttpRequest request) {
        String value = headerOrNull(request, PRAGMA_HEADER);
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Integer.parseInt(value.trim()));
        } catch (NumberFormatException e) {
            // Forms uses a bare number here; anything else is some other use of Pragma
            // (`no-cache`, most commonly) and is not ours.
            return Optional.empty();
        }
    }

    /**
     * Reads a header, tolerating its absence.
     *
     * <p>Montoya's {@code headerValue} returns null for a missing header, but {@code header()} can
     * throw on some implementations, so this stays on the null-returning accessor and guards it.
     */
    private static String headerOrNull(HttpRequest request, String name) {
        try {
            return request.hasHeader(name) ? request.headerValue(name) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }
}
