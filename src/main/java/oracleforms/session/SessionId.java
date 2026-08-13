package oracleforms.session;

import java.util.List;
import java.util.Optional;

/**
 * Extracts the session identifier that keys the whole key store and every replay.
 *
 * <p><strong>The cookie name matters more than anything else in this class.</strong> The captured
 * target sets two:
 *
 * <ul>
 *   <li>{@code JSESSIONID} — constant for the life of the session. This is the one.
 *   <li>{@code JSESSIONID_FORMS} — rotates mid-session, often every few messages.
 * </ul>
 *
 * <p>Keying on {@code JSESSIONID_FORMS} would shatter one continuous RC4 stream into dozens of
 * fragments, all but the first missing the Pragma 1 that carries its key. The symptom would be "no
 * key for this session" on almost every message — a lookup mistake wearing the costume of a
 * decryption bug (architecture &sect;3).
 *
 * <p>Matching is therefore by exact cookie name. A prefix match would accept
 * {@code JSESSIONID_FORMS} for {@code JSESSIONID}, and the two appear in both orders across the
 * capture, so position is no help either.
 */
public final class SessionId {

    /** The cookie that is stable across a session. */
    public static final String COOKIE_NAME = "JSESSIONID";

    /** The cookie that looks right and is not. Never used as a key; named here to stay documented. */
    public static final String ROTATING_COOKIE_NAME = "JSESSIONID_FORMS";

    private SessionId() {
    }

    /**
     * Reads {@code JSESSIONID} from a {@code Cookie} header value.
     *
     * @param cookieHeader the raw header value, e.g. {@code "JSESSIONID_FORMS=a|b; JSESSIONID=xyz"}
     */
    public static Optional<String> fromCookieHeader(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return Optional.empty();
        }
        for (String part : cookieHeader.split(";")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = part.substring(0, eq).trim();
            if (COOKIE_NAME.equals(name)) {
                String value = part.substring(eq + 1).trim();
                if (!value.isEmpty()) {
                    return Optional.of(value);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Reads a {@code ;jsessionid=...} path parameter from a URL.
     *
     * <p>Absent on the captured target, where the id is cookie-only — the reference implementation
     * read <em>only</em> this and so would decode nothing at all here. Kept because other Forms
     * deployments do use URL rewriting, and it costs one string scan.
     */
    public static Optional<String> fromUrl(String url) {
        if (url == null) {
            return Optional.empty();
        }
        int idx = indexOfIgnoreCase(url, ";jsessionid=");
        if (idx < 0) {
            return Optional.empty();
        }
        int start = idx + ";jsessionid=".length();
        if (start > url.length()) {
            // Lower-casing can change a string's length for a few Unicode characters, which would
            // shift the index off the end of the original. Vanishingly rare in a URL, but this is
            // attacker-influenced input and an exception here is not worth the alternative.
            return Optional.empty();
        }
        int end = start;
        while (end < url.length() && "?&;#".indexOf(url.charAt(end)) < 0) {
            end++;
        }
        String value = url.substring(start, end);
        return value.isEmpty() ? Optional.empty() : Optional.of(value);
    }

    /** The pragma whose response, not request, names the session. See {@link #resolveForPragma}. */
    public static final int SESSION_ESTABLISHING_PRAGMA = 0;

    /**
     * The query marker on the servlet-info GET that opens a session.
     *
     * <p>The pragma number of that GET is <em>not</em> reliable. The Web Start launcher
     * ({@code Java/11.0.31}) sends it as Pragma 0, but the applet client
     * ({@code Java/1.8.0_461}) sends it as Pragma 1 — and then sends the {@code GDay} handshake as
     * Pragma 1 as well. Keying only on the number files the applet client's session-establishing GET
     * under the <em>previous</em> session, which is how a session ends up looking like it began
     * without ever being opened.
     *
     * <p>This marker is safe to key on where a bare {@code Set-Cookie} check would not be: every
     * encrypted message is a POST to the bare servlet path, so no message carrying FHT data can
     * match it, and a continuous stream can never be fragmented by it.
     */
    private static final String GET_INFO_MARKER = "ifcmd=getinfo";

    /** Whether this message is the servlet-info GET that opens a session. */
    private static boolean isSessionEstablishing(int pragma, String url) {
        return pragma == SESSION_ESTABLISHING_PRAGMA
                || (url != null && indexOfIgnoreCase(url, GET_INFO_MARKER) >= 0);
    }

    /** Cookie header first, then the URL. */
    public static Optional<String> resolve(String cookieHeader, String url) {
        Optional<String> fromCookie = fromCookieHeader(cookieHeader);
        return fromCookie.isPresent() ? fromCookie : fromUrl(url);
    }

    /**
     * Resolves the session id for a message, accounting for Pragma 0 being special.
     *
     * <p><strong>The servlet-info GET is the one message whose request cookie is the wrong
     * answer.</strong> It is the GET that *establishes* the session, so its request still carries the
     * <em>previous</em> session's {@code JSESSIONID} while its response hands out the new one.
     * Observed directly in the capture: one such request sent {@code JSESSIONID=A5bnVY0l…} and its
     * response replied {@code Set-Cookie: JSESSIONID=HpCezl7m…}, which every later pragma of that
     * session then used.
     *
     * <p>It is recognised by {@link #GET_INFO_MARKER} as well as by Pragma 0, because which pragma
     * number it carries depends on the client — see that constant.
     *
     * <p>For every other pragma the request cookie is authoritative and {@code setCookieHeaders} is
     * ignored — {@code JSESSIONID} does not rotate mid-session, and treating a stray {@code Set-Cookie}
     * as a session change would fragment a stream that is in fact continuous.
     *
     * @param setCookieHeaders every {@code Set-Cookie} value on the response; these carry two cookies
     *                         in no guaranteed order, so all of them are checked
     */
    public static Optional<String> resolveForPragma(
            int pragma, String cookieHeader, String url, List<String> setCookieHeaders) {

        if (isSessionEstablishing(pragma, url) && setCookieHeaders != null) {
            for (String setCookie : setCookieHeaders) {
                Optional<String> assigned = fromSetCookieHeader(setCookie);
                if (assigned.isPresent()) {
                    return assigned;
                }
            }
        }
        return resolve(cookieHeader, url);
    }

    /**
     * Reads {@code JSESSIONID} from a {@code Set-Cookie} header value. The session begins at the
     * Pragma 0 <em>response</em>, which is where this id is first handed out.
     */
    public static Optional<String> fromSetCookieHeader(String setCookie) {
        if (setCookie == null) {
            return Optional.empty();
        }
        int semi = setCookie.indexOf(';');
        String pair = semi < 0 ? setCookie : setCookie.substring(0, semi);
        return fromCookieHeader(pair);
    }

    private static int indexOfIgnoreCase(String haystack, String needle) {
        return haystack.toLowerCase(java.util.Locale.ROOT).indexOf(needle);
    }
}
