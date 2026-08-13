package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * These are the highest-value tests in the session package despite being the simplest. Picking the
 * wrong cookie shatters every RC4 stream, and the symptom ("no key for this session") points nowhere
 * near the cause.
 */
class SessionIdTest {

    /** A real header from the capture, both cookies present. */
    private static final String REAL_COOKIE =
            "JSESSIONID_FORMS=formsapp_rs1|anAnK; "
                    + "JSESSIONID=HpCezl7mJxic18WHFatPXkZWfk25nsZm_xpO4rBsATmEgvguJ77e!-1111111111";

    @Test
    @DisplayName("picks JSESSIONID out of a real capture header")
    void extractsFromRealHeader() {
        assertEquals(
                Optional.of("HpCezl7mJxic18WHFatPXkZWfk25nsZm_xpO4rBsATmEgvguJ77e!-1111111111"),
                SessionId.fromCookieHeader(REAL_COOKIE));
    }

    /**
     * The failure this class exists to prevent. A prefix match would return the rotating cookie's
     * value, fragmenting one session into dozens.
     */
    @Test
    @DisplayName("never matches JSESSIONID_FORMS, in either cookie order")
    void neverMatchesTheRotatingCookie() {
        String formsFirst = "JSESSIONID_FORMS=formsapp_rs1|anQtg; JSESSIONID=stable-value";
        String formsSecond = "JSESSIONID=stable-value; JSESSIONID_FORMS=formsapp_rs1|anQ0T";

        assertEquals(Optional.of("stable-value"), SessionId.fromCookieHeader(formsFirst));
        assertEquals(Optional.of("stable-value"), SessionId.fromCookieHeader(formsSecond));

        // With only the rotating cookie present, the answer must be "no id", not its value.
        assertTrue(SessionId.fromCookieHeader("JSESSIONID_FORMS=formsapp_rs1|anQtg").isEmpty());
    }

    @Test
    @DisplayName("the rotating cookie's value does not leak through as the session id")
    void rotatingValueNeverReturned() {
        String a = "JSESSIONID_FORMS=formsapp_rs1|anQtg; JSESSIONID=constant";
        String b = "JSESSIONID_FORMS=formsapp_rs1|anQ0T; JSESSIONID=constant";

        // Same session, rotated forms cookie: the extracted id must not move.
        assertEquals(SessionId.fromCookieHeader(a), SessionId.fromCookieHeader(b));
    }

    @Test
    void toleratesWhitespaceAndMissingValues() {
        assertEquals(Optional.of("x"), SessionId.fromCookieHeader("  JSESSIONID = x  "));
        assertTrue(SessionId.fromCookieHeader("JSESSIONID=").isEmpty());
        assertTrue(SessionId.fromCookieHeader("novalue; JSESSIONID").isEmpty());
        assertTrue(SessionId.fromCookieHeader("").isEmpty());
        assertTrue(SessionId.fromCookieHeader(null).isEmpty());
    }

    @Test
    @DisplayName("reads the id from a Set-Cookie response header")
    void readsSetCookie() {
        assertEquals(Optional.of("abc123!-1111111111"),
                SessionId.fromSetCookieHeader("JSESSIONID=abc123!-1111111111; path=/; HttpOnly"));
        assertTrue(SessionId.fromSetCookieHeader("JSESSIONID_FORMS=formsapp_rs1|anAnD; path=/")
                .isEmpty());
    }

    @Test
    @DisplayName("reads a URL-rewritten id, which this target never uses but others do")
    void readsFromUrl() {
        assertEquals(Optional.of("URLVALUE"),
                SessionId.fromUrl("https://h/forms/lservlet;jsessionid=URLVALUE?ifcmd=getinfo"));
        assertEquals(Optional.of("URLVALUE"),
                SessionId.fromUrl("https://h/forms/lservlet;JSESSIONID=URLVALUE"));
        assertTrue(SessionId.fromUrl("https://h/forms/lservlet").isEmpty());
    }

    /**
     * Pragma 0 is the GET that establishes the session, so its request still carries the previous
     * session's id while its response hands out the new one. Both values below are taken verbatim
     * from one Pragma 0 exchange in the capture.
     */
    @Test
    @DisplayName("Pragma 0 is attributed to the session its response establishes, not the stale one")
    void pragmaZeroPrefersTheAssignedId() {
        String staleRequestCookie =
                "JSESSIONID_FORMS=formsapp_rs1|anAis; "
                        + "JSESSIONID=A5bnVY0lbICChzGJFT9uYK9-kbVd3uieh_B5Jyic8ZlFHg6uk8wc!-1111111111";
        List<String> setCookies = List.of(
                "JSESSIONID=HpCezl7mJxic18WHFatPXkZWfk25nsZm_xpO4rBsATmEgvguJ77e!-1111111111;"
                        + " path=/; HttpOnly;HttpOnly",
                "JSESSIONID_FORMS=formsapp_rs1|anAnK; path=/");

        assertEquals(
                Optional.of("HpCezl7mJxic18WHFatPXkZWfk25nsZm_xpO4rBsATmEgvguJ77e!-1111111111"),
                SessionId.resolveForPragma(0, staleRequestCookie, "https://h/forms/lservlet", setCookies),
                "reading the request cookie here files pragma 0 under an unrelated session");
    }

    @Test
    @DisplayName("Set-Cookie order does not matter, and JSESSIONID_FORMS is never picked")
    void pragmaZeroIgnoresTheRotatingSetCookie() {
        List<String> formsFirst = List.of(
                "JSESSIONID_FORMS=formsapp_rs1|anAnK; path=/",
                "JSESSIONID=the-real-one; path=/; HttpOnly");

        assertEquals(Optional.of("the-real-one"),
                SessionId.resolveForPragma(0, null, null, formsFirst));

        // Only the rotating cookie assigned: fall back to the request cookie rather than take it.
        assertEquals(Optional.of("from-request"),
                SessionId.resolveForPragma(0, "JSESSIONID=from-request", null,
                        List.of("JSESSIONID_FORMS=formsapp_rs1|anAnK; path=/")));
    }

    /**
     * Applying the Pragma 0 rule to every message would be worse than not having it: a stray
     * Set-Cookie mid-session would look like a session change and shatter a continuous RC4 stream.
     */
    @Test
    @DisplayName("every pragma other than 0 trusts the request cookie, ignoring Set-Cookie")
    void laterPragmasIgnoreSetCookie() {
        List<String> setCookies = List.of("JSESSIONID=a-new-id; path=/");

        for (int pragma : new int[] {1, 3, 4, 65}) {
            assertEquals(Optional.of("the-session"),
                    SessionId.resolveForPragma(pragma, "JSESSIONID=the-session", null, setCookies),
                    "pragma " + pragma + " must not follow a Set-Cookie");
        }
    }

    /**
     * The applet client numbers its servlet-info GET as Pragma 1, not 0 — and then numbers the
     * {@code GDay} handshake Pragma 1 as well. Both messages observed in one session on 2026-08-13.
     */
    @Test
    @DisplayName("the servlet-info GET establishes the session whatever pragma it carries")
    void getInfoEstablishesTheSessionAtAnyPragma() {
        String staleRequestCookie =
                "JSESSIONID_FORMS=formsapp_rs2|an1s+; "
                        + "JSESSIONID=Fd5x3qn7VQcgK5jjzzCI3p8iI0piuMb0KT6NXr2VwXaZd5r8_PhT!-2222222222";
        List<String> setCookies = List.of(
                "JSESSIONID=xJ5grzn3xNpznVZFgfND4t1N5TWrV9s5gUNiDHUVcsVMsbNLnw_j!-2222222222;"
                        + " path=/; HttpOnly;HttpOnly;Secure",
                "JSESSIONID_FORMS=formsapp_rs2|an1tD; path=/");
        String getInfoUrl =
                "https://h/forms/lservlet?ifcmd=getinfo&iflocale=en-US&ifhost=ubuntu&ifip=127.0.1.1";

        assertEquals(
                Optional.of("xJ5grzn3xNpznVZFgfND4t1N5TWrV9s5gUNiDHUVcsVMsbNLnw_j!-2222222222"),
                SessionId.resolveForPragma(1, staleRequestCookie, getInfoUrl, setCookies),
                "the applet client's Pragma 1 getinfo GET opens the session its response assigns");
    }

    /**
     * The other half of the rule: the handshake shares Pragma 1 with the getinfo GET, but posts to
     * the bare servlet path and already carries the new cookie. It must keep trusting that cookie,
     * or the handshake — and so the key — lands under the wrong session.
     */
    @Test
    @DisplayName("a Pragma 1 handshake POST still trusts its request cookie")
    void handshakePostIsNotSessionEstablishing() {
        assertEquals(Optional.of("the-new-session"),
                SessionId.resolveForPragma(1, "JSESSIONID=the-new-session",
                        "https://h/forms/lservlet", List.of("JSESSIONID=something-else; path=/")));
    }

    @Test
    @DisplayName("Pragma 0 falls back to the request cookie when nothing is assigned")
    void pragmaZeroFallsBack() {
        assertEquals(Optional.of("from-request"),
                SessionId.resolveForPragma(0, "JSESSIONID=from-request", null, List.of()));
        assertEquals(Optional.of("from-request"),
                SessionId.resolveForPragma(0, "JSESSIONID=from-request", null, null));
    }

    @Test
    @DisplayName("resolve() prefers the cookie, falling back to the URL")
    void resolvePrefersCookie() {
        assertEquals(Optional.of("cookie-value"),
                SessionId.resolve("JSESSIONID=cookie-value", "https://h/x;jsessionid=url-value"));
        assertEquals(Optional.of("url-value"),
                SessionId.resolve(null, "https://h/x;jsessionid=url-value"));
        assertTrue(SessionId.resolve(null, null).isEmpty());
    }
}
