package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Reading and refreshing the rotating cookie.
 *
 * <p>The behaviour that matters is what is <em>preserved</em>. An injected message's Cookie header is
 * whatever the user has in their Repeater tab, and the extension is only entitled to update the one
 * cookie it knows has gone stale.
 */
class CookieHeaderTest {

    private static final String HEADER =
            "JSESSIONID_FORMS=formsapp_rs1|rot01; JSESSIONID=X43xQtj1!-1111111111; extra=keepme";

    @Test
    @DisplayName("reads a named cookie, matching exactly rather than by prefix")
    void readsByExactName() {
        assertEquals(Optional.of("formsapp_rs1|rot01"),
                CookieHeader.value(HEADER, SessionId.ROTATING_COOKIE_NAME));
        assertEquals(Optional.of("X43xQtj1!-1111111111"),
                CookieHeader.value(HEADER, SessionId.COOKIE_NAME),
                "JSESSIONID must not be satisfied by JSESSIONID_FORMS");
        assertTrue(CookieHeader.value(HEADER, "NOT_PRESENT").isEmpty());
        assertTrue(CookieHeader.value(null, "JSESSIONID").isEmpty());
    }

    @Test
    @DisplayName("replaces one cookie and preserves every other, in order")
    void replacesOnlyTheNamedCookie() {
        String updated = CookieHeader.withValue(
                HEADER, SessionId.ROTATING_COOKIE_NAME, "formsapp_rs1|rot02");

        assertEquals(Optional.of("formsapp_rs1|rot02"),
                CookieHeader.value(updated, SessionId.ROTATING_COOKIE_NAME));
        assertEquals(Optional.of("X43xQtj1!-1111111111"),
                CookieHeader.value(updated, SessionId.COOKIE_NAME));
        assertEquals(Optional.of("keepme"), CookieHeader.value(updated, "extra"));
        assertTrue(updated.indexOf("JSESSIONID_FORMS") < updated.indexOf("JSESSIONID="),
                "the original ordering should survive");
    }

    @Test
    @DisplayName("spacing is preserved so the header still looks like the client's")
    void preservesSpacing() {
        assertEquals("a=1; JSESSIONID_FORMS=new; b=2",
                CookieHeader.withValue("a=1; JSESSIONID_FORMS=old; b=2",
                        SessionId.ROTATING_COOKIE_NAME, "new"));
    }

    /**
     * A cookie the client never sent is not invented. Adding one would be a guess about how the
     * deployment is configured, and a wrong guess routes the request somewhere unexpected.
     */
    @Test
    @DisplayName("a cookie that is not present is not added")
    void absentCookiesAreNotAdded() {
        String header = "JSESSIONID=abc";
        assertEquals(header,
                CookieHeader.withValue(header, SessionId.ROTATING_COOKIE_NAME, "something"));
    }

    @Test
    @DisplayName("null and malformed input is tolerated")
    void toleratesJunk() {
        assertEquals(null, CookieHeader.withValue(null, "a", "b"));
        assertEquals("nonsense", CookieHeader.withValue("nonsense", "a", "b"));
        assertTrue(CookieHeader.value("=;;=;", "a").isEmpty());
    }
}
