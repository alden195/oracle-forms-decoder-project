package oracleforms.burp.repeater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The marker contract.
 *
 * <p>Worth testing directly because two of its rules are security properties rather than
 * conveniences: markers must come off on <em>every</em> path out, and a request whose mode header is
 * malformed must not be treated as a draft in some default mode. The first keeps a session
 * identifier off the wire; the second keeps the extension from choosing, on the user's behalf,
 * between "encrypt at a historical offset" and "act on a live application session".
 *
 * <p>{@link HttpRequest} is supplied by a reflective proxy over a header map, in the same spirit as
 * {@code ExtensionLifecycleTest} — the project stays dependency-free (BApp criterion 4).
 */
class DraftMarkersTest {

    /** An immutable {@link HttpRequest} that understands only the header methods under test. */
    private static final class FakeRequest implements InvocationHandler {

        private final Map<String, String> headers;

        private FakeRequest(Map<String, String> headers) {
            this.headers = headers;
        }

        static HttpRequest with(String... nameValuePairs) {
            Map<String, String> headers = new LinkedHashMap<>();
            for (int i = 0; i + 1 < nameValuePairs.length; i += 2) {
                headers.put(nameValuePairs[i], nameValuePairs[i + 1]);
            }
            return proxy(headers);
        }

        private static HttpRequest proxy(Map<String, String> headers) {
            return (HttpRequest) Proxy.newProxyInstance(
                    HttpRequest.class.getClassLoader(),
                    new Class<?>[]{HttpRequest.class},
                    new FakeRequest(headers));
        }

        @Override
        public Object invoke(Object self, Method method, Object[] args) {
            switch (method.getName()) {
                case "hasHeader" -> {
                    return args.length == 1 && args[0] instanceof String name && find(name) != null;
                }
                case "headerValue" -> {
                    String name = find((String) args[0]);
                    return name == null ? null : headers.get(name);
                }
                case "withAddedHeader" -> {
                    Map<String, String> copy = new LinkedHashMap<>(headers);
                    copy.put((String) args[0], (String) args[1]);
                    return proxy(copy);
                }
                case "withUpdatedHeader" -> {
                    Map<String, String> copy = new LinkedHashMap<>(headers);
                    String existing = find((String) args[0]);
                    copy.put(existing == null ? (String) args[0] : existing, (String) args[1]);
                    return proxy(copy);
                }
                case "withRemovedHeader" -> {
                    Map<String, String> copy = new LinkedHashMap<>(headers);
                    copy.remove(find((String) args[0]));
                    return proxy(copy);
                }
                case "toString" -> {
                    return headers.toString();
                }
                default -> {
                    return null;
                }
            }
        }

        /** Header names are case-insensitive on the wire, and Burp treats them so. */
        private String find(String name) {
            return headers.keySet().stream()
                    .filter(existing -> existing.equalsIgnoreCase(name))
                    .findFirst()
                    .orElse(null);
        }
    }

    private static HttpRequest draft(String sessionId, String mode, String origin) {
        return FakeRequest.with(
                "Pragma", "17",
                DraftMarkers.SESSION_HEADER, sessionId,
                DraftMarkers.SEND_HEADER, mode,
                DraftMarkers.ORIGIN_HEADER, origin);
    }

    @Test
    @DisplayName("a well-formed draft parses")
    void parsesAWellFormedDraft() {
        Optional<DraftMarkers> markers = DraftMarkers.from(draft("SESSION-1", "tail", "17"));

        assertTrue(markers.isPresent());
        assertEquals("SESSION-1", markers.get().sessionId());
        assertEquals(SendMode.TAIL, markers.get().mode());
        assertEquals(17, markers.get().originPragma());
    }

    @Test
    @DisplayName("a request with no markers is not a draft")
    void plainRequestsAreNotDrafts() {
        HttpRequest plain = FakeRequest.with("Pragma", "17", "Cookie", "JSESSIONID=abc");
        assertFalse(DraftMarkers.isMarked(plain));
        assertTrue(DraftMarkers.from(plain).isEmpty());
    }

    /**
     * The mode is never defaulted. Guessing here would pick between inspecting a message and acting
     * on somebody's running application session.
     */
    @Test
    @DisplayName("a malformed or missing send mode makes it not a draft, never a default one")
    void modeIsNeverGuessed() {
        assertTrue(DraftMarkers.from(draft("SESSION-1", "", "17")).isEmpty());
        assertTrue(DraftMarkers.from(draft("SESSION-1", "sideways", "17")).isEmpty());
        assertTrue(DraftMarkers.from(
                FakeRequest.with(DraftMarkers.SESSION_HEADER, "SESSION-1")).isEmpty());

        // But it is still *marked*, so the interceptor sees it and refuses rather than sending
        // plaintext straight through.
        assertTrue(DraftMarkers.isMarked(draft("SESSION-1", "sideways", "17")));
    }

    @Test
    @DisplayName("an empty session id is not a draft")
    void emptySessionIdIsNotADraft() {
        assertFalse(DraftMarkers.isMarked(draft("", "tail", "17")));
        assertFalse(DraftMarkers.isMarked(draft("   ", "tail", "17")));
    }

    @Test
    @DisplayName("a missing or unparseable origin defaults to zero rather than failing")
    void originIsOptional() {
        assertEquals(0, DraftMarkers.from(draft("SESSION-1", "tail", "not a number"))
                .orElseThrow().originPragma());
        assertEquals(0, DraftMarkers.from(
                        FakeRequest.with(DraftMarkers.SESSION_HEADER, "SESSION-1",
                                DraftMarkers.SEND_HEADER, "tail"))
                .orElseThrow().originPragma());
    }

    /** The security property: nothing we invented gets onto the wire. */
    @Test
    @DisplayName("stripping removes every marker and leaves everything else alone")
    void strippingIsComplete() {
        HttpRequest marked = FakeRequest.with(
                "Pragma", "17",
                "Cookie", "JSESSIONID=abc",
                DraftMarkers.SESSION_HEADER, "SESSION-1",
                DraftMarkers.SEND_HEADER, "tail",
                DraftMarkers.ORIGIN_HEADER, "17");

        HttpRequest stripped = DraftMarkers.strip(marked);

        assertFalse(stripped.hasHeader(DraftMarkers.SESSION_HEADER));
        assertFalse(stripped.hasHeader(DraftMarkers.SEND_HEADER));
        assertFalse(stripped.hasHeader(DraftMarkers.ORIGIN_HEADER));
        assertFalse(DraftMarkers.isMarked(stripped));

        assertTrue(stripped.hasHeader("Pragma"));
        assertEquals("JSESSIONID=abc", stripped.headerValue("Cookie"));
    }

    @Test
    @DisplayName("stripping an unmarked request changes nothing and does not throw")
    void strippingIsSafeOnPlainRequests() {
        HttpRequest plain = FakeRequest.with("Pragma", "17");
        assertEquals("17", DraftMarkers.strip(plain).headerValue("Pragma"));
    }

    @Test
    @DisplayName("applying markers then reading them back round-trips")
    void applyAndReadRoundTrip() {
        HttpRequest plain = FakeRequest.with("Pragma", "17");

        HttpRequest marked =
                new DraftMarkers("SESSION-9", SendMode.OFFSET, 42).applyTo(plain);
        DraftMarkers read = DraftMarkers.from(marked).orElseThrow();

        assertEquals("SESSION-9", read.sessionId());
        assertEquals(SendMode.OFFSET, read.mode());
        assertEquals(42, read.originPragma());
    }

    @Test
    @DisplayName("applying markers twice replaces rather than duplicates them")
    void applyIsIdempotent() {
        HttpRequest once = new DraftMarkers("SESSION-1", SendMode.TAIL, 5)
                .applyTo(FakeRequest.with("Pragma", "5"));
        HttpRequest twice = new DraftMarkers("SESSION-2", SendMode.OFFSET, 6).applyTo(once);

        DraftMarkers read = DraftMarkers.from(twice).orElseThrow();
        assertEquals("SESSION-2", read.sessionId());
        assertEquals(SendMode.OFFSET, read.mode());
        assertEquals(6, read.originPragma());
    }

    @Test
    @DisplayName("send modes survive a round trip through their wire names")
    void sendModeWireNames() {
        for (SendMode mode : SendMode.values()) {
            assertEquals(Optional.of(mode), SendMode.fromWireName(mode.wireName()));
            assertEquals(Optional.of(mode), SendMode.fromWireName(
                    "  " + mode.wireName().toUpperCase(java.util.Locale.ROOT) + " "));
        }
        assertTrue(SendMode.fromWireName(null).isEmpty());
        assertTrue(SendMode.fromWireName("bootstrap").isEmpty(),
                "mode B is designed but not built; it must not parse as something else");
        assertTrue(SendMode.TAIL.touchesLiveSession());
        assertFalse(SendMode.OFFSET.touchesLiveSession());
    }
}
