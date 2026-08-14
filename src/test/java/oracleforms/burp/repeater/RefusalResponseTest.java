package oracleforms.burp.repeater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Regression test for a bug found by sending a real refusal through a live Burp.
 *
 * <p>The refusal response used to be assembled as a {@code String} with its {@code Content-Length}
 * computed from the UTF-8 encoding, then handed to {@code HttpResponse.httpResponse(String)} — which
 * encodes as Latin-1. Every multi-byte character therefore shrank on the way out while the header
 * kept the larger count. Two em dashes in the "no key stored" message were enough to make a live
 * refusal declare 391 bytes and send 387, and a client honouring {@code Content-Length} waits
 * forever for the difference.
 *
 * <p>The invariant below is the fix, and it has to hold for any {@code reason} — one of them
 * interpolates a session id read straight off a request header.
 */
class RefusalResponseTest {

    /** Splits the assembled response into its header block and its body. */
    private static byte[][] split(byte[] raw) {
        byte[] separator = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i + separator.length <= raw.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(raw, i, i + separator.length), separator)) {
                return new byte[][]{
                        Arrays.copyOfRange(raw, 0, i),
                        Arrays.copyOfRange(raw, i + separator.length, raw.length)};
            }
        }
        throw new AssertionError("no header/body separator in the refusal response");
    }

    private static int declaredLength(byte[] head) {
        for (String line : new String(head, StandardCharsets.US_ASCII).split("\r\n")) {
            if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                return Integer.parseInt(line.split(":", 2)[1].trim());
            }
        }
        throw new AssertionError("no Content-Length in the refusal response");
    }

    private static void assertLengthMatchesBody(String host, String reason) {
        byte[][] parts = split(RepeaterSendInterceptor.refusalBytes(host, reason));
        assertEquals(parts[1].length, declaredLength(parts[0]),
                "Content-Length must equal the body's actual byte count for reason: " + reason);
    }

    @Test
    @DisplayName("Content-Length matches the body for plain ASCII")
    void asciiLengthIsCorrect() {
        assertLengthMatchesBody("example.test", "No key is stored for session ABC123.");
    }

    /** The exact shape that was wrong in production: an em dash inside the reason. */
    @Test
    @DisplayName("Content-Length matches the body when the reason contains multi-byte characters")
    void multiByteCharactersDoNotDesynchroniseTheLength() {
        assertLengthMatchesBody("example.test",
                "Recover the key from the Sessions tab — run a scan — and send again.");
    }

    @Test
    @DisplayName("Content-Length holds for a session id carrying non-ASCII bytes")
    void hostileSessionIdsAreCountedInBytes() {
        // The session id is read from a request header, so it is not the extension's to trust.
        // The last one is the shape a WebLogic route suffix takes, with a synthetic value.
        for (String sessionId : new String[]{
                "éèê", "你好世界", "😀", "!-1111111111"}) {
            assertLengthMatchesBody("example.test", "No key is stored for session " + sessionId + ".");
        }
    }

    @Test
    @DisplayName("the response is a well-formed 599 that names itself, and carries the reason")
    void responseIsWellFormedAndExplains() {
        byte[][] parts = split(RepeaterSendInterceptor.refusalBytes(
                "forms.example.edu", "Pragma 17 was not captured."));
        String head = new String(parts[0], StandardCharsets.US_ASCII);
        String body = new String(parts[1], StandardCharsets.UTF_8);

        assertTrue(head.startsWith("HTTP/1.1 599 "), head);
        assertTrue(head.contains("Oracle Forms Decoder"),
                "a refusal must not look like the server's own answer");
        assertTrue(body.contains("Pragma 17 was not captured."), body);
        assertTrue(body.contains("forms.example.edu"), "the user should see what was not contacted");
        assertTrue(body.contains("refused to send"), body);
    }

    @Test
    @DisplayName("an empty reason still produces a valid response")
    void emptyReasonIsSafe() {
        assertLengthMatchesBody("example.test", "");
    }

    /**
     * A reason cannot inject headers: it is interpolated after the blank line, so CRLF in it is
     * body content. Worth pinning, because the reason is partly attacker-influenced.
     */
    @Test
    @DisplayName("CRLF in the reason cannot forge a header")
    void crlfInTheReasonStaysInTheBody() {
        byte[][] parts = split(RepeaterSendInterceptor.refusalBytes(
                "example.test", "broken\r\nX-Injected: yes\r\n\r\nstill body"));
        String head = new String(parts[0], StandardCharsets.US_ASCII);

        assertTrue(head.lines().noneMatch(l -> l.startsWith("X-Injected")),
                "the reason must not be able to add a header: " + head);
        assertLengthMatchesBody("example.test", "broken\r\nX-Injected: yes\r\n\r\nstill body");
    }
}
