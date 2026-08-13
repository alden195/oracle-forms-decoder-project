package oracleforms.session;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * One captured message body, tagged with its {@code Pragma} sequence number.
 *
 * <p>Deliberately free of any Burp type. This is the unit {@link StreamReplayer} consumes, which is
 * what lets replay — the subtlest code in the project — be tested against a recorded fixture with no
 * running Burp (architecture &sect;4).
 *
 * @param pragma the {@code Pragma} header value; the ordering key for the whole design
 * @param body   the raw, still-encrypted body exactly as it appeared on the wire
 */
public record PragmaBody(int pragma, byte[] body) implements Comparable<PragmaBody> {

    /**
     * The literal request body the Forms client sends when it has nothing to say.
     *
     * <p>When the server owes the client more data than fits in one HTTP response, the client keeps
     * the exchange going by POSTing the eight ASCII bytes {@code NULLPOST} — "I have no payload,
     * send me the rest". Two consequences follow, and missing either one corrupts a session:
     *
     * <ul>
     *   <li><b>It is cleartext.</b> It never passes through the client's RC4 request cipher, so it
     *       must contribute <em>zero</em> bytes to the request keystream. Advancing by its 8 bytes
     *       desynchronises every later request in the session — see {@link #streamLength}.
     *   <li><b>It marks a response continuation.</b> The response it draws is the next fragment of
     *       the previous response's message, not a message of its own — see
     *       {@link StreamReplayer} and the fragment grouping there.
     * </ul>
     *
     * <p>Confirmed on the live capture: pragmas 8, 9 and 10 of one session each carry exactly these
     * bytes, against responses of exactly 66000, 66000 and 20892 bytes.
     */
    public static final byte[] NULL_POST = "NULLPOST".getBytes(StandardCharsets.US_ASCII);

    public PragmaBody {
        if (body == null) {
            throw new IllegalArgumentException("body must not be null");
        }
        body = body.clone();
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    /** Length without copying, for the common case where only the stream advance matters. */
    public int length() {
        return body.length;
    }

    /**
     * Whether this body is the cleartext {@link #NULL_POST} sentinel.
     *
     * <p>Only meaningful in the request direction; the server never sends it. Callers pair this with
     * a direction check so that ciphertext which happens to collide with these eight bytes — a
     * 2<sup>-64</sup> event — cannot be mistaken for the sentinel in the response stream.
     */
    public boolean isNullPost() {
        return isNullPost(body);
    }

    /**
     * As {@link #isNullPost()}, for callers holding raw bytes.
     *
     * <p>Used on the proxy hot path, where constructing a {@link PragmaBody} would copy the body for
     * nothing. The length test short-circuits everything that is not the sentinel.
     */
    public static boolean isNullPost(byte[] body) {
        return body != null && body.length == NULL_POST.length && Arrays.equals(body, NULL_POST);
    }

    /**
     * How many bytes this body contributes to its direction's RC4 keystream.
     *
     * <p>Everything except a {@link #isNullPost() NULLPOST} contributes its full length. A NULLPOST
     * contributes nothing, because the client wrote it straight to the socket without encrypting it.
     */
    public int streamLength(Direction direction) {
        return direction == Direction.REQUEST && isNullPost() ? 0 : body.length;
    }

    @Override
    public int compareTo(PragmaBody other) {
        return Integer.compare(pragma, other.pragma);
    }
}
