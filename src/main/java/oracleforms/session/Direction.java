package oracleforms.session;

/**
 * Which of a session's two independent RC4 streams a body belongs to.
 *
 * <p>Both streams are seeded from the same 5-byte key and both start at keystream offset 0 at Pragma
 * 3, but they advance independently thereafter. Mixing them up decrypts to noise.
 */
public enum Direction {

    /** Client to server: the bodies of the {@code lservlet} POSTs. */
    REQUEST,

    /** Server to client: the bodies of their responses. */
    RESPONSE;

    public Direction opposite() {
        return this == REQUEST ? RESPONSE : REQUEST;
    }
}
