package oracleforms.session;

/**
 * One of the four cipher relationships Burp sits between (architecture &sect;6.2).
 *
 * <p>The reference implementation keeps one RC4 state per {@link Direction}, which is correct only
 * while Burp forwards every byte unchanged. Burp is a man in the middle with <em>two</em> independent
 * cipher relationships — one with the client, one with the server — and the moment a message is
 * edited, or one is injected that the client never sent, the two sides stop being at the same
 * keystream position.
 *
 * <p>Keeping four states lets each side stay internally consistent across that divergence: the client
 * is decrypted at the position the client thinks it is at, and the server is encrypted at the
 * position the server thinks it is at. Neither can tell.
 */
public enum StreamLeg {

    /** Decrypting what the client sends. Advances only on traffic the real client actually sent. */
    CLIENT_REQUEST(Direction.REQUEST),

    /** Encrypting what we forward to the server. Also advances on an injected Repeater message. */
    SERVER_REQUEST(Direction.REQUEST),

    /** Decrypting what the server sends, including replies to messages the client never sent. */
    SERVER_RESPONSE(Direction.RESPONSE),

    /** Encrypting what we forward to the client. Does not advance on an injected message's reply. */
    CLIENT_RESPONSE(Direction.RESPONSE);

    private final Direction direction;

    StreamLeg(Direction direction) {
        this.direction = direction;
    }

    /** Which of the session's two wire directions this leg belongs to. */
    public Direction direction() {
        return direction;
    }

    /** The leg carrying the same direction on the other side of the proxy. */
    public StreamLeg peer() {
        return switch (this) {
            case CLIENT_REQUEST -> SERVER_REQUEST;
            case SERVER_REQUEST -> CLIENT_REQUEST;
            case SERVER_RESPONSE -> CLIENT_RESPONSE;
            case CLIENT_RESPONSE -> SERVER_RESPONSE;
        };
    }
}
