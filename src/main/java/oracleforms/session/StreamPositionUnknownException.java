package oracleforms.session;

/**
 * A session's current keystream position cannot be established, so nothing can be encrypted for it.
 *
 * <p>The parent of the two ways that happens, which are worth keeping distinct because the remedies
 * differ completely:
 *
 * <ul>
 *   <li>{@link StreamGapException} — proxy history has a hole, so replaying the capture does not
 *       reach the server's position. Capturing the missing pragma would fix it.
 *   <li>{@link StreamDesyncException} — traffic reached the server that history never recorded, so
 *       the server is <em>ahead</em> of anything the capture can show. Nothing fixes it; the session
 *       is spent.
 * </ul>
 *
 * <p>Callers that only need to know "can I encrypt for this session" catch this. Callers that want to
 * tell the user which of the two happened catch the subclasses, or read {@link #getMessage()}, which
 * is written to be shown verbatim.
 *
 * <p>The reason this is an exception rather than an {@code Optional} is that there is no sensible
 * fallback value. Encrypting at a position the server is not at does not fail politely — the server
 * reads the message as noise, and can tear down the session being tested (architecture &sect;6.4,
 * Mode A). Refusing is the only safe answer, so the type makes it impossible to forget.
 */
public abstract class StreamPositionUnknownException extends Exception {

    private final String sessionId;

    protected StreamPositionUnknownException(String sessionId, String message) {
        super(message);
        this.sessionId = sessionId;
    }

    /** The session whose position is unknown, or empty when the failure is not session-specific. */
    public String sessionId() {
        return sessionId == null ? "" : sessionId;
    }

    /**
     * Whether the situation can be recovered by capturing more traffic.
     *
     * <p>A gap can, in principle — the pragma might still be proxied. A desync cannot: the bytes the
     * server consumed are gone, and no amount of later capture reconstructs them.
     */
    public abstract boolean isRecoverable();
}
