package oracleforms.session;

/**
 * Traffic reached the server that Burp's proxy history never recorded, so the session's keystream
 * position can no longer be reconstructed from the capture.
 *
 * <p>The cause in practice is sending captured ciphertext from Repeater or Intruder <em>without</em>
 * the {@code X-OracleForms-*} draft markers. Such a request is a perfectly valid Forms message: it
 * passes detection, carries no markers so {@code RepeaterSendInterceptor} leaves it alone, and is
 * forwarded unchanged. The server's request cipher consumes its bytes — but
 * {@code api.proxy().history()} is proxy-only, so the send leaves no trace there, and every later
 * tail measurement is short by exactly that body's length.
 *
 * <h2>Why this is an exception and not a silent adjustment</h2>
 *
 * <p>Because the correct offset is <strong>not knowable</strong>, not merely unrecorded. We know the
 * server moved, and we know by how much — but only for the sends this extension happened to observe.
 * A user can resend from a second Burp instance, from curl, or from the application itself while the
 * proxy is bypassed, and none of those are visible here. Adjusting by the amount we did see would
 * turn a detectable failure into an undetectable one.
 *
 * <p>Architecture &sect;6.9 previously recorded this offset as "deliberately not modelled". The first
 * live-target send (&sect;6.11) showed what not-modelled meant in practice: <em>guessed</em>, silently,
 * with the failure surfacing as a dead application session rather than as a message. Every other
 * unknown in this design refuses and says why; this one now does too.
 */
public final class StreamDesyncException extends StreamPositionUnknownException {

    private final String detail;

    public StreamDesyncException(String sessionId, String detail) {
        super(sessionId, "The keystream position of session " + sessionId
                + " can no longer be recovered.\n\n" + detail
                + "\n\nBecause the server's request cipher is now ahead of everything proxy history "
                + "can show, there is no offset to encrypt at. This session cannot be appended to "
                + "again.\n\nRestart the application to get a fresh session, and use \"Send decoded "
                + "to Repeater\" rather than Burp's own Send to Repeater — a draft is encrypted at "
                + "send time and is accounted for, whereas a plain resend of captured ciphertext is "
                + "forwarded unchanged and is not.");
        this.detail = detail == null ? "" : detail;
    }

    /** What was sent that history did not record, as recorded at the time it happened. */
    public String detail() {
        return detail;
    }

    /**
     * Always false. The bytes the server consumed are gone; no later capture reconstructs them.
     */
    @Override
    public boolean isRecoverable() {
        return false;
    }
}
