package oracleforms.session;

import java.util.Optional;

/**
 * Where a session's two streams have got to, measured from its captured traffic.
 *
 * <p>This is the number a Repeater injection needs: to append a message the server will accept, it
 * must be encrypted at exactly the keystream offset the server's request cipher currently sits at,
 * and that offset is the total of every request byte the server has already consumed.
 *
 * <p>Computing it is a sum, but the interesting work is the <strong>gap check</strong>. Walking
 * forward from pragma 3 and stopping at the first absence is not enough: if pragma 17 were missing
 * while 18–40 were captured, that would report a tail of 16 and encrypt roughly 24 messages' worth of
 * keystream too early. So the scan distinguishes "the session ends here" from "there is a hole here",
 * and only the former yields a usable tail.
 *
 * @param requestPragma  the last contiguously captured pragma in the request direction
 * @param requestBytes   bytes the server's request cipher has consumed
 * @param responsePragma the last contiguously captured pragma in the response direction
 * @param responseBytes  bytes the server's response cipher has produced
 */
public record SessionTail(
        int requestPragma, long requestBytes, int responsePragma, long responseBytes) {

    /** The pragma number an injected message should carry: one past the last one captured. */
    public int nextPragma() {
        return Math.max(requestPragma, responsePragma) + 1;
    }

    /** Whether any encrypted traffic was captured at all. */
    public boolean hasTraffic() {
        return requestPragma >= StreamReplayer.FIRST_ENCRYPTED_PRAGMA;
    }

    /**
     * Measures a session's tail, refusing if either direction has an interior gap.
     *
     * @param highestPragma the highest pragma the source knows about, which bounds the scan
     * @throws StreamGapException if a pragma is missing but a later one was captured
     */
    public static SessionTail measure(PragmaSource source, int highestPragma)
            throws StreamGapException {

        Leg request = scan(source, Direction.REQUEST, highestPragma);
        Leg response = scan(source, Direction.RESPONSE, highestPragma);
        return new SessionTail(request.lastPragma, request.bytes, response.lastPragma, response.bytes);
    }

    /** As {@link #measure(PragmaSource, int)}, taking the bound from the source itself. */
    public static SessionTail measure(PragmaSource source) throws StreamGapException {
        return measure(source, source.highestPragma());
    }

    /**
     * Where the session's streams stood immediately <em>before</em> {@code pragma}.
     *
     * <p>A different question from {@link #measure(PragmaSource)}, and the difference is what broke
     * Mode D: <strong>Burp records a request in the proxy history as soon as it intercepts it, not
     * when it forwards it.</strong> So while a request is held in the Intercept tab it is already in
     * history, indistinguishable from one the server has read — and the tail, which means "what the
     * server's cipher has consumed", counted bytes that had not been sent. An in-flight edit
     * decrypted at that position is one whole message too far along the keystream.
     *
     * <p>Bounding the scan at {@code pragma - 1} is exact rather than cautious: the message at
     * {@code pragma} is the one being held, so by construction neither it nor anything after it has
     * reached the server. It also leaves {@link #nextPragma()} equal to {@code pragma}, which is the
     * number the message about to go out actually carries.
     *
     * @throws StreamGapException if the traffic before {@code pragma} has a hole in it
     */
    public static SessionTail before(PragmaSource source, int pragma) throws StreamGapException {
        return measure(source, pragma - 1);
    }

    private record Leg(int lastPragma, long bytes) {
    }

    private static Leg scan(PragmaSource source, Direction direction, int highestPragma)
            throws StreamGapException {

        int last = StreamReplayer.FIRST_ENCRYPTED_PRAGMA - 1;
        long bytes = 0;

        for (int pragma = StreamReplayer.FIRST_ENCRYPTED_PRAGMA; pragma <= highestPragma; pragma++) {
            Optional<PragmaBody> body = source.body(direction, pragma);
            if (body.isEmpty()) {
                break;
            }
            // A NULLPOST contributes nothing: the client wrote it straight to the socket without
            // encrypting it, so the server's cipher never saw those eight bytes.
            bytes += body.get().streamLength(direction);
            last = pragma;
        }

        // Everything after the stopping point must be absent too. A single capture beyond it means
        // this was a hole rather than the end of the session, and the total above is wrong.
        for (int pragma = last + 1; pragma <= highestPragma; pragma++) {
            if (source.body(direction, pragma).isPresent()) {
                throw new StreamGapException(direction, last + 1, pragma);
            }
        }
        return new Leg(last, bytes);
    }
}
