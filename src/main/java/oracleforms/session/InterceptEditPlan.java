package oracleforms.session;

/**
 * Works out the bytes for a request the user has edited while Burp was holding it.
 *
 * <p>Mode D (architecture &sect;6.12). The counterpart to {@link InjectionPlan}, and deliberately not
 * a third method on it, because the two answer different questions: {@code InjectionPlan} decides
 * what a message <em>this extension is sending</em> should look like and owns the sequence number,
 * whereas this is rewriting a message <em>the client sent</em>, keeps that message's own number, and
 * has to move a second leg by a length only the editor knows.
 *
 * <p>Free of any Burp type for the same reason as {@code InjectionPlan}: a mistake here does not
 * fail, it produces a well-formed request full of noise, and the server may answer by tearing down
 * the session under test. Keeping the arithmetic here means it can be driven directly against a
 * synthetic session holding its own client and server ciphers.
 *
 * <h2>Why this is the safest of the send modes</h2>
 *
 * <p>Nothing is invented. Mode A measures a tail and rewrites a pragma and a cookie, and any of the
 * three can be stale by the time the message lands. Here the offset is wherever the two legs already
 * are, the pragma and the cookies are the client's own, and the message is in sequence by
 * construction — the client is blocked waiting for it. The caller has also, by this point, decrypted
 * the message at that very offset and checked that the result reads as FHT, which is evidence about
 * the offset that no other mode can obtain before sending.
 */
public final class InterceptEditPlan {

    /** The outcome of planning an in-flight edit. */
    public sealed interface Result {

        /**
         * The edited message is ready to forward.
         *
         * @param ciphertext  what to put on the wire
         * @param position    the server-facing keystream offset it was encrypted at
         * @param diverged    whether the two request legs have now parted company, so the caller
         *                    knows whether the counters have to reach the project file
         */
        record Ready(byte[] ciphertext, long position, boolean diverged) implements Result {
        }

        /** The message must not be forwarded as edited, and this is why. */
        record Refused(String reason) implements Result {
        }
    }

    private InterceptEditPlan() {
    }

    /**
     * Advances the client's leg over what the client sent, and encrypts the edit on the server's.
     *
     * <p>Refuses rather than throws on every foreseeable condition, because the caller's job on a
     * refusal is to explain and drop, not to recover.
     *
     * @param originalStreamLength what the client's own body contributed to its request keystream:
     *                             its ciphertext length, or zero for a {@code NULLPOST}
     */
    public static Result edit(
            SessionStreams streams, byte[] editedPlaintext, int originalStreamLength, int pragma) {

        if (streams == null) {
            return new Result.Refused("no stream state for this session");
        }
        if (editedPlaintext == null || editedPlaintext.length == 0) {
            return new Result.Refused("the edited message is empty, so there is nothing to send");
        }
        if (originalStreamLength < 0) {
            return new Result.Refused("the original message's length was not recorded, so the "
                    + "client's keystream position cannot be advanced past it");
        }
        if (pragma < StreamReplayer.FIRST_ENCRYPTED_PRAGMA) {
            return new Result.Refused("pragma " + pragma + " is cleartext; encryption starts at "
                    + StreamReplayer.FIRST_ENCRYPTED_PRAGMA);
        }

        long position = streams.consumed(StreamLeg.SERVER_REQUEST);
        byte[] ciphertext = streams.editInFlight(editedPlaintext, originalStreamLength, pragma);
        return new Result.Ready(ciphertext, position, streams.diverged());
    }
}
