package oracleforms.session;

import oracleforms.codec.Rc4Stream;

/**
 * Works out the bytes and the sequence number for a message the extension is about to send.
 *
 * <p>Deliberately free of any Burp type, because this is where a mistake is expensive and silent: an
 * encryption at the wrong keystream offset does not fail, it produces a well-formed HTTP request full
 * of noise, and the server may respond by tearing the session down. Keeping the arithmetic here means
 * it can be driven directly by a test with a synthetic session (architecture &sect;6.6).
 *
 * <p>Every failure is a {@link Result.Refused} carrying a sentence for the user. Nothing here throws
 * on a foreseeable condition, because the caller's job on refusal is to explain rather than to
 * recover.
 */
public final class InjectionPlan {

    /** The outcome of planning a send. */
    public sealed interface Result {

        /** The message is ready to go out. */
        record Ready(byte[] ciphertext, int pragma, long position) implements Result {
        }

        /** The message must not be sent, and this is why. */
        record Refused(String reason) implements Result {
        }
    }

    private InjectionPlan() {
    }

    /**
     * Encrypts at the session's current tail and commits the ledger to it.
     *
     * <p>This is Mode A. The position used is wherever the server's request cipher has got to, which
     * is the only offset at which the server can read anything. Committing advances
     * {@link StreamLeg#SERVER_REQUEST} and leaves {@link StreamLeg#CLIENT_REQUEST} where the real
     * client is — the divergence that keeps the live session alive.
     *
     * <p>Caller must hold the session's lock: two sends racing here would both encrypt at the same
     * offset and each would make the other unreadable.
     */
    public static Result atTail(SessionStreams streams, byte[] plaintext) {
        if (streams == null) {
            return new Result.Refused("no stream state for this session");
        }
        if (plaintext == null || plaintext.length == 0) {
            return new Result.Refused("the message body is empty, so there is nothing to send");
        }

        long position = streams.consumed(StreamLeg.SERVER_REQUEST);
        int pragma = streams.nextPragma();
        byte[] ciphertext = streams.apply(StreamLeg.SERVER_REQUEST, plaintext);
        streams.notePragma(pragma);
        return new Result.Ready(ciphertext, pragma, position);
    }

    /**
     * Encrypts at the offset a captured pragma originally occupied, without touching the ledger.
     *
     * <p>This is Mode C. It reproduces what the message would have looked like on the wire in its
     * original position, which is what makes it useful for diffing ciphertext and for checking the
     * re-encoder against a capture. It is <em>not</em> generally valid to send: unless the target
     * pragma happens to be the session's last, the server is long past this offset and will read the
     * result as noise.
     */
    public static Result atCapturedOffset(
            PragmaSource source, byte[] key, int pragma, byte[] plaintext) {

        if (plaintext == null || plaintext.length == 0) {
            return new Result.Refused("the message body is empty, so there is nothing to send");
        }
        if (pragma < StreamReplayer.FIRST_ENCRYPTED_PRAGMA) {
            return new Result.Refused("pragma " + pragma + " is cleartext; encryption starts at "
                    + StreamReplayer.FIRST_ENCRYPTED_PRAGMA);
        }

        long position;
        try {
            // Everything strictly before the target, in the request direction. Reusing the tail
            // measurement gets the NULLPOST rule and the gap check for free.
            position = SessionTail.measure(source, pragma - 1).requestBytes();
        } catch (StreamGapException e) {
            return new Result.Refused(e.getMessage());
        }

        Rc4Stream cipher = new Rc4Stream(key);
        skip(cipher, position);
        return new Result.Ready(cipher.applied(plaintext), pragma, position);
    }

    private static void skip(Rc4Stream cipher, long offset) {
        long remaining = offset;
        while (remaining > 0) {
            int chunk = (int) Math.min(remaining, Integer.MAX_VALUE);
            cipher.skip(chunk);
            remaining -= chunk;
        }
    }
}
