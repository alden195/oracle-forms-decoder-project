package oracleforms.session;

import java.util.Optional;
import oracleforms.codec.Rc4Stream;

/**
 * Finds the keystream offset a reply was actually encrypted at, when the ledger's is short.
 *
 * <h2>Why the ledger can be short, and why this is not a race</h2>
 *
 * <p>The response tail is measured from proxy history, and history is asymmetric about traffic in
 * flight. A Forms client <strong>long-polls</strong> — the capture shows requests held open for tens
 * of seconds — so at almost any moment there is one request that Burp has recorded and one response
 * that has not come back yet. The request tail is therefore right and the response tail is short by
 * exactly that outstanding response's length.
 *
 * <p>That asymmetry does not hurt the send: the server's <em>request</em> cipher really is at the
 * measured position, which is why an appended message is accepted. It hurts the reply, because
 * answering an injected message is what makes the runtime flush its pending output down the waiting
 * poll first. The server emits that response — advancing its response cipher — and only then answers
 * us. So our reply arrives encrypted one whole response further on than the ledger believes.
 *
 * <p><strong>The length of a response that has not arrived cannot be known at send time.</strong>
 * That is structural, not a timing bug, and no amount of care at the moment of sending recovers it.
 *
 * <h2>Solving for it rather than guessing</h2>
 *
 * <p>This is deliberately not a guess of the kind architecture &sect;6.11 forbids. A guessed offset
 * is one nothing can check; this one is <em>verified</em> before it is believed, by the same oracle
 * &sect;8 uses to validate a key: the plaintext must parse into property ids drawn from the
 * 470-entry table. A correct offset scores near 100%, a wrong one 16–24%. The search reports a
 * result only when it lands on a body that parses cleanly and beats that noise floor decisively, and
 * it refuses when two candidates in the window are equally good.
 *
 * <p>It also measures the gap, which is the useful part: the number of bytes recovered is exactly the
 * outstanding response's length, so the caller can resynchronise the ledger instead of carrying the
 * error into the next send.
 */
public final class ReplyOffsetRecovery {

    /**
     * How far ahead of the ledger to look.
     *
     * <p>The gap is one response body, and the largest seen on the wire is a 66,000-byte fragment
     * (architecture &sect;1). A quarter of a megabyte covers several of those and still bounds the
     * work; the search is only ever reached on a body the ledger already failed to read.
     */
    public static final int DEFAULT_WINDOW = 256 * 1024;

    /**
     * Properties a candidate must produce before its hit rate means anything.
     *
     * <p>Deliberately higher than {@link KeyValidation#MIN_PROPERTIES}, and the reason is the number
     * of chances a wrong answer gets. That threshold judges <em>one</em> candidate key against a
     * whole Pragma 3 body. This one judges a quarter of a million candidate offsets against as little
     * as a hundred bytes, so a test that is merely unlikely to pass by luck will still pass by luck
     * somewhere in the window — which it did, at three properties, during development.
     */
    private static final int MIN_PROPERTIES = 4;

    /** What was found, and how far it was from where the ledger thought it was. */
    public record Found(long offset, long gap, KeyValidation.Signals signals) {

        public String describe() {
            return "offset " + offset + " (" + gap + " bytes further on than the ledger), "
                    + signals.describe();
        }
    }

    private ReplyOffsetRecovery() {
    }

    /**
     * Everything one pass over the window learned.
     *
     * @param accepted the offset to believe, if one earned it
     * @param closest  the most FHT-like offset seen, <em>whether or not</em> it was believed. Never
     *                 acted on — it exists so a refusal can say what it nearly found, which is the
     *                 difference between "no offset in range decrypts this" and "the right-looking
     *                 offset was rejected by one unknown property id". Those need opposite fixes and
     *                 a bare empty result cannot tell them apart.
     */
    public record Scan(Optional<Found> accepted, Optional<Found> closest) {

        public String describeRefusal() {
            return closest.map(c -> "the closest candidate was " + c.describe()
                            + ", which was not enough to believe")
                    .orElse("no candidate in the window produced even " + MIN_PROPERTIES
                            + " properties");
        }
    }

    /**
     * Searches forward from {@code from} for the offset this ciphertext decrypts cleanly at.
     *
     * <p>Forward only, and on purpose: the ledger can be short of the truth because a response it
     * never saw has gone by, but it cannot be ahead of it — nothing removes bytes from a keystream.
     * A backward search would be looking for something that cannot be there, and every offset it
     * examined would be another chance at a false positive.
     *
     * @param window how many bytes past {@code from} to consider
     */
    public static Scan scan(byte[] key, byte[] ciphertext, long from, int window) {

        if (key == null || ciphertext == null || ciphertext.length == 0 || from < 0 || window <= 0) {
            return new Scan(Optional.empty(), Optional.empty());
        }

        // One keystream run covering every candidate, rather than reseeding per offset: RC4 from a
        // standing start is linear in the offset, so the naive loop would be quadratic in the window.
        byte[] keystream = keystreamFrom(key, from, window + ciphertext.length);

        Found best = null;
        boolean tied = false;
        Found closest = null;

        for (int shift = 0; shift <= window; shift++) {
            byte[] candidate = new byte[ciphertext.length];
            for (int i = 0; i < candidate.length; i++) {
                candidate[i] = (byte) (ciphertext[i] ^ keystream[shift + i]);
            }

            KeyValidation.Signals signals = KeyValidation.signalsOf(candidate);

            if (signals.properties() >= MIN_PROPERTIES
                    && (closest == null || isCloser(signals, closest.signals()))) {
                closest = new Found(from + shift, shift, signals);
            }

            if (!convincing(signals)) {
                continue;
            }
            if (best == null || signals.knownFraction() > best.signals().knownFraction()
                    || (signals.knownFraction() == best.signals().knownFraction()
                            && signals.bytesConsumed() > best.signals().bytesConsumed())) {
                tied = best != null
                        && signals.knownFraction() == best.signals().knownFraction()
                        && signals.bytesConsumed() == best.signals().bytesConsumed();
                best = new Found(from + shift, shift, signals);
            } else if (signals.knownFraction() == best.signals().knownFraction()
                    && signals.bytesConsumed() == best.signals().bytesConsumed()) {
                tied = true;
            }
        }

        // Two offsets that read equally well is not an answer, it is a coincidence with a second
        // opinion. Refusing is the same instinct as everywhere else in the send path.
        Optional<Found> accepted =
                best == null || tied ? Optional.empty() : Optional.of(best);
        return new Scan(accepted, Optional.ofNullable(closest));
    }

    /** Which of two candidates reads more like FHT, ignoring whether either is believable. */
    private static boolean isCloser(KeyValidation.Signals candidate, KeyValidation.Signals best) {
        if (candidate.knownFraction() != best.knownFraction()) {
            return candidate.knownFraction() > best.knownFraction();
        }
        if (candidate.complete() != best.complete()) {
            return candidate.complete();
        }
        return candidate.bytesConsumed() > best.bytesConsumed();
    }

    /**
     * The offset to believe, or empty.
     *
     * @return the offset, or empty if nothing in the window parses convincingly or more than one does
     */
    public static Optional<Found> search(
            byte[] key, byte[] ciphertext, long from, int window) {
        return scan(key, ciphertext, from, window).accepted();
    }

    /** As {@link #search(byte[], byte[], long, int)} with the default window. */
    public static Optional<Found> search(byte[] key, byte[] ciphertext, long from) {
        return search(key, ciphertext, from, DEFAULT_WINDOW);
    }

    /**
     * Whether a candidate is good enough to be believed at all.
     *
     * <p>Three demands, and the third is what makes the other two safe at this scale:
     *
     * <ul>
     *   <li>Enough properties to judge — see {@link #MIN_PROPERTIES}.
     *   <li><b>Every</b> id known, not most of them. A threshold that admitted "mostly right" would
     *       be assuming after all, which is the thing this class exists not to do.
     *   <li>The parse ran to the terminator. A wrong offset can produce a few plausible properties
     *       and then demand a string longer than the body; reaching a clean end means every length
     *       and every type marker in the body agreed with each other, which is a far larger
     *       coincidence than any single id being real.
     * </ul>
     *
     * <p>The cost of the last one is that a reply which is genuinely a fragment of a larger message
     * cannot be recovered, because it has no terminator to reach. Refusing there is the right way
     * round: a fragment is exactly the case where a confident-looking wrong answer is easiest to
     * produce.
     */
    private static boolean convincing(KeyValidation.Signals signals) {
        return signals.properties() >= MIN_PROPERTIES
                && signals.knownFraction() >= 1.0
                && signals.complete();
    }

    private static byte[] keystreamFrom(byte[] key, long from, int length) {
        Rc4Stream cipher = new Rc4Stream(key);
        long remaining = from;
        while (remaining > 0) {
            int chunk = (int) Math.min(remaining, Integer.MAX_VALUE);
            cipher.skip(chunk);
            remaining -= chunk;
        }
        // RC4 is its own inverse, so running it over zeros yields the keystream itself.
        return cipher.applied(new byte[length]);
    }
}
