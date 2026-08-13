package oracleforms.session;

import oracleforms.codec.StringDictionary;

/**
 * The outcome of replaying a stream up to a target pragma.
 *
 * <p>Sealed, so the editor can render every case deliberately. The failures are the interesting
 * part: because the ordering key is explicit and history retains the bodies, this decoder can say
 * <em>which</em> pragma is missing instead of showing an empty tab — a diagnostic the reference
 * implementation's live-only model cannot produce at all (architecture &sect;2).
 */
public sealed interface ReplayResult {

    /** A one-line explanation for the UI. */
    String describe();

    /**
     * The target was decrypted.
     *
     * @param plaintext the decrypted bytes — for a response this is the whole reassembled
     *                  {@link FragmentGroup}, not just the target pragma's own fragment
     * @param fragments which pragmas were reassembled to produce {@code plaintext}
     */
    record Decrypted(int pragma, Direction direction, byte[] plaintext, StringDictionary dictionary,
                     FragmentGroup fragments) implements ReplayResult {

        /** A message that stands alone, occupying exactly one pragma. */
        public Decrypted(
                int pragma, Direction direction, byte[] plaintext, StringDictionary dictionary) {
            this(pragma, direction, plaintext, dictionary, FragmentGroup.single(pragma));
        }

        @Override
        public String describe() {
            return "decrypted pragma " + pragma + " (" + plaintext.length + " bytes"
                    + (fragments.isSplit() ? ", " + fragments.describe() : "") + ")";
        }
    }

    /**
     * Which pragmas were concatenated to rebuild one logical message.
     *
     * <p>A large server message does not fit in one HTTP response: Forms flushes it in fragments and
     * the client pulls each continuation with a
     * {@link PragmaBody#NULL_POST NULLPOST}. The fragments share one continuous RC4 stream, so
     * decryption of any single fragment succeeds — but a fragment other than the first begins in the
     * middle of an FHT structure, and parsing it alone yields plausible-looking nonsense. That is the
     * failure this record exists to make impossible to overlook.
     *
     * @param first    the pragma holding the start of the message
     * @param last     the last fragment that was captured and reassembled
     * @param target   the pragma the user actually asked for
     * @param complete whether the group ran to its natural end rather than stopping at a gap
     */
    record FragmentGroup(int first, int last, int target, boolean complete) {

        public static FragmentGroup single(int pragma) {
            return new FragmentGroup(pragma, pragma, pragma, true);
        }

        /** Whether the message spans more than one pragma. */
        public boolean isSplit() {
            return last > first;
        }

        /** How many fragments were joined. */
        public int count() {
            return last - first + 1;
        }

        /** Which fragment the target is, counting from 1. */
        public int targetIndex() {
            return target - first + 1;
        }

        public String describe() {
            if (!isSplit()) {
                return "a single unfragmented message";
            }
            return "reassembled from pragmas " + first + "-" + last + " (" + count()
                    + " fragments; you selected fragment " + targetIndex() + ")"
                    + (complete ? "" : " - the group is incomplete, later fragments were not captured");
        }
    }

    /**
     * The target is a {@link PragmaBody#NULL_POST NULLPOST}: a request with no payload at all.
     *
     * <p>Not a failure. The client sends it to collect the remainder of an oversized response, so
     * there is nothing here to decrypt and nothing was ever encrypted.
     */
    record NullPost(int pragma) implements ReplayResult {

        @Override
        public String describe() {
            return "Pragma " + pragma + " is a NULLPOST: the client sent no payload, it is polling "
                    + "for the rest of the response to pragma " + (pragma - 1)
                    + ". It is cleartext and does not advance the request keystream.";
        }
    }

    /**
     * A pragma between the last checkpoint and the target was never captured, so the keystream
     * position at the target cannot be reached.
     */
    record MissingPragma(int missing, int target, Direction direction) implements ReplayResult {

        @Override
        public String describe() {
            return "Pragma " + missing + " was not captured in this direction, so the RC4 stream "
                    + "position for pragma " + target + " cannot be reconstructed. Everything from "
                    + missing + " onward is undecodable in this session.";
        }
    }

    /** The pragma is below the first encrypted one — it is cleartext and needs no decoding. */
    record NotEncrypted(int pragma) implements ReplayResult {

        @Override
        public String describe() {
            return "Pragma " + pragma + " is not encrypted (encryption starts at pragma "
                    + StreamReplayer.FIRST_ENCRYPTED_PRAGMA + ").";
        }
    }

    /** No key is stored for this session. */
    record NoKey(String sessionId) implements ReplayResult {

        @Override
        public String describe() {
            return "No key stored for session " + sessionId
                    + ". Its Pragma 1 handshake was never seen - run a retroactive history scan, "
                    + "or enter the key manually from the Sessions tab.";
        }
    }
}
