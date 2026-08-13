package oracleforms.session;

import java.io.ByteArrayOutputStream;
import java.util.Optional;
import oracleforms.codec.FhtParser;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.StringDictionary;

/**
 * Reconstructs the RC4 stream position for an arbitrary pragma and decrypts it.
 *
 * <p>This class is the reason the project exists in the shape it does. Because the keystream is
 * continuous across a session, a stored key alone cannot decrypt pragma 42: RC4 has by then consumed
 * every byte of pragmas 3–41 in that direction. So decoding is
 * <em>stored key → replay preceding pragmas in order → decrypt the target</em>, which is what makes
 * traffic captured before the extension was even installed readable (architecture &sect;2).
 *
 * <p>Two costs are avoided along the way:
 *
 * <ul>
 *   <li><b>Checkpoints</b> turn O(n) per message and O(n²) per session into something closer to
 *       constant, by resuming from the nearest cached state rather than from pragma 3.
 *   <li>Under {@link DictionaryScope#PACKET}, intervening packets are never decrypted at all — the
 *       stream is simply advanced by their length, which skips both the XOR and the parse.
 * </ul>
 *
 * <p>No Burp types appear here; bodies arrive through {@link PragmaSource}.
 */
public final class StreamReplayer {

    /**
     * Encryption begins at pragma 3, at keystream offset 0, in both directions. Pragma 0 is the
     * cleartext servlet-info GET, pragma 1 the cleartext handshake, and pragma 2 does not exist.
     */
    public static final int FIRST_ENCRYPTED_PRAGMA = 3;

    /** Checkpoint every this many pragmas while replaying forward. */
    private static final int CHECKPOINT_INTERVAL = 25;

    private final CheckpointCache checkpoints;
    private final DictionaryScope scope;
    private final FhtParser parser = new FhtParser();

    public StreamReplayer(CheckpointCache checkpoints, DictionaryScope scope) {
        this.checkpoints = checkpoints;
        this.scope = scope;
    }

    public DictionaryScope scope() {
        return scope;
    }

    /**
     * Decrypts {@code target} in {@code direction}, replaying from the nearest checkpoint.
     *
     * @param key    the session's key, or {@code null} if none is stored
     * @param source supplies the captured bodies
     */
    public ReplayResult replay(
            String sessionId, SessionKey key, Direction direction, int target, PragmaSource source) {

        if (target < FIRST_ENCRYPTED_PRAGMA) {
            return new ReplayResult.NotEncrypted(target);
        }
        if (key == null) {
            return new ReplayResult.NoKey(sessionId);
        }

        // A NULLPOST request has no payload and never entered the cipher, so there is nothing to
        // decrypt and no stream position to reach.
        if (direction == Direction.REQUEST && isNullPost(source, target)) {
            return new ReplayResult.NullPost(target);
        }

        // A response message can be split across several pragmas, so the bytes to parse start
        // earlier than the target and may continue past it.
        int first = direction == Direction.RESPONSE ? groupStart(source, target) : target;

        Rc4Stream rc4;
        StringDictionary dictionary;
        int next;

        Optional<Checkpoint> resume = checkpoints.nearestAtOrBefore(sessionId, direction, first - 1);
        if (resume.isPresent()) {
            Checkpoint cp = resume.get();
            rc4 = cp.rc4();
            dictionary = cp.dictionary();
            next = cp.pragma() + 1;
        } else {
            rc4 = new Rc4Stream(key.key());
            dictionary = new StringDictionary();
            next = FIRST_ENCRYPTED_PRAGMA;
        }

        // Phase 1: replay everything strictly before the message, advancing the keystream by each
        // body without keeping its plaintext.
        ReplayResult skipped = advanceTo(sessionId, direction, next, first, target, source, rc4, dictionary);
        if (skipped != null) {
            return skipped;
        }

        // Phase 2: decrypt the message's own fragments, in order, into one buffer.
        Optional<PragmaBody> firstBody = source.body(direction, first);
        if (firstBody.isEmpty()) {
            return new ReplayResult.MissingPragma(first, target, direction);
        }

        ByteArrayOutputStream assembled = new ByteArrayOutputStream();
        writeDecrypted(assembled, direction, rc4, firstBody.get());

        int last = first;
        boolean complete = true;
        while (direction == Direction.RESPONSE && isNullPost(source, last + 1)) {
            Optional<PragmaBody> continuation = source.body(direction, last + 1);
            if (continuation.isEmpty()) {
                // The continuation was requested on the wire but never captured, so the message
                // genuinely ends short. Say so rather than presenting a truncated parse as whole.
                complete = false;
                break;
            }
            last++;
            writeDecrypted(assembled, direction, rc4, continuation.get());
        }

        byte[] plaintext = assembled.toByteArray();

        StringDictionary targetDictionary;
        if (scope == DictionaryScope.SESSION) {
            // The caller parses the message against the dictionary as it stood *before* it, so it
            // gets its own copy.
            targetDictionary = dictionary.copy();

            // The session dictionary must then absorb the message's own strings before the
            // checkpoint is taken. Skipping this stores a checkpoint whose dictionary is missing
            // exactly the slots this message defined, so a later resume from it would silently
            // resolve those back-references to empty strings -- the §7.2 failure mode,
            // reintroduced by the cache rather than by the scope.
            parser.parse(plaintext, dictionary);
        } else {
            // Under PACKET scope the message reads back-references only from its own strings, so it
            // starts clean regardless of what replay accumulated.
            targetDictionary = new StringDictionary();
        }

        // One checkpoint per message, at its last fragment: the stream position mid-group is not a
        // useful place to resume, and under SESSION scope its dictionary would be incomplete.
        checkpoints.put(sessionId, direction, Checkpoint.after(last, rc4, dictionary));

        return new ReplayResult.Decrypted(target, direction, plaintext, targetDictionary,
                new ReplayResult.FragmentGroup(first, last, target, complete));
    }

    /**
     * Advances the keystream over pragmas {@code [from, until)}, returning a failure result if one
     * of them was never captured and {@code null} on success.
     */
    private ReplayResult advanceTo(
            String sessionId, Direction direction, int from, int until, int target,
            PragmaSource source, Rc4Stream rc4, StringDictionary dictionary) {

        // Under SESSION scope a response's strings can be referenced later, so intervening messages
        // must be parsed -- and parsed whole, which means holding fragments until their group ends.
        ByteArrayOutputStream pending =
                scope == DictionaryScope.SESSION ? new ByteArrayOutputStream() : null;

        for (int pragma = from; pragma < until; pragma++) {
            Optional<PragmaBody> body = source.body(direction, pragma);
            if (body.isEmpty()) {
                return new ReplayResult.MissingPragma(pragma, target, direction);
            }

            if (pending == null) {
                // Nothing about an intervening body can affect the target, so only its effect on
                // the stream position matters -- no XOR and no parse.
                rc4.skip(body.get().streamLength(direction));
            } else {
                writeDecrypted(pending, direction, rc4, body.get());
                boolean groupContinues =
                        direction == Direction.RESPONSE && isNullPost(source, pragma + 1);
                if (!groupContinues) {
                    parser.parse(pending.toByteArray(), dictionary);
                    pending.reset();
                }
            }

            if (pragma % CHECKPOINT_INTERVAL == 0) {
                checkpoints.put(sessionId, direction, Checkpoint.after(pragma, rc4, dictionary));
            }
        }
        return null;
    }

    /** Decrypts one body onto the end of {@code sink}, advancing the stream by what it contributed. */
    private static void writeDecrypted(
            ByteArrayOutputStream sink, Direction direction, Rc4Stream rc4, PragmaBody body) {
        if (body.streamLength(direction) == 0) {
            // Cleartext sentinel: no ciphertext, no keystream consumed, nothing to contribute.
            return;
        }
        byte[] plaintext = rc4.applied(body.body());
        sink.write(plaintext, 0, plaintext.length);
    }

    /**
     * The pragma holding the start of the message that {@code target}'s response belongs to.
     *
     * <p>Walks back while each pragma's <em>request</em> is a NULLPOST, because that is precisely
     * the client saying "send me the rest of what you already owe me". Grouping on this wire
     * sentinel rather than on a fragment size keeps the rule independent of however the server has
     * its response buffer configured.
     */
    private static int groupStart(PragmaSource source, int target) {
        int first = target;
        while (first > FIRST_ENCRYPTED_PRAGMA && isNullPost(source, first)) {
            first--;
        }
        return first;
    }

    /** Whether the request at {@code pragma} is the cleartext NULLPOST sentinel. */
    private static boolean isNullPost(PragmaSource source, int pragma) {
        return source.body(Direction.REQUEST, pragma)
                .map(PragmaBody::isNullPost)
                .orElse(false);
    }
}
