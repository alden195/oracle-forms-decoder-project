package oracleforms.session;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.OptionalInt;
import oracleforms.codec.Rc4Stream;

/**
 * Validation for a session's key and for the stream-start assumption, in two stages.
 *
 * <h2>Why this is not the check architecture §1 originally described</h2>
 *
 * <p>That check was: "decrypt the first 4 bytes of the Pragma 3 request and of the Pragma 3
 * response; if they do not match, the key or the stream start is wrong." It cannot work, and the
 * reason is worth stating plainly so nobody re-derives it.
 *
 * <p>The premise is an observation about <em>ciphertext</em>: the first four ciphertext bytes of the
 * Pragma 3 request and response are identical. Both directions are seeded from the same key and both
 * sit at keystream offset 0, so both prefixes get XORed with the <em>same</em> four keystream bytes.
 * Decrypting two identical ciphertexts with the same keystream always yields two identical
 * plaintexts — whatever that keystream is. A completely wrong key produces two identical wrong
 * prefixes, and the comparison passes. The test has no discriminating power whatsoever.
 *
 * <p>What survives is still useful, but it splits into two different checks:
 *
 * <ol>
 *   <li>{@link #checkStreamSymmetry} — compares the <em>raw ciphertext</em> prefixes. It needs no key
 *       at all. It validates the architectural assumption that both directions share one key and
 *       both start at pragma 3 offset 0; if it fails, that assumption is wrong and the whole replay
 *       model needs revisiting. This is the real content of the original observation.
 *   <li>{@link #checkKey} — compares a decrypted prefix against the known opening constant. This is
 *       the one that can actually falsify a key, and it is unavailable until the constant's value is
 *       learned by decoding one session by hand.
 * </ol>
 *
 * <p>Until the constant is known, {@link #recoverOpeningConstant} gives the candidate value a key
 * implies. Run it across the captured sessions: if the derivation is right, every session yields the
 * <em>same</em> constant, and that agreement across independent keys and randoms is strong evidence
 * for the derivation — much stronger than the original check, which was no evidence at all. Once the
 * value is known, hard-code it and {@link #checkKey} becomes a true assertion.
 */
public final class Pragma3SelfTest {

    /** How many bytes of the opening constant to compare. */
    public static final int PREFIX_LENGTH = 4;

    /**
     * @param passed whether the check succeeded
     * @param detail human-readable explanation
     */
    public record Result(boolean passed, String detail) {
    }

    private Pragma3SelfTest() {
    }

    /**
     * Stage one: do both directions really share a key and a stream start?
     *
     * <p>Needs no key, so it can be run over every captured session immediately. A pass means the
     * two Pragma 3 bodies begin with the same plaintext encrypted by the same keystream, which is
     * what the four-stream replay model assumes. A failure means either the directions do not share
     * a key, or they do not both start at pragma 3 offset 0, or FHT messages do not open with a
     * shared constant — all three worth knowing before anything else is built.
     *
     * <p>A caveat inherited from how the observation was made: it was read off the Burp MCP's
     * escaped-text rendering, which is lossy for binary, so it is strong evidence rather than proof
     * until re-confirmed on exported bytes.
     */
    public static Result checkStreamSymmetry(byte[] pragma3RequestBody, byte[] pragma3ResponseBody) {
        if (tooShort(pragma3RequestBody) || tooShort(pragma3ResponseBody)) {
            return new Result(false,
                    "need at least " + PREFIX_LENGTH + " bytes of both Pragma 3 bodies");
        }
        byte[] request = Arrays.copyOf(pragma3RequestBody, PREFIX_LENGTH);
        byte[] response = Arrays.copyOf(pragma3ResponseBody, PREFIX_LENGTH);

        if (Arrays.equals(request, response)) {
            return new Result(true, "both Pragma 3 bodies open with ciphertext "
                    + HexFormat.of().formatHex(request)
                    + ", consistent with one shared key and both streams starting at offset 0");
        }
        return new Result(false, "Pragma 3 request opens with " + HexFormat.of().formatHex(request)
                + " but the response opens with " + HexFormat.of().formatHex(response)
                + " - the two directions do not share a key and stream start, so the replay model's "
                + "assumption is wrong");
    }

    /**
     * Stage two: is this key right?
     *
     * <p>The only check that can falsify a key, and it needs the opening constant, which is still
     * unknown. Pass the value once it is established.
     *
     * @param pragma3Body      either direction's Pragma 3 body; both open with the same constant
     * @param expectedConstant the known opening constant, {@link #PREFIX_LENGTH} bytes
     */
    public static Result checkKey(byte[] key, byte[] pragma3Body, byte[] expectedConstant) {
        if (key == null || key.length != KeyDerivation.KEY_LENGTH) {
            return new Result(false, "key is not " + KeyDerivation.KEY_LENGTH + " bytes");
        }
        if (expectedConstant == null || expectedConstant.length != PREFIX_LENGTH) {
            return new Result(false, "the opening constant is not yet known, so the key cannot be "
                    + "checked - use recoverOpeningConstant() and compare across sessions instead");
        }
        if (tooShort(pragma3Body)) {
            return new Result(false, "Pragma 3 body is shorter than " + PREFIX_LENGTH + " bytes");
        }

        byte[] actual = recoverOpeningConstant(key, pragma3Body);
        if (Arrays.equals(actual, expectedConstant)) {
            return new Result(true, "Pragma 3 decrypts to the expected opening constant "
                    + HexFormat.of().formatHex(expectedConstant));
        }
        return new Result(false, "Pragma 3 decrypts to " + HexFormat.of().formatHex(actual)
                + " but the opening constant is " + HexFormat.of().formatHex(expectedConstant)
                + " - this key is wrong");
    }

    /**
     * The opening constant this key implies for this session.
     *
     * <p>Not a check on its own. Its value is in cross-session comparison: a correct derivation makes
     * every session agree, and agreement across sessions with different randoms is what actually
     * validates the derivation formula.
     */
    public static byte[] recoverOpeningConstant(byte[] key, byte[] pragma3Body) {
        byte[] prefix = Arrays.copyOf(pragma3Body, PREFIX_LENGTH);
        new Rc4Stream(key).apply(prefix);
        return prefix;
    }

    /**
     * Derives a key from the handshake bodies and runs whatever validation is currently possible:
     * the symmetry check always, and the key check when the opening constant is known.
     *
     * <p>The form the retroactive history scan uses, since it holds all four bodies at once.
     *
     * @param expectedConstant the opening constant if known, otherwise {@code null}
     */
    public static Result deriveAndCheck(
            KeyDerivation derivation,
            byte[] pragma1RequestBody,
            byte[] pragma1ResponseBody,
            byte[] pragma3RequestBody,
            byte[] pragma3ResponseBody,
            byte[] expectedConstant) {

        OptionalInt clientRandom = Handshake.clientRandom(pragma1RequestBody);
        if (clientRandom.isEmpty()) {
            return new Result(false, "no GDay magic in the Pragma 1 request");
        }
        OptionalInt serverRandom = Handshake.serverRandom(pragma1ResponseBody);
        if (serverRandom.isEmpty()) {
            return new Result(false, "no Mate magic in the Pragma 1 response");
        }

        Result symmetry = checkStreamSymmetry(pragma3RequestBody, pragma3ResponseBody);
        if (!symmetry.passed()) {
            return symmetry;
        }
        if (expectedConstant == null) {
            byte[] key = derivation.deriveKey(clientRandom.getAsInt(), serverRandom.getAsInt());
            return new Result(true, symmetry.detail() + "; this key implies an opening constant of "
                    + HexFormat.of().formatHex(recoverOpeningConstant(key, pragma3RequestBody))
                    + " (compare across sessions - they should all agree)");
        }
        byte[] key = derivation.deriveKey(clientRandom.getAsInt(), serverRandom.getAsInt());
        return checkKey(key, pragma3RequestBody, expectedConstant);
    }

    private static boolean tooShort(byte[] body) {
        return body == null || body.length < PREFIX_LENGTH;
    }
}
