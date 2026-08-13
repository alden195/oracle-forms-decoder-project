package oracleforms.session;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.OptionalInt;
import java.util.Random;
import oracleforms.codec.FhtParser;
import oracleforms.codec.PropertyIds;
import oracleforms.codec.Rc4Stream;
import oracleforms.codec.StringDictionary;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.ParseOutcome;

/**
 * Falsifies — or fails to falsify — a key derivation scheme against captured traffic.
 *
 * <h2>Why this exists, and why {@link Pragma3SelfTest} was not enough</h2>
 *
 * <p>{@code Pragma3SelfTest} concluded that a key could only be checked once the 4-byte constant that
 * opens every FHT message was known, and that learning it required decoding a session by hand. That
 * made the constant the blocker for validating key derivation at all.
 *
 * <p><strong>The constant was never necessary.</strong> It is a 4-byte oracle, but the parser is a
 * far stronger one: a correct key turns a Pragma 3 request into a well-formed FHT message —
 * structurally valid headers, property ids drawn from a 470-entry table, type markers from a small
 * set, string lengths that land inside the buffer. A wrong key turns it into uniform random bytes,
 * which the bounded reader rejects within a handful of bytes. Asking "does it parse?" tests hundreds
 * of bits of structure instead of 32, and it needs nothing known in advance.
 *
 * <p>The constant then falls out for free: it is simply the first four bytes of a message that parsed.
 *
 * <h2>Controls, so this cannot rubber-stamp</h2>
 *
 * <p>A validator that only ever looks at the real key can talk itself into anything. Every check here
 * is therefore run against a control group of random keys on the same ciphertext. The verdict is
 * comparative — the derived key must out-parse <em>every</em> control — so if the derivation is
 * wrong, the derived key sits in the middle of the control distribution and the check fails. There
 * are no hand-tuned thresholds standing between a wrong answer and a pass.
 *
 * <p>{@link #crossCheck} adds the independent signal {@code Pragma3SelfTest} already described:
 * across sessions with different randoms and therefore different keys, a correct derivation must
 * recover the <em>same</em> opening constant every time.
 */
public final class KeyValidation {

    /** How many random keys to test alongside the derived one. */
    public static final int CONTROL_KEYS = 32;

    /** Fixed so a run is reproducible; the controls are a baseline, not a source of randomness. */
    private static final long CONTROL_SEED = 20260813L;

    /**
     * How many property ids a candidate must produce before its hit rate means anything.
     *
     * <p>One lucky id is not evidence; a dozen consecutive ones is overwhelming.
     */
    public static final int MIN_PROPERTIES = 4;

    /**
     * The share of property ids that must be real.
     *
     * <p>Measured, not guessed: random keys against a real body land in the 470-entry table about a
     * fifth of the time, because the parser is lenient and keeps walking through nonsense. A correct
     * key produces genuine ids, so it sits near 1.0. The gap between the two is what this threshold
     * lives in — and the verdict additionally requires beating the best control outright, so the
     * threshold alone can never carry a pass.
     */
    public static final double MIN_KNOWN_FRACTION = 0.9;

    /** What a parse of one candidate decryption looked like. */
    public record Signals(
            boolean complete, int bytesConsumed, int messages, int properties, int knownProperties) {

        /**
         * The share of property ids that appear in the id table. Random bytes land on known ids only
         * by luck, and the table covers a small part of the 16-bit space.
         */
        public double knownFraction() {
            return properties == 0 ? 0.0 : (double) knownProperties / properties;
        }

        public String describe() {
            return bytesConsumed + " bytes consumed, " + messages + " message(s), "
                    + knownProperties + "/" + properties + " property ids known"
                    + (complete ? ", parsed to the end" : "");
        }
    }

    /**
     * The case for or against one session's key.
     *
     * @param distinguishable whether the derived key out-parsed every control key. This is the
     *                        verdict that matters: false means the derived key behaves like a random
     *                        one, which is what a wrong derivation looks like.
     */
    public record Evidence(
            String sessionId,
            byte[] key,
            byte[] openingConstant,
            Signals derived,
            Signals bestControl,
            boolean distinguishable,
            String detail) {

        public String describe() {
            return sessionId + ": " + (distinguishable ? "PASS" : "FAIL") + " - " + detail;
        }
    }

    /** The result of comparing every session's evidence. */
    public record Verdict(boolean validated, String detail, List<Evidence> evidence) {
    }

    private KeyValidation() {
    }

    /**
     * Derives a key from one session's handshake and tests it against that session's Pragma 3.
     *
     * @param pragma3Body either direction's Pragma 3 body — both start at keystream offset 0
     */
    public static Evidence validate(
            String sessionId,
            KeyDerivation derivation,
            byte[] pragma1RequestBody,
            byte[] pragma1ResponseBody,
            byte[] pragma3Body) {

        OptionalInt clientRandom = Handshake.clientRandom(pragma1RequestBody);
        if (clientRandom.isEmpty()) {
            return failed(sessionId, "no GDay magic in the Pragma 1 request");
        }
        OptionalInt serverRandom = Handshake.serverRandom(pragma1ResponseBody);
        if (serverRandom.isEmpty()) {
            return failed(sessionId, "no Mate magic in the Pragma 1 response");
        }
        if (pragma3Body == null || pragma3Body.length < Pragma3SelfTest.PREFIX_LENGTH) {
            return failed(sessionId, "Pragma 3 body is too short to test");
        }

        byte[] key = derivation.deriveKey(clientRandom.getAsInt(), serverRandom.getAsInt());
        Signals derived = parseWith(key, pragma3Body);

        // The control group: same ciphertext, same parser, keys that are definitely wrong.
        Random random = new Random(CONTROL_SEED);
        Signals best = null;
        for (int n = 0; n < CONTROL_KEYS; n++) {
            byte[] control = new byte[KeyDerivation.KEY_LENGTH];
            random.nextBytes(control);
            Signals signals = parseWith(control, pragma3Body);
            if (best == null || isBetter(signals, best)) {
                best = signals;
            }
        }

        boolean distinguishable = derived.properties() >= MIN_PROPERTIES
                && derived.knownFraction() >= MIN_KNOWN_FRACTION
                && derived.knownProperties() > best.knownProperties();

        String detail = distinguishable
                ? "derived key parses (" + derived.describe() + ") where the best of "
                        + CONTROL_KEYS + " random keys managed only " + best.describe()
                : "derived key (" + derived.describe() + ") is not clearly better than the best of "
                        + CONTROL_KEYS + " random keys (" + best.describe()
                        + "), so this ciphertext gives no evidence the derivation is right";

        return new Evidence(sessionId, key,
                Pragma3SelfTest.recoverOpeningConstant(key, pragma3Body),
                derived, best, distinguishable, detail);
    }

    /**
     * Combines per-session evidence into a verdict on the derivation formula itself.
     *
     * <p>Two independent things must hold. Every session's key must beat its controls, and every
     * session must recover the same opening constant — the latter being the check
     * {@link Pragma3SelfTest} described, which is meaningful precisely because the sessions have
     * different randoms and therefore different keys.
     */
    public static Verdict crossCheck(List<Evidence> evidence) {
        if (evidence == null || evidence.isEmpty()) {
            return new Verdict(false, "no sessions to check", List.of());
        }

        List<Evidence> failures = evidence.stream().filter(e -> !e.distinguishable()).toList();
        if (!failures.isEmpty()) {
            return new Verdict(false, failures.size() + " of " + evidence.size()
                    + " sessions failed to distinguish the derived key from random keys; the first is "
                    + failures.get(0).describe(), evidence);
        }

        byte[] constant = evidence.get(0).openingConstant();
        for (Evidence e : evidence) {
            if (!Arrays.equals(constant, e.openingConstant())) {
                return new Verdict(false, "sessions disagree on the opening constant: "
                        + evidence.get(0).sessionId() + " recovers "
                        + HexFormat.of().formatHex(constant) + " but " + e.sessionId()
                        + " recovers " + HexFormat.of().formatHex(e.openingConstant())
                        + " - the derivation formula is wrong", evidence);
            }
        }

        return new Verdict(true, "all " + evidence.size()
                + " sessions parse under their derived key and agree that the FHT opening constant is "
                + HexFormat.of().formatHex(constant), evidence);
    }

    /**
     * Which of two candidate decryptions looks more like real FHT.
     *
     * <p>Ranks on the <em>count</em> of ids found in the property table. Two other measures were
     * tried and are worse:
     *
     * <ul>
     *   <li><b>Bytes consumed</b> — the parser is deliberately lenient, so random bytes routinely
     *       walk further through a body than a short well-formed message does.
     *   <li><b>Hit rate</b> — a control that stumbles onto a single real id scores a perfect 1.0 and
     *       ties a genuine decryption that found seven out of seven. The fraction is only meaningful
     *       once the denominator is large, which is what {@link #MIN_PROPERTIES} guards for the
     *       derived key; the count is what makes the comparison against controls sound.
     * </ul>
     */
    private static boolean isBetter(Signals candidate, Signals incumbent) {
        if (candidate.knownProperties() != incumbent.knownProperties()) {
            return candidate.knownProperties() > incumbent.knownProperties();
        }
        return candidate.knownFraction() > incumbent.knownFraction();
    }

    /** Decrypts the body with a candidate key and reports how well the result parses. */
    private static Signals parseWith(byte[] key, byte[] body) {
        byte[] plaintext = body.clone();
        new Rc4Stream(key).apply(plaintext);

        FhtPacket packet = new FhtParser().parse(plaintext, new StringDictionary());

        int properties = 0;
        int known = 0;
        for (FhtMessage message : packet.messages()) {
            for (FhtProperty property : message.properties()) {
                if (property.id() == FhtProperty.PSEUDO_ID) {
                    continue;
                }
                properties++;
                if (PropertyIds.isKnown(property.id())) {
                    known++;
                }
            }
        }

        return new Signals(packet.outcome().isComplete(), consumed(packet, plaintext.length),
                packet.messages().size(), properties, known);
    }

    /** How far the parser got before stopping, which is the single best wrong-key discriminator. */
    private static int consumed(FhtPacket packet, int length) {
        return switch (packet.outcome()) {
            case ParseOutcome.Complete ignored -> length;
            case ParseOutcome.Truncated truncated -> truncated.offset();
            case ParseOutcome.Failed failed -> failed.offset();
        };
    }

    private static Evidence failed(String sessionId, String detail) {
        Signals none = new Signals(false, 0, 0, 0, 0);
        return new Evidence(sessionId, new byte[0], new byte[0], none, none, false, detail);
    }
}
