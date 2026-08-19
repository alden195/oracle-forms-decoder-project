package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests that the key validator can actually be wrong.
 *
 * <p>A validator is only worth having if it fails when it should, so the load-bearing test here is
 * {@link #doesNotRubberStampAWrongDerivation}: ciphertext produced under a key the derivation would
 * <em>not</em> produce must come back as a failure. Without that, "the derivation is validated" would
 * mean nothing at all — which is exactly the trap the original Pragma 3 self-test fell into.
 */
class KeyValidationTest {

    /** Builds FHT bytes the way the wire format lays them out. */
    private static final class PacketBuilder {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        PacketBuilder u8(int v) {
            out.write(v & 0xFF);
            return this;
        }

        PacketBuilder u16(int v) {
            return u8(v >> 8).u8(v);
        }

        PacketBuilder i32(int v) {
            return u8(v >> 24).u8(v >> 16).u8(v >> 8).u8(v);
        }

        PacketBuilder message(int actionMarker, int classId, int handlerId) {
            u8((actionMarker | classId) >> 8);
            return u16(handlerId);
        }

        PacketBuilder intProperty(int id, int value) {
            return u16(id).i32(value);
        }

        PacketBuilder stringProperty(int id, int slot, String text) {
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            u16(0x4000 | id).u8(slot).u16(bytes.length);
            out.writeBytes(bytes);
            return this;
        }

        PacketBuilder endProperties() {
            return u8(0xF0);
        }

        PacketBuilder endPacket() {
            return u8(0xF0);
        }

        byte[] build() {
            return out.toByteArray();
        }
    }

    /** A plausible opening message, using property ids that really are in the table. */
    private static byte[] realisticPlaintext() {
        // Action marker 0x1000 (UPDATE) keeps the message header one byte wide; 0x0000 and 0x4000
        // select the two-byte form and would shift every property that follows.
        return new PacketBuilder()
                .message(0x1000, 0, 42)
                .intProperty(16, 1)                      // TAG
                .intProperty(109, 640)                   // COLWIDTH
                .stringProperty(103, 0, "MAIN_WINDOW")   // NAME
                .stringProperty(101, 1, "APP")           // APPLICATION
                .endProperties()
                .message(0x1000, 0, 43)
                .intProperty(105, 2)                     // CANCEL
                .stringProperty(102, 2, "LOGIN_BLOCK")   // FORM_MODULE
                .stringProperty(104, 3, "PARENT_WIN")    // PARENT
                .endProperties()
                .endPacket()
                .build();
    }

    private static byte[] handshakeBody(int magic, int random) {
        return new PacketBuilder().i32(magic).i32(random).build();
    }

    private static final KeyDerivation DERIVATION = new GdayMateKeyDerivation();

    /** One session's four bodies, with the Pragma 3 ciphertext produced under {@code encryptWith}. */
    private static ValidationFixtures.Fixture session(
            String id, int clientRandom, int serverRandom, byte[] encryptWith) {

        byte[] plaintext = realisticPlaintext();
        byte[] ciphertext = plaintext.clone();
        new Rc4Stream(encryptWith).apply(ciphertext);

        return new ValidationFixtures.Fixture(
                id,
                "host",
                handshakeBody(Handshake.GDAY_MAGIC, clientRandom),
                handshakeBody(Handshake.MATE_MAGIC, serverRandom),
                ciphertext,
                ciphertext);
    }

    /** A session encrypted with exactly the key the derivation produces — a correct formula. */
    private static ValidationFixtures.Fixture correctSession(
            String id, int clientRandom, int serverRandom) {
        return session(id, clientRandom, serverRandom,
                DERIVATION.deriveKey(clientRandom, serverRandom));
    }

    private static KeyValidation.Evidence validate(ValidationFixtures.Fixture fixture) {
        return KeyValidation.validate(fixture.sessionId(), DERIVATION,
                fixture.pragma1Request(), fixture.pragma1Response(), fixture.pragma3Request());
    }

    @Test
    @DisplayName("a correct key parses where random keys cannot")
    void distinguishesACorrectKey() {
        KeyValidation.Evidence evidence = validate(correctSession("s1", 0x0AE5_2011, 0x2FBC_D219));

        assertTrue(evidence.distinguishable(), evidence.describe());
        assertTrue(evidence.derived().messages() >= 1, evidence.describe());
        assertEquals(1.0, evidence.derived().knownFraction(), 1e-9,
                "every property id in the fixture is a real one");
        assertTrue(evidence.derived().bytesConsumed() > evidence.bestControl().bytesConsumed(),
                evidence.describe());
    }

    /**
     * The test that gives the rest their meaning. Here the traffic was encrypted with a key the
     * derivation formula does not produce — which is precisely what a wrong formula looks like from
     * the outside — and the validator must say so.
     */
    @Test
    @DisplayName("a derivation that produces the wrong key is reported as unvalidated")
    void doesNotRubberStampAWrongDerivation() {
        byte[] wrongKey = {0x01, 0x02, 0x03, 0x04, 0x05};
        KeyValidation.Evidence evidence =
                validate(session("s-wrong", 0x0AE5_2011, 0x2FBC_D219, wrongKey));

        assertFalse(evidence.distinguishable(),
                "ciphertext under an unrelated key must not validate the derivation: "
                        + evidence.describe());

        KeyValidation.Verdict verdict = KeyValidation.crossCheck(List.of(evidence));
        assertFalse(verdict.validated(), verdict.detail());
    }

    @Test
    @DisplayName("sessions that agree on the opening constant validate the formula")
    void crossCheckPassesWhenSessionsAgree() {
        List<KeyValidation.Evidence> evidence = new ArrayList<>();
        evidence.add(validate(correctSession("s1", 0x0AE5_2011, 0x2FBC_D219)));
        evidence.add(validate(correctSession("s2", 0x5A18_1F03, 0x2C63_B974)));
        evidence.add(validate(correctSession("s3", 0x7213_8899, 0x1144_AB01)));

        KeyValidation.Verdict verdict = KeyValidation.crossCheck(evidence);

        assertTrue(verdict.validated(), verdict.detail());
        // Different randoms, different keys, same recovered constant -- that is the real evidence.
        assertTrue(verdict.detail().contains("opening constant"), verdict.detail());
    }

    /**
     * The cross-session check must be able to fail too. One session whose ciphertext came from a
     * different key recovers a different constant, and that must sink the verdict.
     */
    @Test
    @DisplayName("sessions that disagree on the opening constant sink the verdict")
    void crossCheckFailsWhenSessionsDisagree() {
        List<KeyValidation.Evidence> evidence = new ArrayList<>();
        evidence.add(validate(correctSession("s1", 0x0AE5_2011, 0x2FBC_D219)));
        evidence.add(validate(session("s2", 0x5A18_1F03, 0x2C63_B974,
                new byte[] {0x09, 0x08, 0x07, 0x06, 0x05})));

        KeyValidation.Verdict verdict = KeyValidation.crossCheck(evidence);

        assertFalse(verdict.validated(), verdict.detail());
    }

    @Test
    @DisplayName("a handshake without the magic is reported, not guessed at")
    void rejectsAMissingHandshake() {
        KeyValidation.Evidence evidence = KeyValidation.validate("s", DERIVATION,
                "not a handshake".getBytes(StandardCharsets.UTF_8),
                handshakeBody(Handshake.MATE_MAGIC, 1),
                new byte[64]);

        assertFalse(evidence.distinguishable());
        assertTrue(evidence.detail().contains("GDay"), evidence.detail());
    }

    @Test
    @DisplayName("fixtures survive a round trip through the file format")
    void fixturesRoundTrip() {
        List<ValidationFixtures.Fixture> original =
                List.of(correctSession("s1", 0x0AE5_2011, 0x2FBC_D219),
                        correctSession("s2", 0x5A18_1F03, 0x2C63_B974));

        List<String> problems = new ArrayList<>();
        List<ValidationFixtures.Fixture> parsed =
                ValidationFixtures.importFrom(ValidationFixtures.export(original), problems);

        assertTrue(problems.isEmpty(), problems.toString());
        assertEquals(original.size(), parsed.size());

        for (int i = 0; i < original.size(); i++) {
            assertEquals(original.get(i).sessionId(), parsed.get(i).sessionId());
            org.junit.jupiter.api.Assertions.assertArrayEquals(
                    original.get(i).pragma1Request(), parsed.get(i).pragma1Request());
            org.junit.jupiter.api.Assertions.assertArrayEquals(
                    original.get(i).pragma3Request(), parsed.get(i).pragma3Request());
        }

        // And the round trip preserves enough to still reach a verdict.
        assertTrue(KeyValidation.crossCheck(parsed.stream()
                .map(KeyValidationTest::validate).toList()).validated());
    }

    // ---- reading a decode as FHT -------------------------------------------------------------

    /**
     * The real message that exposed the bar, reconstructed byte for byte from a live edit
     * (2026-08-19): a text item's value, its selection and its caret, then the focus move.
     *
     * <p>Its text property is id 99, which the ported table has no name for — so a perfectly
     * decoded message from the target scores four names out of five.
     */
    private static byte[] liveTextItemUpdate() {
        return new oracleforms.codec.TestPackets()
                .message(0x1000, 0, 113)
                .stringProperty(99, 0, "elevenchars")
                .point8Property(195, 11, 11)
                .uint8Property(193, 11)
                .endProperties()
                .message(0x1000, 0, 113)
                .boolProperty(174, false)
                .endProperties()
                .message(0x1000, 0, 96)
                .boolProperty(174, true)
                .endProperties()
                .endPacket()
                .build();
    }

    @Test
    @DisplayName("a real message with an id the table has no name for still reads as FHT")
    void anIncompleteIdTableDoesNotCondemnACorrectDecode() {
        KeyValidation.Signals signals = KeyValidation.signalsOf(liveTextItemUpdate());

        assertEquals(5, signals.properties());
        assertEquals(4, signals.knownProperties());
        assertTrue(signals.complete());
        assertTrue(signals.knownFraction() < KeyValidation.MIN_KNOWN_FRACTION,
                "0.8: the bar this message used to be refused by");
        assertTrue(KeyValidation.readsAsFht(signals),
                "it parses from the first byte to a terminator; the table's gaps are not its fault");
    }

    @Test
    @DisplayName("noise does not read as FHT, whichever signal it leans on")
    void noiseIsStillRejected() {
        byte[] plaintext = liveTextItemUpdate();
        // The wrong-offset failure this check exists to catch: the right bytes, the wrong keystream.
        byte[] noise = plaintext.clone();
        new Rc4Stream(new byte[] {1, 2, 3, 4, 5}).apply(noise);

        assertFalse(KeyValidation.readsAsFht(KeyValidation.signalsOf(noise)));
    }

    @Test
    @DisplayName("a complete parse alone is not enough")
    void aCleanParseWithUnknownIdsIsNotEnough() {
        byte[] unrecognisable = new oracleforms.codec.TestPackets()
                .message(0x1000, 0, 113)
                .int32Property(0x7A1, 1)
                .int32Property(0x7A2, 2)
                .int32Property(0x7A3, 3)
                .int32Property(0x7A4, 4)
                .endProperties()
                .endPacket()
                .build();

        KeyValidation.Signals signals = KeyValidation.signalsOf(unrecognisable);
        assertTrue(signals.complete());
        assertEquals(0, signals.knownProperties());
        assertFalse(KeyValidation.readsAsFht(signals));
    }
}
