package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import oracleforms.codec.Rc4Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Works against a synthetic session reproducing the observed property: both directions open with the
 * same 4-byte constant, and each direction's stream starts at pragma 3, offset 0.
 */
class Pragma3SelfTestTest {

    private static final byte[] KEY = {0x33, (byte) 0xCD, (byte) 0xAE, 0x22, (byte) 0xBC};
    private static final byte[] WRONG_KEY = {1, 2, 3, 4, 5};

    /** The unknown 4-byte constant every FHT message is believed to open with. */
    private static final byte[] OPENING_CONSTANT = {0x00, 0x11, 0x22, 0x33};

    private static byte[] encryptedPragma3(byte[] key, int totalLength, int fillerSeed) {
        byte[] body = new byte[totalLength];
        System.arraycopy(OPENING_CONSTANT, 0, body, 0, OPENING_CONSTANT.length);
        for (int i = OPENING_CONSTANT.length; i < totalLength; i++) {
            body[i] = (byte) (i + fillerSeed); // direction-specific content after the shared opening
        }
        return new Rc4Stream(key).applied(body);
    }

    // Stage one: the key-free structural check.

    @Test
    @DisplayName("symmetry check passes when both directions share a key and stream start")
    void symmetryPasses() {
        byte[] request = encryptedPragma3(KEY, 8, 0);
        byte[] response = encryptedPragma3(KEY, 28_296, 7);

        assertTrue(Pragma3SelfTest.checkStreamSymmetry(request, response).passed());
    }

    @Test
    @DisplayName("symmetry check catches a stream that did not start at pragma 3")
    void symmetryCatchesWrongStreamStart() {
        byte[] request = encryptedPragma3(KEY, 8, 0);

        Rc4Stream advanced = new Rc4Stream(KEY);
        advanced.skip(16);
        byte[] body = new byte[400];
        System.arraycopy(OPENING_CONSTANT, 0, body, 0, 4);
        byte[] response = advanced.applied(body);

        Pragma3SelfTest.Result result = Pragma3SelfTest.checkStreamSymmetry(request, response);
        assertFalse(result.passed());
        assertTrue(result.detail().contains("do not share"));
    }

    @Test
    @DisplayName("symmetry check catches directions keyed differently")
    void symmetryCatchesDifferentKeys() {
        byte[] request = encryptedPragma3(KEY, 8, 0);
        byte[] response = encryptedPragma3(WRONG_KEY, 400, 0);

        assertFalse(Pragma3SelfTest.checkStreamSymmetry(request, response).passed());
    }

    /**
     * Pins down why the original §1 formulation was dropped. Decrypting both prefixes and comparing
     * them to each other passes for <em>any</em> key, so it cannot detect a wrong one.
     */
    @Test
    @DisplayName("the old decrypt-and-compare check would pass even for a wrong key")
    void demonstratesWhyTheOriginalCheckWasVacuous() {
        byte[] request = encryptedPragma3(KEY, 8, 0);
        byte[] response = encryptedPragma3(KEY, 400, 7);

        byte[] fromRequest = Pragma3SelfTest.recoverOpeningConstant(WRONG_KEY, request);
        byte[] fromResponse = Pragma3SelfTest.recoverOpeningConstant(WRONG_KEY, response);

        assertArrayEquals(fromRequest, fromResponse,
                "identical ciphertext under one keystream always decrypts identically, so comparing "
                        + "the two directions to each other says nothing about the key");
        assertFalse(java.util.Arrays.equals(OPENING_CONSTANT, fromRequest),
                "...even though the key is in fact wrong");
    }

    // Stage two: the check that can actually falsify a key.

    @Test
    @DisplayName("key check passes for the right key against the known constant")
    void keyCheckPasses() {
        byte[] request = encryptedPragma3(KEY, 8, 0);
        assertTrue(Pragma3SelfTest.checkKey(KEY, request, OPENING_CONSTANT).passed());
    }

    @Test
    @DisplayName("key check fails for a wrong key")
    void keyCheckFailsForWrongKey() {
        byte[] request = encryptedPragma3(KEY, 8, 0);

        Pragma3SelfTest.Result result =
                Pragma3SelfTest.checkKey(WRONG_KEY, request, OPENING_CONSTANT);

        assertFalse(result.passed());
        assertTrue(result.detail().contains("wrong"));
    }

    @Test
    @DisplayName("key check says so when the constant is not yet known")
    void keyCheckNeedsTheConstant() {
        byte[] request = encryptedPragma3(KEY, 8, 0);

        Pragma3SelfTest.Result result = Pragma3SelfTest.checkKey(KEY, request, null);

        assertFalse(result.passed());
        assertTrue(result.detail().contains("not yet known"));
    }

    /**
     * The cross-session agreement that stands in for a known constant. Different sessions have
     * different randoms and therefore different keys, but a correct derivation must make them all
     * recover the same opening constant.
     */
    @Test
    @DisplayName("independent sessions recover the same opening constant under a correct derivation")
    void independentSessionsAgreeOnTheConstant() {
        GdayMateKeyDerivation derivation = new GdayMateKeyDerivation();
        int[][] randoms = {
                {0x07E5A020, 0x2FBCD219},
                {0x5A181F00, 0x2C63B974},
                {0x1234ABCD, 0x7FEEDD11}};

        String first = null;
        for (int[] pair : randoms) {
            byte[] key = derivation.deriveKey(pair[0], pair[1]);
            byte[] body = encryptedPragma3(key, 64, 0);

            String recovered = HexFormat.of()
                    .formatHex(Pragma3SelfTest.recoverOpeningConstant(key, body));
            if (first == null) {
                first = recovered;
            }
            assertTrue(first.equals(recovered), "sessions disagree on the opening constant");
        }
        assertTrue("00112233".equals(first));
    }

    @Test
    @DisplayName("derives from the handshake and reports the implied constant")
    void deriveAndCheckWithoutKnownConstant() {
        int clientRandom = 0x11223344;
        int serverRandom = 0xAABBCCDD;
        GdayMateKeyDerivation derivation = new GdayMateKeyDerivation();
        byte[] key = derivation.deriveKey(clientRandom, serverRandom);

        Pragma3SelfTest.Result result = Pragma3SelfTest.deriveAndCheck(
                derivation,
                handshake("GDay", clientRandom),
                handshake("Mate", serverRandom),
                encryptedPragma3(key, 8, 0),
                encryptedPragma3(key, 500, 7),
                null);

        assertTrue(result.passed(), result.detail());
        assertTrue(result.detail().contains("00112233"));
    }

    @Test
    @DisplayName("derive-and-check falsifies a bad key once the constant is known")
    void deriveAndCheckWithKnownConstant() {
        GdayMateKeyDerivation derivation = new GdayMateKeyDerivation();
        byte[] realKey = derivation.deriveKey(0x11223344, 0xAABBCCDD);

        // Handshake randoms that do not correspond to the key the traffic was encrypted with.
        Pragma3SelfTest.Result result = Pragma3SelfTest.deriveAndCheck(
                derivation,
                handshake("GDay", 0x00000000),
                handshake("Mate", 0x00000000),
                encryptedPragma3(realKey, 8, 0),
                encryptedPragma3(realKey, 500, 7),
                OPENING_CONSTANT);

        assertFalse(result.passed());
    }

    @Test
    @DisplayName("degrades gracefully on unusable input")
    void handlesUnusableInput() {
        assertFalse(Pragma3SelfTest.checkStreamSymmetry(new byte[2], new byte[8]).passed());
        assertFalse(Pragma3SelfTest.checkStreamSymmetry(new byte[8], null).passed());
        assertFalse(Pragma3SelfTest.checkKey(new byte[3], new byte[8], OPENING_CONSTANT).passed());

        Pragma3SelfTest.Result noMagic = Pragma3SelfTest.deriveAndCheck(
                new GdayMateKeyDerivation(),
                new byte[8], new byte[8], new byte[8], new byte[8], null);
        assertFalse(noMagic.passed());
        assertTrue(noMagic.detail().contains("GDay"));
    }

    private static byte[] handshake(String magic, int random) {
        byte[] out = new byte[8];
        System.arraycopy(magic.getBytes(StandardCharsets.US_ASCII), 0, out, 0, 4);
        out[4] = (byte) (random >> 24);
        out[5] = (byte) (random >> 16);
        out[6] = (byte) (random >> 8);
        out[7] = (byte) random;
        return out;
    }
}
