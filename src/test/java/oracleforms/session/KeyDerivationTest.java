package oracleforms.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.OptionalInt;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class KeyDerivationTest {

    private final GdayMateKeyDerivation derivation = new GdayMateKeyDerivation();

    private static byte[] handshake(String magic, int random) {
        byte[] out = new byte[8];
        System.arraycopy(magic.getBytes(StandardCharsets.US_ASCII), 0, out, 0, 4);
        out[4] = (byte) (random >> 24);
        out[5] = (byte) (random >> 16);
        out[6] = (byte) (random >> 8);
        out[7] = (byte) random;
        return out;
    }

    @Test
    @DisplayName("derives the five key bytes per the documented formula")
    void derivesDocumentedKey() {
        int client = 0x11223344;
        int server = 0xAABBCCDD;

        byte[] key = derivation.deriveKey(client, server);

        assertEquals(KeyDerivation.KEY_LENGTH, key.length);
        assertEquals(0x33, key[0] & 0xFF, "client >> 8");
        assertEquals(0xCD, key[1] & 0xFF, "server >> 4");
        assertEquals(0xAE, key[2] & 0xFF, "the constant byte");
        assertEquals(0x22, key[3] & 0xFF, "client >> 16");
        assertEquals(0xBC, key[4] & 0xFF, "server >> 12");
    }

    /**
     * The reference uses Java's arithmetic {@code >>} on randoms read as signed ints. This confirms
     * the sign extension is invisible after masking, so signedness can be ruled out as a suspect if
     * a derived key ever turns out to be wrong.
     */
    @Test
    @DisplayName("signed and unsigned shifts agree, so signedness cannot be the bug")
    void signednessDoesNotMatter() {
        Random random = new Random(20260813L);
        for (int i = 0; i < 10_000; i++) {
            int client = random.nextInt();
            int server = random.nextInt();

            byte[] arithmetic = derivation.deriveKey(client, server);
            byte[] logical = {
                    (byte) ((client >>> 8) & 0xFF),
                    (byte) ((server >>> 4) & 0xFF),
                    (byte) 0xAE,
                    (byte) ((client >>> 16) & 0xFF),
                    (byte) ((server >>> 12) & 0xFF)};

            assertEquals(HexFormat.of().formatHex(logical), HexFormat.of().formatHex(arithmetic));
        }
    }

    @Test
    @DisplayName("reads the randoms out of 8-byte handshake bodies")
    void readsHandshakeRandoms() {
        assertEquals(OptionalInt.of(0x07E5A020),
                Handshake.clientRandom(handshake("GDay", 0x07E5A020)));
        assertEquals(OptionalInt.of(0x2FBCD219),
                Handshake.serverRandom(handshake("Mate", 0x2FBCD219)));
    }

    @Test
    @DisplayName("a body without the magic yields no random rather than a garbage key")
    void rejectsBodiesWithoutMagic() {
        assertTrue(Handshake.clientRandom(handshake("Mate", 1)).isEmpty());
        assertTrue(Handshake.serverRandom(handshake("GDay", 1)).isEmpty());
        assertTrue(Handshake.clientRandom(new byte[] {1, 2, 3}).isEmpty());
        assertTrue(Handshake.clientRandom(null).isEmpty());
        assertTrue(Handshake.clientRandom(new byte[64]).isEmpty());
    }

    /**
     * The applet client sends <em>two</em> Pragma 1 messages per session: the {@code ifcmd=getinfo}
     * GET, which has an empty body and arrives first, and then the {@code GDay} POST that actually
     * carries the key material. Anything gathering "the Pragma 1 request" must therefore select on
     * the magic rather than on arrival order — taking the first one latches onto the empty body and
     * the session looks like it never handshook at all.
     */
    @Test
    @DisplayName("the empty getinfo body is not mistaken for the handshake that follows it")
    void picksTheHandshakeNotTheFirstPragmaOne() {
        byte[] getInfoBody = new byte[0];
        byte[] gdayBody = handshake("GDay", 0x0AE52011);

        assertTrue(Handshake.clientRandom(getInfoBody).isEmpty(),
                "the getinfo GET carries no handshake");
        assertEquals(OptionalInt.of(0x0AE52011), Handshake.clientRandom(gdayBody));

        // Selecting on the magic picks the right one whichever order they arrive in.
        byte[] chosen = null;
        for (byte[] body : new byte[][] {getInfoBody, gdayBody}) {
            if (chosen == null && Handshake.clientRandom(body).isPresent()) {
                chosen = body;
            }
        }
        assertEquals(OptionalInt.of(0x0AE52011), Handshake.clientRandom(chosen));
    }

    @Test
    @DisplayName("finds the magic at a non-zero offset")
    void toleratesAPrefix() {
        byte[] prefixed = new byte[10];
        System.arraycopy(handshake("GDay", 0x01020304), 0, prefixed, 2, 8);
        assertEquals(OptionalInt.of(0x01020304), Handshake.clientRandom(prefixed));
    }

    @Test
    @DisplayName("distinct handshakes give distinct keys")
    void distinctSessionsGiveDistinctKeys() {
        byte[] a = derivation.deriveKey(0x07E5A020, 0x2FBCD219);
        byte[] b = derivation.deriveKey(0x5A181F00, 0x2C63B974);
        assertTrue(!java.util.Arrays.equals(a, b));
    }
}
