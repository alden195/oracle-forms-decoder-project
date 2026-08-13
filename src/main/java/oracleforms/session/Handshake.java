package oracleforms.session;

import java.util.OptionalInt;

/**
 * Reads the two randoms out of the Pragma 1 handshake bodies.
 *
 * <p>Kept apart from {@link KeyDerivation} because locating the randoms on the wire and combining
 * them into a key are separately wrong-able, and only the second is version-specific.
 *
 * <p>Both bodies are 8 bytes on the captured target — a 4-byte magic then a 4-byte random — but the
 * magic is searched for rather than assumed to be at offset 0, since these bodies are untrusted
 * input and a longer framing would otherwise silently yield a garbage key.
 */
public final class Handshake {

    /** {@code "GDay"}, opening the Pragma 1 request. */
    public static final int GDAY_MAGIC = 0x47446179;

    /** {@code "Mate"}, opening the Pragma 1 response. */
    public static final int MATE_MAGIC = 0x4D617465;

    /** The pragma number that carries the handshake. */
    public static final int HANDSHAKE_PRAGMA = 1;

    /**
     * How far into a body to look for the magic. The real offset is 0; a small window tolerates an
     * unexpected prefix without turning a hostile 28 KB body into a long scan.
     */
    private static final int MAX_SCAN = 64;

    private Handshake() {
    }

    /** The client random from a Pragma 1 request body, or empty if the {@code GDay} magic is absent. */
    public static OptionalInt clientRandom(byte[] body) {
        return randomAfter(body, GDAY_MAGIC);
    }

    /** The server random from a Pragma 1 response body, or empty if the {@code Mate} magic is absent. */
    public static OptionalInt serverRandom(byte[] body) {
        return randomAfter(body, MATE_MAGIC);
    }

    private static OptionalInt randomAfter(byte[] body, int magic) {
        if (body == null || body.length < 8) {
            return OptionalInt.empty();
        }
        int limit = Math.min(body.length - 8, MAX_SCAN);
        for (int off = 0; off <= limit; off++) {
            if (readInt(body, off) == magic) {
                return OptionalInt.of(readInt(body, off + 4));
            }
        }
        return OptionalInt.empty();
    }

    private static int readInt(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24)
                | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8)
                | (b[off + 3] & 0xFF);
    }
}
