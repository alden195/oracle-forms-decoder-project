package oracleforms.session;

/**
 * The Forms 10g/11g {@code GDay}/{@code Mate} key derivation (architecture &sect;1).
 *
 * <p>Confirmed to be the scheme in use on the captured target: the Pragma 1 request body is exactly
 * {@code "GDay"} plus a 4-byte random, and the response exactly {@code "Mate"} plus another.
 *
 * <p>A note on the shift, because it looks like a bug and is not. The reference derives the key from
 * the randoms read as <em>signed</em> big-endian ints using Java's arithmetic {@code >>}, which
 * sign-extends. That difference is invisible here: for any shift of 24 bits or fewer,
 * {@code (x >> n) & 0xFF} and {@code (x >>> n) & 0xFF} produce the same byte, because the masking
 * discards every bit the sign extension could have changed. So signedness cannot be the cause if a
 * derived key turns out to be wrong — look at the byte order of the randoms instead.
 */
public final class GdayMateKeyDerivation implements KeyDerivation {

    /** Third key byte is a constant, not derived from either random. */
    private static final int CONSTANT_BYTE = 0xAE;

    @Override
    public byte[] deriveKey(int clientRandom, int serverRandom) {
        byte[] key = new byte[KEY_LENGTH];
        key[0] = (byte) ((clientRandom >> 8) & 0xFF);
        key[1] = (byte) ((serverRandom >> 4) & 0xFF);
        key[2] = (byte) CONSTANT_BYTE;
        key[3] = (byte) ((clientRandom >> 16) & 0xFF);
        key[4] = (byte) ((serverRandom >> 12) & 0xFF);
        return key;
    }

    @Override
    public String name() {
        return "gday-mate";
    }
}
