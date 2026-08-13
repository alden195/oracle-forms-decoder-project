package oracleforms.session;

/**
 * Derives a session's RC4 key from the two cleartext randoms exchanged in the Pragma 1 handshake.
 *
 * <p>An interface with one implementation, on purpose. The derivation in
 * {@link GdayMateKeyDerivation} was reverse-engineered from the {@code oracle/forms/net/HTTPConnection}
 * bytecode of one Forms version; 12c, or a deployment using {@code INITIAL_ENCRYPTKEY} (property
 * 271), may well compute the key differently. Isolating it here means a second scheme can be added
 * without touching the replayer, the store, or the UI (architecture &sect;1, version risk).
 */
public interface KeyDerivation {

    /** Oracle Forms uses a 40-bit RC4 key. */
    int KEY_LENGTH = 5;

    /**
     * @param clientRandom the 4 bytes following the {@code GDay} magic, as a big-endian int
     * @param serverRandom the 4 bytes following the {@code Mate} magic, as a big-endian int
     * @return exactly {@link #KEY_LENGTH} bytes
     */
    byte[] deriveKey(int clientRandom, int serverRandom);

    /** Short identifier recorded with a derived key, so a stored key says which scheme made it. */
    String name();
}
