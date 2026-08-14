package oracleforms.codec;

/**
 * A property could not be re-encoded, so the edit that needed it must not be applied.
 *
 * <p>Checked rather than unchecked on purpose. Every caller is on a path that ends in bytes going to
 * a server over a shared RC4 stream, and an edit that silently half-applied would corrupt not just
 * this message but every message after it in the session. The compiler should insist the caller says
 * what happens instead.
 */
public final class FhtUnwritableException extends Exception {

    private final int offset;

    public FhtUnwritableException(int offset, String reason) {
        super(reason);
        this.offset = offset;
    }

    /** Byte offset of the property that could not be written, within the decrypted packet. */
    public int offset() {
        return offset;
    }
}
