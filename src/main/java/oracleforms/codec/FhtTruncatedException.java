package oracleforms.codec;

/**
 * Thrown when a read runs past the end of the buffer, carrying the offset it happened at so the
 * parser can report <em>where</em> a message stopped making sense rather than failing blankly.
 */
public final class FhtTruncatedException extends Exception {

    private final int offset;

    public FhtTruncatedException(int offset, String message) {
        super(message + " at offset " + offset);
        this.offset = offset;
    }

    public int offset() {
        return offset;
    }
}
