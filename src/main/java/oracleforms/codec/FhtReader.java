package oracleforms.codec;

import java.nio.charset.StandardCharsets;

/**
 * Bounded cursor over a decrypted FHT packet.
 *
 * <p>Message bodies come from the tested application, so every read is checked against the remaining
 * length and throws {@link FhtTruncatedException} rather than over-reading (BApp criterion 3). Length
 * prefixes read off the wire are validated before they are used to size anything: a hostile or
 * corrupt packet can otherwise ask for a 2 GB array.
 */
public final class FhtReader {

    private final byte[] buf;
    private int pos;

    public FhtReader(byte[] buf) {
        this.buf = buf;
    }

    public int position() {
        return pos;
    }

    public int remaining() {
        return buf.length - pos;
    }

    public boolean hasRemaining() {
        return pos < buf.length;
    }

    /** Next byte without consuming it, or {@code -1} at end of buffer. */
    public int peek() {
        return pos < buf.length ? buf[pos] & 0xFF : -1;
    }

    private void require(int n) throws FhtTruncatedException {
        if (n < 0 || n > remaining()) {
            throw new FhtTruncatedException(pos, "need " + n + " bytes, have " + remaining());
        }
    }

    /** Unsigned byte. */
    public int u8() throws FhtTruncatedException {
        require(1);
        return buf[pos++] & 0xFF;
    }

    /** Signed byte. */
    public byte i8() throws FhtTruncatedException {
        require(1);
        return buf[pos++];
    }

    /** Unsigned big-endian 16-bit. */
    public int u16() throws FhtTruncatedException {
        require(2);
        return ((buf[pos++] & 0xFF) << 8) | (buf[pos++] & 0xFF);
    }

    /** Signed big-endian 16-bit. */
    public short i16() throws FhtTruncatedException {
        return (short) u16();
    }

    /** Signed big-endian 32-bit. */
    public int i32() throws FhtTruncatedException {
        require(4);
        return ((buf[pos++] & 0xFF) << 24)
                | ((buf[pos++] & 0xFF) << 16)
                | ((buf[pos++] & 0xFF) << 8)
                | (buf[pos++] & 0xFF);
    }

    public byte[] bytes(int n) throws FhtTruncatedException {
        require(n);
        byte[] out = new byte[n];
        System.arraycopy(buf, pos, out, 0, n);
        pos += n;
        return out;
    }

    public void skip(int n) throws FhtTruncatedException {
        require(n);
        pos += n;
    }

    /**
     * Java {@code DataInput.readUTF}-style string: unsigned 16-bit length then that many bytes.
     * Decoded leniently — malformed sequences become replacement characters rather than throwing,
     * since a mis-parse should degrade the text, not abort the packet.
     */
    public String utf() throws FhtTruncatedException {
        int len = u16();
        require(len);
        String out = new String(buf, pos, len, StandardCharsets.UTF_8);
        pos += len;
        return out;
    }

    /**
     * Oracle's variable-width unsigned integer: two bytes, or four when the top bit of the first is
     * set. Used for handler ids.
     */
    public int optionalUint() throws FhtTruncatedException {
        int a = u8();
        int b = u8();
        if ((a & 0x80) != 0) {
            int c = u8();
            int d = u8();
            return ((a & 0x7F) << 24) | (b << 16) | (c << 8) | d;
        }
        return (a << 8) | b;
    }
}
