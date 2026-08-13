package oracleforms.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FhtReaderTest {

    @Test
    void readsWidthsAndSignsCorrectly() throws Exception {
        FhtReader r = new FhtReader(new byte[] {
                (byte) 0xFF,                                     // u8 / i8
                (byte) 0x80, 0x01,                               // u16 / i16
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE // i32
        });

        assertEquals(255, r.u8());
        assertEquals(0x8001, r.u16());

        FhtReader signed = new FhtReader(new byte[] {(byte) 0xFF, (byte) 0x80, 0x01});
        assertEquals((byte) -1, signed.i8());
        assertEquals((short) -32767, signed.i16());

        assertEquals(-2, r.i32());
    }

    @Test
    @DisplayName("utf() reads a length-prefixed string")
    void readsUtf() throws Exception {
        byte[] text = "héllo".getBytes(StandardCharsets.UTF_8);
        byte[] buf = new byte[2 + text.length];
        buf[0] = 0;
        buf[1] = (byte) text.length;
        System.arraycopy(text, 0, buf, 2, text.length);

        assertEquals("héllo", new FhtReader(buf).utf());
    }

    @Test
    @DisplayName("optionalUint() widens to four bytes when the top bit is set")
    void optionalUintWidths() throws Exception {
        assertEquals(0x1234, new FhtReader(new byte[] {0x12, 0x34}).optionalUint());
        assertEquals(0x01020304,
                new FhtReader(new byte[] {(byte) 0x81, 0x02, 0x03, 0x04}).optionalUint());
    }

    // Bodies are untrusted (BApp criterion 3): every over-read must be refused, with the offset.

    @Test
    @DisplayName("throws rather than over-reading, and reports where")
    void refusesToOverRead() {
        FhtReader r = new FhtReader(new byte[] {0x01, 0x02});
        FhtTruncatedException e = assertThrows(FhtTruncatedException.class, r::i32);
        assertEquals(0, e.offset());

        assertThrows(FhtTruncatedException.class, () -> new FhtReader(new byte[0]).u8());
        assertThrows(FhtTruncatedException.class, () -> new FhtReader(new byte[] {0x01}).u16());
    }

    @Test
    @DisplayName("a hostile length prefix cannot size an allocation")
    void hostileLengthPrefixIsRefused() {
        // 0x7FFFFFFF-byte string in a 6-byte buffer.
        FhtReader r = new FhtReader(new byte[] {(byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x00});
        assertThrows(FhtTruncatedException.class, r::utf);

        FhtReader neg = new FhtReader(new byte[] {0x01, 0x02, 0x03});
        assertThrows(FhtTruncatedException.class, () -> neg.skip(-1));
        assertThrows(FhtTruncatedException.class, () -> neg.bytes(Integer.MAX_VALUE));
    }

    @Test
    void tracksPositionAndRemaining() throws Exception {
        FhtReader r = new FhtReader(new byte[] {1, 2, 3, 4});
        assertEquals(0, r.position());
        assertEquals(4, r.remaining());

        assertArrayEquals(new byte[] {1, 2}, r.bytes(2));
        assertEquals(2, r.position());
        assertEquals(2, r.remaining());

        r.skip(2);
        assertEquals(0, r.remaining());
        assertEquals(-1, r.peek(), "peek past the end must report -1, not throw");
    }
}
