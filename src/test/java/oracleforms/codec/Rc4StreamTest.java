package oracleforms.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class Rc4StreamTest {

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    // The published RC4 vectors. If these fail, nothing downstream is worth debugging.

    @Test
    @DisplayName("matches the published RC4 test vectors")
    void knownAnswerVectors() {
        assertEquals("bbf316e8d940af0ad3",
                hex(new Rc4Stream(ascii("Key")).applied(ascii("Plaintext"))));
        assertEquals("1021bf0420",
                hex(new Rc4Stream(ascii("Wiki")).applied(ascii("pedia"))));
        assertEquals("45a01f645fc35b383552544b9bf5",
                hex(new Rc4Stream(ascii("Secret")).applied(ascii("Attack at dawn"))));
    }

    @Test
    @DisplayName("is symmetric: encrypting twice returns the original")
    void symmetric() {
        byte[] plain = ascii("the quick brown fox");
        byte[] key = {0x01, 0x02, (byte) 0xAE, 0x03, 0x04};

        byte[] cipher = new Rc4Stream(key).applied(plain);
        byte[] back = new Rc4Stream(key).applied(cipher);

        assertArrayEquals(plain, back);
    }

    /**
     * The load-bearing property of the whole design: the stream does not reset between messages, so
     * processing bodies separately must equal processing their concatenation.
     */
    @Test
    @DisplayName("keystream is continuous across separate apply() calls")
    void continuousAcrossMessages() {
        byte[] key = ascii("Key");
        byte[] whole = ascii("first-messagesecond-messagethird");

        byte[] oneShot = new Rc4Stream(key).applied(whole);

        Rc4Stream stream = new Rc4Stream(key);
        byte[] a = stream.applied(ascii("first-message"));
        byte[] b = stream.applied(ascii("second-message"));
        byte[] c = stream.applied(ascii("third"));

        byte[] joined = new byte[oneShot.length];
        System.arraycopy(a, 0, joined, 0, a.length);
        System.arraycopy(b, 0, joined, a.length, b.length);
        System.arraycopy(c, 0, joined, a.length + b.length, c.length);

        assertArrayEquals(oneShot, joined);
    }

    @Test
    @DisplayName("skip(n) advances exactly as applying n bytes would")
    void skipMatchesApply() {
        byte[] key = ascii("Key");

        Rc4Stream skipped = new Rc4Stream(key);
        skipped.skip(13);
        byte[] afterSkip = skipped.applied(ascii("payload"));

        Rc4Stream applied = new Rc4Stream(key);
        applied.applied(new byte[13]);
        byte[] afterApply = applied.applied(ascii("payload"));

        assertArrayEquals(afterApply, afterSkip);
    }

    @Test
    @DisplayName("copy() is independent and resumes at the same position")
    void copyIsIndependent() {
        Rc4Stream original = new Rc4Stream(ascii("Key"));
        original.skip(7);

        Rc4Stream copy = original.copy();

        byte[] fromOriginal = original.applied(ascii("same input"));
        byte[] fromCopy = copy.applied(ascii("same input"));
        assertArrayEquals(fromOriginal, fromCopy, "copy must resume at the same keystream position");

        // Advancing the copy must not disturb the original.
        copy.skip(100);
        assertArrayEquals(
                original.copy().applied(ascii("x")),
                original.copy().applied(ascii("x")));
    }

    @Test
    @DisplayName("rejects an empty key rather than producing a silent identity cipher")
    void rejectsEmptyKey() {
        assertThrows(IllegalArgumentException.class, () -> new Rc4Stream(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new Rc4Stream(null));
    }

    @Test
    @DisplayName("applied() leaves its input untouched")
    void appliedDoesNotMutateInput() {
        byte[] plain = ascii("do not modify me");
        byte[] copy = plain.clone();
        new Rc4Stream(ascii("Key")).applied(plain);
        assertArrayEquals(copy, plain);
    }
}
