package oracleforms.codec;

/**
 * RC4 keystream state.
 *
 * <p>Oracle Forms does not reset the cipher per message: one stream runs for the whole session in
 * each direction. So this class exists to be <em>held</em> and advanced across many messages, and to
 * be {@link #copy() copied} into a checkpoint. That is the whole reason decoding needs replay rather
 * than a per-message decrypt.
 *
 * <p>RC4 is symmetric, so {@link #apply} both encrypts and decrypts. Not thread safe; each replay
 * gets its own instance.
 */
public final class Rc4Stream {

    private final int[] s = new int[256];
    private int i;
    private int j;

    public Rc4Stream(byte[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("RC4 key must be non-empty");
        }
        for (int n = 0; n < 256; n++) {
            s[n] = n;
        }
        int k = 0;
        for (int n = 0; n < 256; n++) {
            k = (k + s[n] + (key[n % key.length] & 0xFF)) & 0xFF;
            int t = s[n];
            s[n] = s[k];
            s[k] = t;
        }
    }

    private Rc4Stream(Rc4Stream other) {
        System.arraycopy(other.s, 0, this.s, 0, 256);
        this.i = other.i;
        this.j = other.j;
    }

    /** An independent copy at the same stream position. */
    public Rc4Stream copy() {
        return new Rc4Stream(this);
    }

    /**
     * Applies the keystream to {@code data} in place, advancing the stream by {@code data.length}.
     */
    public void apply(byte[] data) {
        for (int n = 0; n < data.length; n++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
            data[n] = (byte) (data[n] ^ s[(s[i] + s[j]) & 0xFF]);
        }
    }

    /** As {@link #apply} but returns a new array, leaving the input untouched. */
    public byte[] applied(byte[] data) {
        byte[] out = data.clone();
        apply(out);
        return out;
    }

    /**
     * Advances the stream by {@code count} bytes without producing output. Used when a message's
     * plaintext is not wanted but its effect on the stream position must still be accounted for.
     */
    public void skip(int count) {
        for (int n = 0; n < count; n++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
        }
    }
}
