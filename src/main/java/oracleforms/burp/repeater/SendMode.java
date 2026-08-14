package oracleforms.burp.repeater;

import java.util.Locale;
import java.util.Optional;

/**
 * How a drafted message should be encrypted when it leaves Burp (architecture &sect;6.4).
 *
 * <p>The mode is always chosen explicitly, never defaulted silently, because the three differ in what
 * they do to a live application session and that difference is far too large to guess at.
 */
public enum SendMode {

    /**
     * Mode A: append to the live session, at whatever offset the server's cipher has reached.
     *
     * <p>The only mode that reliably produces a message the server will act on — and for the same
     * reason, the only one that changes the state of somebody's running application.
     */
    TAIL("tail"),

    /**
     * Mode C: encrypt at the offset the original message occupied, changing nothing.
     *
     * <p>For comparing ciphertext and for checking the re-encoder against a capture. Valid to send
     * only in the degenerate case where the target pragma is already the session's last.
     */
    OFFSET("offset");

    private final String wireName;

    SendMode(String wireName) {
        this.wireName = wireName;
    }

    /** The value carried in the {@code X-OracleForms-Send} header. */
    public String wireName() {
        return wireName;
    }

    public static Optional<SendMode> fromWireName(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String cleaned = value.trim().toLowerCase(Locale.ROOT);
        for (SendMode mode : values()) {
            if (mode.wireName.equals(cleaned)) {
                return Optional.of(mode);
            }
        }
        return Optional.empty();
    }

    /** Whether sending in this mode acts on a live application session. */
    public boolean touchesLiveSession() {
        return this == TAIL;
    }
}
