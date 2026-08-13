package oracleforms.session;

import java.util.HexFormat;

/**
 * A session's RC4 key plus the provenance metadata the Sessions tab displays.
 *
 * <p>These are session secrets, and the Burp project file is not encrypted. That is an acceptable
 * tradeoff for a pentest tool — the traffic they unlock already contains plaintext credentials — but
 * it is a documented choice, and the store offers "forget" and "clear all" because of it
 * (architecture &sect;3).
 *
 * @param sessionId the {@code JSESSIONID} value; unique across backends, so it needs no host qualifier
 * @param key       exactly {@link KeyDerivation#KEY_LENGTH} bytes
 * @param host      the host the session was seen on, for display
 * @param firstSeen epoch millis
 * @param lastSeen  epoch millis
 * @param label     user-editable note, may be empty
 * @param source    how the key was obtained
 */
public record SessionKey(
        String sessionId,
        byte[] key,
        String host,
        long firstSeen,
        long lastSeen,
        String label,
        KeySource source) {

    public SessionKey {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }
        if (key == null || key.length != KeyDerivation.KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "key must be exactly " + KeyDerivation.KEY_LENGTH + " bytes");
        }
        key = key.clone();
        host = host == null ? "" : host;
        label = label == null ? "" : label;
        source = source == null ? KeySource.DERIVED : source;
    }

    @Override
    public byte[] key() {
        return key.clone();
    }

    /** Lowercase hex, the form shown in the UI and used by manual entry and export. */
    public String keyHex() {
        return HexFormat.of().formatHex(key);
    }

    /**
     * Parses the hex form used by manual entry, tolerating spaces, colons and a {@code 0x} prefix.
     *
     * @throws IllegalArgumentException if the text is not exactly 5 bytes of valid hex
     */
    public static byte[] parseKeyHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("key must not be empty");
        }
        String cleaned = hex.trim().replaceAll("(?i)^0x", "").replaceAll("[\\s:_-]", "");
        if (cleaned.length() != KeyDerivation.KEY_LENGTH * 2) {
            throw new IllegalArgumentException(
                    "key must be " + KeyDerivation.KEY_LENGTH + " bytes ("
                            + (KeyDerivation.KEY_LENGTH * 2) + " hex digits), got "
                            + cleaned.length() + " digits");
        }
        if (!cleaned.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("key contains non-hex characters");
        }
        return HexFormat.of().parseHex(cleaned.toLowerCase(java.util.Locale.ROOT));
    }

    public SessionKey withLastSeen(long when) {
        return new SessionKey(sessionId, key, host, firstSeen, when, label, source);
    }

    public SessionKey withLabel(String newLabel) {
        return new SessionKey(sessionId, key, host, firstSeen, lastSeen, newLabel, source);
    }

    // Records give identity semantics on the array reference, which is never what a caller wants
    // for a value object holding bytes.

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        return o instanceof SessionKey other
                && sessionId.equals(other.sessionId)
                && java.util.Arrays.equals(key, other.key)
                && host.equals(other.host)
                && firstSeen == other.firstSeen
                && lastSeen == other.lastSeen
                && label.equals(other.label)
                && source == other.source;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(
                sessionId, java.util.Arrays.hashCode(key), host, firstSeen, lastSeen, label, source);
    }

    @Override
    public String toString() {
        return "SessionKey[" + sessionId + " key=" + keyHex() + " source=" + source + "]";
    }
}
