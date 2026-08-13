package oracleforms.session;

/**
 * How a key got into the store. Recorded because it governs how much to trust a failed decode:
 * a {@link #DERIVED} key that fails suggests a protocol assumption is wrong, whereas a
 * {@link #MANUAL} one that fails was probably just mistyped.
 */
public enum KeySource {

    /** Derived from an observed Pragma 1 handshake, live or by retroactive history scan. */
    DERIVED("derived"),

    /** Typed or pasted in by the user. */
    MANUAL("manual"),

    /** Read from a JSON export of another project's store. */
    IMPORTED("imported");

    private final String wireName;

    KeySource(String wireName) {
        this.wireName = wireName;
    }

    /** The stable string persisted in the project file; do not change these values. */
    public String wireName() {
        return wireName;
    }

    public static KeySource fromWireName(String name) {
        for (KeySource s : values()) {
            if (s.wireName.equalsIgnoreCase(name)) {
                return s;
            }
        }
        return DERIVED;
    }
}
