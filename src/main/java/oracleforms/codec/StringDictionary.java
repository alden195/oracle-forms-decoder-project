package oracleforms.codec;

/**
 * The 256-slot string dictionary FHT uses for back-references.
 *
 * <p>Its <em>scope</em> is an open question (architecture &sect;7.2): the reference resets it per
 * packet, while the RC4 stream it rides on is explicitly per session. If Oracle scopes it to the
 * session, resetting per packet makes every back-reference resolve to an empty string and values
 * silently vanish. So this is a passed-in object rather than parser-internal state — the caller
 * decides the scope, and {@link oracleforms.session.DictionaryScope} makes the choice explicit.
 */
public final class StringDictionary {

    public static final int SLOTS = 256;

    private final String[] slots;

    public StringDictionary() {
        this.slots = new String[SLOTS];
        java.util.Arrays.fill(this.slots, "");
    }

    private StringDictionary(String[] slots) {
        this.slots = slots;
    }

    /** Bounded read; an out-of-range index yields an empty string rather than throwing. */
    public String get(int index) {
        return index >= 0 && index < SLOTS ? slots[index] : "";
    }

    /** Bounded write; an out-of-range index is ignored. */
    public void put(int index, String value) {
        if (index >= 0 && index < SLOTS) {
            slots[index] = value == null ? "" : value;
        }
    }

    /** An independent copy, for storing in a checkpoint. */
    public StringDictionary copy() {
        return new StringDictionary(slots.clone());
    }

    public void clear() {
        java.util.Arrays.fill(slots, "");
    }
}
