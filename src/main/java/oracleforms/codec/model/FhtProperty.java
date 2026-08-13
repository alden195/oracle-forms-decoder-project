package oracleforms.codec.model;

import oracleforms.codec.PropertyIds;

/**
 * One property of an FHT message.
 *
 * <p>{@code offset} and {@code length} span the property's encoding in the decrypted packet,
 * including its two-byte header. Recording them is what lets an edit be applied at a known-good
 * position; the reference scanned the plaintext for a two-byte header pattern, which can match
 * arbitrary bytes inside string contents or image data (architecture &sect;6).
 *
 * @param id     property id, or {@link #PSEUDO_ID} for the tag and delete-mask markers
 * @param name   resolved name, or {@code ID_<n>} when the id is not in the table
 * @param offset byte offset of the property header within the decrypted packet
 * @param length total encoded length in bytes
 */
public record FhtProperty(int id, String name, PropertyValue value, int offset, int length) {

    /** Id used for the tag and delete-mask markers, which are not real properties. */
    public static final int PSEUDO_ID = -1;

    public boolean isSensitive() {
        return id != PSEUDO_ID && PropertyIds.isSensitive(id);
    }

    /** True when this property carries a string, which is what editing and highlighting act on. */
    public boolean isString() {
        return value instanceof PropertyValue.StrValue;
    }
}
