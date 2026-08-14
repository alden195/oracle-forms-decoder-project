package oracleforms.codec;

import java.util.Locale;
import java.util.Optional;
import oracleforms.codec.model.PropertyValue;

/**
 * Text in, {@link PropertyValue} out — the bridge between an editable cell and the model.
 *
 * <p>Parsing is deliberately <strong>shape-preserving</strong>: whatever the user types is read back
 * as the same kind of value the property already held, and anything that will not read that way is
 * refused. An integer property whose text is edited to "yes" does not quietly become a string; it
 * fails, and the cell reverts.
 *
 * <p>That matters more than it looks. {@link FhtWriter} refuses a type change anyway, but it refuses
 * at send time, and a user who has typed six edits should learn about the bad one when they type it
 * rather than when the send is blocked.
 */
public final class PropertyValues {

    private PropertyValues() {
    }

    /**
     * The text form of a value for editing.
     *
     * <p>Not {@link PropertyValue#display()}: that is for reading, and decorates points as
     * {@code (x, y)}. This is the form {@link #parseLike} must accept back unchanged.
     */
    public static String editableText(PropertyValue value) {
        return switch (value) {
            case PropertyValue.IntValue v -> Integer.toString(v.value());
            case PropertyValue.StrValue v -> v.value();
            case PropertyValue.BoolValue v -> Boolean.toString(v.value());
            case PropertyValue.ByteValue v -> Byte.toString(v.value());
            case PropertyValue.PointValue v -> v.x() + ", " + v.y();
            default -> value.display();
        };
    }

    /**
     * Parses {@code text} into a value of the same shape as {@code template}.
     *
     * @return empty when the text cannot be read as that shape
     */
    public static Optional<PropertyValue> parseLike(PropertyValue template, String text) {
        if (template == null || text == null) {
            return Optional.empty();
        }
        try {
            return switch (template) {
                case PropertyValue.IntValue ignored ->
                        Optional.of(new PropertyValue.IntValue(Integer.parseInt(text.trim())));
                case PropertyValue.StrValue ignored ->
                        Optional.of(new PropertyValue.StrValue(text));
                case PropertyValue.BoolValue ignored -> parseBoolean(text);
                case PropertyValue.ByteValue ignored ->
                        Optional.of(new PropertyValue.ByteValue(Byte.parseByte(text.trim())));
                case PropertyValue.PointValue ignored -> parsePoint(text);
                default -> Optional.empty();
            };
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /** Whether a value's shape can be typed at all, regardless of what the writer will accept. */
    public static boolean isTextEditable(PropertyValue value) {
        return value instanceof PropertyValue.IntValue
                || value instanceof PropertyValue.StrValue
                || value instanceof PropertyValue.BoolValue
                || value instanceof PropertyValue.ByteValue
                || value instanceof PropertyValue.PointValue;
    }

    private static Optional<PropertyValue> parseBoolean(String text) {
        String cleaned = text.trim().toLowerCase(Locale.ROOT);
        if (cleaned.equals("true") || cleaned.equals("1") || cleaned.equals("yes")) {
            return Optional.of(new PropertyValue.BoolValue(true));
        }
        if (cleaned.equals("false") || cleaned.equals("0") || cleaned.equals("no")) {
            return Optional.of(new PropertyValue.BoolValue(false));
        }
        return Optional.empty();
    }

    /** Accepts {@code x, y} and the {@code (x, y)} form {@code display()} produces. */
    private static Optional<PropertyValue> parsePoint(String text) {
        String cleaned = text.trim();
        if (cleaned.startsWith("(") && cleaned.endsWith(")")) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }
        String[] parts = cleaned.split(",");
        if (parts.length != 2) {
            return Optional.empty();
        }
        return Optional.of(new PropertyValue.PointValue(
                Integer.parseInt(parts[0].trim()), Integer.parseInt(parts[1].trim())));
    }
}
