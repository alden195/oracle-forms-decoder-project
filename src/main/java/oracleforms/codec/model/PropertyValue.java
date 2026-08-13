package oracleforms.codec.model;

/**
 * A decoded property value.
 *
 * <p>Sealed so that consumers — sensitive-value detection, the renderer, a future re-encoder — can
 * switch exhaustively over the real shape of the data. The reference implementation instead
 * regex-parsed its own formatted output to find string properties, which breaks on any value
 * containing a quote or newline (architecture &sect;7.5).
 */
public sealed interface PropertyValue {

    /** Rendered form, for display only. Never re-parse this; work from the record instead. */
    String display();

    record IntValue(int value) implements PropertyValue {
        @Override
        public String display() {
            return Integer.toString(value);
        }
    }

    record StrValue(String value) implements PropertyValue {
        @Override
        public String display() {
            return value;
        }
    }

    record BoolValue(boolean value) implements PropertyValue {
        @Override
        public String display() {
            return Boolean.toString(value);
        }
    }

    record ByteValue(byte value) implements PropertyValue {
        @Override
        public String display() {
            return Byte.toString(value);
        }
    }

    record PointValue(int x, int y) implements PropertyValue {
        @Override
        public String display() {
            return "(" + x + ", " + y + ")";
        }
    }

    /** A property present with no value, type marker {@code 0x8000}. */
    record VoidValue() implements PropertyValue {
        @Override
        public String display() {
            return "<void>";
        }
    }

    /**
     * An extended type ({@code 0xE000}). The payload is recorded as raw bytes rather than decoded;
     * these carry arrays, dates, floats and nested messages, and are skipped structurally.
     */
    record ExtValue(int subtype, int byteLength) implements PropertyValue {
        @Override
        public String display() {
            return "<ext:" + subtype + " " + byteLength + " bytes>";
        }
    }

    /** A type marker the parser does not know. Recorded rather than dropped. */
    record UnknownValue(int typeMarker) implements PropertyValue {
        @Override
        public String display() {
            return String.format("<unknown type 0x%04X>", typeMarker);
        }
    }
}
