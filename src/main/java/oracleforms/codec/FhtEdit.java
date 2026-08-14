package oracleforms.codec;

import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;

/**
 * One pending change to a decoded packet: replace a property's value, leaving everything else alone.
 *
 * <p>An edit is bound to the {@link FhtProperty} the parser produced, not to a byte offset the caller
 * worked out. The property carries the offset and length of its own encoding, so
 * {@link FhtWriter#applyEdits} always knows exactly which bytes it is allowed to touch — and, just as
 * importantly, which it is not.
 *
 * @param property the property as parsed, supplying the offset, length and original value
 * @param newValue the replacement value; must be the same {@link PropertyValue} shape as the original
 */
public record FhtEdit(FhtProperty property, PropertyValue newValue) {

    public FhtEdit {
        if (property == null) {
            throw new IllegalArgumentException("property must not be null");
        }
        if (newValue == null) {
            throw new IllegalArgumentException("newValue must not be null");
        }
    }

    /** True when the replacement is equal to what was already there, making this edit a no-op. */
    public boolean isNoOp() {
        return newValue.equals(property.value());
    }

    public int offset() {
        return property.offset();
    }

    public int endOffset() {
        return property.offset() + property.length();
    }
}
