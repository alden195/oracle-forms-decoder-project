package oracleforms.codec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Text in, model out, for the editable cells of the draft table. */
class PropertyValuesTest {

    private static final List<PropertyValue> EDITABLE = List.of(
            new PropertyValue.IntValue(-123456),
            new PropertyValue.StrValue("hello, world"),
            new PropertyValue.BoolValue(true),
            new PropertyValue.BoolValue(false),
            new PropertyValue.ByteValue((byte) -7),
            new PropertyValue.PointValue(-300, 400));

    @Test
    @DisplayName("every editable shape survives text and back")
    void editableTextRoundTrips() {
        for (PropertyValue value : EDITABLE) {
            String text = PropertyValues.editableText(value);
            assertEquals(Optional.of(value), PropertyValues.parseLike(value, text),
                    "did not round-trip: " + value);
        }
    }

    /**
     * A type change is refused here rather than at send time. {@link FhtWriter} would refuse it
     * anyway, but a user who has made six edits should learn about the bad one when they type it.
     */
    @Test
    @DisplayName("parsing preserves the value's shape and refuses anything else")
    void shapeIsPreserved() {
        PropertyValue integer = new PropertyValue.IntValue(1);
        assertTrue(PropertyValues.parseLike(integer, "not a number").isEmpty());
        assertTrue(PropertyValues.parseLike(integer, "").isEmpty());
        assertEquals(Optional.of(new PropertyValue.IntValue(42)),
                PropertyValues.parseLike(integer, "  42 "));

        PropertyValue aByte = new PropertyValue.ByteValue((byte) 1);
        assertTrue(PropertyValues.parseLike(aByte, "300").isEmpty(),
                "a value that does not fit the field must not be silently truncated");
    }

    @Test
    @DisplayName("booleans accept the obvious spellings")
    void booleanSpellings() {
        PropertyValue template = new PropertyValue.BoolValue(true);
        for (String yes : List.of("true", "TRUE", " 1 ", "yes")) {
            assertEquals(Optional.of(new PropertyValue.BoolValue(true)),
                    PropertyValues.parseLike(template, yes));
        }
        for (String no : List.of("false", "False", "0", "no")) {
            assertEquals(Optional.of(new PropertyValue.BoolValue(false)),
                    PropertyValues.parseLike(template, no));
        }
        assertTrue(PropertyValues.parseLike(template, "maybe").isEmpty());
    }

    @Test
    @DisplayName("points accept both the editable and the displayed form")
    void pointForms() {
        PropertyValue template = new PropertyValue.PointValue(0, 0);
        assertEquals(Optional.of(new PropertyValue.PointValue(3, 4)),
                PropertyValues.parseLike(template, "3, 4"));
        assertEquals(Optional.of(new PropertyValue.PointValue(3, 4)),
                PropertyValues.parseLike(template, "(3, 4)"));
        assertTrue(PropertyValues.parseLike(template, "3").isEmpty());
        assertTrue(PropertyValues.parseLike(template, "3, 4, 5").isEmpty());
    }

    @Test
    @DisplayName("shapes with no meaningful text form are not offered for editing")
    void unsupportedShapes() {
        assertFalse(PropertyValues.isTextEditable(new PropertyValue.ExtValue(5, 4)));
        assertFalse(PropertyValues.isTextEditable(new PropertyValue.VoidValue()));
        assertFalse(PropertyValues.isTextEditable(new PropertyValue.UnknownValue(0xF000)));

        assertTrue(PropertyValues.parseLike(new PropertyValue.VoidValue(), "anything").isEmpty());
        for (PropertyValue value : EDITABLE) {
            assertTrue(PropertyValues.isTextEditable(value));
        }
    }

    @Test
    @DisplayName("null input is refused rather than throwing")
    void nullsAreRefused() {
        assertTrue(PropertyValues.parseLike(null, "x").isEmpty());
        assertTrue(PropertyValues.parseLike(new PropertyValue.IntValue(0), null).isEmpty());
    }
}
