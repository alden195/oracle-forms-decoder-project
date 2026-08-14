package oracleforms.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The gate on build order step 6 (architecture §6.8, 6a).
 *
 * <p>The central test is {@link #everySupportedTypeRoundTrips}: re-encoding a property with its own
 * unchanged value must reproduce the original bytes exactly. Everything else in the Repeater feature
 * rests on that, because {@code FhtWriter} refuses to change bytes it cannot first reproduce.
 */
class FhtWriterTest {

    private final FhtParser parser = new FhtParser();

    /** A packet exercising every type marker the parser distinguishes. */
    private static byte[] everyTypePacket() {
        return new TestPackets()
                .message(0x1000, 0, 42)
                .int32Property(0x005, -123456)
                .implicitZeroProperty(0x006)
                .uint8Property(0x007, 200)
                .uint16Property(0x008, 60000)
                .stringProperty(0x009, 12, "hello world")
                .boolProperty(0x00A, true)
                .boolProperty(0x00B, false)
                .byteProperty(0x00C, 0xFE)
                .voidProperty(0x00D)
                .backReference(0x00E, 13, 12)
                .point16Property(0x00F, -300, 400)
                .point8Property(0x010, 10, 20)
                .extFloatProperty(0x011, 0x3F800000)
                .unknownMarkerProperty()
                .tag(3)
                .deleteMask(0xBEEF)
                .endProperties()
                .endPacket()
                .build();
    }

    private List<FhtProperty> propertiesOf(byte[] bytes) {
        FhtPacket packet = parser.parse(bytes, new StringDictionary());
        List<FhtProperty> all = new ArrayList<>();
        for (FhtMessage message : packet.messages()) {
            all.addAll(message.properties());
        }
        return all;
    }

    private FhtProperty propertyNamed(byte[] bytes, int id) {
        return propertiesOf(bytes).stream()
                .filter(p -> p.id() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no property with id " + id));
    }

    // ---- the gate -------------------------------------------------------------------------

    @Test
    @DisplayName("re-encoding any property with its own value reproduces the original bytes")
    void everySupportedTypeRoundTrips() {
        byte[] bytes = everyTypePacket();
        List<FhtProperty> properties = propertiesOf(bytes);
        assertEquals(16, properties.size(), "the fixture should cover every marker");

        for (FhtProperty property : properties) {
            assertTrue(FhtWriter.roundTrips(bytes, property),
                    "property " + property.name() + " at offset " + property.offset()
                            + " (" + property.value().display() + ") did not round-trip");
        }
    }

    @Test
    @DisplayName("an identity edit over every editable property leaves the packet byte-identical")
    void identityEditsChangeNothing() throws Exception {
        byte[] bytes = everyTypePacket();
        List<FhtEdit> edits = new ArrayList<>();
        for (FhtProperty property : propertiesOf(bytes)) {
            edits.add(new FhtEdit(property, property.value()));
        }
        assertArrayEquals(bytes, FhtWriter.applyEdits(bytes, edits));
    }

    // ---- what can and cannot be edited ----------------------------------------------------

    @Test
    @DisplayName("value types are editable; structural and undecoded ones are refused with a reason")
    void editabilityIsDecidedPerType() {
        byte[] bytes = everyTypePacket();

        for (int editable : List.of(0x005, 0x007, 0x008, 0x009, 0x00A, 0x00B, 0x00C, 0x00E, 0x00F,
                0x010)) {
            FhtProperty property = propertyNamed(bytes, editable);
            assertTrue(FhtWriter.isEditable(bytes, property),
                    "id " + editable + " should be editable but was refused: "
                            + FhtWriter.editRefusal(bytes, property).orElse(""));
        }

        assertRefused(bytes, propertyNamed(bytes, 0x006), "implicit zero");
        assertRefused(bytes, propertyNamed(bytes, 0x00D), "void");
        assertRefused(bytes, propertyNamed(bytes, 0x011), "extended type");

        for (FhtProperty pseudo : propertiesOf(bytes)) {
            if (pseudo.id() == FhtProperty.PSEUDO_ID) {
                assertRefused(bytes, pseudo, "structural marker");
            }
        }
    }

    private static void assertRefused(byte[] bytes, FhtProperty property, String expectedFragment) {
        Optional<String> refusal = FhtWriter.editRefusal(bytes, property);
        assertTrue(refusal.isPresent(), property.name() + " should not be editable");
        assertTrue(refusal.get().contains(expectedFragment),
                "refusal for " + property.name() + " should mention '" + expectedFragment
                        + "' but said: " + refusal.get());
    }

    @Test
    @DisplayName("a string whose bytes are not valid UTF-8 is refused, not mangled")
    void lossyStringDecodingIsCaughtByTheIdentityGate() {
        // 0xFF is not a legal UTF-8 lead byte. FhtReader decodes leniently, so the parser produces a
        // replacement character -- and re-encoding that would write three different bytes. The
        // identity gate is what stops the writer from doing so.
        byte[] bytes = new TestPackets()
                .message(0x1000, 0, 1)
                .stringPropertyRaw(0x009, 4, new byte[]{'o', 'k', (byte) 0xFF})
                .endProperties()
                .endPacket()
                .build();

        FhtProperty property = propertyNamed(bytes, 0x009);
        assertFalse(FhtWriter.roundTrips(bytes, property));
        assertRefused(bytes, property, "does not reproduce the original bytes");
    }

    // ---- edits that change bytes ----------------------------------------------------------

    @Test
    @DisplayName("editing an integer rewrites only its own four value bytes")
    void integerEditIsLocal() throws Exception {
        byte[] bytes = everyTypePacket();
        FhtProperty property = propertyNamed(bytes, 0x005);

        byte[] edited = FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(property, new PropertyValue.IntValue(7))));

        assertEquals(bytes.length, edited.length, "an int edit cannot change the length");
        assertEquals(new PropertyValue.IntValue(7), propertyNamed(edited, 0x005).value());

        int changed = 0;
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != edited[i]) {
                changed++;
                assertTrue(i >= property.offset() + 2 && i < property.offset() + property.length(),
                        "byte " + i + " changed but lies outside the edited property");
            }
        }
        assertTrue(changed > 0 && changed <= 4, "expected at most the four value bytes to move");
    }

    @Test
    @DisplayName("editing a string to a longer one grows the packet and preserves everything else")
    void stringEditMayChangeLength() throws Exception {
        byte[] bytes = everyTypePacket();
        FhtProperty property = propertyNamed(bytes, 0x009);

        byte[] edited = FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(property, new PropertyValue.StrValue("a much longer value"))));

        assertEquals(bytes.length + "a much longer value".length() - "hello world".length(),
                edited.length);

        // The prefix before the edit is untouched, and every other property still parses the same.
        assertArrayEquals(Arrays.copyOf(bytes, property.offset()),
                Arrays.copyOf(edited, property.offset()));
        assertEquals(new PropertyValue.StrValue("a much longer value"),
                propertyNamed(edited, 0x009).value());
        assertEquals(new PropertyValue.IntValue(-123456), propertyNamed(edited, 0x005).value());
        assertEquals(new PropertyValue.PointValue(-300, 400), propertyNamed(edited, 0x00F).value());
        assertTrue(parser.parse(edited, new StringDictionary()).outcome().isComplete());
    }

    @Test
    @DisplayName("flipping a boolean rewrites the header and keeps the length")
    void booleanFlipKeepsLength() throws Exception {
        byte[] bytes = everyTypePacket();
        FhtProperty property = propertyNamed(bytes, 0x00A);

        byte[] edited = FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(property, new PropertyValue.BoolValue(false))));

        assertEquals(bytes.length, edited.length);
        assertEquals(new PropertyValue.BoolValue(false), propertyNamed(edited, 0x00A).value());
        assertEquals(0x60, edited[property.offset()] & 0xF0, "the marker should now say false");
    }

    /**
     * The subtle one. A back-reference's value lives in the dictionary, and its side effect is
     * copying one slot into another. Promoting it to a literal stored into the same destination slot
     * reproduces that side effect exactly, so a later property reading that slot sees the new text.
     */
    @Test
    @DisplayName("editing a back-referenced string promotes it to a literal in the same slot")
    void backReferenceEditPreservesTheDictionaryWrite() throws Exception {
        byte[] bytes = new TestPackets()
                .message(0x1000, 0, 1)
                .stringProperty(0x009, 12, "original")
                .backReference(0x00E, 13, 12)
                .backReference(0x00F, 14, 13)
                .endProperties()
                .endPacket()
                .build();

        // Before the edit, both back-references resolve to the literal.
        assertEquals(new PropertyValue.StrValue("original"), propertyNamed(bytes, 0x00E).value());
        assertEquals(new PropertyValue.StrValue("original"), propertyNamed(bytes, 0x00F).value());

        FhtProperty backRef = propertyNamed(bytes, 0x00E);
        byte[] edited = FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(backRef, new PropertyValue.StrValue("replaced"))));

        assertEquals(0x40, edited[backRef.offset()] & 0xF0, "promoted to a literal string");
        assertEquals(new PropertyValue.StrValue("replaced"), propertyNamed(edited, 0x00E).value());
        assertEquals(new PropertyValue.StrValue("replaced"), propertyNamed(edited, 0x00F).value(),
                "the chained back-reference must follow the new text, not the old");
    }

    @Test
    @DisplayName("several edits in one packet all apply, in offset order")
    void multipleEditsApplyTogether() throws Exception {
        byte[] bytes = everyTypePacket();

        byte[] edited = FhtWriter.applyEdits(bytes, List.of(
                new FhtEdit(propertyNamed(bytes, 0x009), new PropertyValue.StrValue("first")),
                new FhtEdit(propertyNamed(bytes, 0x005), new PropertyValue.IntValue(1)),
                new FhtEdit(propertyNamed(bytes, 0x010), new PropertyValue.PointValue(1, 2))));

        assertEquals(new PropertyValue.StrValue("first"), propertyNamed(edited, 0x009).value());
        assertEquals(new PropertyValue.IntValue(1), propertyNamed(edited, 0x005).value());
        assertEquals(new PropertyValue.PointValue(1, 2), propertyNamed(edited, 0x010).value());
        assertTrue(parser.parse(edited, new StringDictionary()).outcome().isComplete());
    }

    // ---- refusals -------------------------------------------------------------------------

    @Test
    @DisplayName("an out-of-range value is refused rather than truncated into the field")
    void valuesTooLargeForTheirFieldAreRefused() {
        byte[] bytes = everyTypePacket();

        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(propertyNamed(bytes, 0x007),
                        new PropertyValue.IntValue(300)))));
        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(propertyNamed(bytes, 0x008),
                        new PropertyValue.IntValue(-1)))));
        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(propertyNamed(bytes, 0x010),
                        new PropertyValue.PointValue(999, 0)))));
    }

    @Test
    @DisplayName("changing a value's type is refused")
    void typeChangesAreRefused() {
        byte[] bytes = everyTypePacket();
        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(propertyNamed(bytes, 0x005),
                        new PropertyValue.StrValue("not an int")))));
    }

    @Test
    @DisplayName("editing an undecoded extended value is refused")
    void extendedValuesCannotBeEdited() {
        byte[] bytes = everyTypePacket();
        // A *different* ExtValue, so this is a real change rather than a no-op the writer drops.
        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(propertyNamed(bytes, 0x011),
                        new PropertyValue.ExtValue(5, 8)))));
        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(propertyNamed(bytes, 0x011),
                        new PropertyValue.StrValue("cannot become a string")))));
    }

    @Test
    @DisplayName("overlapping edits are rejected before anything is written")
    void overlappingEditsAreRejected() {
        byte[] bytes = everyTypePacket();
        FhtProperty property = propertyNamed(bytes, 0x005);
        FhtProperty overlapping = new FhtProperty(property.id(), property.name(), property.value(),
                property.offset() + 1, property.length());

        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes, List.of(
                new FhtEdit(property, new PropertyValue.IntValue(1)),
                new FhtEdit(overlapping, new PropertyValue.IntValue(2)))));
    }

    @Test
    @DisplayName("an edit whose bytes run past the end of the packet is rejected")
    void outOfRangeEditsAreRejected() {
        byte[] bytes = everyTypePacket();
        FhtProperty bogus = new FhtProperty(5, "BOGUS", new PropertyValue.IntValue(0),
                bytes.length - 2, 8);

        assertThrows(FhtUnwritableException.class, () -> FhtWriter.applyEdits(bytes,
                List.of(new FhtEdit(bogus, new PropertyValue.IntValue(1)))));
    }

    @Test
    @DisplayName("an empty or no-op edit list returns the packet unchanged")
    void noOpEditsAreFree() throws Exception {
        byte[] bytes = everyTypePacket();
        assertArrayEquals(bytes, FhtWriter.applyEdits(bytes, List.of()));

        FhtProperty property = propertyNamed(bytes, 0x005);
        assertArrayEquals(bytes,
                FhtWriter.applyEdits(bytes, List.of(new FhtEdit(property, property.value()))));
    }

    // ---- hostile input --------------------------------------------------------------------

    /**
     * Bodies come from the tested application (BApp criterion 3). Whatever the parser makes of
     * random bytes, the writer must never claim it can edit something it cannot reproduce, and an
     * identity edit must always give back exactly what it was handed.
     */
    @Test
    @DisplayName("on arbitrary bytes, editability is never claimed falsely")
    void fuzzNeverCorrupts() throws Exception {
        Random random = new Random(20260814L);
        int editableSeen = 0;

        for (int i = 0; i < 2000; i++) {
            byte[] junk = new byte[random.nextInt(400)];
            random.nextBytes(junk);

            List<FhtEdit> identity = new ArrayList<>();
            for (FhtProperty property : propertiesOf(junk)) {
                assertNotNull(FhtWriter.editRefusal(junk, property));
                if (FhtWriter.isEditable(junk, property)) {
                    editableSeen++;
                    assertTrue(FhtWriter.roundTrips(junk, property),
                            "claimed editable without round-tripping");
                }
                identity.add(new FhtEdit(property, property.value()));
            }
            assertArrayEquals(junk, FhtWriter.applyEdits(junk, identity),
                    "an identity edit changed random input");
        }

        assertTrue(editableSeen > 0, "the fuzz corpus should reach the editable paths at all");
    }
}
