package oracleforms.codec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Keeping a text item's caret and selection inside the text an edit changed.
 *
 * <p>The fixture is the shape of a real message, reconstructed from a live edit on 2026-08-19 (the
 * values are synthetic, per architecture §1, but the lengths and the structure are not): a text item
 * whose value went from eleven characters to seven, was forwarded, and was ignored by the
 * application. The message it produced said the text was seven characters long and the caret was at
 * eleven — which no client can send, because both numbers are indices into the same string.
 */
class TextIndexEditsTest {

    /** The text property in a text-item update. Id 99 has no name in the ported table. */
    private static final int TEXT_ID = 99;

    private final FhtParser parser = new FhtParser();

    /**
     * The message as the client sent it: value, selection and caret, then the focus move.
     *
     * @param text the item's value; the caret and selection sit at its end, as the client leaves them
     */
    private static byte[] textItemUpdate(String text) {
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        return new TestPackets()
                .message(0x1000, 0, 113)
                .stringPropertyRaw(TEXT_ID, 0, utf8)
                .point8Property(TextIndexEdits.SELECTION, utf8.length, utf8.length)
                .uint8Property(TextIndexEdits.CURSOR_POSITION, utf8.length)
                .endProperties()
                .message(0x1000, 0, 113)
                .boolProperty(174, false)
                .endProperties()
                .message(0x1000, 0, 96)
                .boolProperty(174, true)
                .endProperties()
                .endPacket()
                .build();
    }

    private FhtProperty property(FhtPacket packet, int messageIndex, int id) {
        FhtMessage message = packet.messages().get(messageIndex);
        return message.properties().stream()
                .filter(p -> p.id() == id)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no property " + id));
    }

    private List<String> describe(List<TextIndexEdits.Adjustment> adjustments) {
        List<String> out = new ArrayList<>();
        adjustments.forEach(a -> out.add(a.description()));
        return out;
    }

    @Test
    @DisplayName("shortening the text pulls the caret and selection back to its end")
    void clampsWhenTheTextShrinks() {
        byte[] original = textItemUpdate("elevenchars");
        FhtPacket packet = parser.parse(original, new StringDictionary());
        FhtEdit edit = new FhtEdit(
                property(packet, 0, TEXT_ID), new PropertyValue.StrValue("sevench"));

        List<TextIndexEdits.Adjustment> adjustments =
                TextIndexEdits.forEdits(packet, List.of(edit));

        assertEquals(List.of("SELECTION (11, 11) → (7, 7)", "CURSOR_POSITION 11 → 7"),
                describe(adjustments));
    }

    @Test
    @DisplayName("the adjusted message is what the server actually receives")
    void theAdjustmentsSurviveTheSplice() throws Exception {
        byte[] original = textItemUpdate("elevenchars");
        FhtPacket packet = parser.parse(original, new StringDictionary());

        List<FhtEdit> edits = new ArrayList<>();
        edits.add(new FhtEdit(property(packet, 0, TEXT_ID), new PropertyValue.StrValue("sevench")));
        TextIndexEdits.forEdits(packet, edits).forEach(a -> edits.add(a.edit()));

        FhtPacket sent = parser.parse(FhtWriter.applyEdits(original, edits), new StringDictionary());

        assertTrue(sent.outcome().isComplete(), sent.outcome().describe());
        assertEquals(new PropertyValue.StrValue("sevench"), property(sent, 0, TEXT_ID).value());
        assertEquals(new PropertyValue.PointValue(7, 7),
                property(sent, 0, TextIndexEdits.SELECTION).value());
        assertEquals(new PropertyValue.IntValue(7),
                property(sent, 0, TextIndexEdits.CURSOR_POSITION).value());

        // The rest of the packet is the client's own, untouched: the focus move still says what it
        // said, which is the whole point of splicing rather than re-serialising.
        assertEquals(new PropertyValue.BoolValue(false), property(sent, 1, 174).value());
        assertEquals(new PropertyValue.BoolValue(true), property(sent, 2, 174).value());
    }

    @Test
    @DisplayName("a caret already inside the new text is left exactly where the user put it")
    void leavesAnInRangeCaretAlone() {
        // The 2026-08-19 capture has this case too: a three-character value replaced by six, caret
        // at three. That is a position a client could genuinely send, so nothing is owed here.
        byte[] original = textItemUpdate("thr");
        FhtPacket packet = parser.parse(original, new StringDictionary());
        FhtEdit edit = new FhtEdit(
                property(packet, 0, TEXT_ID), new PropertyValue.StrValue("sixchr"));

        assertTrue(TextIndexEdits.forEdits(packet, List.of(edit)).isEmpty());
    }

    @Test
    @DisplayName("a caret the user edited by hand outranks the inference")
    void neverOverridesAnExplicitEdit() {
        byte[] original = textItemUpdate("elevenchars");
        FhtPacket packet = parser.parse(original, new StringDictionary());

        List<FhtEdit> edits = List.of(
                new FhtEdit(property(packet, 0, TEXT_ID), new PropertyValue.StrValue("ab")),
                new FhtEdit(property(packet, 0, TextIndexEdits.CURSOR_POSITION),
                        new PropertyValue.IntValue(1)));

        assertEquals(List.of("SELECTION (11, 11) → (2, 2)"),
                describe(TextIndexEdits.forEdits(packet, edits)));
    }

    @Test
    @DisplayName("a same-length edit moves nothing")
    void sameLengthEditsAdjustNothing() {
        byte[] original = textItemUpdate("elevenchars");
        FhtPacket packet = parser.parse(original, new StringDictionary());
        FhtEdit edit = new FhtEdit(
                property(packet, 0, TEXT_ID), new PropertyValue.StrValue("CHANGEDWORD"));

        assertTrue(TextIndexEdits.forEdits(packet, List.of(edit)).isEmpty());
    }

    @Test
    @DisplayName("two changed strings in one message leave the caret alone, rather than guessing")
    void refusesToGuessBetweenTwoStrings() {
        byte[] original = new TestPackets()
                .message(0x1000, 0, 113)
                .stringProperty(TEXT_ID, 0, "elevenchars")
                .stringProperty(103, 1, "second")
                .point8Property(TextIndexEdits.SELECTION, 11, 11)
                .uint8Property(TextIndexEdits.CURSOR_POSITION, 11)
                .endProperties()
                .endPacket()
                .build();
        FhtPacket packet = parser.parse(original, new StringDictionary());

        List<FhtEdit> edits = List.of(
                new FhtEdit(property(packet, 0, TEXT_ID), new PropertyValue.StrValue("ab")),
                new FhtEdit(property(packet, 0, 103), new PropertyValue.StrValue("cd")));

        assertTrue(TextIndexEdits.forEdits(packet, edits).isEmpty(),
                "the caret indexes one of them and nothing here can say which");
    }

    @Test
    @DisplayName("a caret in a different message is not touched")
    void doesNotReachAcrossMessages() {
        byte[] original = new TestPackets()
                .message(0x1000, 0, 113)
                .stringProperty(TEXT_ID, 0, "elevenchars")
                .endProperties()
                .message(0x1000, 0, 96)
                .uint8Property(TextIndexEdits.CURSOR_POSITION, 11)
                .endProperties()
                .endPacket()
                .build();
        FhtPacket packet = parser.parse(original, new StringDictionary());
        FhtEdit edit = new FhtEdit(
                property(packet, 0, TEXT_ID), new PropertyValue.StrValue("ab"));

        assertTrue(TextIndexEdits.forEdits(packet, List.of(edit)).isEmpty(),
                "another object's caret is not an index into this string");
    }
}
