package oracleforms.codec;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;

/**
 * Keeps the caret and the selection inside the text an edit has just changed.
 *
 * <h2>Why this exists</h2>
 *
 * <p>A Forms client does not send a text item's new value on its own. It sends the value together
 * with where the caret is and what is selected, and both of those are <em>indices into that very
 * string</em>. Read off the wire (2026-08-19), one field edit looks like this:
 *
 * <pre>
 * UPDATE handler=113
 *     ID_99            = "elevenchars"    &lt;- the text
 *     SELECTION        = (11, 11)         &lt;- caret at the end of it
 *     CURSOR_POSITION  = 11
 * </pre>
 *
 * <p>Shorten the text to seven characters and the other two still say eleven, so the message now
 * describes a caret four characters past the end of its own string. <strong>No client can produce
 * that</strong>, and the Forms runtime is under no obligation to make sense of it — which is what an
 * edit that reaches the server and changes nothing looks like. Confirmed across three consecutive
 * live edits, where {@code SELECTION} and {@code CURSOR_POSITION} held the length of the text the
 * client had, every time.
 *
 * <h2>Why this is not the writer overreaching</h2>
 *
 * <p>{@link FhtWriter} splices, so that everything the user did not edit is untouched <em>by
 * construction</em> (architecture &sect;6.3). This adds edits rather than weakening that: they go
 * through the same splice and the same identity gate, and they are visible to the caller so they can
 * be reported rather than slipped in.
 *
 * <p>The condition is deliberately narrow — <b>only an index that now points past the end of the
 * edited text is moved</b>, and only to the end of it. A caret the user has left in the middle of
 * the string is a position a client could genuinely send, so it is left exactly where it is; so is
 * one the user has edited by hand, since an explicit edit outranks an inference. And clamping only
 * ever makes a value smaller, so it cannot overflow the width the property was encoded at.
 */
public final class TextIndexEdits {

    /** Where the caret sits within a text item's value. */
    public static final int CURSOR_POSITION = 193;

    /** What is selected within it, as (start, end). */
    public static final int SELECTION = 195;

    /**
     * One companion change, with the sentence that explains it.
     *
     * @param edit        the change to apply, alongside the user's own
     * @param description what changed and why, for the banner and the log
     */
    public record Adjustment(FhtEdit edit, String description) {
    }

    private TextIndexEdits() {
    }

    /**
     * The companion edits that keep {@code edits} internally consistent.
     *
     * @param packet the packet as parsed from the buffer the edits were made against
     * @param edits  the user's own edits
     * @return the adjustments to apply as well, in packet order; empty when nothing is stale
     */
    public static List<Adjustment> forEdits(FhtPacket packet, List<FhtEdit> edits) {
        if (packet == null || edits == null || edits.isEmpty()) {
            return List.of();
        }

        // Matched on byte offset rather than on identity: the caller may have parsed the buffer a
        // second time since, and two parses of the same bytes agree on every offset.
        Set<Integer> editedOffsets = new HashSet<>();
        for (FhtEdit edit : edits) {
            editedOffsets.add(edit.offset());
        }

        Map<FhtMessage, String> retexted = messagesWithOneChangedText(packet, edits);
        List<Adjustment> adjustments = new ArrayList<>();

        retexted.forEach((message, text) -> {
            int limit = text.length();
            for (FhtProperty property : message.properties()) {
                if (editedOffsets.contains(property.offset())) {
                    continue;
                }
                adjust(property, limit).ifPresent(adjustments::add);
            }
        });

        adjustments.sort((a, b) -> Integer.compare(a.edit().offset(), b.edit().offset()));
        return adjustments;
    }

    /**
     * Messages in which exactly one string property changed length, mapped to its new text.
     *
     * <p>Exactly one, because the caret belongs to a text item and a message that changed two
     * strings gives no way to say which one it indexes. Adjusting against a guess would be worse
     * than leaving a stale value the user can see and correct.
     */
    private static Map<FhtMessage, String> messagesWithOneChangedText(
            FhtPacket packet, List<FhtEdit> edits) {

        Map<FhtMessage, String> single = new HashMap<>();
        Set<FhtMessage> ambiguous = new HashSet<>();

        for (FhtEdit edit : edits) {
            if (!(edit.newValue() instanceof PropertyValue.StrValue replacement)
                    || !(edit.property().value() instanceof PropertyValue.StrValue original)
                    || replacement.value().length() == original.value().length()) {
                continue;
            }
            FhtMessage message = messageContaining(packet, edit.offset());
            if (message == null || ambiguous.contains(message)) {
                continue;
            }
            if (single.put(message, replacement.value()) != null) {
                single.remove(message);
                ambiguous.add(message);
            }
        }
        return single;
    }

    /** The adjustment this property needs, if it indexes past {@code limit}. */
    private static java.util.Optional<Adjustment> adjust(FhtProperty property, int limit) {
        if (property.id() == CURSOR_POSITION
                && property.value() instanceof PropertyValue.IntValue caret
                && caret.value() > limit) {
            return java.util.Optional.of(new Adjustment(
                    new FhtEdit(property, new PropertyValue.IntValue(limit)),
                    "CURSOR_POSITION " + caret.value() + " → " + limit));
        }
        if (property.id() == SELECTION
                && property.value() instanceof PropertyValue.PointValue selection
                && (selection.x() > limit || selection.y() > limit)) {
            PropertyValue.PointValue clamped = new PropertyValue.PointValue(
                    Math.min(selection.x(), limit), Math.min(selection.y(), limit));
            return java.util.Optional.of(new Adjustment(
                    new FhtEdit(property, clamped),
                    "SELECTION " + selection.display() + " → " + clamped.display()));
        }
        return java.util.Optional.empty();
    }

    /** The message whose properties include the one at {@code offset}. */
    private static FhtMessage messageContaining(FhtPacket packet, int offset) {
        for (FhtMessage message : packet.messages()) {
            for (FhtProperty property : message.properties()) {
                if (property.offset() == offset) {
                    return message;
                }
            }
        }
        return null;
    }
}
