package oracleforms.burp;

import java.nio.charset.StandardCharsets;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.session.ReplayResult;

/**
 * Formats a parsed packet for display.
 *
 * <p>Rendering is one-way. Nothing re-reads this text — sensitive-value detection and any future
 * editing work from the model instead. The reference implementation regex-parsed its own formatted
 * output to find string properties, which breaks on any value containing a quote or a newline
 * (architecture &sect;7.5).
 */
public final class FhtRenderer {

    private static final int HEX_BYTES_PER_LINE = 16;

    /** Beyond this, the hex fallback is truncated: a 28 KB body would otherwise stall the editor. */
    private static final int MAX_HEX_BYTES = 8192;

    private FhtRenderer() {
    }

    /** The full display for a decoded packet, including a header line and any parse warning. */
    public static String render(FhtPacket packet, String header, byte[] plaintext) {
        return render(packet, header, plaintext, ReplayResult.FragmentGroup.single(0));
    }

    /**
     * As {@link #render(FhtPacket, String, byte[])}, but states how the bytes were assembled.
     *
     * <p>When a message arrived split across several pragmas, saying so matters: the user clicked
     * one pragma and is being shown the parse of several, and without the note the offsets in the
     * listing would look wrong.
     */
    public static String render(
            FhtPacket packet, String header, byte[] plaintext, ReplayResult.FragmentGroup fragments) {
        StringBuilder out = new StringBuilder(1024);
        out.append(header).append('\n');
        out.append("-".repeat(Math.min(header.length(), 100))).append('\n');

        if (fragments.isSplit()) {
            out.append("~~ Oversized response: ").append(fragments.describe()).append('\n');
            out.append("~~ Offsets below are into the reassembled message, not into this pragma's "
                    + "own body.\n");
        }
        if (!fragments.complete()) {
            out.append("!! The final fragments were never captured, so this message is cut short.\n");
        }

        if (!packet.outcome().isComplete()) {
            // Stated prominently rather than left implicit: a partial decode must never be
            // mistakable for a complete one.
            out.append("!! ").append(packet.outcome().describe()).append('\n');
            out.append("!! Showing what was recovered; the raw bytes follow at the end.\n");
        }
        if (packet.hasSensitiveValues()) {
            out.append("** This message contains properties flagged as sensitive.\n");
        }
        out.append('\n');

        if (packet.isEmpty()) {
            out.append("(no messages recovered)\n");
        }
        for (int i = 0; i < packet.messages().size(); i++) {
            renderMessage(out, packet.messages().get(i), i);
        }

        if (!packet.outcome().isComplete()) {
            out.append('\n').append("Raw decrypted bytes:\n").append(hexDump(plaintext));
        }
        return out.toString();
    }

    private static void renderMessage(StringBuilder out, FhtMessage message, int index) {
        out.append('[').append(index).append("] ").append(message.action())
                .append("  class=").append(message.classId())
                .append("  handler=").append(message.handlerId())
                .append("  @").append(message.offset())
                .append(String.format("  (raw header 0x%04X)", message.rawHeader()))
                .append('\n');

        for (FhtProperty property : message.properties()) {
            out.append("      ");
            out.append(property.isSensitive() ? "** " : "   ");
            out.append(property.name());
            if (property.id() >= 0) {
                out.append(" (").append(property.id()).append(')');
            }
            out.append(" = ").append(escape(property.value().display()));
            out.append("   @").append(property.offset()).append('+').append(property.length());
            out.append('\n');
        }
        out.append('\n');
    }

    /**
     * Makes a value safe to show on one line. Control characters in values are common in this
     * protocol and would otherwise break the layout.
     */
    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7F) {
                        out.append(String.format("\\x%02X", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /** Classic offset / hex / ASCII dump, used whenever decoding cannot produce something better. */
    public static String hexDump(byte[] data) {
        if (data == null || data.length == 0) {
            return "(empty body)\n";
        }
        int limit = Math.min(data.length, MAX_HEX_BYTES);
        StringBuilder out = new StringBuilder(limit * 4);

        for (int offset = 0; offset < limit; offset += HEX_BYTES_PER_LINE) {
            out.append(String.format("%08X  ", offset));

            StringBuilder ascii = new StringBuilder(HEX_BYTES_PER_LINE);
            for (int i = 0; i < HEX_BYTES_PER_LINE; i++) {
                if (offset + i < limit) {
                    int b = data[offset + i] & 0xFF;
                    out.append(String.format("%02X ", b));
                    ascii.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
                } else {
                    out.append("   ");
                }
                if (i == 7) {
                    out.append(' ');
                }
            }
            out.append(" |").append(ascii).append("|\n");
        }
        if (data.length > limit) {
            out.append("... ").append(data.length - limit).append(" more bytes not shown\n");
        }
        return out.toString();
    }

    /**
     * The display for a NULLPOST request.
     *
     * <p>Deliberately not a hex dump with an error over it. Nothing went wrong: the client sent no
     * payload, and presenting that as a failed decode sends the reader hunting for a bug that is not
     * there.
     */
    public static String renderNullPost(byte[] body, String header, String explanation) {
        StringBuilder out = new StringBuilder(256);
        out.append(header).append('\n');
        out.append("-".repeat(Math.min(header.length(), 100))).append("\n\n");
        out.append("NULLPOST - no payload.\n\n");
        out.append(explanation).append("\n\n");
        out.append(hexDump(body));
        return out.toString();
    }

    /** A best-effort text view of a cleartext body, for pragmas 0 and 1. */
    public static String renderCleartext(byte[] body, String header) {
        StringBuilder out = new StringBuilder();
        out.append(header).append('\n');
        out.append("-".repeat(Math.min(header.length(), 100))).append("\n\n");
        out.append(new String(body, StandardCharsets.ISO_8859_1).replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", "."));
        out.append("\n\n").append(hexDump(body));
        return out.toString();
    }
}
