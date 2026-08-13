package oracleforms.codec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.ParseOutcome;
import oracleforms.codec.model.PropertyValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FhtParserTest {

    private final FhtParser parser = new FhtParser();

    /** Builds FHT bytes the way the wire format lays them out. */
    private static final class PacketBuilder {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        PacketBuilder u8(int v) {
            out.write(v & 0xFF);
            return this;
        }

        PacketBuilder u16(int v) {
            return u8(v >> 8).u8(v);
        }

        PacketBuilder i32(int v) {
            return u8(v >> 24).u8(v >> 16).u8(v >> 8).u8(v);
        }

        /** Single-byte header: action marker in the high nibble, class id in the rest. */
        PacketBuilder message(int actionMarker, int classId, int handlerId) {
            u8((actionMarker | classId) >> 8);
            return u16(handlerId);
        }

        PacketBuilder intProperty(int id, int value) {
            return u16(0x0000 | id).i32(value);
        }

        PacketBuilder stringProperty(int id, int slot, String text) {
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            u16(0x4000 | id).u8(slot).u16(bytes.length);
            out.writeBytes(bytes);
            return this;
        }

        PacketBuilder backReference(int id, int dstSlot, int srcSlot) {
            return u16(0x9000 | id).u8(dstSlot).u8(srcSlot);
        }

        PacketBuilder boolProperty(int id, boolean value) {
            return u16((value ? 0x5000 : 0x6000) | id);
        }

        PacketBuilder endProperties() {
            return u8(0xF0);
        }

        PacketBuilder endPacket() {
            return u8(0xF0);
        }

        byte[] build() {
            return out.toByteArray();
        }
    }

    @Test
    @DisplayName("parses a well-formed packet completely")
    void parsesWellFormedPacket() {
        byte[] bytes = new PacketBuilder()
                .message(0x1000, 0, 42)
                .intProperty(5, 99)
                .stringProperty(1, 0, "hello")
                .boolProperty(7, true)
                .endProperties()
                .endPacket()
                .build();

        FhtPacket packet = parser.parse(bytes, new StringDictionary());

        assertTrue(packet.outcome().isComplete(), packet.outcome().describe());
        assertEquals(1, packet.messages().size());

        FhtMessage message = packet.messages().get(0);
        assertEquals("UPDATE", message.action());
        assertEquals(42, message.handlerId());
        assertEquals(3, message.properties().size());

        assertEquals(new PropertyValue.IntValue(99), message.properties().get(0).value());
        assertEquals(new PropertyValue.StrValue("hello"), message.properties().get(1).value());
        assertEquals(new PropertyValue.BoolValue(true), message.properties().get(2).value());
    }

    @Test
    @DisplayName("records byte offsets so edits can be applied structurally")
    void recordsPropertyOffsets() {
        byte[] bytes = new PacketBuilder()
                .message(0x1000, 0, 1)
                .intProperty(5, 7)
                .stringProperty(1, 0, "abc")
                .endProperties()
                .endPacket()
                .build();

        FhtMessage message = parser.parse(bytes, new StringDictionary()).messages().get(0);

        // Header is 1 byte, handler id 2 -> first property starts at offset 3 and spans 2 + 4 bytes.
        assertEquals(3, message.properties().get(0).offset());
        assertEquals(6, message.properties().get(0).length());

        // The string property follows it, spanning 2 header + 1 slot + 2 length + 3 text.
        assertEquals(9, message.properties().get(1).offset());
        assertEquals(8, message.properties().get(1).length());

        // Offsets must actually address the property inside the original buffer.
        int off = message.properties().get(1).offset();
        assertEquals(0x40, bytes[off] & 0xF0);
    }

    @Test
    @DisplayName("resolves a back-reference through the string dictionary")
    void resolvesBackReference() {
        byte[] bytes = new PacketBuilder()
                .message(0x1000, 0, 1)
                .stringProperty(1, 12, "remembered")
                .backReference(2, 13, 12)
                .endProperties()
                .endPacket()
                .build();

        FhtPacket packet = parser.parse(bytes, new StringDictionary());
        assertEquals(new PropertyValue.StrValue("remembered"),
                packet.messages().get(0).properties().get(1).value());
    }

    /**
     * The dictionary is supplied by the caller precisely so this can differ. A back-reference to a
     * slot filled by an <em>earlier packet</em> resolves only if the caller carries the dictionary
     * over -- architecture §7.2's open question, made testable.
     */
    @Test
    @DisplayName("a cross-packet back-reference resolves only with a carried dictionary")
    void crossPacketBackReferenceDependsOnScope() {
        byte[] first = new PacketBuilder()
                .message(0x1000, 0, 1).stringProperty(1, 30, "from-packet-one")
                .endProperties().endPacket().build();
        byte[] second = new PacketBuilder()
                .message(0x1000, 0, 2).backReference(2, 31, 30)
                .endProperties().endPacket().build();

        StringDictionary carried = new StringDictionary();
        parser.parse(first, carried);
        FhtPacket sessionScoped = parser.parse(second, carried);
        assertEquals(new PropertyValue.StrValue("from-packet-one"),
                sessionScoped.messages().get(0).properties().get(0).value());

        FhtPacket packetScoped = parser.parse(second, new StringDictionary());
        assertEquals(new PropertyValue.StrValue(""),
                packetScoped.messages().get(0).properties().get(0).value(),
                "with a fresh dictionary the value silently vanishes -- the failure mode §7.2 warns about");
    }

    @Test
    @DisplayName("a truncated packet yields partial results and says where it stopped")
    void truncationIsReportedNotSwallowed() {
        byte[] full = new PacketBuilder()
                .message(0x1000, 0, 1)
                .intProperty(5, 99)
                .stringProperty(1, 0, "this string is cut off")
                .endProperties()
                .endPacket()
                .build();
        byte[] cut = java.util.Arrays.copyOf(full, full.length - 10);

        FhtPacket packet = parser.parse(cut, new StringDictionary());

        assertFalse(packet.outcome().isComplete());
        ParseOutcome.Truncated truncated =
                assertInstanceOf(ParseOutcome.Truncated.class, packet.outcome());
        assertTrue(truncated.offset() > 0);
        assertTrue(truncated.describe().contains("offset"));

        // The int property read before the cut is still recovered.
        assertEquals(1, packet.messages().size());
        assertEquals(new PropertyValue.IntValue(99),
                packet.messages().get(0).properties().get(0).value());
    }

    @Test
    @DisplayName("never throws on arbitrary bytes, however malformed")
    void fuzzNeverThrows() {
        Random random = new Random(20260813L);
        for (int i = 0; i < 3000; i++) {
            byte[] junk = new byte[random.nextInt(600)];
            random.nextBytes(junk);

            FhtPacket packet = parser.parse(junk, new StringDictionary());

            assertNotNull(packet, "parser must always return a packet");
            assertNotNull(packet.outcome());
            assertNotNull(packet.messages());
        }
    }

    @Test
    @DisplayName("an empty body parses to an empty, complete packet")
    void emptyBody() {
        FhtPacket packet = parser.parse(new byte[0], new StringDictionary());
        assertTrue(packet.outcome().isComplete());
        assertTrue(packet.isEmpty());
    }

    @Test
    @DisplayName("a huge declared array count cannot make the parser hang or allocate")
    void hostileArrayCountIsBounded() {
        // Extended type 0xE000, subtype 2 (String[]), claiming Integer.MAX_VALUE entries.
        byte[] bytes = new PacketBuilder()
                .message(0x1000, 0, 1)
                .u16(0xE000 | 9).u8(2).i32(Integer.MAX_VALUE)
                .endProperties()
                .endPacket()
                .build();

        FhtPacket packet = parser.parse(bytes, new StringDictionary());
        assertNotNull(packet);
        assertFalse(packet.outcome().isComplete(),
                "the claimed count outruns the buffer, which must be reported");
    }
}
