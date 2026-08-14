package oracleforms.codec;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Builds FHT bytes the way the wire format lays them out, covering every type marker.
 *
 * <p>Shared between the codec tests and the end-to-end injection test, which needs real FHT packets
 * rather than random bytes: the point of that test is that an edited <em>message</em> arrives at the
 * server as an edited message, and that only means something if it parses at both ends.
 */
public final class TestPackets {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public TestPackets u8(int v) {
        out.write(v & 0xFF);
        return this;
    }

    public TestPackets u16(int v) {
        return u8(v >> 8).u8(v);
    }

    public TestPackets i32(int v) {
        return u8(v >> 24).u8(v >> 16).u8(v >> 8).u8(v);
    }

    public TestPackets raw(byte[] bytes) {
        out.writeBytes(bytes);
        return this;
    }

    public TestPackets message(int actionMarker, int classId, int handlerId) {
        u8((actionMarker | classId) >> 8);
        return u16(handlerId);
    }

    public TestPackets int32Property(int id, int value) {
        return u16(0x0000 | id).i32(value);
    }

    public TestPackets implicitZeroProperty(int id) {
        return u16(0x1000 | id);
    }

    public TestPackets uint8Property(int id, int value) {
        return u16(0x2000 | id).u8(value);
    }

    public TestPackets uint16Property(int id, int value) {
        return u16(0x3000 | id).u16(value);
    }

    public TestPackets stringProperty(int id, int slot, String text) {
        return stringPropertyRaw(id, slot, text.getBytes(StandardCharsets.UTF_8));
    }

    public TestPackets stringPropertyRaw(int id, int slot, byte[] utf8) {
        u16(0x4000 | id).u8(slot).u16(utf8.length);
        return raw(utf8);
    }

    public TestPackets boolProperty(int id, boolean value) {
        return u16((value ? 0x5000 : 0x6000) | id);
    }

    public TestPackets byteProperty(int id, int value) {
        return u16(0x7000 | id).u8(value);
    }

    public TestPackets voidProperty(int id) {
        return u16(0x8000 | id);
    }

    public TestPackets backReference(int id, int dstSlot, int srcSlot) {
        return u16(0x9000 | id).u8(dstSlot).u8(srcSlot);
    }

    public TestPackets point16Property(int id, int x, int y) {
        return u16(0xA000 | id).u16(x).u16(y);
    }

    public TestPackets point8Property(int id, int x, int y) {
        return u16(0xC000 | id).u8(x).u8(y);
    }

    /** Extended type, subtype 5 (float), whose payload is four bytes the parser only measures. */
    public TestPackets extFloatProperty(int id, int bits) {
        return u16(0xE000 | id).u8(5).i32(bits);
    }

    /** A type marker the parser has no case for, so it becomes an UnknownValue. */
    public TestPackets unknownMarkerProperty() {
        return u16(0xF123);
    }

    public TestPackets tag(int n) {
        return u8(0xB0 | n);
    }

    public TestPackets deleteMask(int mask) {
        return u8(0xD0).u16(mask);
    }

    public TestPackets endProperties() {
        return u8(0xF0);
    }

    public TestPackets endPacket() {
        return u8(0xF0);
    }

    public byte[] build() {
        return out.toByteArray();
    }
}
