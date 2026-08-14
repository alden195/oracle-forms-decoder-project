package oracleforms.codec;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.PropertyValue;

/**
 * Re-encodes edited properties back into a decrypted FHT packet.
 *
 * <h2>Why this splices rather than re-serializing</h2>
 *
 * <p>Architecture &sect;6.3 originally preferred rebuilding the whole packet from the model. That is
 * not available, because <strong>{@link FhtParser} is deliberately lossy</strong>: it discards the
 * delta-index byte on {@code ACTION_5}/{@code ACTION_6} messages, keeps only the subtype and length
 * of an {@link PropertyValue.ExtValue} rather than its payload, resolves back-references into plain
 * strings without recording which dictionary slots produced them, and never records the slot number a
 * literal string was stored into. Re-serializing from that model would silently rewrite bytes nobody
 * asked to change — on a shared, continuous RC4 stream, where the blast radius of a wrong byte is
 * every message after it in the session.
 *
 * <p>So this class copies the original packet verbatim and replaces only the byte ranges the parser
 * recorded for the edited properties. Everything untouched is untouched <em>by construction</em>,
 * which is a much stronger guarantee than any test can give.
 *
 * <h2>The identity gate</h2>
 *
 * <p>Splicing is only as safe as the encoder that produces the replacement bytes. So before any edit
 * is applied, {@link #roundTrips} re-encodes the property with its <em>unchanged</em> value and
 * checks the result is byte-identical to what is already there. If the encoder cannot reproduce bytes
 * it can read, it does not get to replace them.
 *
 * <p>That check runs on every edit at runtime, not only in tests. It is what lets the writer be
 * honest about types it only partly understands: an encoding this class gets subtly wrong shows up as
 * a refused edit rather than as a corrupted session.
 */
public final class FhtWriter {

    /** Type markers, matching the value decoder in {@link FhtParser}. */
    private static final int T_INT32 = 0x0000;
    private static final int T_INT_ZERO = 0x1000;
    private static final int T_UINT8 = 0x2000;
    private static final int T_UINT16 = 0x3000;
    private static final int T_STRING = 0x4000;
    private static final int T_TRUE = 0x5000;
    private static final int T_FALSE = 0x6000;
    private static final int T_BYTE = 0x7000;
    private static final int T_VOID = 0x8000;
    private static final int T_BACKREF = 0x9000;
    private static final int T_POINT16 = 0xA000;
    private static final int T_POINT8 = 0xC000;
    private static final int T_EXT = 0xE000;

    private FhtWriter() {
    }

    /**
     * Why this property cannot be edited, or empty when it can be.
     *
     * <p>The string is shown to the user, so it says what is wrong rather than naming a type marker.
     */
    public static Optional<String> editRefusal(byte[] plaintext, FhtProperty property) {
        if (plaintext == null || property == null) {
            return Optional.of("no property selected");
        }
        if (property.id() == FhtProperty.PSEUDO_ID) {
            return Optional.of("structural marker, not a value");
        }
        if (property.length() < 2 || property.offset() < 0
                || property.offset() + property.length() > plaintext.length) {
            return Optional.of("the property's bytes run past the end of the message");
        }

        int marker = headerOf(plaintext, property) & 0xF000;
        Optional<String> unsupported = switch (marker) {
            case T_INT32, T_UINT8, T_UINT16, T_STRING, T_TRUE, T_FALSE, T_BYTE, T_BACKREF,
                 T_POINT16, T_POINT8 -> Optional.<String>empty();
            case T_INT_ZERO -> Optional.of("implicit zero: the encoding has no value field to change");
            case T_VOID -> Optional.of("void: the property has no value");
            case T_EXT -> Optional.of("extended type: the payload is not decoded, only measured");
            default -> Optional.of(String.format("unrecognised type marker 0x%04X", marker));
        };
        if (unsupported.isPresent()) {
            return unsupported;
        }

        // The decisive check: if re-encoding what is already there does not reproduce it, this
        // encoder does not understand the property well enough to be trusted with a change.
        if (!roundTrips(plaintext, property)) {
            return Optional.of("re-encoding this value does not reproduce the original bytes");
        }
        return Optional.empty();
    }

    /** Whether the property can be edited. Shorthand for {@link #editRefusal} being empty. */
    public static boolean isEditable(byte[] plaintext, FhtProperty property) {
        return editRefusal(plaintext, property).isEmpty();
    }

    /**
     * The identity check: does re-encoding with the unchanged value reproduce the original bytes?
     *
     * <p>Never throws. A property this cannot encode simply does not round-trip.
     */
    public static boolean roundTrips(byte[] plaintext, FhtProperty property) {
        try {
            byte[] encoded = encodeProperty(plaintext, property, property.value());
            return Arrays.equals(
                    encoded,
                    Arrays.copyOfRange(plaintext, property.offset(),
                            property.offset() + property.length()));
        } catch (FhtUnwritableException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Re-encodes one property, header included, with {@code newValue} in place of its own.
     *
     * <p>The original bytes are consulted for everything the model does not carry — the type marker,
     * a literal string's dictionary slot, a back-reference's slot pair — so the result differs from
     * the original in exactly the value and nothing else.
     */
    public static byte[] encodeProperty(
            byte[] plaintext, FhtProperty property, PropertyValue newValue)
            throws FhtUnwritableException {

        int offset = property.offset();
        int length = property.length();
        if (offset < 0 || length < 0 || offset + length > plaintext.length) {
            throw new FhtUnwritableException(offset,
                    "property bytes [" + offset + ", " + (offset + length) + ") are outside the "
                            + plaintext.length + "-byte message");
        }

        // Structural markers (TAG, DELETE_MASK) and anything the parser could not type are copied
        // exactly. They are never editable, so this path only ever runs for an identity rewrite.
        if (property.id() == FhtProperty.PSEUDO_ID) {
            return verbatim(plaintext, property, newValue);
        }
        if (length < 2) {
            throw new FhtUnwritableException(offset, "property is shorter than its own header");
        }

        int header = headerOf(plaintext, property);
        int marker = header & 0xF000;
        int id = header & 0x0FFF;
        int valueAt = offset + 2;
        int valueLength = length - 2;

        return switch (marker) {
            case T_INT32 -> header(header, int32(offset, newValue));
            case T_UINT8 -> header(header, u8(offset, newValue, "8-bit integer"));
            case T_UINT16 -> header(header, u16(offset, newValue));
            case T_BYTE -> header(header, i8(offset, newValue));
            case T_POINT16 -> header(header, point16(offset, newValue));
            case T_POINT8 -> header(header, point8(offset, newValue));
            case T_STRING -> header(header, stringValue(plaintext, offset, valueAt, newValue));
            case T_TRUE, T_FALSE -> bool(offset, id, newValue);
            case T_BACKREF -> backReference(plaintext, property, offset, id, valueAt, newValue);
            default -> verbatim(plaintext, property, newValue);
        };
    }

    /**
     * Applies edits to a decrypted packet, returning the new plaintext.
     *
     * <p>Every edit is verified before any byte is written: overlapping or out-of-range edits are
     * rejected, and each property must pass the identity round-trip. Either the whole edit set
     * applies or none of it does — a half-applied packet is worse than an unapplied one, because it
     * will still encrypt cleanly and be misparsed at the far end.
     */
    public static byte[] applyEdits(byte[] plaintext, List<FhtEdit> edits)
            throws FhtUnwritableException {

        List<FhtEdit> pending = new ArrayList<>();
        for (FhtEdit edit : edits) {
            if (!edit.isNoOp()) {
                pending.add(edit);
            }
        }
        if (pending.isEmpty()) {
            return plaintext.clone();
        }
        pending.sort(Comparator.comparingInt(FhtEdit::offset));

        int previousEnd = 0;
        for (FhtEdit edit : pending) {
            if (edit.offset() < previousEnd) {
                throw new FhtUnwritableException(edit.offset(),
                        "two edits cover the same bytes; the packet would be corrupted");
            }
            if (edit.offset() < 0 || edit.endOffset() > plaintext.length) {
                throw new FhtUnwritableException(edit.offset(),
                        "edit falls outside the " + plaintext.length + "-byte message");
            }
            Optional<String> refusal = editRefusal(plaintext, edit.property());
            if (refusal.isPresent()) {
                throw new FhtUnwritableException(edit.offset(),
                        "cannot edit " + edit.property().name() + ": " + refusal.get());
            }
            previousEnd = edit.endOffset();
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(plaintext.length + 64);
        int copied = 0;
        for (FhtEdit edit : pending) {
            out.write(plaintext, copied, edit.offset() - copied);
            byte[] replacement = encodeProperty(plaintext, edit.property(), edit.newValue());
            out.write(replacement, 0, replacement.length);
            copied = edit.endOffset();
        }
        out.write(plaintext, copied, plaintext.length - copied);
        return out.toByteArray();
    }

    // ---- value encoders -------------------------------------------------------------------

    private static byte[] header(int header, byte[] value) {
        byte[] out = new byte[2 + value.length];
        out[0] = (byte) (header >>> 8);
        out[1] = (byte) header;
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }

    private static byte[] int32(int offset, PropertyValue value) throws FhtUnwritableException {
        int n = intOf(offset, value, "32-bit integer");
        return new byte[]{(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
    }

    private static byte[] u8(int offset, PropertyValue value, String what)
            throws FhtUnwritableException {
        int n = intOf(offset, value, what);
        if (n < 0 || n > 0xFF) {
            throw new FhtUnwritableException(offset, n + " does not fit in an unsigned byte");
        }
        return new byte[]{(byte) n};
    }

    private static byte[] u16(int offset, PropertyValue value) throws FhtUnwritableException {
        int n = intOf(offset, value, "16-bit integer");
        if (n < 0 || n > 0xFFFF) {
            throw new FhtUnwritableException(offset, n + " does not fit in an unsigned 16-bit field");
        }
        return new byte[]{(byte) (n >>> 8), (byte) n};
    }

    private static byte[] i8(int offset, PropertyValue value) throws FhtUnwritableException {
        if (!(value instanceof PropertyValue.ByteValue b)) {
            throw new FhtUnwritableException(offset, "expected a byte value, got " + shape(value));
        }
        return new byte[]{b.value()};
    }

    private static byte[] point16(int offset, PropertyValue value) throws FhtUnwritableException {
        if (!(value instanceof PropertyValue.PointValue p)) {
            throw new FhtUnwritableException(offset, "expected a point, got " + shape(value));
        }
        if (p.x() < Short.MIN_VALUE || p.x() > Short.MAX_VALUE
                || p.y() < Short.MIN_VALUE || p.y() > Short.MAX_VALUE) {
            throw new FhtUnwritableException(offset, "point coordinates do not fit in 16 bits");
        }
        return new byte[]{
                (byte) (p.x() >>> 8), (byte) p.x(),
                (byte) (p.y() >>> 8), (byte) p.y()};
    }

    private static byte[] point8(int offset, PropertyValue value) throws FhtUnwritableException {
        if (!(value instanceof PropertyValue.PointValue p)) {
            throw new FhtUnwritableException(offset, "expected a point, got " + shape(value));
        }
        if (p.x() < 0 || p.x() > 0xFF || p.y() < 0 || p.y() > 0xFF) {
            throw new FhtUnwritableException(offset,
                    "point coordinates do not fit in unsigned bytes");
        }
        return new byte[]{(byte) p.x(), (byte) p.y()};
    }

    /**
     * A literal string: one dictionary slot byte, then a 16-bit length and that many UTF-8 bytes.
     *
     * <p>The slot is read from the original encoding rather than invented. It is a side effect the
     * message carries — later properties resolve back-references against it — so changing it would
     * change what a completely different property means.
     */
    private static byte[] stringValue(
            byte[] plaintext, int offset, int valueAt, PropertyValue value)
            throws FhtUnwritableException {

        if (!(value instanceof PropertyValue.StrValue s)) {
            throw new FhtUnwritableException(offset, "expected a string, got " + shape(value));
        }
        if (valueAt >= plaintext.length) {
            throw new FhtUnwritableException(offset, "string property has no dictionary slot byte");
        }
        return literalString(offset, plaintext[valueAt] & 0xFF, s.value());
    }

    private static byte[] literalString(int offset, int slot, String text)
            throws FhtUnwritableException {

        // FhtReader decodes with standard UTF-8, so this encodes with standard UTF-8. Java's
        // DataInput.readUTF uses *modified* UTF-8, which differs for NUL and for characters outside
        // the BMP; if this target turns out to use that instead, the identity check fails on any
        // string containing one and the property is refused rather than mangled.
        byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        if (utf8.length > 0xFFFF) {
            throw new FhtUnwritableException(offset,
                    "string is " + utf8.length + " bytes; the length field holds at most 65535");
        }
        byte[] out = new byte[3 + utf8.length];
        out[0] = (byte) slot;
        out[1] = (byte) (utf8.length >>> 8);
        out[2] = (byte) utf8.length;
        System.arraycopy(utf8, 0, out, 3, utf8.length);
        return out;
    }

    /**
     * A boolean, whose value lives in the type marker rather than in a value field.
     *
     * <p>Flipping one rewrites the two header bytes and leaves the length unchanged, so it is the one
     * edit that cannot shift anything downstream.
     */
    private static byte[] bool(int offset, int id, PropertyValue value)
            throws FhtUnwritableException {

        if (!(value instanceof PropertyValue.BoolValue b)) {
            throw new FhtUnwritableException(offset, "expected a boolean, got " + shape(value));
        }
        return header(id | (b.value() ? T_TRUE : T_FALSE), new byte[0]);
    }

    /**
     * A back-reference: "copy dictionary slot {@code src} into slot {@code dst}".
     *
     * <p>Unchanged, it is rewritten as the same four bytes. Changed, it is <em>promoted</em> to a
     * literal string stored into the same {@code dst} slot. That is what keeps the edit local: the
     * back-reference's only observable effect besides its own value is the dictionary write, and a
     * literal into the same slot performs exactly that write. Any later property referring to
     * {@code dst} therefore sees the new text, which is what a user changing a string expects.
     *
     * <p>This is an inference from the client's own parser rather than something observed on the
     * wire — the two forms are interchangeable there, and a self-describing format should accept
     * either. Nothing is promoted unless the user actually changes the value.
     */
    private static byte[] backReference(
            byte[] plaintext, FhtProperty property, int offset, int id, int valueAt,
            PropertyValue value) throws FhtUnwritableException {

        if (!(value instanceof PropertyValue.StrValue s)) {
            throw new FhtUnwritableException(offset,
                    "expected a string for a back-reference, got " + shape(value));
        }
        if (value.equals(property.value())) {
            return verbatim(plaintext, property, value);
        }
        if (valueAt + 1 >= plaintext.length) {
            throw new FhtUnwritableException(offset, "back-reference is missing its slot bytes");
        }
        int dst = plaintext[valueAt] & 0xFF;
        return header(id | T_STRING, literalString(offset, dst, s.value()));
    }

    /** Copies the property's original bytes, permitted only when the value is unchanged. */
    private static byte[] verbatim(byte[] plaintext, FhtProperty property, PropertyValue newValue)
            throws FhtUnwritableException {

        if (!newValue.equals(property.value())) {
            throw new FhtUnwritableException(property.offset(),
                    "this property's encoding is not understood well enough to change it");
        }
        return Arrays.copyOfRange(plaintext, property.offset(),
                property.offset() + property.length());
    }

    // ---- helpers --------------------------------------------------------------------------

    private static int headerOf(byte[] plaintext, FhtProperty property) {
        return ((plaintext[property.offset()] & 0xFF) << 8)
                | (plaintext[property.offset() + 1] & 0xFF);
    }

    private static int intOf(int offset, PropertyValue value, String what)
            throws FhtUnwritableException {
        if (value instanceof PropertyValue.IntValue i) {
            return i.value();
        }
        throw new FhtUnwritableException(offset,
                "expected " + what + ", got " + shape(value));
    }

    private static String shape(PropertyValue value) {
        return value.getClass().getSimpleName();
    }
}
