package oracleforms.codec;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import oracleforms.codec.model.FhtMessage;
import oracleforms.codec.model.FhtPacket;
import oracleforms.codec.model.FhtProperty;
import oracleforms.codec.model.ParseOutcome;
import oracleforms.codec.model.PropertyValue;

/**
 * Decrypted FHT bytes to a {@link FhtPacket}.
 *
 * <p>Never throws on malformed input: a short or corrupt packet yields whatever was recovered plus a
 * {@link ParseOutcome} saying where it stopped. Byte offsets are recorded for every property so that
 * a later re-encoder can edit structurally.
 */
public final class FhtParser {

    private static final int TERMINATOR = 0xF0;
    private static final int TAG_MARKER = 0xB0;
    private static final int DELETE_MASK_MARKER = 0xD0;

    private static final Map<Integer, String> ACTIONS = Map.of(
            0x0000, "CREATE",
            0x1000, "UPDATE",
            0x2000, "DESTROY",
            0x3000, "GET",
            0x4000, "ACTION_5",
            0x5000, "ACTION_6",
            0x6000, "CLIENT_GET",
            0x7000, "CLIENT_SET");

    /** Actions that carry an extra delta-index byte before the handler id. */
    private static final int ACTION_5 = 0x4000;
    private static final int ACTION_6 = 0x5000;

    /**
     * Parses a packet, updating {@code dictionary} as it goes.
     *
     * <p>The dictionary is supplied rather than created so the caller controls whether it is scoped
     * to the packet or to the session.
     */
    public FhtPacket parse(byte[] plaintext, StringDictionary dictionary) {
        FhtReader r = new FhtReader(plaintext);
        List<FhtMessage> messages = new ArrayList<>();
        ParseOutcome outcome;

        try {
            while (r.hasRemaining()) {
                if (r.peek() == TERMINATOR) {
                    r.skip(1);
                    break;
                }
                FhtMessage message = readMessage(r, dictionary, messages);
                if (message == null) {
                    break;
                }
                messages.add(message);
            }
            outcome = new ParseOutcome.Complete();
        } catch (FhtTruncatedException e) {
            outcome = new ParseOutcome.Truncated(e.offset(), e.getMessage());
        } catch (RuntimeException e) {
            // Defensive: the target's bytes are untrusted, and a bug here must not blank the tab.
            outcome = new ParseOutcome.Failed(r.position(), e.toString());
        }

        return new FhtPacket(messages, outcome, plaintext.length);
    }

    /**
     * Reads one message.
     *
     * <p>{@code partialSink} receives the message if a read runs off the end partway through its
     * properties. Without that, a truncated packet would lose every property it had already
     * recovered — the packet would report "stopped at offset N" while showing nothing, which is the
     * blank tab {@link ParseOutcome} exists to prevent.
     */
    private FhtMessage readMessage(FhtReader r, StringDictionary dict, List<FhtMessage> partialSink)
            throws FhtTruncatedException {
        int offset = r.position();
        int b0 = r.u8();
        if (b0 == TERMINATOR) {
            return null;
        }

        int header = b0 << 8;
        // A leading nibble of 0x0 or 0x4 means the header is two bytes wide.
        if ((header & 0xF000) == 0x0000 || (header & 0xF000) == 0x4000) {
            header |= r.u8();
        }

        int actionMarker = header & 0xF000;
        String action = ACTIONS.getOrDefault(actionMarker, "ACTION_" + (actionMarker >>> 12));

        if (actionMarker == ACTION_5 || actionMarker == ACTION_6) {
            r.u8(); // delta index, unused
        }

        // See FhtMessage.rawHeader: 0x0FFF rather than the reference's 0x3FF, which made the
        // adjustment below dead code.
        int classId = header & 0x0FFF;
        if (classId >= 2000) {
            classId += 3000;
        }

        int handlerId = r.optionalUint();

        List<FhtProperty> properties = new ArrayList<>();
        try {
            readProperties(r, dict, properties);
        } catch (FhtTruncatedException e) {
            partialSink.add(new FhtMessage(action, classId, handlerId, properties, offset, header));
            throw e;
        }

        return new FhtMessage(action, classId, handlerId, properties, offset, header);
    }

    /** Appends to {@code props} as it goes, so a truncation leaves the caller what was recovered. */
    private void readProperties(FhtReader r, StringDictionary dict, List<FhtProperty> props)
            throws FhtTruncatedException {
        while (true) {
            int offset = r.position();
            int b0 = r.u8();

            if (b0 == TERMINATOR) {
                break;
            }
            if ((b0 & 0xF0) == TAG_MARKER) {
                props.add(new FhtProperty(FhtProperty.PSEUDO_ID, "TAG",
                        new PropertyValue.IntValue(b0 & 0x0F), offset, r.position() - offset));
                continue;
            }
            if ((b0 & 0xF0) == DELETE_MASK_MARKER) {
                int mask = r.u16();
                props.add(new FhtProperty(FhtProperty.PSEUDO_ID, "DELETE_MASK",
                        new PropertyValue.IntValue(mask), offset, r.position() - offset));
                continue;
            }

            int combined = (b0 << 8) | r.u8();
            int typeMarker = combined & 0xF000;
            int id = combined & 0x0FFF;

            PropertyValue value = readValue(r, typeMarker, dict);
            props.add(new FhtProperty(id, PropertyIds.name(id), value, offset,
                    r.position() - offset));
        }
    }

    private PropertyValue readValue(FhtReader r, int typeMarker, StringDictionary dict)
            throws FhtTruncatedException {
        switch (typeMarker) {
            case 0x0000:
                return new PropertyValue.IntValue(r.i32());
            case 0x1000:
                return new PropertyValue.IntValue(0);
            case 0x2000:
                return new PropertyValue.IntValue(r.u8());
            case 0x3000:
                return new PropertyValue.IntValue(r.u16());
            case 0x4000: {
                int slot = r.u8();
                String text = r.utf();
                dict.put(slot, text);
                return new PropertyValue.StrValue(text);
            }
            case 0x5000:
                return new PropertyValue.BoolValue(true);
            case 0x6000:
                return new PropertyValue.BoolValue(false);
            case 0x7000:
                return new PropertyValue.ByteValue(r.i8());
            case 0x8000:
                return new PropertyValue.VoidValue();
            case 0x9000: {
                // Back-reference: copy a dictionary slot into another.
                int dst = r.u8();
                int src = r.u8();
                String text = dict.get(src);
                dict.put(dst, text);
                return new PropertyValue.StrValue(text);
            }
            case 0xA000:
                return new PropertyValue.PointValue(r.i16(), r.i16());
            case 0xC000:
                return new PropertyValue.PointValue(r.u8(), r.u8());
            case 0xE000: {
                int subtype = r.i8();
                int start = r.position();
                skipExtended(r, subtype, dict);
                return new PropertyValue.ExtValue(subtype, r.position() - start);
            }
            default:
                return new PropertyValue.UnknownValue(typeMarker);
        }
    }

    private void skipExtended(FhtReader r, int subtype, StringDictionary dict)
            throws FhtTruncatedException {
        switch (subtype) {
            case 2: { // String[]
                // The count comes off the wire, so it is untrusted and may be huge or negative.
                // Each entry costs at least its 2-byte length prefix, so the remaining buffer is a
                // hard upper bound on how many can really be present.
                int n = r.i32();
                int max = r.remaining() / 2;
                for (int i = 0; i < n && i < max; i++) {
                    r.utf();
                }
                break;
            }
            case 4: // Character
                r.skip(2);
                break;
            case 5: // Float
                r.skip(4);
                break;
            case 6: // Date / Long
                r.skip(8);
                break;
            case 7:
            case 15: { // byte[]
                int n = r.i32();
                r.skip(Math.max(0, n));
                break;
            }
            case 8: // nested message properties
                readProperties(r, dict, new ArrayList<>());
                break;
            case 10: // Rectangle
                r.skip(8);
                break;
            default:
                // Unknown subtype: no length information, so nothing can safely be skipped.
                // Leaving the cursor put means the next read will most likely report truncation
                // at this offset, which is the honest outcome.
                break;
        }
    }
}
