package oracleforms.session;

import java.util.EnumMap;
import java.util.Map;

/**
 * The durable form of a {@link SessionStreams}: four byte counters and a sequence number.
 *
 * <p>This is the whole of what has to survive an extension reload for a diverged session to keep
 * working. An {@link oracleforms.codec.Rc4Stream} at position <i>n</i> is a pure function of the key
 * and <i>n</i>, so nothing about the cipher state itself needs storing — architecture &sect;6.2.
 *
 * <p>The counters are meaningless without the key they were measured under, so the key's
 * fingerprint travels with them. RC4 state is a function of <em>both</em>, and skipping a cipher
 * seeded with key B to a byte count accumulated under key A lands on an offset that corresponds to
 * nothing — which encrypts successfully and is read by the server as noise.
 *
 * @param legs           bytes consumed on each of the four legs
 * @param nextPragma     the sequence number the next injected message should carry
 * @param keyFingerprint identifies the key these counters belong to; see {@link #fingerprint}
 */
public record StreamPositions(Map<StreamLeg, Long> legs, int nextPragma, long keyFingerprint) {

    public StreamPositions {
        Map<StreamLeg, Long> copy = new EnumMap<>(StreamLeg.class);
        for (StreamLeg leg : StreamLeg.values()) {
            long at = legs == null ? 0L : legs.getOrDefault(leg, 0L);
            if (at < 0) {
                throw new IllegalArgumentException("stream position must not be negative: " + at);
            }
            copy.put(leg, at);
        }
        legs = Map.copyOf(copy);
    }

    /**
     * A short, stable identifier for a key.
     *
     * <p>A digest rather than the key itself, so that resuming a ledger does not require a second
     * copy of the session secret in the project file.
     */
    public static long fingerprint(byte[] key) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(key);
            long out = 0;
            for (int i = 0; i < 8; i++) {
                out = (out << 8) | (digest[i] & 0xFF);
            }
            return out;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    /** Whether these counters were measured under {@code key}. */
    public boolean belongsTo(byte[] key) {
        return key != null && keyFingerprint == fingerprint(key);
    }

    public long at(StreamLeg leg) {
        return legs.get(leg);
    }

    /** Whether the client-facing and server-facing legs have parted company. */
    public boolean diverged() {
        return at(StreamLeg.CLIENT_REQUEST) != at(StreamLeg.SERVER_REQUEST)
                || at(StreamLeg.SERVER_RESPONSE) != at(StreamLeg.CLIENT_RESPONSE);
    }
}
