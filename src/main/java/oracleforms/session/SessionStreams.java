package oracleforms.session;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import oracleforms.codec.Rc4Stream;

/**
 * The four cipher states of one live session, and the byte counts that define them.
 *
 * <p>This is the ledger architecture &sect;6.2 describes. Its whole job is to let the client side and
 * the server side of the proxy sit at <em>different</em> keystream positions while each stays
 * internally consistent — which is what makes both a length-changing edit and an injected Repeater
 * message survivable by a session that is still running.
 *
 * <h2>Why the counters exist alongside the ciphers</h2>
 *
 * <p>An {@link Rc4Stream} at position <i>n</i> is a pure function of the key and <i>n</i>: nothing
 * else influences it. So the durable form of this object is four {@code long}s, not four 256-byte
 * S-boxes, and {@link #resumedAt} rebuilds every cipher with one {@code skip} each. That is what lets
 * a divergence survive an extension reload for the cost of four numbers in the project file — the
 * caveat &sect;6.2 used to carry, removed.
 *
 * <p>The live ciphers are kept as well, because rebuilding on every message would be quadratic in
 * exactly the case that already costs the most.
 *
 * <h2>NULLPOST</h2>
 *
 * <p>{@link #apply} enforces the outbound half of the {@code NULLPOST} rule: the sentinel is written
 * straight to the socket without passing through the cipher, so it must contribute zero bytes to the
 * request keystream. Architecture &sect;6.6 listed this as a separate {@code OutboundEncoder}; it is
 * two lines and it belongs next to the state it protects, so it lives here instead.
 *
 * <p>Thread-safe: the HTTP handler touches this from Burp's request and response threads.
 */
public final class SessionStreams {

    private final String sessionId;
    private final byte[] key;
    private final Map<StreamLeg, Rc4Stream> ciphers = new EnumMap<>(StreamLeg.class);
    private final Map<StreamLeg, Long> consumed = new EnumMap<>(StreamLeg.class);

    /**
     * The number an injected message should carry.
     *
     * <p>Tracked here rather than recomputed from history because history stops being the authority
     * the moment the extension sends something of its own: after one injection the session has a
     * pragma the capture has never seen.
     */
    private int nextPragma;

    private SessionStreams(
            String sessionId, byte[] key, Map<StreamLeg, Long> positions, int nextPragma) {
        this.sessionId = sessionId;
        this.key = key.clone();
        this.nextPragma = Math.max(nextPragma, StreamReplayer.FIRST_ENCRYPTED_PRAGMA);
        for (StreamLeg leg : StreamLeg.values()) {
            long at = positions.getOrDefault(leg, 0L);
            if (at < 0) {
                throw new IllegalArgumentException("stream position must not be negative: " + at);
            }
            Rc4Stream cipher = new Rc4Stream(this.key);
            skipTo(cipher, at);
            ciphers.put(leg, cipher);
            consumed.put(leg, at);
        }
    }

    /** All four legs at keystream offset zero, which is where pragma 3 starts. */
    public static SessionStreams atOrigin(String sessionId, byte[] key) {
        return new SessionStreams(sessionId, key, Map.of(), StreamReplayer.FIRST_ENCRYPTED_PRAGMA);
    }

    /**
     * All four legs at the positions a session's captured traffic implies: both request legs at the
     * request tail, both response legs at the response tail. This is the undiverged state, and it is
     * where a session that has only ever been observed — never edited — always sits.
     */
    public static SessionStreams atTail(String sessionId, byte[] key, SessionTail tail) {
        return new SessionStreams(sessionId, key, Map.of(
                StreamLeg.CLIENT_REQUEST, tail.requestBytes(),
                StreamLeg.SERVER_REQUEST, tail.requestBytes(),
                StreamLeg.SERVER_RESPONSE, tail.responseBytes(),
                StreamLeg.CLIENT_RESPONSE, tail.responseBytes()), tail.nextPragma());
    }

    /** Rebuilds a diverged ledger from its persisted counters. */
    public static SessionStreams resumedAt(
            String sessionId, byte[] key, StreamPositions positions) {
        return new SessionStreams(sessionId, key, positions.legs(), positions.nextPragma());
    }

    public String sessionId() {
        return sessionId;
    }

    /** The {@code Pragma} number the next message this extension sends should carry. */
    public synchronized int nextPragma() {
        return nextPragma;
    }

    /**
     * Records that a pragma has gone by, so the next injected one follows it.
     *
     * <p>Called both when the extension injects a message and when it watches the real client send
     * one. Monotonic: a retransmission or an out-of-order callback cannot pull the sequence back.
     */
    public synchronized void notePragma(int pragma) {
        nextPragma = Math.max(nextPragma, pragma + 1);
    }

    public synchronized long consumed(StreamLeg leg) {
        return consumed.get(leg);
    }

    /** The counters and sequence number, in the form the project file persists. */
    public synchronized StreamPositions positions() {
        return new StreamPositions(consumed, nextPragma, StreamPositions.fingerprint(key));
    }

    /**
     * Whether the client-facing and server-facing legs have parted company.
     *
     * <p>False for every session that has only been watched. Once true, the ledger is no longer
     * reconstructible from proxy history alone and has to be persisted to survive a reload.
     */
    public synchronized boolean diverged() {
        return !consumed.get(StreamLeg.CLIENT_REQUEST).equals(consumed.get(StreamLeg.SERVER_REQUEST))
                || !consumed.get(StreamLeg.SERVER_RESPONSE)
                        .equals(consumed.get(StreamLeg.CLIENT_RESPONSE));
    }

    /**
     * Applies a leg's keystream to a body, advancing that leg by what the body contributed.
     *
     * <p>RC4 is symmetric, so this both encrypts and decrypts; which one it is depends only on
     * whether the caller handed in plaintext or ciphertext.
     *
     * @return the transformed bytes, or the input unchanged if it is a cleartext {@code NULLPOST}
     */
    public synchronized byte[] apply(StreamLeg leg, byte[] body) {
        if (body == null || body.length == 0) {
            return new byte[0];
        }
        if (leg.direction() == Direction.REQUEST && PragmaBody.isNullPost(body)) {
            // Never encrypted on the wire, so it must not consume keystream here either. Advancing
            // over its eight bytes desynchronises every later request in the session.
            return body.clone();
        }
        byte[] out = ciphers.get(leg).applied(body);
        consumed.merge(leg, (long) body.length, Long::sum);
        return out;
    }

    /**
     * Records a message that passed through unchanged, advancing both legs of its direction.
     *
     * <p>This is the ordinary case — the client says something, Burp forwards it verbatim — and it
     * has to be tracked or the ledger goes stale the moment the live client sends anything after the
     * session was opened. Advancing both legs by the same amount preserves whatever divergence an
     * earlier edit or injection created.
     *
     * <p>The {@code NULLPOST} rule applies here too: the sentinel never entered the cipher, so it
     * moves nothing.
     */
    public synchronized void observeUnmodified(Direction direction, byte[] body, int pragma) {
        notePragma(pragma);
        if (body == null || body.length == 0) {
            return;
        }
        if (direction == Direction.REQUEST && PragmaBody.isNullPost(body)) {
            return;
        }
        for (StreamLeg leg : StreamLeg.values()) {
            if (leg.direction() == direction) {
                advance(leg, body.length);
            }
        }
    }

    /** Advances a leg without producing output, for a body whose content is not wanted. */
    public synchronized void advance(StreamLeg leg, int bytes) {
        if (bytes <= 0) {
            return;
        }
        ciphers.get(leg).skip(bytes);
        consumed.merge(leg, (long) bytes, Long::sum);
    }

    /**
     * A detached cipher at a leg's current position, for an encryption that may not happen.
     *
     * <p>Used when a send might still be refused after the bytes are produced: the returned stream
     * advances, this ledger does not, and the caller commits with {@link #advance} only once the
     * request is actually going out.
     */
    public synchronized Rc4Stream cipherAt(StreamLeg leg) {
        return ciphers.get(leg).copy();
    }

    /** A detached cipher at an arbitrary offset, for decoding a message out of sequence. */
    public Rc4Stream cipherAtOffset(long offset) {
        Rc4Stream cipher = new Rc4Stream(key);
        skipTo(cipher, offset);
        return cipher;
    }

    private static void skipTo(Rc4Stream cipher, long offset) {
        // Rc4Stream.skip takes an int; a session large enough to need more than one pass is
        // theoretical, but wrapping would be silent and catastrophic, so it is done in chunks.
        long remaining = offset;
        while (remaining > 0) {
            int chunk = (int) Math.min(remaining, Integer.MAX_VALUE);
            cipher.skip(chunk);
            remaining -= chunk;
        }
    }

    @Override
    public String toString() {
        return "SessionStreams[" + sessionId + " " + Arrays.toString(StreamLeg.values())
                + "=" + consumed + (diverged() ? " DIVERGED" : "") + "]";
    }
}
