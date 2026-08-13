package oracleforms.session;

/**
 * Whether the FHT string dictionary lives for one packet or for the whole session.
 *
 * <p>This is architecture &sect;7.2's open question, made explicit rather than hard-coded. The
 * reference implementation resets the dictionary per packet, while the RC4 stream it rides on is
 * emphatically per session. If Oracle in fact scopes the dictionary to the session, resetting it per
 * packet makes every back-reference resolve to an empty string and values silently disappear — a
 * failure that looks like missing data, not like a bug.
 *
 * <p>The two differ in cost as well as in meaning, which is why the choice is not free:
 *
 * <ul>
 *   <li>{@link #PACKET} — intervening packets need only advance the keystream. Replay can
 *       {@link oracleforms.codec.Rc4Stream#skip skip} them without decrypting or parsing.
 *   <li>{@link #SESSION} — intervening packets must be decrypted <em>and</em> parsed, because their
 *       strings populate the dictionary the target packet reads back from.
 * </ul>
 *
 * <p>Settle it by decoding one session both ways and looking for empty back-references.
 */
public enum DictionaryScope {

    /** Reset per packet, as the reference implementation does. The current default. */
    PACKET,

    /** Carried across the whole session, as the RC4 stream is. */
    SESSION
}
