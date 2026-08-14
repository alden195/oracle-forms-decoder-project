package oracleforms.burp;

import java.util.Optional;

/**
 * Plaintext for message bodies that cannot be reached by replaying proxy history.
 *
 * <p>Exists because a Repeater send and its reply never enter the proxy history, so the
 * "stored key → replay preceding pragmas → decrypt" path that decodes everything else has nothing to
 * work from. The interceptor already holds the plaintext at the moment it decrypts the reply, so it
 * deposits it here and the response editor finds it (architecture &sect;6.5).
 *
 * <p>Keyed on a hash of the <em>ciphertext</em> rather than on (session, pragma). Repeated sends of
 * different bodies reuse the same pragma number, so keying on the number would have them overwrite
 * each other; the ciphertext is what the editor is actually holding and asking about.
 */
public interface DecodedBodyCache {

    /** Records the plaintext for a body, replacing any previous entry for the same bytes. */
    void put(byte[] ciphertext, byte[] plaintext);

    /** The plaintext for a body, if it was decoded outside the replay path. */
    Optional<byte[]> get(byte[] ciphertext);
}
