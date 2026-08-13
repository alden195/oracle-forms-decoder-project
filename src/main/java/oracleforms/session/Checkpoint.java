package oracleforms.session;

import oracleforms.codec.Rc4Stream;
import oracleforms.codec.StringDictionary;

/**
 * A snapshot of one direction's decode state immediately after a given pragma.
 *
 * <p>Replaying from Pragma 3 every time makes browsing a session O(n²). A checkpoint is the cure:
 * find the nearest one at or below the target, replay forward from there.
 *
 * <p>It carries the string dictionary as well as the cipher state because
 * {@link DictionaryScope#SESSION} would otherwise make the dictionary unreconstructible from a
 * checkpoint — and which scope is correct is still an open question. Holding both means either
 * answer is cheap to adopt.
 *
 * <p>Checkpoints are never persisted. They are derivable from the key, so storing them would trade
 * project-file size for nothing.
 */
public final class Checkpoint {

    private final int pragma;
    private final Rc4Stream rc4;
    private final StringDictionary dictionary;

    private Checkpoint(int pragma, Rc4Stream rc4, StringDictionary dictionary) {
        this.pragma = pragma;
        this.rc4 = rc4;
        this.dictionary = dictionary;
    }

    /** Snapshots the supplied state; later mutation of the originals does not affect the checkpoint. */
    public static Checkpoint after(int pragma, Rc4Stream rc4, StringDictionary dictionary) {
        return new Checkpoint(pragma, rc4.copy(), dictionary.copy());
    }

    /** The pragma this state is <em>after</em>; replay resumes at {@code pragma + 1}. */
    public int pragma() {
        return pragma;
    }

    /** A fresh copy, so a replay can advance it without corrupting the cached state. */
    public Rc4Stream rc4() {
        return rc4.copy();
    }

    /** A fresh copy, for the same reason. */
    public StringDictionary dictionary() {
        return dictionary.copy();
    }
}
