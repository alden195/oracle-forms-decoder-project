package oracleforms.session;

/**
 * A session's captured traffic has a hole in it, so its current keystream position is unknown.
 *
 * <p>Thrown when opening a session's live streams, and the reason a send is <strong>refused rather
 * than guessed</strong> (architecture &sect;6.4, Mode A). Encrypting at a position the server is not
 * at does not produce a polite error: the server reads the message as garbage and may tear the
 * session down. Refusing is the only safe answer, and naming the missing pragma is what lets the user
 * do something about it.
 */
public final class StreamGapException extends StreamPositionUnknownException {

    private final Direction direction;
    private final int missing;
    private final int seenLater;

    public StreamGapException(Direction direction, int missing, int seenLater) {
        super(null, "Pragma " + missing + " is missing from the " + direction.name().toLowerCase()
                + " stream, but pragma " + seenLater + " was captured after it. The keystream "
                + "position at the end of this session cannot be reconstructed, so nothing can be "
                + "encrypted for it.");
        this.direction = direction;
        this.missing = missing;
        this.seenLater = seenLater;
    }

    /**
     * True: the pragma is absent from <em>this</em> capture, not necessarily from the world. It may
     * be recoverable by importing the traffic, or the session may simply need re-running with the
     * proxy catching everything.
     */
    @Override
    public boolean isRecoverable() {
        return true;
    }

    public Direction direction() {
        return direction;
    }

    /** The first pragma that is absent. */
    public int missing() {
        return missing;
    }

    /** A pragma captured after the gap, which is what proves this is a hole and not the end. */
    public int seenLater() {
        return seenLater;
    }
}
