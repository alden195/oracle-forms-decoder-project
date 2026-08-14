package oracleforms.session;

import java.util.Optional;

/**
 * Supplies a session's captured bodies to the replayer, one pragma at a time.
 *
 * <p>The seam that keeps {@link StreamReplayer} testable. The replayer knows about RC4 and ordering
 * and nothing about where bodies come from; the Burp-side implementation knows about proxy history
 * and nothing about RC4 (architecture &sect;4). Replay is where the subtle bugs will be, and this is
 * what lets it be driven by a recorded fixture.
 *
 * <p>Returning {@link Optional#empty()} means "not captured", which the replayer reports as a
 * specific missing pragma rather than a blank failure.
 */
@FunctionalInterface
public interface PragmaSource {

    Optional<PragmaBody> body(Direction direction, int pragma);

    /**
     * The highest pragma number this source holds anything for, in either direction.
     *
     * <p>Only {@link SessionTail} needs this, and it needs it for a specific reason: a forward walk
     * cannot tell "the session ends here" from "there is a hole here" without knowing how far the
     * capture actually goes. Zero means the source cannot say, which makes a tail measurement come
     * back empty rather than wrong.
     */
    default int highestPragma() {
        return 0;
    }

    /** A source backed by an in-memory map, for tests and fixtures. */
    static PragmaSource of(java.util.Map<Direction, ? extends java.util.Map<Integer, byte[]>> bodies) {
        int highest = 0;
        for (java.util.Map<Integer, byte[]> perDirection : bodies.values()) {
            for (Integer pragma : perDirection.keySet()) {
                highest = Math.max(highest, pragma);
            }
        }
        int highestPragma = highest;

        return new PragmaSource() {
            @Override
            public Optional<PragmaBody> body(Direction direction, int pragma) {
                return Optional.ofNullable(bodies.get(direction))
                        .map(m -> m.get(pragma))
                        .map(b -> new PragmaBody(pragma, b));
            }

            @Override
            public int highestPragma() {
                return highestPragma;
            }
        };
    }
}
