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

    /** A source backed by an in-memory map, for tests and fixtures. */
    static PragmaSource of(java.util.Map<Direction, ? extends java.util.Map<Integer, byte[]>> bodies) {
        return (direction, pragma) -> Optional.ofNullable(bodies.get(direction))
                .map(m -> m.get(pragma))
                .map(b -> new PragmaBody(pragma, b));
    }
}
