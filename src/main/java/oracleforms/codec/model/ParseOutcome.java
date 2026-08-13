package oracleforms.codec.model;

/**
 * How a parse ended.
 *
 * <p>A first-class result, not an exception and not a silent truncation. The reference swallowed
 * parse errors with a bare {@code except: pass} and returned partial results indistinguishable from
 * complete ones (architecture &sect;7.6) — so a malformed message from an untrusted target looked
 * exactly like a short one.
 */
public sealed interface ParseOutcome {

    boolean isComplete();

    /** Human-readable explanation, shown alongside partial results. */
    String describe();

    /** The packet was consumed cleanly to its end or to an explicit terminator. */
    record Complete() implements ParseOutcome {
        @Override
        public boolean isComplete() {
            return true;
        }

        @Override
        public String describe() {
            return "parsed completely";
        }
    }

    /** A read ran past the end of the buffer. Everything before {@code offset} is still valid. */
    record Truncated(int offset, String detail) implements ParseOutcome {
        @Override
        public boolean isComplete() {
            return false;
        }

        @Override
        public String describe() {
            return "parsing stopped at offset " + offset + " (" + detail + ")";
        }
    }

    /** The bytes were structurally wrong in a way that is not simply a short read. */
    record Failed(int offset, String reason) implements ParseOutcome {
        @Override
        public boolean isComplete() {
            return false;
        }

        @Override
        public String describe() {
            return "parsing failed at offset " + offset + " (" + reason + ")";
        }
    }
}
