package oracleforms.session;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * The handful of bytes per session that {@link KeyValidation} needs, and its file format.
 *
 * <h2>Why a file at all</h2>
 *
 * <p>Because the protocol assumptions have only ever been tested against synthetic sessions. Proving
 * them needs bytes from the wire, and the Burp MCP server renders message bodies as escaped text,
 * which is lossy for binary — an 8-byte handshake body can arrive as seven visible characters, so
 * the 4-byte randoms cannot be recovered from it. Exporting from inside the extension, where the
 * bytes are still bytes, is the only reliable route.
 *
 * <p>Deliberately tiny: four bodies per session, and only the first {@link #MAX_BODY_BYTES} of the
 * Pragma 3 ones. That is enough to derive a key and parse the opening message, while keeping the file
 * small enough to commit as a test fixture and free of the session's actual application data.
 *
 * <p><strong>These files still contain session secrets</strong> — the handshake randoms are exactly
 * what the key is derived from. Treat an exported fixture the same as the key store.
 */
public final class ValidationFixtures {

    /**
     * How much of each Pragma 3 body to keep.
     *
     * <p>The Pragma 3 request is around 145 bytes and the response can be 28 KB. Only the opening
     * message is needed, and a wrong key never survives even the first few bytes, so keeping the
     * whole response would bloat the file for no extra evidence.
     */
    public static final int MAX_BODY_BYTES = 512;

    /** Refuse pathological inputs outright rather than trying to parse them. */
    private static final int MAX_INPUT_CHARS = 4 * 1024 * 1024;

    /**
     * One session's evidence.
     *
     * <p>Both Pragma 3 bodies are carried because they support different checks: either one drives
     * {@link KeyValidation}, while the pair together drive
     * {@link Pragma3SelfTest#checkStreamSymmetry}, which needs no key at all.
     */
    public record Fixture(
            String sessionId,
            String host,
            byte[] pragma1Request,
            byte[] pragma1Response,
            byte[] pragma3Request,
            byte[] pragma3Response) {

        /** Whether this fixture has everything the validator needs. */
        public boolean isComplete() {
            return pragma1Request.length > 0 && pragma1Response.length > 0
                    && pragma3Request.length > 0;
        }
    }

    private ValidationFixtures() {
    }

    /** Trims a body to {@link #MAX_BODY_BYTES}, tolerating null. */
    public static byte[] trim(byte[] body) {
        if (body == null) {
            return new byte[0];
        }
        return body.length <= MAX_BODY_BYTES
                ? body.clone()
                : java.util.Arrays.copyOf(body, MAX_BODY_BYTES);
    }

    public static String export(List<Fixture> fixtures) {
        HexFormat hex = HexFormat.of();
        StringBuilder out = new StringBuilder(256 + fixtures.size() * 600);
        out.append("[\n");
        for (int i = 0; i < fixtures.size(); i++) {
            Fixture fixture = fixtures.get(i);
            out.append("  {\n");
            field(out, "sessionId", fixture.sessionId(), true);
            field(out, "host", fixture.host(), true);
            field(out, "pragma1Request", hex.formatHex(fixture.pragma1Request()), true);
            field(out, "pragma1Response", hex.formatHex(fixture.pragma1Response()), true);
            field(out, "pragma3Request", hex.formatHex(fixture.pragma3Request()), true);
            field(out, "pragma3Response", hex.formatHex(fixture.pragma3Response()), false);
            out.append("  }").append(i < fixtures.size() - 1 ? "," : "").append('\n');
        }
        out.append("]\n");
        return out.toString();
    }

    /**
     * Parses an exported file, skipping entries that are malformed rather than failing the lot.
     *
     * @param problems collects one message per rejected entry; may be null
     */
    public static List<Fixture> importFrom(String json, List<String> problems) {
        List<Fixture> out = new ArrayList<>();
        if (json == null || json.length() > MAX_INPUT_CHARS) {
            addProblem(problems, "input is empty or too large to parse");
            return out;
        }

        for (Map<String, String> object : KeyStoreJson.objects(json)) {
            String sessionId = object.get("sessionId");
            if (sessionId == null || sessionId.isEmpty()) {
                addProblem(problems, "entry without a sessionId, skipped");
                continue;
            }
            try {
                out.add(new Fixture(
                        sessionId,
                        object.getOrDefault("host", ""),
                        parseHex(object.get("pragma1Request")),
                        parseHex(object.get("pragma1Response")),
                        parseHex(object.get("pragma3Request")),
                        parseHex(object.get("pragma3Response"))));
            } catch (RuntimeException e) {
                addProblem(problems, "entry for session " + sessionId + " skipped: " + e.getMessage());
            }
        }
        return out;
    }

    private static byte[] parseHex(String value) {
        if (value == null || value.isEmpty()) {
            return new byte[0];
        }
        return HexFormat.of().parseHex(value.trim());
    }

    private static void field(StringBuilder out, String name, String value, boolean comma) {
        out.append("    \"").append(name).append("\": \"").append(escape(value)).append('"')
                .append(comma ? "," : "").append('\n');
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static void addProblem(List<String> problems, String message) {
        if (problems != null) {
            problems.add(message);
        }
    }
}
